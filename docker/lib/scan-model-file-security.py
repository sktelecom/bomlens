#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# scan-model-file-security.py — decide whether a scanned model file executes
# code when it is loaded, and record the answer on its component.
#
# Usage: scan-model-file-security.py <sbom.json> <model_file>
#
# Why: pickle is not a data format. Loading one runs whatever the stream tells
# the interpreter to run, which is why a weight file in that format is a
# supply-chain risk in its own right. BomLens already reports this for models on
# HuggingFace by reading the scan the Hub itself ran (bomlens:hf:scan:*), so the
# gap was exactly the case MODE=MODELFILE was added for: a file nobody
# published, that no Hub API knows about.
#
# picklescan (MIT) does the pickle analysis — the same tool HuggingFace runs.
# Writing our own opcode walker was considered and rejected: a subtle bug in a
# hand-rolled parser produces false reassurance, which is worse than no verdict.
# What is ours is deciding WHICH bytes to hand it, since the tool will happily
# scan a file that holds no pickle at all and report nothing wrong.
#
# Keras (.h5/.keras) is not pickle at all — the equivalent risk is a Lambda
# layer carrying marshal.dumps()'d bytecode, which identify-model-file.py
# already looked for (header-bytes-only) and recorded as
# bomlens:weights:marshalledCode. This step's only job for that format is
# translating that flag into the same status vocabulary below; no picklescan
# call is involved, and bomlens:localscan:tool says so.
#
# Verdicts (bomlens:localscan:status):
#   unsafe          a dangerous global (os.system, subprocess, …) is reachable
#   suspicious      globals that could be code, e.g. a custom class — a human
#                   has to look. Common in legitimate checkpoints. Also used
#                   for a detected Keras Lambda layer, for the same reason.
#   clean           pickle bytes were parsed and held nothing of the kind (or,
#                   for Keras, no Lambda layer was found)
#   not-applicable  the format does not execute code on load (GGUF,
#                   safetensors, ONNX, plain npy)
#   error           the file could not be parsed; explicitly NOT a pass
#
# Best-effort by design: a failure here leaves the property unset and the
# assessment simply has no security axis, which reads as "not scanned" rather
# than "safe".

import ast
import io
import json
import os
import struct
import sys
import zipfile

MAX_FINDINGS = 8          # named in the property; the full list is in the tool
MAX_NPZ_MEMBERS = 64      # bounded work on a hostile archive
MAX_NPZ_BYTES = 64 * 1024 * 1024

# Formats whose payload is a Python pickle, i.e. the ones worth scanning. Kept
# in step with identify-model-file.py, which is what wrote the property.
PICKLE_FORMATS = ("pickle", "pytorch-zip")

# Formats whose code-execution risk is a Keras Lambda layer, not a pickle.
# Kept in step with identify-model-file.py's EXT_CLAIMS/sniff_format.
KERAS_FORMATS = ("keras-h5", "keras-zip")


def tool_version(fmt=None):
    if fmt in KERAS_FORMATS:
        # This verdict is a translation of the static Lambda-layer scan
        # identify-model-file.py already ran; picklescan was never invoked on
        # this file, so naming it here would credit a tool that never ran.
        return "bomlens-modelfile-scan"
    try:
        from importlib.metadata import version
        return "picklescan@%s" % version("picklescan")
    except Exception:
        return "picklescan"


def npy_object_payload(raw):
    """Return the pickle bytes inside a .npy member, or None.

    A numpy array of dtype object is stored as a header followed by a pickle of
    the objects. Any other dtype is plain numeric data with nothing to execute,
    so it is skipped rather than handed to the scanner.
    """
    if not raw.startswith(b"\x93NUMPY") or len(raw) < 10:
        return None
    major = raw[6]
    if major == 1:
        (hlen,) = struct.unpack("<H", raw[8:10])
        start = 10
    else:
        (hlen,) = struct.unpack("<I", raw[8:12])
        start = 12
    header = raw[start:start + hlen]
    try:
        meta = ast.literal_eval(header.decode("latin-1").strip())
    except (ValueError, SyntaxError, UnicodeDecodeError):
        return None
    descr = meta.get("descr") if isinstance(meta, dict) else None
    # '|O', 'O', "|O8" — the object dtypes, and the only ones carrying a pickle.
    if not isinstance(descr, str) or "O" not in descr:
        return None
    return raw[start + hlen:]


def scan(path, fmt, marshalled_code=False):
    """(status, findings) for one model file.

    marshalled_code is the bomlens:weights:marshalledCode flag
    identify-model-file.py already stamped for a Keras file; it is the only
    input the Keras branch below needs, since the detection itself already
    happened there.
    """
    from picklescan.scanner import scan_file_path, scan_pickle_bytes

    def verdict(result):
        dangerous = [g for g in result.globals if str(g.safety).endswith("Dangerous")]
        if dangerous:
            return "unsafe", ["%s.%s" % (g.module, g.name) for g in dangerous]
        suspicious = [g for g in result.globals if str(g.safety).endswith("Suspicious")]
        if suspicious:
            return "suspicious", ["%s.%s" % (g.module, g.name) for g in suspicious]
        return "clean", []

    if fmt in PICKLE_FORMATS:
        result = scan_file_path(path)
        if result.scan_err:
            return "error", []
        return verdict(result)

    if fmt == "npz":
        # Only the members that actually hold a pickle are scanned, so a plain
        # numeric archive is reported as what it is rather than as "clean",
        # which would imply something was examined.
        worst, found, examined = "not-applicable", [], 0
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:MAX_NPZ_MEMBERS]:
                if not info.filename.endswith(".npy"):
                    continue
                if info.file_size > MAX_NPZ_BYTES:
                    continue
                payload = npy_object_payload(archive.read(info))
                if payload is None:
                    continue
                examined += 1
                result = scan_pickle_bytes(io.BytesIO(payload), info.filename)
                status, names = verdict(result)
                found += ["%s: %s" % (info.filename, n) for n in names]
                if status == "unsafe" or (status == "suspicious" and worst != "unsafe"):
                    worst = status
                elif worst == "not-applicable":
                    worst = "clean"
        if examined == 0:
            return "not-applicable", []
        return worst, found

    if fmt in KERAS_FORMATS:
        # A human still has to look — a Lambda layer is common in legitimate
        # checkpoints (a custom activation function is enough), same as a
        # custom class reachable from a pickle. This is a translation of the
        # header-bytes scan identify-model-file.py already ran, not a new scan.
        if marshalled_code:
            return "suspicious", ["Keras Lambda layer with embedded marshalled code"]
        return "clean", []

    return "not-applicable", []


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: scan-model-file-security.py <sbom.json> <model_file>\n")
        return 2
    sbom_path, model_path = sys.argv[1], sys.argv[2]
    if not os.path.isfile(sbom_path) or not os.path.isfile(model_path):
        sys.stderr.write("[modelscan] input missing\n")
        return 1

    with open(sbom_path, encoding="utf-8") as handle:
        bom = json.load(handle)

    components = [c for c in bom.get("components", [])
                  if isinstance(c, dict) and c.get("type") == "machine-learning-model"]
    if not components:
        sys.stderr.write("[modelscan] no model component; nothing to scan.\n")
        return 0
    component = components[0]

    props = component.setdefault("properties", [])
    fmt = next((p.get("value") for p in props
                if p.get("name") == "bomlens:modelfile:format"), "")
    marshalled_code = any(p.get("name") == "bomlens:weights:marshalledCode"
                           and p.get("value") == "1" for p in props)

    try:
        status, findings = scan(model_path, fmt, marshalled_code)
    except ImportError:
        sys.stderr.write("[modelscan] picklescan is not installed in this image; "
                         "no local security verdict.\n")
        return 1
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        sys.stderr.write("[modelscan] could not scan %s: %s\n"
                         % (os.path.basename(model_path), exc))
        status, findings = "error", []

    # Idempotent: a re-run replaces its own properties rather than appending, so
    # --byte-stable output stays byte-identical.
    props[:] = [p for p in props if not str(p.get("name", "")).startswith("bomlens:localscan:")]
    props.append({"name": "bomlens:localscan:status", "value": status})
    props.append({"name": "bomlens:localscan:tool", "value": tool_version(fmt)})
    if findings:
        props.append({"name": "bomlens:localscan:findings",
                      "value": "; ".join(findings[:MAX_FINDINGS])})

    with open(sbom_path, "w", encoding="utf-8") as handle:
        json.dump(bom, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    detail = (" (%s)" % "; ".join(findings[:3])) if findings else ""
    sys.stderr.write("[modelscan] %s: %s%s\n"
                     % (os.path.basename(model_path), status, detail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
