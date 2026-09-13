#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# verify-model-weights.py — download a HuggingFace repo's pickle-format weight
# files and run the same local picklescan verification MODE=MODELFILE already
# runs on a supplied file, so an AI-model (--model) scan gets an independent
# verdict instead of only trusting HuggingFace's own scan (bomlens:hf:scan:*,
# stamped by enrich-aibom.sh from the Hub's metadata API — no download there).
#
# Opt-in (--verify-weights / VERIFY_MODEL_WEIGHTS=true): unlike the
# metadata-only enrichment steps, this downloads real bytes, so it costs real
# network time and disk, and it runs code-adjacent analysis (picklescan) over
# content BomLens fetched rather than only reading what the Hub already
# published about it.
#
# Only the pickle-family weight extensions are ever downloaded: .bin, .pt,
# .pth, .ckpt — the ones whose payload is a Python pickle and therefore run
# code on load. This mirrors enrich-aibom.sh's PICKLE_EXTS and the EXT_CLAIMS
# entries identify-model-file.py maps to "pickle"/"pytorch". safetensors, GGUF,
# ONNX and friends are never fetched here: they do not execute code on load,
# so picklescan has nothing to check and downloading them would only spend
# bandwidth on files that can run into the gigabytes.
#
# Bounded by design: AIBOM_VERIFY_MAX_FILES caps how many weight files are
# checked (extra files beyond the cap are left unchecked, not queued) and
# AIBOM_VERIFY_MAX_BYTES caps the size of any one file that is downloaded (a
# file over the cap is skipped, not truncated — picklescan needs the whole
# stream). Every downloaded file is deleted right after it is scanned, and the
# HuggingFace cache used for the download is confined to a temp directory that
# is removed when this script exits either way.
#
# Multiple weight files roll up onto the model component the same way
# enrich-aibom.sh's Hub-scan section already rolls up multiple per-file
# results: worst status wins (unsafe > suspicious > error > clean >
# not-applicable), and each finding is prefixed with the file it came from.
# The property names are the same ones scan-model-file-security.py (MODELFILE)
# writes — bomlens:localscan:status / :tool / :findings — so a consumer of the
# SBOM does not need to know which mode produced them; assess-ai-risk.sh
# already reads bomlens:localscan:* regardless of source.
#
# If every candidate file was skipped (size cap) or none exist, nothing is
# stamped: "not-applicable" would falsely claim the format was checked and
# found safe, when it was simply never looked at.
#
# Best-effort by design, matching every other AIBOM enrichment step: missing
# huggingface_hub, a network failure, or an unreadable file leaves the SBOM
# unchanged (or, once at least one file scanned, honestly reflects only what
# was actually checked) rather than failing the whole scan.
#
# Usage: verify-model-weights.py <sbom.json> <hf_model_id>

import importlib.util
import json
import os
import shutil
import sys
import tempfile

LIBDIR = os.path.dirname(os.path.abspath(__file__))

# The pickle-family extensions: the only weight formats that execute code on
# load. Restated here rather than imported — enrich-aibom.sh's PICKLE_EXTS
# lives inside a bash heredoc, not an importable module, and this project's
# convention is to restate such small constants at each site with a comment
# pointing at the sibling that must stay in step (see identify-model-file.py's
# own restatement of scan-model-file-security.py's PICKLE_FORMATS).
PICKLE_WEIGHT_EXTS = (".bin", ".pt", ".pth", ".ckpt")

# Worst-wins rank for bomlens:localscan:status, the same ordering
# assess-ai-risk.sh already applies when judging the property's value.
STATUS_RANK = {"not-applicable": 0, "clean": 1, "error": 2, "suspicious": 3, "unsafe": 4}

MAX_FINDINGS = 8  # same cap scan-model-file-security.py uses for the property


def cap(name, default):
    """A positive integer from the environment, or the default.

    Empty/malformed input falls back to the default rather than being read as
    zero — a cap is a safety limit, not a way to silently verify nothing.
    """
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_FILES = cap("AIBOM_VERIFY_MAX_FILES", 5)
MAX_BYTES = cap("AIBOM_VERIFY_MAX_BYTES", 2 * 1024 * 1024 * 1024)  # per file


def _load_sibling(filename):
    """Import a hyphenated sibling script in docker/lib/ for its functions.

    The scripts in this directory are invoked as standalone CLIs (hyphenated
    filenames, not valid Python module names), so a plain `import` cannot
    reach them; this loads by path instead.
    """
    modname = "_bomlens_" + filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(modname, os.path.join(LIBDIR, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _get(o, name, default=None):
    if isinstance(o, dict):
        return o.get(name, default)
    return getattr(o, name, default)


def model_components(doc):
    """Every machine-learning-model component in the document, wherever it
    sits. Mirrors enrich-aibom.sh's model_components(): the AIBOM generator
    leaves the model in components[] and fills metadata.component with its own
    scan job, and either place is a valid model to stamp."""
    found = []
    meta = doc.get("metadata")
    root = meta.get("component") if isinstance(meta, dict) else None
    for c in ([root] if isinstance(root, dict) else []) + list(doc.get("components") or []):
        if isinstance(c, dict) and c.get("type") == "machine-learning-model":
            found.append(c)
    return found


def list_pickle_weights(hf_api, model_id):
    """[(path, size_or_None)] for the repo's pickle-family weight files.

    Sorted for a deterministic pick when AIBOM_VERIFY_MAX_FILES cuts the list,
    so --byte-stable output does not depend on API listing order.
    """
    out = []
    for f in hf_api.list_repo_tree(model_id, expand=True):
        path = str(_get(f, "path", "") or "")
        if not path.lower().endswith(PICKLE_WEIGHT_EXTS):
            continue
        size = _get(f, "size", None)
        out.append((path, int(size) if isinstance(size, (int, float)) else None))
    out.sort()
    return out


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: verify-model-weights.py <sbom.json> <hf_model_id>\n")
        return 2
    sbom_path, model_id = sys.argv[1], sys.argv[2]
    if not os.path.isfile(sbom_path):
        sys.stderr.write("[verify-weights] SBOM file not found: %s\n" % sbom_path)
        return 1
    if not model_id:
        sys.stderr.write("[verify-weights] no model id given; nothing to verify.\n")
        return 0

    # Confine both the download and the huggingface_hub cache to one temp
    # directory: whatever hf_hub_download does internally (copy or symlink
    # from a blob cache), everything lands under here and one rmtree clears it
    # all, regardless of huggingface_hub version behavior.
    tmp_root = tempfile.mkdtemp(prefix="bomlens-verify-weights-")
    os.environ["HF_HUB_CACHE"] = os.path.join(tmp_root, "cache")

    try:
        from huggingface_hub import HfApi, hf_hub_download
    except ImportError:
        sys.stderr.write("[verify-weights] huggingface_hub is not installed in this image; skipping.\n")
        shutil.rmtree(tmp_root, ignore_errors=True)
        return 1

    scanmod = _load_sibling("scan-model-file-security.py")
    identmod = _load_sibling("identify-model-file.py")

    hf_api = HfApi()
    try:
        candidates = list_pickle_weights(hf_api, model_id)
    except Exception as e:
        sys.stderr.write("[verify-weights] could not list repository files: %s\n" % e)
        shutil.rmtree(tmp_root, ignore_errors=True)
        return 1

    if not candidates:
        sys.stderr.write("[verify-weights] no pickle-format weight file found; nothing to verify.\n")
        shutil.rmtree(tmp_root, ignore_errors=True)
        return 0

    oversized = [p for p, s in candidates if s is not None and s > MAX_BYTES]
    within_cap = [(p, s) for p, s in candidates if not (s is not None and s > MAX_BYTES)]
    truncated = len(within_cap) > MAX_FILES
    checked_list = within_cap[:MAX_FILES]

    results = []  # (path, status, [finding, ...])
    try:
        for path, _size in checked_list:
            try:
                local = hf_hub_download(model_id, path, cache_dir=tmp_root)
            except Exception as e:
                results.append((path, "error", ["download failed: %s" % e]))
                continue
            try:
                if os.path.getsize(local) > MAX_BYTES:
                    # The tree API's size can be stale; the bytes are the truth.
                    results.append((path, None, []))  # None: don't count as scanned
                    continue
                head = identmod.read_head(local, 8)
                fmt, _extra = identmod.sniff_format(local, head)
                status, findings = scanmod.scan(local, fmt)
                results.append((path, status, findings))
            except Exception as e:
                results.append((path, "error", ["scan failed: %s" % e]))
            finally:
                try:
                    os.remove(local)
                except OSError:
                    pass
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    scanned = [(p, s, f) for p, s, f in results if s is not None]
    skipped_after_download = [p for p, s, _f in results if s is None]

    if not scanned:
        sys.stderr.write("[verify-weights] no candidate weight file could be scanned within the "
                          "size cap (%d file(s) skipped); nothing stamped.\n"
                          % (len(oversized) + len(skipped_after_download)))
        return 0

    agg_status = "not-applicable"
    findings = []
    for path, status, per_findings in scanned:
        if STATUS_RANK.get(status, STATUS_RANK["error"]) > STATUS_RANK[agg_status]:
            agg_status = status
        findings.extend("%s: %s" % (path, f) for f in per_findings)

    with open(sbom_path, encoding="utf-8") as fh:
        bom = json.load(fh)

    components = model_components(bom)
    if not components:
        sys.stderr.write("[verify-weights] no model component; nothing to stamp.\n")
        return 0

    tool_version = scanmod.tool_version()
    skipped_total = len(oversized) + len(skipped_after_download)
    for component in components:
        props = component.setdefault("properties", [])
        # Idempotent: a re-run replaces its own properties, matching
        # scan-model-file-security.py's contract for --byte-stable output.
        props[:] = [p for p in props if not str(p.get("name", "")).startswith("bomlens:localscan:")]
        props.append({"name": "bomlens:localscan:status", "value": agg_status})
        props.append({"name": "bomlens:localscan:tool", "value": tool_version})
        props.append({"name": "bomlens:localscan:filesChecked", "value": str(len(scanned))})
        if truncated or skipped_total:
            props.append({"name": "bomlens:localscan:filesSkipped", "value": str(skipped_total)})
        if findings:
            props.append({"name": "bomlens:localscan:findings",
                          "value": "; ".join(findings[:MAX_FINDINGS])[:500]})

    with open(sbom_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    detail = (" (%s)" % "; ".join(findings[:3])) if findings else ""
    sys.stderr.write("[verify-weights] %s: %d file(s) checked, %d skipped%s\n"
                     % (agg_status, len(scanned), skipped_total, detail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
