#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Add the components a declaration file lists to the SBOM of a source scan.

Usage: apply-declared-components.py <bom.json> <scan-root> <declaration.json>...

A declaration file (sbom-declared.cdx.json by default, or each --components
file) is a CycloneDX document that lists what a scan cannot find: the
supplier's own build outputs, and third-party parts added by hand (a chip
vendor's binary, a HAL copied into the tree). Every component says which of
the two it is in the property bomlens:origin (first-party or third-party), and
the value is kept as it is.

The file is someone else's input, so a component may carry only the CycloneDX
1.6 fields listed in ALLOWED, each checked against the shape the schema gives
it. Anything else is refused with the field's name rather than copied into the
SBOM unseen.

A component may name its build outputs in bomlens:artifact, a path relative to
the scan root (the property may repeat). The file is read here, and its
SHA-512 and SHA-256 hashes, its file name (bsi:component:filename) and what
kind of file it is (bsi:component:executable, bsi:component:archive and
bsi:component:structured, from the file's own bytes) are filled in. A value
for one of the three kinds that the declaration gives itself is kept instead
of the one read from the file. With one artifact these go on the component
itself. With several, each file becomes a nested component of type "file"
under the declared one (a CycloneDX assembly), carrying its own hashes and
properties, and the declared component carries none: one set of hashes cannot
describe several files.

A first-party component with no version takes the product's version
(metadata.component.version). A file that has `dependencies` keeps them, and
the product depends on each of its components that nothing else in the file
depends on; a file without them makes the product depend on each component.
Any declared component still not reachable from the product afterwards is
linked from it too.

A build output that is missing because --exclude left its folder out of the
scanned copy (SCAN_EXCLUDE_PATHS, one path per line) is reported as such. When
the file is the one found at the scan target root rather than one given with
--components (DECLARED_COMPONENTS_DEFAULT=1), a missing build output says how
to scan without it (--no-components).

The labels the user knows the files by (the paths given on the command line)
come from DECLARED_COMPONENTS_LABELS, one per line in the order of the
arguments; without it the path is used.

Every component added here carries bomlens:declared = true. Components an
earlier run added (that mark and a bomlens:origin value) are replaced, so
applying the same files twice gives the same SBOM.

Exit 0 when applied, 3 when a file is refused (every problem is printed, and
the SBOM is left as it was), 1 when the SBOM itself cannot be read or written.
"""
import bz2
import copy
import hashlib
import json
import lzma
import os
import re
import sys
import zlib

MAX_DECLARATION_BYTES = 4 * 1024 * 1024
MAX_COMPONENTS = 10000
MAX_PROBLEMS = 50
# Enough of a file to see an ISO 9660 volume descriptor (at 0x8001).
HEAD_BYTES = 0x8800
# A PE header further into the file than this is not looked for.
MAX_PE_OFFSET = 16 * 1024 * 1024
ORIGIN = "bomlens:origin"
ARTIFACT = "bomlens:artifact"
MARK = "bomlens:declared"
ORIGINS = ("first-party", "third-party")
FILENAME = "bsi:component:filename"
EXECUTABLE = "bsi:component:executable"
ARCHIVE = "bsi:component:archive"
STRUCTURED = "bsi:component:structured"
# The values BSI TR-03183-2 v2.1.0 gives each file property.
KIND_VALUES = {
    EXECUTABLE: ("executable", "non-executable"),
    ARCHIVE: ("archive", "no archive"),
    STRUCTURED: ("structured", "unstructured"),
}
FILLED_HASHES = ("SHA-512", "SHA-256")

# CycloneDX 1.6 component types.
TYPES = ("application", "framework", "library", "container", "platform",
         "operating-system", "device", "device-driver", "firmware", "file",
         "machine-learning-model", "data", "cryptographic-asset")
HASH_ALGS = ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256",
             "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3")
HASH_CONTENT = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$")
EXTREF_TYPES = (
    "vcs", "issue-tracker", "website", "advisories", "bom", "mailing-list", "social",
    "chat", "documentation", "support", "source-distribution", "distribution",
    "distribution-intake", "license", "build-meta", "build-system", "release-notes",
    "security-contact", "model-card", "log", "configuration", "evidence", "formulation",
    "attestation", "threat-model", "adversary-model", "risk-assessment",
    "vulnerability-assertion", "exploitability-statement", "pentest-report",
    "static-analysis-report", "dynamic-analysis-report", "runtime-analysis-report",
    "component-analysis-report", "maturity-report", "certification-report",
    "codified-infrastructure", "quality-metrics", "poam", "electronic-signature",
    "digital-signature", "rfc-9116", "other")
SCOPES = ("required", "optional", "excluded")
SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")
PURL = re.compile(r"^pkg:[A-Za-z.+-][A-Za-z0-9.+-]*/.+")
MIME = re.compile(r"^[-+a-z0-9.]+/[-+a-z0-9.]+$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

STRING_FIELDS = ("name", "version", "bom-ref", "group", "description", "copyright",
                 "cpe", "purl", "publisher", "author", "mime-type")
# Single-line identifiers: a control character in one is a mistake, not text.
LINE_FIELDS = ("name", "version", "bom-ref", "group", "cpe", "purl", "publisher", "author")
ALLOWED = set(STRING_FIELDS) | {"type", "scope", "tags", "supplier", "manufacturer", "authors",
                                "hashes", "licenses", "externalReferences", "properties"}


class Refused(Exception):
    pass


def log(msg):
    print("[declared-components] " + msg, file=sys.stderr)


def props(comp, name):
    return [p.get("value") for p in comp.get("properties") or []
            if isinstance(p, dict) and p.get("name") == name]


# ---------------------------------------------------------------- field shapes
def _str_list(value):
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _string_map(value, keys):
    """A JSON object whose keys are among `keys` and whose values are strings."""
    return isinstance(value, dict) and set(value) <= set(keys) \
        and all(isinstance(v, str) for v in value.values())


def _contact(value):
    return _string_map(value, ("name", "email", "phone", "bom-ref"))


def _entity(value):
    """CycloneDX organizationalEntity (supplier, manufacturer)."""
    if not isinstance(value, dict) or not set(value) <= {"name", "url", "contact", "address", "bom-ref"}:
        return False
    if "name" in value and not isinstance(value["name"], str):
        return False
    if "bom-ref" in value and not isinstance(value["bom-ref"], str):
        return False
    if "url" in value and not _str_list(value["url"]):
        return False
    if "contact" in value and not (isinstance(value["contact"], list) and all(_contact(c) for c in value["contact"])):
        return False
    if "address" in value and not _string_map(value["address"], (
            "bom-ref", "country", "region", "locality", "postOfficeBoxNumber", "postalCode", "streetAddress")):
        return False
    return True


def _hashes(value):
    return isinstance(value, list) and all(
        isinstance(h, dict) and set(h) == {"alg", "content"}
        and h["alg"] in HASH_ALGS and isinstance(h["content"], str) and HASH_CONTENT.match(h["content"])
        for h in value)


def _license(value):
    if not isinstance(value, dict) or not set(value) <= {"id", "name", "text", "url", "acknowledgement", "bom-ref"}:
        return False
    if ("id" in value) == ("name" in value):
        return False
    if "id" in value and not (isinstance(value["id"], str) and SPDX_ID.match(value["id"])):
        return False
    if "name" in value and not (isinstance(value["name"], str) and value["name"].strip()):
        return False
    if "text" in value and not (_string_map(value["text"], ("content", "contentType", "encoding"))
                                and "content" in value["text"]
                                and value["text"].get("encoding", "base64") == "base64"):
        return False
    for key in ("url", "bom-ref"):
        if key in value and not isinstance(value[key], str):
            return False
    return value.get("acknowledgement", "declared") in ("declared", "concluded")


def _licenses(value):
    """A list of {"license": ...} objects, or one {"expression": ...}."""
    if not isinstance(value, list):
        return False
    if any(isinstance(x, dict) and "expression" in x for x in value):
        return len(value) == 1 and isinstance(value[0], dict) \
            and set(value[0]) <= {"expression", "acknowledgement", "bom-ref"} \
            and isinstance(value[0]["expression"], str) and value[0]["expression"].strip() != "" \
            and value[0].get("acknowledgement", "declared") in ("declared", "concluded") \
            and isinstance(value[0].get("bom-ref", ""), str)
    return all(isinstance(x, dict) and set(x) == {"license"} and _license(x["license"]) for x in value)


def _extrefs(value):
    return isinstance(value, list) and all(
        isinstance(r, dict) and set(r) <= {"url", "type", "comment", "hashes"}
        and isinstance(r.get("url"), str) and r["url"].strip() != ""
        and r.get("type") in EXTREF_TYPES
        and isinstance(r.get("comment", ""), str)
        and ("hashes" not in r or _hashes(r["hashes"]))
        for r in value)


def _properties(value):
    return isinstance(value, list) and all(
        isinstance(p, dict) and set(p) <= {"name", "value"}
        and isinstance(p.get("name"), str) and isinstance(p.get("value", ""), str)
        for p in value)


SHAPES = {
    "supplier": (_entity, 'an organization ({"name": ..., "url": [...], "contact": [...]})'),
    "manufacturer": (_entity, 'an organization ({"name": ..., "url": [...], "contact": [...]})'),
    "authors": (lambda v: isinstance(v, list) and all(_contact(c) for c in v),
                'a list of {"name": ..., "email": ..., "phone": ...}'),
    "hashes": (_hashes, 'a list of {"alg": ..., "content": ...} with a CycloneDX algorithm and a hex digest'),
    "licenses": (_licenses, 'a list of {"license": {"id": ...}} or {"license": {"name": ...}}, '
                            'or a single {"expression": ...}'),
    "externalReferences": (_extrefs, 'a list of {"url": ..., "type": ...} with a CycloneDX reference type'),
    "properties": (_properties, 'a list of {"name": ..., "value": ...}'),
    "tags": (_str_list, "a list of strings"),
}


# ---------------------------------------------------------------- file type
def _decompressed_head(head):
    """The first bytes inside a gzip, bzip2 or xz stream, or None."""
    try:
        if head[:2] == b"\x1f\x8b":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head, 512)
        if head[:3] == b"BZh":
            return bz2.BZ2Decompressor().decompress(head, 512)
        if head[:6] == b"\xfd7zXZ\x00":
            return lzma.LZMADecompressor().decompress(head, 512)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    return None


def file_kind(head, pe_signature=b""):
    """(executable, archive, structured) from the first bytes of a file.

    structured follows BSI TR-03183-2 v2.1.0 (8.1.6): an archive that holds
    metadata about what it contains (zip, tar, also compressed, 7z, rar, rpm,
    deb and other ar archives, cpio, ISO 9660) is structured; a plain
    executable, a firmware image and a single compressed stream that is not a
    tar are not. zstd and lz4 cannot be opened with the standard library, so a
    tar inside one is not seen and the file counts as unstructured.
    """
    executable = False
    if head[:4] == b"\x7fELF" and len(head) >= 18:
        # e_type: 2 executable, 3 shared object or position-independent
        # executable. A relocatable object (1) or a core dump (4) is not.
        order = "little" if head[5:6] == b"\x01" else "big"
        executable = int.from_bytes(head[16:18], order) in (2, 3)
    elif head[:2] == b"MZ":
        executable = pe_signature == b"PE\x00\x00"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                      b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        executable = True
    elif head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # A universal Mach-O binary and a Java class file share this magic.
        # The next word is the number of architectures in the first, a small
        # number, and the class file version in the second (45 or more).
        executable = int.from_bytes(head[4:8], "big") < 45
    tar = head[257:262] == b"ustar"
    with_index = (head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
                  or head[:6] == b"7z\xbc\xaf\x27\x1c"
                  or head[:7] == b"Rar!\x1a\x07"
                  or head[:8] == b"!<arch>\n"
                  or head[:4] == b"\xed\xab\xee\xdb"
                  or head[:6] in (b"070701", b"070702", b"070707")
                  or head[0x8001:0x8006] == b"CD001"
                  or tar)
    stream = (head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"
              or head[:4] == b"\x28\xb5\x2f\xfd" or head[:4] == b"\x04\x22\x4d\x18")
    inner = _decompressed_head(head) if stream else None
    compressed_tar = inner is not None and inner[257:262] == b"ustar"
    archive = with_index or stream
    structured = with_index or compressed_tar
    return executable, archive, structured


def read_artifact(path):
    sha512 = hashlib.sha512()
    sha256 = hashlib.sha256()
    head = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            if len(head) < HEAD_BYTES:
                head += chunk[:HEAD_BYTES - len(head)]
            sha512.update(chunk)
            sha256.update(chunk)
        signature = b""
        if head[:2] == b"MZ" and len(head) >= 64:
            # The PE header sits where e_lfanew says, which can be past the
            # bytes kept above; read the four signature bytes there.
            offset = int.from_bytes(head[60:64], "little")
            if 64 <= offset <= MAX_PE_OFFSET:
                fh.seek(offset)
                signature = fh.read(4)
    executable, archive, structured = file_kind(head, signature)
    return {
        "hashes": [{"alg": "SHA-512", "content": sha512.hexdigest()},
                   {"alg": "SHA-256", "content": sha256.hexdigest()}],
        "kinds": {
            EXECUTABLE: "executable" if executable else "non-executable",
            ARCHIVE: "archive" if archive else "no archive",
            STRUCTURED: "structured" if structured else "unstructured",
        },
    }


def excluded_paths():
    """The paths --exclude took out of the scanned copy (SCAN_EXCLUDE_PATHS,
    one relative path per line), so a missing artifact under one of them is
    reported as excluded rather than as not built."""
    out = []
    for line in os.environ.get("SCAN_EXCLUDE_PATHS", "").split("\n"):
        p = "/".join(x for x in line.strip().split("/") if x not in ("", "."))
        if p:
            out.append(p)
    return out


def resolve_artifact(root, value):
    """The real path of an artifact inside root, or raise Refused with why."""
    if not isinstance(value, str) or not value.strip():
        raise Refused("bomlens:artifact is empty")
    if CONTROL.search(value):
        raise Refused("bomlens:artifact '%s' holds a control character" % value.encode("unicode_escape").decode())
    if "\\" in value:
        raise Refused("bomlens:artifact '%s' uses a backslash; write the path with forward slashes" % value)
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise Refused("bomlens:artifact '%s' is an absolute path; give the path relative to the scan target root" % value)
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise Refused("bomlens:artifact '%s' contains '..'; it must stay inside the scan target" % value)
    if not parts:
        raise Refused("bomlens:artifact '%s' names the scan target itself, not a file" % value)
    candidate = os.path.join(root, *parts)
    real = os.path.realpath(candidate)
    if os.path.commonpath([root, real]) != root:
        raise Refused("bomlens:artifact '%s' leads outside the scan target through a symbolic link" % value)
    if not os.path.exists(real):
        rel = "/".join(parts)
        # Compared without regard to case: on a file system that ignores it
        # (macOS, Windows) the copy left out the path whatever case it had.
        for ex in excluded_paths():
            if rel.lower() == ex.lower() or rel.lower().startswith(ex.lower() + "/"):
                raise Refused("bomlens:artifact '%s' is under '%s', which --exclude leaves out of the scan; "
                              "drop that --exclude or list the file elsewhere" % (value, ex))
        hint = "build it before the scan, or fix the path"
        if os.environ.get("DECLARED_COMPONENTS_DEFAULT") == "1":
            hint += ("; this file was read because it is at the scan target root, "
                     "so pass --no-components to scan without it")
        raise Refused("bomlens:artifact '%s' does not exist in the scan target; %s" % (value, hint))
    if not os.path.isfile(real):
        raise Refused("bomlens:artifact '%s' is not a regular file" % value)
    return real, "/".join(parts)


# ---------------------------------------------------------------- reading
def load_declaration(path, label):
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise Refused("%s: cannot be read (%s)" % (label, exc.strerror or exc))
    if size > MAX_DECLARATION_BYTES:
        raise Refused("%s: larger than %d MiB" % (label, MAX_DECLARATION_BYTES // (1024 * 1024)))
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except UnicodeDecodeError:
        raise Refused("%s: not UTF-8 text" % label)
    except json.JSONDecodeError as exc:
        raise Refused("%s: not valid JSON (line %d, column %d: %s)" % (label, exc.lineno, exc.colno, exc.msg))
    except (OSError, ValueError, RecursionError) as exc:
        raise Refused("%s: cannot be read (%s)" % (label, exc.__class__.__name__))
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise Refused('%s: not a CycloneDX document (it needs "bomFormat": "CycloneDX")' % label)
    if "specVersion" in doc and not isinstance(doc.get("specVersion"), str):
        raise Refused("%s: specVersion is not a string" % label)
    if not isinstance(doc.get("components"), list):
        raise Refused('%s: has no "components" array' % label)
    if len(doc["components"]) > MAX_COMPONENTS:
        raise Refused("%s: lists more than %d components" % (label, MAX_COMPONENTS))
    deps = doc.get("dependencies")
    if deps is not None:
        ok = isinstance(deps, list) and all(
            isinstance(d, dict) and set(d) <= {"ref", "dependsOn"} and isinstance(d.get("ref"), str)
            and isinstance(d.get("dependsOn", []), list)
            and all(isinstance(x, str) for x in d.get("dependsOn", []))
            for d in deps)
        if not ok:
            raise Refused('%s: "dependencies" is not a CycloneDX dependency list ({"ref": ..., "dependsOn": [...]})' % label)
    return doc


def check_component(comp, where, product_version, problems):
    """A cleaned copy of a declared component, or None when it is refused."""
    if not isinstance(comp, dict):
        problems.append("%s: is not a JSON object" % where)
        return None
    name = comp.get("name")
    if not isinstance(name, str) or not name.strip():
        problems.append("%s: has no name" % where)
        return None
    name = name.strip()
    where = "%s '%s'" % (where, name)
    bad = len(problems)
    if "components" in comp:
        problems.append("%s: nested components are not read; list each one at the top level of the file" % where)
    for key in sorted(set(comp) - ALLOWED - {"components"}):
        problems.append("%s: field '%s' is not read from a declaration file (allowed: %s)"
                        % (where, key, ", ".join(sorted(ALLOWED))))
    if comp.get("type") not in TYPES:
        problems.append("%s: type '%s' is not a CycloneDX component type (%s)" % (where, comp.get("type"), ", ".join(TYPES)))
    for key in STRING_FIELDS:
        if key in comp and not isinstance(comp[key], str):
            problems.append("%s: %s is not a string" % (where, key))
        elif key in LINE_FIELDS and key in comp and CONTROL.search(comp[key]):
            problems.append("%s: %s holds a control character" % (where, key))
    if isinstance(comp.get("bom-ref"), str) and not comp["bom-ref"].strip():
        problems.append("%s: bom-ref is empty" % where)
    if isinstance(comp.get("purl"), str) and not PURL.match(comp["purl"]):
        problems.append("%s: purl '%s' is not a package URL (pkg:type/name@version)" % (where, comp["purl"]))
    if isinstance(comp.get("mime-type"), str) and not MIME.match(comp["mime-type"]):
        problems.append("%s: mime-type '%s' is not a media type" % (where, comp["mime-type"]))
    if "scope" in comp and comp["scope"] not in SCOPES:
        problems.append("%s: scope must be one of %s" % (where, ", ".join(SCOPES)))
    for key, (check, shape) in SHAPES.items():
        if key in comp and not check(comp[key]):
            problems.append("%s: %s is not %s" % (where, key, shape))
    if len(problems) > bad:
        return None
    origin = props(comp, ORIGIN)
    if not origin:
        problems.append("%s: has no bomlens:origin property; add one with the value first-party or third-party" % where)
    elif len(origin) > 1:
        problems.append("%s: has bomlens:origin more than once" % where)
    elif origin[0] not in ORIGINS:
        problems.append("%s: bomlens:origin is '%s'; it must be first-party or third-party" % (where, origin[0]))
    for key, values in KIND_VALUES.items():
        given = props(comp, key)
        if len(given) > 1 or any(v not in values for v in given):
            problems.append("%s: %s must be given once, as %s" % (where, key, " or ".join("'%s'" % v for v in values)))
    if len(props(comp, ARTIFACT)) > 1 and any(props(comp, key) for key in KIND_VALUES):
        problems.append("%s: has several bomlens:artifact files, so it cannot give one %s value for all of them"
                        % (where, "/".join(KIND_VALUES)))
    version = comp.get("version", "").strip()
    if not version and origin == ["third-party"]:
        problems.append("%s: is third-party and has no version; write the version the supplier gave" % where)
    if len(problems) > bad:
        return None
    out = copy.deepcopy(comp)
    out["name"] = name
    out["version"] = version or product_version
    # The mark is this step's own; one written in the file is not trusted.
    out["properties"] = [p for p in out.get("properties", []) if p.get("name") != MARK] \
        + [{"name": MARK, "value": "true"}]
    return out


def is_declared(comp):
    """A component an earlier run of this step added."""
    return isinstance(comp, dict) and props(comp, MARK) == ["true"] \
        and len(props(comp, ORIGIN)) == 1 and props(comp, ORIGIN)[0] in ORIGINS


def read_files(files, labels, root, given_root, product, product_version, existing_refs, existing_purls, problems):
    seen = {}          # (name, version) -> label
    declared = []      # (label, component)
    file_deps = []     # (label, dependencies or None, [refs of the file])
    refs_seen = {}
    for path, label in zip(files, labels):
        # A declaration that sits in the scanned tree (the default file) is
        # read only when it really is there, not through a link out of it.
        lexical = os.path.abspath(path)
        if os.path.commonpath([given_root, lexical]) == given_root \
                and os.path.commonpath([root, os.path.realpath(lexical)]) != root:
            problems.append("%s: leads outside the scan target through a symbolic link" % label)
            continue
        before = len(problems)
        try:
            doc = load_declaration(path, label)
            if not doc["components"]:
                log("WARN: %s lists no components" % label)
            file_refs = []
            for i, raw in enumerate(doc["components"]):
                comp = check_component(raw, "%s: component #%d" % (label, i + 1), product_version, problems)
                if comp is None:
                    continue
                where = "%s: component '%s'" % (label, comp["name"])
                key = (comp["name"], comp["version"])
                if key in seen:
                    problems.append("%s@%s is declared twice (%s and %s); keep it in one place"
                                    % (comp["name"], comp["version"], seen[key], label))
                    continue
                seen[key] = label
                ref = comp.get("bom-ref") or "declared:%s@%s" % key
                comp["bom-ref"] = ref
                if ref in existing_refs or ref == product.get("bom-ref"):
                    problems.append("%s: bom-ref '%s' is already used by a component the scan found; choose another" % (where, ref))
                    continue
                if ref in refs_seen:
                    problems.append("%s: bom-ref '%s' is used twice (%s and %s)" % (where, ref, refs_seen[ref], label))
                    continue
                refs_seen[ref] = label
                artifacts = props(comp, ARTIFACT)
                resolved = []
                for value in artifacts:
                    try:
                        resolved.append(resolve_artifact(root, value))
                    except Refused as exc:
                        problems.append("%s: %s" % (where, exc))
                if len(resolved) != len(artifacts):
                    continue
                rels = [rel for _, rel in resolved]
                twice = sorted({rel for rel in rels if rels.count(rel) > 1})
                if twice:
                    problems.append("%s: lists bomlens:artifact '%s' more than once" % (where, twice[0]))
                    continue
                comp["_artifacts"] = resolved
                if comp.get("purl") in existing_purls:
                    log("WARN: %s: the scan already lists %s; both are kept" % (where, comp["purl"]))
                declared.append((label, comp))
                file_refs.append(ref)
            file_deps.append((label, doc.get("dependencies"), file_refs))
        except Refused as exc:
            problems.append(str(exc))
        except (RecursionError, AttributeError, TypeError, KeyError, ValueError) as exc:
            del problems[before:]
            problems.append("%s: could not be read as a declaration file (%s); check it against the CycloneDX 1.6 component format"
                            % (label, exc.__class__.__name__))
    return declared, file_deps, refs_seen


def check_refs(declared, file_deps, refs_seen, existing_refs, problems):
    """Graph and reference checks that need every file read first."""
    all_refs = existing_refs | set(refs_seen)
    for label, fdeps, file_refs in file_deps:
        for d in fdeps or []:
            if d["ref"] not in file_refs:
                problems.append("%s: dependencies names '%s', which is not a component of this file" % (label, d["ref"]))
            for target in d.get("dependsOn", []):
                if target not in all_refs:
                    problems.append("%s: dependencies of '%s' name '%s', which is neither a declared component nor one the scan found"
                                    % (label, d["ref"], target))
    # The nested file components of a multi-artifact component get
    # <ref>#<path>; such a reference must not be one already in use.
    children = {}
    for label, comp in declared:
        if len(comp["_artifacts"]) < 2:
            continue
        for _, rel in comp["_artifacts"]:
            child = "%s#%s" % (comp["bom-ref"], rel)
            if child in all_refs or child in children:
                problems.append("%s: component '%s': the reference '%s' its file %s would get is already used; "
                                "give the component another bom-ref" % (label, comp["name"], child, rel))
            children[child] = label
    return all_refs


def fill_artifacts(declared):
    """Fill what the build outputs say about themselves."""
    for _, comp in declared:
        resolved = comp.pop("_artifacts")
        if not resolved:
            continue
        origin = props(comp, ORIGIN)[0]
        if len(resolved) == 1:
            real, rel = resolved[0]
            facts = read_artifact(real)
            kinds = facts["kinds"]
            for key in KIND_VALUES:
                given = props(comp, key)
                if given:
                    kinds[key] = given[0]
            comp["hashes"] = [h for h in comp.get("hashes") or [] if h.get("alg") not in FILLED_HASHES] + facts["hashes"]
            comp["properties"] = [p for p in comp["properties"] if p.get("name") not in (FILENAME,) + tuple(KIND_VALUES)] \
                + [{"name": FILENAME, "value": os.path.basename(rel)}] \
                + [{"name": key, "value": kinds[key]} for key in KIND_VALUES]
            continue
        files_out = []
        for real, rel in resolved:
            facts = read_artifact(real)
            child = {
                "type": "file",
                "bom-ref": "%s#%s" % (comp["bom-ref"], rel),
                "name": rel,
                "version": comp["version"],
                "hashes": facts["hashes"],
                "properties": [{"name": ORIGIN, "value": origin}, {"name": ARTIFACT, "value": rel},
                               {"name": MARK, "value": "true"},
                               {"name": FILENAME, "value": os.path.basename(rel)}]
                + [{"name": key, "value": facts["kinds"][key]} for key in KIND_VALUES],
            }
            if isinstance(comp.get("supplier"), dict):
                child["supplier"] = copy.deepcopy(comp["supplier"])
            files_out.append(child)
        comp["components"] = files_out
        comp["properties"] = [p for p in comp["properties"] if p.get("name") != FILENAME]
        comp["hashes"] = [h for h in comp.get("hashes") or [] if h.get("alg") not in FILLED_HASHES]
        if not comp["hashes"]:
            del comp["hashes"]


def link_graph(product, product_version, deps, declared, file_deps, all_refs):
    if not product.get("bom-ref"):
        base = "%s@%s" % (product.get("name") or "product", product_version)
        ref, n = base, 1
        while ref in all_refs:
            n += 1
            ref = "%s-%d" % (base, n)
        product["bom-ref"] = ref
    root_ref = product["bom-ref"]
    by_ref = {d["ref"]: d for d in deps if isinstance(d.get("ref"), str)}

    def entry(ref):
        if ref not in by_ref:
            by_ref[ref] = {"ref": ref, "dependsOn": []}
            deps.append(by_ref[ref])
        by_ref[ref].setdefault("dependsOn", [])
        return by_ref[ref]

    def link(src, dst):
        e = entry(src)
        if dst not in e["dependsOn"]:
            e["dependsOn"].append(dst)

    entry(root_ref)
    for _, fdeps, file_refs in file_deps:
        for ref in file_refs:
            entry(ref)
        if fdeps:
            depended = set()
            for d in fdeps:
                for target in d.get("dependsOn", []):
                    link(d["ref"], target)
                    depended.add(target)
            for ref in file_refs:
                if ref not in depended:
                    link(root_ref, ref)
        else:
            for ref in file_refs:
                link(root_ref, ref)

    # A cycle in a file's own graph has no component nothing depends on: link
    # whatever the product still cannot reach.
    reach = set()

    def walk(start):
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in reach:
                continue
            reach.add(cur)
            stack.extend((by_ref.get(cur) or {}).get("dependsOn") or [])

    walk(root_ref)
    for _, comp in declared:
        if comp["bom-ref"] not in reach:
            link(root_ref, comp["bom-ref"])
            walk(comp["bom-ref"])


def sbom_problem(bom):
    """Why the SBOM is not one this step can add to, or None."""
    if not isinstance(bom, dict):
        return "it is not a JSON object"
    if not isinstance(bom.get("metadata", {}), dict) \
            or not isinstance((bom.get("metadata") or {}).get("component", {}), dict):
        return "metadata.component is not an object"
    for key in ("components", "dependencies"):
        value = bom.get(key)
        if value is not None and not (isinstance(value, list) and all(isinstance(x, dict) for x in value)):
            return "%s is not a list of objects" % key
    for d in bom.get("dependencies") or []:
        if not isinstance(d.get("ref"), str) or not _str_list(d.get("dependsOn", [])):
            return "dependencies holds an entry that is not {\"ref\": ..., \"dependsOn\": [...]}"
    return None


def main(argv):
    if len(argv) < 4:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 1
    bom_path, root, files = argv[1], argv[2], argv[3:]
    given = os.environ.get("DECLARED_COMPONENTS_LABELS", "").split("\n")
    labels = [given[i] if i < len(given) and given[i].strip() else f for i, f in enumerate(files)]
    given_root = os.path.abspath(root)
    root = os.path.realpath(root)
    if not os.path.isdir(root):
        log("ERROR: the scan target root %s is not a folder" % root)
        return 1
    try:
        with open(bom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        log("ERROR: cannot read the SBOM %s: %s" % (bom_path, exc.__class__.__name__))
        return 1
    why = sbom_problem(bom)
    if why:
        log("ERROR: the SBOM %s cannot take declared components: %s" % (bom_path, why))
        return 1

    meta = bom.setdefault("metadata", {})
    product = meta.setdefault("component", {})
    product_version = product.get("version") if isinstance(product.get("version"), str) else ""
    product_version = product_version or os.environ.get("PROJECT_VERSION", "")

    # What an earlier run added is taken out first, so the result is the same
    # however many times the files are applied.
    old = bom.get("components") or []
    comps = [c for c in old if not is_declared(c)]
    dropped = {c.get("bom-ref") for c in old if is_declared(c) and c.get("bom-ref")}
    deps = [d for d in (bom.get("dependencies") or []) if d.get("ref") not in dropped]
    for d in deps:
        if isinstance(d.get("dependsOn"), list):
            d["dependsOn"] = [r for r in d["dependsOn"] if r not in dropped]

    existing_refs = set()

    def collect(items):
        for c in items:
            if isinstance(c, dict):
                if isinstance(c.get("bom-ref"), str):
                    existing_refs.add(c["bom-ref"])
                if isinstance(c.get("components"), list):
                    collect(c["components"])
    try:
        collect(comps)
    except RecursionError:
        log("ERROR: the SBOM %s nests components too deeply to read" % bom_path)
        return 1
    existing_purls = {c.get("purl") for c in comps if isinstance(c.get("purl"), str)}

    problems = []
    declared, file_deps, refs_seen = read_files(files, labels, root, given_root, product, product_version,
                                                existing_refs, existing_purls, problems)
    all_refs = check_refs(declared, file_deps, refs_seen, existing_refs, problems)
    if problems:
        for p in problems[:MAX_PROBLEMS]:
            log("ERROR: " + p)
        if len(problems) > MAX_PROBLEMS:
            log("ERROR: ... and %d more" % (len(problems) - MAX_PROBLEMS))
        return 3

    try:
        fill_artifacts(declared)
    except OSError as exc:
        log("ERROR: a build output could not be read: %s" % exc)
        return 1
    link_graph(product, product_version, deps, declared, file_deps, all_refs)

    bom["components"] = comps + [comp for _, comp in declared]
    bom["dependencies"] = deps
    tmp = bom_path + ".declared.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, bom_path)
    except OSError as exc:
        log("ERROR: cannot write the SBOM %s: %s" % (bom_path, exc))
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return 1
    first = sum(1 for _, c in declared if props(c, ORIGIN) == ["first-party"])
    print("[declared-components] added %d declared component(s) (%d first-party, %d third-party) from %d file(s)"
          % (len(declared), first, len(declared) - first, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
