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

A component may name its build outputs in bomlens:artifact, a path relative to
the scan root (the property may repeat). The file is read here, and its
SHA-512 and SHA-256 hashes, its file name (bsi:component:filename) and whether
it is an executable or an archive (bsi:component:executable,
bsi:component:archive, from the first bytes of the file) are filled in. With
one artifact these go on the component itself. With several, each file becomes
a nested component of type "file" under the declared one (a CycloneDX
assembly), carrying its own hashes and properties, and the declared component
carries none: one set of hashes cannot describe several files.

A first-party component with no version takes the product's version
(metadata.component.version). A file that has `dependencies` keeps them, and
the product depends on each of its components that nothing else in the file
depends on; a file without them makes the product depend on each component.
Any declared component still not reachable from the product afterwards is
linked from it too.

A build output that is missing because --exclude left its folder out of the
scanned copy (SCAN_EXCLUDE_PATHS, one path per line) is reported as such.

The labels the user knows the files by (the paths given on the command line)
come from DECLARED_COMPONENTS_LABELS, one per line in the order of the
arguments; without it the path is used.

Components an earlier run added (they carry bomlens:origin) are replaced, so
applying the same files twice gives the same SBOM.

Exit 0 when applied, 3 when a file is refused (every problem is printed, and
the SBOM is left as it was), 1 when the SBOM itself cannot be read or written.
"""
import copy
import hashlib
import json
import os
import re
import sys

MAX_DECLARATION_BYTES = 4 * 1024 * 1024
MAX_COMPONENTS = 10000
MAX_PROBLEMS = 50
ORIGIN = "bomlens:origin"
ARTIFACT = "bomlens:artifact"
ORIGINS = ("first-party", "third-party")
FILENAME = "bsi:component:filename"
EXECUTABLE = "bsi:component:executable"
ARCHIVE = "bsi:component:archive"
FILLED = (FILENAME, EXECUTABLE, ARCHIVE)
FILLED_HASHES = ("SHA-512", "SHA-256")
# CycloneDX 1.6 component types.
TYPES = ("application", "framework", "library", "container", "platform",
         "operating-system", "device", "device-driver", "firmware", "file",
         "machine-learning-model", "data", "cryptographic-asset")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Refused(Exception):
    pass


def log(msg):
    print("[declared-components] " + msg, file=sys.stderr)


def props(comp, name):
    return [p.get("value") for p in comp.get("properties") or []
            if isinstance(p, dict) and p.get("name") == name]


# ---------------------------------------------------------------- file type
def file_kind(head):
    """(executable, archive) from the first bytes of a file."""
    executable = False
    archive = False
    if head[:4] == b"\x7fELF" and len(head) >= 18:
        # e_type: 2 executable, 3 shared object or position-independent
        # executable. A relocatable object (1) or a core dump (4) is not.
        order = "little" if head[5:6] == b"\x01" else "big"
        executable = int.from_bytes(head[16:18], order) in (2, 3)
    elif head[:2] == b"MZ" and len(head) >= 64:
        pe = int.from_bytes(head[60:64], "little")
        executable = pe + 4 <= len(head) and head[pe:pe + 4] == b"PE\x00\x00"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                      b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        executable = True
    elif head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # A universal Mach-O binary and a Java class file share this magic.
        # The next word is the number of architectures in the first, a small
        # number, and the class file version in the second (45 or more).
        executable = int.from_bytes(head[4:8], "big") < 45
    if (head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
            or head[:2] == b"\x1f\x8b"
            or head[:3] == b"BZh"
            or head[:6] == b"\xfd7zXZ\x00"
            or head[:4] == b"\x28\xb5\x2f\xfd"
            or head[:6] == b"7z\xbc\xaf\x27\x1c"
            or head[:4] == b"\x04\x22\x4d\x18"
            or head[:7] == b"Rar!\x1a\x07"
            or head[:8] == b"!<arch>\n"
            or head[:4] == b"\xed\xab\xee\xdb"
            or head[:6] in (b"070701", b"070702", b"070707")
            or head[257:262] == b"ustar"):
        archive = True
    return executable, archive


def read_artifact(path):
    sha512 = hashlib.sha512()
    sha256 = hashlib.sha256()
    head = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            if len(head) < 512:
                head += chunk[:512 - len(head)]
            sha512.update(chunk)
            sha256.update(chunk)
    executable, archive = file_kind(head)
    return {
        "hashes": [{"alg": "SHA-512", "content": sha512.hexdigest()},
                   {"alg": "SHA-256", "content": sha256.hexdigest()}],
        "properties": [
            {"name": EXECUTABLE, "value": "executable" if executable else "non-executable"},
            {"name": ARCHIVE, "value": "archive" if archive else "no archive"},
        ],
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
        for ex in excluded_paths():
            if rel == ex or rel.startswith(ex + "/"):
                raise Refused("bomlens:artifact '%s' is under '%s', which --exclude leaves out of the scan; "
                              "drop that --exclude or list the file elsewhere" % (value, ex))
        raise Refused("bomlens:artifact '%s' does not exist in the scan target; build it before the scan, or fix the path" % value)
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
        raise Refused("%s: cannot be read (%s)" % (label, exc))
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
            isinstance(d, dict) and isinstance(d.get("ref"), str)
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
    where = "%s '%s'" % (where, name)
    bad = len(problems)
    if comp.get("type") not in TYPES:
        problems.append("%s: type '%s' is not a CycloneDX component type (%s)" % (where, comp.get("type"), ", ".join(TYPES)))
    if "components" in comp:
        problems.append("%s: nested components are not read; list each one at the top level of the file" % where)
    properties = comp.get("properties", [])
    if not isinstance(properties, list) or not all(
            isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("value", ""), str)
            for p in properties):
        problems.append('%s: "properties" is not a list of {"name": ..., "value": ...}' % where)
        return None
    for key in ("bom-ref", "purl", "version"):
        if key in comp and not isinstance(comp[key], str):
            problems.append("%s: %s is not a string" % (where, key))
    if "bom-ref" in comp and isinstance(comp["bom-ref"], str) and not comp["bom-ref"].strip():
        problems.append("%s: bom-ref is empty" % where)
    origin = props(comp, ORIGIN)
    if not origin:
        problems.append("%s: has no bomlens:origin property; add one with the value first-party or third-party" % where)
    elif len(origin) > 1:
        problems.append("%s: has bomlens:origin more than once" % where)
    elif origin[0] not in ORIGINS:
        problems.append("%s: bomlens:origin is '%s'; it must be first-party or third-party" % (where, origin[0]))
    version = comp.get("version") if isinstance(comp.get("version"), str) else ""
    version = version.strip()
    if not version and origin == ["third-party"]:
        problems.append("%s: is third-party and has no version; write the version the supplier gave" % where)
    if len(problems) > bad:
        return None
    out = copy.deepcopy(comp)
    out["name"] = name
    out["version"] = version or product_version
    return out


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
    except (OSError, ValueError) as exc:
        log("ERROR: cannot read the SBOM %s: %s" % (bom_path, exc))
        return 1

    meta = bom.setdefault("metadata", {})
    product = meta.setdefault("component", {})
    product_version = product.get("version") or os.environ.get("PROJECT_VERSION", "")

    # What an earlier run added is taken out first, so the result is the same
    # however many times the files are applied.
    comps = [c for c in (bom.get("components") or []) if not (isinstance(c, dict) and props(c, ORIGIN))]
    dropped = {c.get("bom-ref") for c in (bom.get("components") or [])
               if isinstance(c, dict) and props(c, ORIGIN) and c.get("bom-ref")}
    deps = [d for d in (bom.get("dependencies") or []) if isinstance(d, dict) and d.get("ref") not in dropped]
    for d in deps:
        if isinstance(d.get("dependsOn"), list):
            d["dependsOn"] = [r for r in d["dependsOn"] if r not in dropped]

    existing_refs = set()

    def collect(items):
        for c in items:
            if isinstance(c, dict):
                if c.get("bom-ref"):
                    existing_refs.add(c["bom-ref"])
                collect(c.get("components") or [])
    collect(comps)
    existing_purls = {c.get("purl") for c in comps if isinstance(c, dict) and c.get("purl")}

    problems = []
    seen = {}          # (name, version) -> label
    declared = []      # (label, component, file index)
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
        try:
            doc = load_declaration(path, label)
        except Refused as exc:
            problems.append(str(exc))
            continue
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
            comp["_artifacts"] = resolved
            if comp.get("purl") in existing_purls:
                log("WARN: %s: the scan already lists %s; both are kept" % (where, comp["purl"]))
            declared.append((label, comp))
            file_refs.append(ref)
        file_deps.append((label, doc.get("dependencies"), file_refs))

    all_refs = existing_refs | set(refs_seen)
    for label, fdeps, file_refs in file_deps:
        for d in fdeps or []:
            if d["ref"] not in file_refs:
                problems.append("%s: dependencies names '%s', which is not a component of this file" % (label, d["ref"]))
            for target in d.get("dependsOn", []):
                if target not in all_refs:
                    problems.append("%s: dependencies of '%s' name '%s', which is neither a declared component nor one the scan found"
                                    % (label, d["ref"], target))

    if problems:
        for p in problems[:MAX_PROBLEMS]:
            log("ERROR: " + p)
        if len(problems) > MAX_PROBLEMS:
            log("ERROR: ... and %d more" % (len(problems) - MAX_PROBLEMS))
        return 3

    # Fill what the build outputs say about themselves.
    for label, comp in declared:
        resolved = comp.pop("_artifacts")
        if not resolved:
            continue
        origin = props(comp, ORIGIN)[0]
        if len(resolved) == 1:
            real, rel = resolved[0]
            facts = read_artifact(real)
            comp["hashes"] = [h for h in comp.get("hashes") or []
                              if not (isinstance(h, dict) and h.get("alg") in FILLED_HASHES)] + facts["hashes"]
            comp["properties"] = [p for p in comp["properties"] if p.get("name") not in FILLED] \
                + [{"name": FILENAME, "value": os.path.basename(rel)}] + facts["properties"]
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
                               {"name": FILENAME, "value": os.path.basename(rel)}] + facts["properties"],
            }
            if isinstance(comp.get("supplier"), dict):
                child["supplier"] = copy.deepcopy(comp["supplier"])
            files_out.append(child)
        comp["components"] = files_out
        comp["properties"] = [p for p in comp["properties"] if p.get("name") not in FILLED]
        comp["hashes"] = [h for h in comp.get("hashes") or []
                          if not (isinstance(h, dict) and h.get("alg") in FILLED_HASHES)]
        if not comp["hashes"]:
            del comp["hashes"]

    # The product's own entry in the graph.
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
    for label, fdeps, file_refs in file_deps:
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
