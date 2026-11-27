#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""List the Python dependencies a project declares when nothing resolved them.

Usage: python-declared.py <source-root> <sbom.json>

When stage 1 (cdxgen) ends without an SBOM, for example when the container is
stopped while pip installs a large requirement, the manifest-only scan that
takes its place lists only exact pins. A requirements.txt of version ranges
then leaves the SBOM with almost no Python package. This adds each direct
dependency that requirements.txt and the [project] dependencies of
pyproject.toml at the scan root declare and the SBOM does not already list,
without a version (a range is not an installed version), marked
bomlens:evidenceGrade=declared-only with the range in bomlens:declaredRange,
and linked from the root. A URL, a local path, an option line or an included
file is left out. When anything was added, the SBOM records the resolution
hint python-declared-only, which grades the result unreliable.

Prints the number of components added. The SBOM is left as it was on any error.
"""
import json
import os
import re
import sys

NAME = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
MAX_FILE = 1 << 20


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement(line):
    """(name, range) of one requirement line, or None when it names no
    package of the index."""
    line = re.sub(r"(^|\s)#.*$", "", line).strip()
    if not line or line.startswith("-"):
        return None
    line = line.split(";", 1)[0].strip()
    m = NAME.match(line)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    # A direct reference (name @ url) or anything that is not a version
    # specifier list is not a package of the index.
    if rest.startswith("@") or "://" in line:
        return None
    if rest and not re.fullmatch(r"\(?\s*(?:(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)+\)?", rest):
        return None
    return name, re.sub(r"[()\s]", "", rest)


def read_text(path):
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_FILE:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def declared(root):
    found = []
    text = read_text(os.path.join(root, "requirements.txt"))
    if text is not None:
        joined = re.sub(r"\\\r?\n", " ", text)
        for line in joined.splitlines():
            r = requirement(line)
            if r:
                found.append((r[0], r[1], "requirements.txt"))
    text = read_text(os.path.join(root, "pyproject.toml"))
    if text is not None:
        try:
            import tomllib
            deps = tomllib.loads(text).get("project", {}).get("dependencies", [])
        except Exception:
            deps = []
        if isinstance(deps, list):
            for d in deps:
                r = requirement(d) if isinstance(d, str) else None
                if r:
                    found.append((r[0], r[1], "pyproject.toml"))
    return found


def main():
    if len(sys.argv) != 3:
        print("0")
        return 0
    root, sbom_path = sys.argv[1], sys.argv[2]
    try:
        with open(sbom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError):
        print("0")
        return 0
    components = bom.get("components")
    if not isinstance(components, list):
        components = []
    present = set()
    for c in components:
        purl = c.get("purl") if isinstance(c, dict) else None
        if isinstance(purl, str) and purl.startswith("pkg:pypi/"):
            present.add(pep503(purl[len("pkg:pypi/"):].split("@", 1)[0].split("?", 1)[0]))
    added, refs = {}, []
    for name, spec, src in declared(root):
        key = pep503(name)
        if key in present or key in added:
            continue
        purl = "pkg:pypi/" + key
        props = [
            {"name": "internal:SrcFile", "value": src},
            {"name": "bomlens:evidenceGrade", "value": "declared-only"},
        ]
        if spec:
            props.append({"name": "bomlens:declaredRange", "value": spec[:100]})
        added[key] = {"type": "library", "name": name, "purl": purl, "bom-ref": purl, "properties": props}
        refs.append(purl)
    if not added:
        print("0")
        return 0
    bom["components"] = components + [added[k] for k in sorted(added)]
    root_ref = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if isinstance(root_ref, str) and root_ref:
        deps = bom.get("dependencies")
        if not isinstance(deps, list):
            deps = []
            bom["dependencies"] = deps
        node = next((d for d in deps if isinstance(d, dict) and d.get("ref") == root_ref), None)
        if node is None:
            node = {"ref": root_ref, "dependsOn": []}
            deps.append(node)
        node["dependsOn"] = list(dict.fromkeys(list(node.get("dependsOn") or []) + sorted(refs)))
    meta = bom.setdefault("metadata", {})
    props = meta.setdefault("properties", [])
    if not any(p.get("name") == "bomlens:resolution-hint" and p.get("value") == "python-declared-only"
               for p in props if isinstance(p, dict)):
        props.append({"name": "bomlens:resolution-hint", "value": "python-declared-only"})
    tmp = sbom_path + ".pydecl.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)
        os.replace(tmp, sbom_path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        print("0")
        return 0
    print(len(added))
    return 0


if __name__ == "__main__":
    sys.exit(main())
