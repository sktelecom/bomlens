#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Give a jar the scan read as a component its own file hashes and its real path.

Usage: jar-file-hashes.py <source-root> <sbom.json>

cdxgen reads a jar in the scanned tree and reports the component named in the
jar's own pom.properties. It records the file as internal:SrcFile under a
temporary folder (jar-deps-XXXXXX/name.jar), which does not exist after the
scan, and gives the component no hash. When exactly one file of that name is in
the scanned tree, the component takes the file's path and its SHA-256 and
SHA-1; a component that already has hashes keeps them. A name found more than
once, or not at all, leaves the component as it was. Always exits 0.
"""
import hashlib
import json
import os
import re
import sys

TEMP = re.compile(r"^jar-deps-[^/]+/(.+\.jar)$", re.IGNORECASE)
SKIP_DIRS = {".git", "node_modules", ".gradle"}
ALGS = (("SHA-256", "sha256"), ("SHA-1", "sha1"))


def find_jars(root):
    found = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.lower().endswith(".jar"):
                found.setdefault(f, []).append(os.path.join(base, f))
    return found


def digests(path):
    hs = [(a, hashlib.new(n)) for a, n in ALGS]
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for _, h in hs:
                h.update(chunk)
    return [{"alg": a, "content": h.hexdigest()} for a, h in hs]


def main(root, sbom_path):
    with open(sbom_path, encoding="utf-8") as fh:
        bom = json.load(fh)
    comps = bom.get("components")
    if not isinstance(comps, list):
        return
    jars = None
    changed = False
    for c in comps:
        if not isinstance(c, dict):
            continue
        props = [p for p in (c.get("properties") or []) if isinstance(p, dict)]
        hit = None
        for p in props:
            m = TEMP.match(str(p.get("value", ""))) if p.get("name") == "internal:SrcFile" else None
            if m:
                hit = (p, m.group(1))
                break
        if not hit:
            continue
        if jars is None:
            jars = find_jars(root)
        paths = jars.get(os.path.basename(hit[1]), [])
        if len(paths) != 1:
            continue
        hit[0]["value"] = os.path.relpath(paths[0], root).replace(os.sep, "/")
        if not c.get("hashes"):
            c["hashes"] = digests(paths[0])
        changed = True
    if changed:
        with open(sbom_path, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)
            fh.write("\n")


if __name__ == "__main__":
    try:
        main(sys.argv[1], sys.argv[2])
    except Exception as e:  # best effort: the SBOM stays as it was
        print("[WARN] jar file hashes skipped: %s" % e, file=sys.stderr)
    sys.exit(0)
