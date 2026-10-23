#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Carry the declared components' file facts into the SPDX 2.3 export.

Usage: spdx-declared.py <source.cdx.json> <target.spdx.json>

The components a declaration file adds to a source scan
(apply-declared-components.py, marked bomlens:declared = true) carry the
SHA-512 and SHA-256 of their build outputs, and a component with several
build outputs holds them as nested "file" components. `syft convert` keeps
neither: the packages it writes have no checksums, and nested components are
not read at all. Without this step the SPDX file names the supplier's own
programs but nothing that identifies the delivered bytes.

Each declared component's package gets the checksums of its one build output
(SHA512, SHA256) and packageFileName. Each nested file becomes a package of
its own (primaryPackagePurpose FILE, with its checksums and file name) that
the declared component's package CONTAINS. A package is matched by purl, or
by name and version when the name and version are unique in the SPDX file;
one that cannot be matched is left as it is, with a warning.
"""
import json
import os
import re
import sys

MARK = "bomlens:declared"
ALGS = {"SHA-512": "SHA512", "SHA-256": "SHA256"}
ID_UNSAFE = re.compile(r"[^A-Za-z0-9.-]")
NOASSERTION = "NOASSERTION"


def props(component, name):
    return [p.get("value") for p in component.get("properties") or []
            if isinstance(p, dict) and p.get("name") == name]


def checksums(component):
    return [{"algorithm": ALGS[h["alg"]], "checksumValue": h["content"]}
            for h in component.get("hashes") or []
            if isinstance(h, dict) and h.get("alg") in ALGS and isinstance(h.get("content"), str)]


def purl_of(package):
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def index(packages):
    by_purl, by_nv, twice = {}, {}, set()
    for package in packages:
        if not isinstance(package, dict) or not package.get("SPDXID"):
            continue
        purl = purl_of(package)
        if purl:
            by_purl.setdefault(purl, package)
        key = (package.get("name") or "", package.get("versionInfo") or "")
        if key in by_nv:
            twice.add(key)
        else:
            by_nv[key] = package
    for key in twice:
        by_nv.pop(key, None)
    return by_purl, by_nv


def file_name(component):
    names = props(component, "bsi:component:filename")
    return names[0] if names else None


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    source, target = sys.argv[1], sys.argv[2]
    try:
        with open(source, encoding="utf-8") as fh:
            cdx = json.load(fh)
        with open(target, encoding="utf-8") as fh:
            spdx = json.load(fh)
    except (OSError, ValueError) as err:
        print("[spdx] WARN: could not carry the declared components' checksums into the SPDX file: %s" % err,
              file=sys.stderr)
        return 0
    components = cdx.get("components") if isinstance(cdx, dict) else None
    packages = spdx.get("packages") if isinstance(spdx, dict) else None
    if not isinstance(components, list) or not isinstance(packages, list):
        return 0
    declared = [c for c in components if isinstance(c, dict) and props(c, MARK) == ["true"]]
    if not declared:
        return 0

    by_purl, by_nv = index(packages)
    ids = {p.get("SPDXID") for p in packages if isinstance(p, dict)}
    relationships = spdx.get("relationships")
    if not isinstance(relationships, list):
        relationships = []
    changed = False
    for comp in declared:
        package = by_purl.get(comp.get("purl")) if comp.get("purl") else None
        package = package or by_nv.get((comp.get("name") or "", comp.get("version") or ""))
        if package is None:
            print("[spdx] WARN: the declared component %s@%s is not in the SPDX file; its checksums are not carried"
                  % (comp.get("name"), comp.get("version")), file=sys.stderr)
            continue
        sums = checksums(comp)
        if sums:
            package["checksums"] = sums
            changed = True
        if file_name(comp):
            package["packageFileName"] = file_name(comp)
            changed = True
        for child in comp.get("components") or []:
            if not isinstance(child, dict) or child.get("type") != "file":
                continue
            ident = "SPDXRef-Package-file-%s" % ID_UNSAFE.sub("-", str(child.get("bom-ref") or child.get("name")))
            base, n = ident, 1
            while ident in ids:
                n += 1
                ident = "%s-%d" % (base, n)
            ids.add(ident)
            child_package = {
                "SPDXID": ident,
                "name": child.get("name") or "",
                "downloadLocation": NOASSERTION,
                "filesAnalyzed": False,
                "licenseConcluded": NOASSERTION,
                "licenseDeclared": NOASSERTION,
                "copyrightText": NOASSERTION,
                "primaryPackagePurpose": "FILE",
            }
            if child.get("version"):
                child_package["versionInfo"] = child["version"]
            if file_name(child):
                child_package["packageFileName"] = file_name(child)
            if checksums(child):
                child_package["checksums"] = checksums(child)
            supplier = (child.get("supplier") or {}).get("name") if isinstance(child.get("supplier"), dict) else None
            if supplier:
                child_package["supplier"] = "Organization: %s" % supplier
            packages.append(child_package)
            relationships.append({"spdxElementId": package["SPDXID"], "relatedSpdxElement": ident,
                                  "relationshipType": "CONTAINS"})
            changed = True
    if not changed:
        return 0
    spdx["relationships"] = relationships
    tmp = target + ".declared.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(spdx, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, target)
    except OSError as err:
        print("[spdx] WARN: could not write the declared components' checksums: %s" % err, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
