#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Name the package an SPDX export says the document describes.

Usage: spdx-document-root.py <source.cdx.json> <target.spdx.json>

`syft convert` models every conversion the way it models an image scan: the
document DESCRIBES one root package that CONTAINS everything else. A CycloneDX
file has no such wrapper, so the converter invents one and leaves it blank --
`SPDXRef-DocumentRoot-Unknown-` with an empty name and no version -- while the
component the BOM actually stamps as its root ends up as an ordinary package
alongside the dependencies.

A package with no name and no version fails the field coverage every SBOM
regulation asks for, so the export of a scan that passed its own conformance
check fails when it is read back. The fix is not to drop the blank package and
lose what it holds, but to say what the document already knows it describes:

  * when the CycloneDX root is present in the export, the DESCRIBES moves to it,
    the memberships move with it, and the blank package goes away;
  * when it is not (a converter may drop a root it does not count as software),
    the blank package is filled in from the CycloneDX root instead, keeping the
    memberships attached to something that has a name.

Nothing is invented: the name, the version and the identifier all come from the
CycloneDX file's own `metadata.component`. A document whose root is already
named is left untouched.
"""
import json
import sys

# The identifier syft gives the wrapper it invents. Matched as a prefix because
# the trailing segment carries the (here empty) name.
SYFT_ROOT_PREFIX = "SPDXRef-DocumentRoot-"


def package_index(spdx):
    """Two lookups into the export: by purl, and by (name, version)."""
    by_purl = {}
    by_name_version = {}
    for package in spdx.get("packages") or []:
        if not isinstance(package, dict):
            continue
        identifier = package.get("SPDXID")
        if not identifier:
            continue
        for ref in package.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                locator = ref.get("referenceLocator")
                if locator:
                    by_purl.setdefault(locator, identifier)
        key = (package.get("name") or "", package.get("versionInfo") or "")
        if key != ("", ""):
            by_name_version.setdefault(key, identifier)
    return by_purl, by_name_version


def described_package(spdx):
    """(relationship, package) the document describes, or (None, None)."""
    for relationship in spdx.get("relationships") or []:
        if not isinstance(relationship, dict):
            continue
        if relationship.get("spdxElementId") != "SPDXRef-DOCUMENT":
            continue
        if relationship.get("relationshipType") != "DESCRIBES":
            continue
        target = relationship.get("relatedSpdxElement")
        for package in spdx.get("packages") or []:
            if isinstance(package, dict) and package.get("SPDXID") == target:
                return relationship, package
        return relationship, None
    return None, None


def is_blank(package):
    """A wrapper syft invented and never filled in."""
    if not isinstance(package, dict):
        return False
    identifier = package.get("SPDXID") or ""
    if not identifier.startswith(SYFT_ROOT_PREFIX):
        return False
    return not (package.get("name") or "").strip()


def cdx_root(cdx):
    """The component the CycloneDX file stamps as its root, or None."""
    component = (cdx.get("metadata") or {}).get("component")
    return component if isinstance(component, dict) else None


def find_real_root(root, by_purl, by_name_version):
    """The SPDX package that is the CycloneDX root, or None.

    The purl is tried first because it identifies the package rather than
    describing it; `bom-ref` is tried next since a source scan often carries the
    purl only there. Name and version are the last resort, and only when both
    are present -- matching on a name alone could attach the document to a
    dependency that happens to share it.
    """
    for locator in (root.get("purl"), root.get("bom-ref")):
        if locator and locator in by_purl:
            return by_purl[locator]
    name, version = root.get("name") or "", root.get("version") or ""
    if name and version:
        return by_name_version.get((name, version))
    return None


def repoint(spdx, blank_id, real_id):
    """Move every relationship off the blank wrapper and onto the real root."""
    kept = []
    for relationship in spdx.get("relationships") or []:
        if not isinstance(relationship, dict):
            kept.append(relationship)
            continue
        subject = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if subject == blank_id:
            subject = real_id
        if target == blank_id:
            target = real_id
        # The wrapper held the real root too; once they are the same package
        # that membership would say a package contains itself.
        if subject == target:
            continue
        relationship["spdxElementId"] = subject
        relationship["relatedSpdxElement"] = target
        kept.append(relationship)
    spdx["relationships"] = kept
    spdx["packages"] = [p for p in spdx.get("packages") or []
                        if not (isinstance(p, dict) and p.get("SPDXID") == blank_id)]


def fill_in(package, root):
    """Give the wrapper the root's identity, for an export that dropped it."""
    package["name"] = root.get("name") or ""
    version = root.get("version")
    if version:
        package["versionInfo"] = version
    locator = root.get("purl") or root.get("bom-ref")
    if locator and str(locator).startswith("pkg:"):
        refs = package.setdefault("externalRefs", [])
        if isinstance(refs, list):
            refs.append({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": locator,
            })


def main():
    if len(sys.argv) < 3:
        print("usage: spdx-document-root.py <source.cdx.json> <target.spdx.json>",
              file=sys.stderr)
        return 2
    source, target = sys.argv[1], sys.argv[2]

    try:
        with open(source, encoding="utf-8") as fh:
            cdx = json.load(fh)
        with open(target, encoding="utf-8") as fh:
            spdx = json.load(fh)
    except (OSError, ValueError) as err:
        # Same contract as the rest of the SPDX post-processing: the export is an
        # additional artifact produced after the scan already succeeded, so a
        # document that cannot be read costs this correction, not the run.
        print(f"[spdx] WARN: could not name the document root: {err}", file=sys.stderr)
        return 0

    relationship, package = described_package(spdx)
    if relationship is None or not is_blank(package):
        return 0

    root = cdx_root(cdx)
    if not root or not (root.get("name") or "").strip():
        return 0

    blank_id = package.get("SPDXID")
    by_purl, by_name_version = package_index(spdx)
    real_id = find_real_root(root, by_purl, by_name_version)

    if real_id and real_id != blank_id:
        relationship["relatedSpdxElement"] = real_id
        repoint(spdx, blank_id, real_id)
    else:
        fill_in(package, root)

    try:
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(spdx, fh)
    except OSError as err:
        print(f"[spdx] WARN: could not write the SPDX file: {err}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
