#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Carry the containers a firmware holds into its SPDX export.

Usage: spdx-containers.py <source.cdx.json> <target.spdx.json>

`syft convert` writes a package for every component it recognises as software
and drops the rest, so two things a firmware scan establishes do not reach the
SPDX file: the container images the device carries, and which of them each
package belongs to. Both are the answer to the question a reader of a switch
image actually has — `libssl` somewhere in the firmware is a different fact from
`libssl` in the routing daemon's container — and a reader who asked for SPDX gets
the same document as a reader who asked for CycloneDX, minus that answer.

The images become packages and the membership becomes a CONTAINS relationship,
which is what SPDX has for exactly this: a package that holds other packages. The
distribution the firmware runs is carried over the same way, as a package the
document describes; syft drops that too.

Nothing here invents information. A package is added only for a component the
CycloneDX file already carries, and a relationship only where that file records
the membership. A component the SPDX export does not hold — syft's own decision
about what counts as software — is left out rather than added back through this
door, so the two documents keep listing the same software.
"""
import json
import re
import sys

PROP_IMAGE = "bomlens:container:image"
CARRIED_TYPES = ("container", "operating-system")
# SPDX 2.3 allows letters, digits, `.` and `-` after the prefix. Anything else in
# a name (a repository's slashes, a tag's colon) has to go, and what is left is
# not unique on its own — two images can differ only in the part removed — so the
# component's own reference is what makes the identifier unique.
ID_UNSAFE = re.compile(r"[^A-Za-z0-9.-]")

NOASSERTION = "NOASSERTION"


def props(component):
    return {p.get("name"): p.get("value") for p in component.get("properties") or []
            if isinstance(p, dict)}


def image_labels(component):
    """Every container this component was attributed to."""
    return [str(p.get("value")) for p in component.get("properties") or []
            if isinstance(p, dict) and p.get("name") == PROP_IMAGE and p.get("value")]


def label_of(component):
    """How a container component is named in a membership property.

    The membership records `<name>@<version>`, so the same string is rebuilt here
    rather than matched loosely: a store can hold two images whose names differ
    only by version, and attributing one's packages to the other would be worse
    than leaving the relationship out.
    """
    name = component.get("name") or ""
    version = component.get("version") or ""
    return name + ("@" + version if version else "")


def spdx_id(component, index):
    safe = ID_UNSAFE.sub("-", str(component.get("name") or "unnamed"))
    ref = ID_UNSAFE.sub("-", str(component.get("bom-ref") or index))
    return "SPDXRef-Package-{}-{}-{}".format(component.get("type"), safe, ref)


def purl_of_spdx(package):
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def index_spdx_packages(spdx):
    """Two lookups into the SPDX packages: by purl, and by name and version.

    A name that appears twice is dropped from the name lookup rather than
    resolved arbitrarily. The purl is the identifier the two documents share, and
    where there is none, an ambiguous name is no better than no answer.
    """
    by_purl, by_nv, seen_twice = {}, {}, set()
    for package in spdx.get("packages") or []:
        if not isinstance(package, dict) or not package.get("SPDXID"):
            continue
        purl = purl_of_spdx(package)
        if purl and purl not in by_purl:
            by_purl[purl] = package["SPDXID"]
        key = (package.get("name") or "", package.get("versionInfo") or "")
        if key in by_nv:
            seen_twice.add(key)
        else:
            by_nv[key] = package["SPDXID"]
    for key in seen_twice:
        by_nv.pop(key, None)
    return by_purl, by_nv


def spdx_package(component, identifier):
    """The component as an SPDX package, with the fields SPDX 2.3 requires."""
    package = {
        "SPDXID": identifier,
        "name": component.get("name") or "",
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
    }
    if component.get("version"):
        package["versionInfo"] = component["version"]
    if component.get("purl"):
        package["externalRefs"] = [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": component["purl"],
        }]
    return package


def document_root(spdx):
    """The package the document describes, or None."""
    for relationship in spdx.get("relationships") or []:
        if isinstance(relationship, dict) \
           and relationship.get("relationshipType") == "DESCRIBES":
            return relationship.get("relatedSpdxElement")
    return None


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
        # The SPDX file is an additional artifact and the scan has already
        # succeeded by the time this runs, so a document that cannot be read
        # costs the memberships, not the run.
        print(f"[spdx] WARN: could not carry containers into the SPDX file: {err}",
              file=sys.stderr)
        return 0

    components = cdx.get("components")
    if not isinstance(components, list) or not isinstance(spdx.get("packages"), list):
        return 0

    carried = [c for c in components
               if isinstance(c, dict) and c.get("type") in CARRIED_TYPES]
    if not carried:
        return 0

    by_purl, by_nv = index_spdx_packages(spdx)
    ids_by_label = {}
    added = []
    for index, component in enumerate(carried):
        identifier = spdx_id(component, index)
        added.append(spdx_package(component, identifier))
        if component.get("type") == "container":
            ids_by_label.setdefault(label_of(component), identifier)

    relationships = spdx.get("relationships")
    if not isinstance(relationships, list):
        relationships = []
    root = document_root(spdx)
    new_relationships = []
    if root:
        # The images and the distribution are part of what the document is about,
        # the same as every other package syft related to the root.
        for package in added:
            new_relationships.append({
                "spdxElementId": root,
                "relatedSpdxElement": package["SPDXID"],
                "relationshipType": "CONTAINS",
            })

    attributed = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        labels = [lb for lb in image_labels(component) if lb in ids_by_label]
        if not labels:
            continue
        purl = component.get("purl")
        member = by_purl.get(purl) if purl else None
        if not member:
            member = by_nv.get((component.get("name") or "",
                                component.get("version") or ""))
        if not member:
            continue
        for label in labels:
            new_relationships.append({
                "spdxElementId": ids_by_label[label],
                "relatedSpdxElement": member,
                "relationshipType": "CONTAINS",
            })
        attributed += 1

    spdx["packages"] = (spdx.get("packages") or []) + added
    spdx["relationships"] = relationships + new_relationships
    try:
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(spdx, fh)
    except OSError as err:
        print(f"[spdx] WARN: could not write the SPDX file: {err}", file=sys.stderr)
        return 0
    print(f"[spdx] carried {len(added)} image(s) and the distribution into SPDX, "
          f"{attributed} package(s) related to one.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
