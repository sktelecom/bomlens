#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Carry the dependency graph through the merge that builds a firmware SBOM.

Usage: carry-dependencies.py <merged-components.json> <source.cdx.json>... > dependencies.json

syft reads what each installed package depends on out of the package database —
`Depends` in a dpkg status file, and the equivalent for apk and rpm — and writes
it as a dependency graph beside the components. Measured on one root filesystem:
8,158 components and 317 packages with a dependency recorded.

None of it reached the SBOM. The merge assembles components from several
identification passes and takes only the component arrays, so the graph syft
produced was dropped on the floor. The conformance report has been reporting
"0 edges" as a required failure ever since, which read as a limit of reading an
unpacked image and was in fact this.

Carrying it across is not a copy, because the merge changes what the references
point at. One component described by two passes becomes one record, and the
reference the other pass used no longer names anything. So each reference is
followed to the record that survived — by name, version and type, which is what
the merge itself groups on — and an edge whose endpoints did not survive is
dropped rather than left dangling. A dangling reference is worse than a missing
edge: it makes the document invalid for a reader that resolves them.
"""
import json
import sys


def read_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def identity(component):
    """What the merge groups on, so two records of one component agree here."""
    return ((component.get("name") or "").lower(),
            component.get("version") or "",
            component.get("type") or "library")


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2

    merged = read_json(sys.argv[1])
    if not isinstance(merged, list):
        print("[]", end="")
        return 0

    # Where each surviving component can be reached, and what it is called now.
    survivor = {}
    live_refs = set()
    for component in merged:
        if not isinstance(component, dict):
            continue
        ref = component.get("bom-ref")
        if not ref:
            continue
        live_refs.add(ref)
        survivor.setdefault(identity(component), ref)

    # Every reference the sources used, resolved to the record that survived.
    resolves_to = {}
    edges = {}
    for path in sys.argv[2:]:
        doc = read_json(path)
        if not isinstance(doc, dict):
            continue
        for component in doc.get("components") or []:
            if not isinstance(component, dict):
                continue
            ref = component.get("bom-ref")
            if not ref:
                continue
            target = ref if ref in live_refs else survivor.get(identity(component))
            if target:
                resolves_to[ref] = target
        for edge in doc.get("dependencies") or []:
            if not isinstance(edge, dict) or not edge.get("ref"):
                continue
            edges.setdefault(edge["ref"], set()).update(
                d for d in (edge.get("dependsOn") or []) if isinstance(d, str))

    out = {}
    for ref, depends in edges.items():
        source = resolves_to.get(ref)
        if source is None:
            continue
        for dep in depends:
            target = resolves_to.get(dep)
            # A component that depends on itself is what the merge makes of two
            # records that turned out to be one; it says nothing and CycloneDX
            # readers treat it as a cycle.
            if target is None or target == source:
                continue
            out.setdefault(source, set()).add(target)

    result = [{"ref": ref, "dependsOn": sorted(deps)}
              for ref, deps in sorted(out.items())]
    print(json.dumps(result, ensure_ascii=False))
    print(f"[firmware] dependency graph: {len(result)} component(s) with "
          f"{sum(len(d['dependsOn']) for d in result)} edge(s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
