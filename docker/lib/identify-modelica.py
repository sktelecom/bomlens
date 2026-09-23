#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Identify Modelica library dependencies from a source tree's uses() annotations.

Usage: identify-modelica.py <source_dir> <output.json> <version>

cdxgen has no Modelica cataloger — the ecosystem is not in its language image
list at all — so a Modelica project (OpenModelica/Dymola `.mo` files) scans to
zero components today, even though the file itself already states what it
depends on. A `.mo` package that uses another library declares it in an
`annotation(uses(...))` block, each entry a library name and a version, e.g.:

    annotation(uses(Modelica(version="4.0.0"), Buildings(version="13.0.0")));

This is a decisive fact about the file, not an inference an LLM would have to
make, so it is read the same way a lockfile is read elsewhere in this project:
parsed structurally, not summarized. What is out of scope: the model's own
internal structure (its components, parameters, connections) is the user's own
design, not an open-source dependency, and describing it would mean falling
back to exactly the guesswork this script exists to avoid.

Best-effort like identify-cocoapods.sh: no .mo files, or none carrying a
uses() block, degrades to an empty CycloneDX envelope rather than aborting.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SELFDIR = Path(__file__).resolve().parent
LIBRARY_MAP_PATH = SELFDIR / "modelica-library-map.json"

# Matches every other producer in docker/lib/ (see cdx-version.sh for the
# bash side; nothing here can source that file, so it's restated).
CDX_SPEC_VERSION = "1.6"

# One level of nesting only: each entry inside uses(...) is `Name(version =
# "X.Y.Z")` with no further parentheses of its own, so a single non-greedy
# match per entry is enough -- no need to balance nested parens.
USES_ENTRY = re.compile(r'([A-Za-z_]\w*)\s*\(\s*version\s*=\s*"([^"]+)"\s*\)')


def load_library_map():
    try:
        with open(LIBRARY_MAP_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def version_tuple(version):
    """Leading numeric fields of a version ("4.0.0" -> (4, 0, 0)); None if none."""
    if not isinstance(version, str):
        return None
    m = re.match(r"\d+(?:\.\d+)*", version.strip())
    return tuple(int(n) for n in m.group(0).split(".")) if m else None


def curated_license(entry, version):
    """SPDX id the library map records for this version, or None.

    A `uses()` declaration carries no license, so the only source is the map
    (`license`, valid from `licenseFromVersion` on). Earlier releases can be
    under a different license (Modelica Standard Library before 3.2.3 used the
    Modelica License 2), so a version below the recorded floor, or one that
    does not parse, gets no license instead of a guess. An entry with `license`
    but no usable `licenseFromVersion` is a map error: it is reported and
    yields no license, never a license for every version.
    """
    spdx = entry.get("license")
    if not spdx:
        return None
    floor = version_tuple(entry.get("licenseFromVersion"))
    if floor is None:
        print(f"[modelica] WARN: map entry {entry.get('repo', '?')} has a license "
              "but no valid licenseFromVersion; no license attached", file=sys.stderr)
        return None
    have = version_tuple(version)
    if have is None or have < floor:
        return None
    return spdx


def extract_uses_blocks(text):
    """Substrings between a `uses(` and its matching close paren."""
    blocks = []
    for m in re.finditer(r"\buses\s*\(", text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        if depth == 0:
            blocks.append(text[start:i - 1])
    return blocks


def collect_dependencies(source_dir):
    """{name: version} for every uses() entry found under source_dir.

    A name seen more than once (across files, or with conflicting versions)
    keeps the first version read -- the annotation is a per-file statement of
    what that file was written against, not a resolved graph with one true
    answer, so a stable rather than a "latest wins" choice is made.
    """
    found = {}
    for path in sorted(source_dir.rglob("*.mo")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for block in extract_uses_blocks(text):
            for name, version in USES_ENTRY.findall(block):
                found.setdefault(name, version)
    return found


def component(name, version, library_map):
    entry = library_map.get(name)
    spdx = None
    if entry:
        purl = f"pkg:github/{entry['owner']}/{entry['repo']}@{version}"
        spdx = curated_license(entry, version)
    else:
        purl = f"pkg:generic/{name}@{version}"
    props = [
        {"name": "bomlens:layer", "value": "modelica"},
        {"name": "bomlens:identifiedBy", "value": "modelica-uses-annotation"},
    ]
    if spdx:
        props.append({"name": "bomlens:licenseSource", "value": "modelica-library-map"})
    return {
        "bom-ref": purl,
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": [{"license": {"id": spdx}}] if spdx else [],
        "properties": props,
    }


def build(components, project_version):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": "modelica", "version": project_version},
        },
        "components": components,
    }


def main():
    if len(sys.argv) < 3:
        print("usage: identify-modelica.py <source_dir> <output.json> <version>", file=sys.stderr)
        return 2
    source_dir = Path(sys.argv[1])
    output = sys.argv[2]
    project_version = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    dependencies = {}
    if source_dir.is_dir():
        dependencies = collect_dependencies(source_dir)
    else:
        print(f"[modelica] source directory not found: {source_dir}", file=sys.stderr)

    library_map = load_library_map()
    components = [component(name, version, library_map)
                  for name, version in sorted(dependencies.items())]

    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(build(components, project_version), fh, indent=2)
    except OSError as err:
        print(f"[modelica] ERROR: could not write {output}: {err}", file=sys.stderr)
        return 1

    print(f"[modelica] uses() dependencies identified: {len(components)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
