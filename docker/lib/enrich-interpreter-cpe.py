#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-interpreter-cpe.py — attach an NVD-matchable cpe:2.3 to a small,
# hand-verified set of interpreter/runtime components published as an ordinary
# package under an ecosystem package manager, so a CPE-aware scanner (grype)
# can find their CVEs.
#
# Usage: enrich-interpreter-cpe.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: some environments distribute a language interpreter itself (not a
# library written in that language) through a package manager whose ecosystem
# advisory feed was built for libraries, not for the interpreter — e.g. a conda
# environment.yml pinning `python`, or a NuGet package that bundles the CPython
# interpreter. Trivy parses pkg:conda/ and pkg:nuget/ purls fine (unlike
# pkg:github/, which it does not recognize at all), but its ecosystem advisory
# source for these two package managers carries no entries for a package named
# "python": conda's and NuGet's own advisory feeds are not where CPython's CVEs
# are published. Those CVEs live in NVD, keyed by cpe:2.3:a:python:python. A
# scanner can only reach them if the component carries that CPE.
#
# What it does NOT do: derive a CPE from the purl name automatically. A bare
# package name is not a safe vendor:product guess in general — this script
# exists because "python" specifically is confirmed to carry no cpe today and
# to resolve to cpe:2.3:a:python:python in NVD, not because every conda/nuget
# package name is safe to look up this way. So this only ever attaches a CPE
# for a (purl type, name) pair listed in INTERPRETER_CPE_MAP below, each
# individually verified against NVD. Anything else gets no CPE and is left
# exactly as the generator produced it. Restricting to conda/nuget (rather than,
# say, matching "python" by name across every ecosystem) also keeps this from
# touching an unrelated package that merely happens to be named "python" in an
# ecosystem where that name means something else (e.g. an npm helper package).
#
# A pre-existing cpe on the component is never touched.
import json
import re
import sys

# Curated (purl type, name) -> (vendor, product). Verified against NVD; each
# entry's CPE was confirmed to carry real, version-ranged NVD vulnerabilities.
# Keep this list short and hand-checked — do not add an entry by assuming a
# purl name matches its NVD vendor:product.
INTERPRETER_CPE_MAP = {
    ("conda", "python"): ("python", "python"),
    ("nuget", "python"): ("python", "python"),
}

# Versions with a CPE-unsafe shape are left alone: a ':' (cpe field separator),
# whitespace, or a wildcard would shift or break the 13-field cpe:2.3 grammar.
_CPE_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

_PURL_RE = re.compile(r"^pkg:(conda|nuget)/([^@]+)@(.+)$")


def _parse_interpreter(purl):
    """pkg:<type>/<name>@<version> -> (type, name, version), type in {conda, nuget}."""
    m = _PURL_RE.match(purl)
    if not m:
        return None
    ptype, name, version = m.group(1), m.group(2), m.group(3).split("?", 1)[0]
    return ptype, name, version


def derive_cpe(purl):
    """Return an NVD-matchable cpe:2.3 string, or None if this (type, name) is
    not in the curated map or the version is not safe to embed in a cpe:2.3 URI."""
    parsed = _parse_interpreter(purl)
    if not parsed:
        return None
    ptype, name, version = parsed
    if not _CPE_SAFE_VERSION.match(version):
        return None
    entry = INTERPRETER_CPE_MAP.get((ptype, name.lower()))
    if not entry:
        return None
    vendor, product = entry
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[interpreter-cpe] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return
    components = doc.get("components")
    if not isinstance(components, list):
        return

    n = 0
    for c in components:
        purl = c.get("purl", "")
        if not (purl.startswith("pkg:conda/") or purl.startswith("pkg:nuget/")):
            continue  # not a purl type this script curates
        if c.get("cpe"):
            continue  # a cpe is already present; never overwrite it
        cpe = derive_cpe(purl)
        if not cpe:
            continue
        c["cpe"] = cpe
        props = [p for p in (c.get("properties") or []) if p.get("name") != "bomlens:cpeSource"]
        props.append({"name": "bomlens:cpeSource", "value": "interpreter-curated"})
        c["properties"] = props
        n += 1

    if n:
        with open(path, "w") as f:
            json.dump(doc, f, ensure_ascii=False)
        print(f"[interpreter-cpe] attached an NVD-matchable cpe:2.3 to {n} interpreter "
              f"component(s) for CPE-based CVE matching.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-interpreter-cpe.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
