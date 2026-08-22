#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-github-cpe.py — attach an NVD-matchable cpe:2.3 to a small, hand-verified
# set of pkg:github/ components so a CPE-aware scanner (grype) can find their CVEs.
#
# Usage: enrich-github-cpe.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: a component identified only by its source-repository coordinates
# (pkg:github/<owner>/<repo>@<version> — typical for large C/C++ projects that
# have no package-manager ecosystem: browser engines, header-only libraries,
# vendored copies pulled straight from a git tag) carries no purl a package-
# ecosystem vulnerability source (npm/pip/maven/GHSA-by-ecosystem) can match
# against, and Trivy's SBOM scanner does not recognize pkg:github/ at all — it
# neither errors nor emits a Result for it, so a scan silently returns zero
# findings for these components. Their CVEs, when they exist, live in NVD keyed
# by CPE. A scanner can only reach them if the component carries the right CPE.
#
# What it does NOT do: derive a CPE from the github owner/repo automatically.
# That mapping does not hold in general — NVD's vendor:product frequently
# differs from the repo's own org/name (chromium/chromium -> google:chrome, not
# chromium:chromium), and a mirror or vendored fork can carry a completely
# unrelated org name (hunter-packages/boost -> boost:boost). Guessing would
# attach a wrong CPE and inject unrelated CVEs, which is worse than none. So
# this only ever attaches a CPE for an owner/repo pair listed in
# GITHUB_CPE_MAP below, each individually verified against NVD. Anything else
# gets no CPE and is left exactly as cdxgen/syft produced it.
#
# A pre-existing cpe on the component is never touched.
import json
import re
import sys

# Curated (owner/repo) -> (vendor, product). Verified against NVD; each entry's
# CPE was confirmed to carry real, version-ranged NVD vulnerabilities. Keep this
# list short and hand-checked — do not add an entry by pattern-matching a repo
# name against its apparent vendor.
GITHUB_CPE_MAP = {
    ("chromium", "chromium"): ("google", "chrome"),
    ("boostorg", "boost"): ("boost", "boost"),
    ("hunter-packages", "boost"): ("boost", "boost"),
    ("open5gs", "open5gs"): ("open5gs", "open5gs"),
}

# Versions with a CPE-unsafe shape are left alone: a ':' (cpe field separator),
# whitespace, or a wildcard would shift or break the 13-field cpe:2.3 grammar.
_CPE_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def _parse_github(purl):
    """pkg:github/<owner>/<repo>@<version> -> (owner, repo, version)."""
    m = re.match(r"pkg:github/([^/]+)/([^@]+)@(.+)$", purl)
    if not m:
        return None
    owner, repo, version = m.group(1), m.group(2), m.group(3).split("?", 1)[0]
    return owner, repo, version


def derive_cpe(purl):
    """Return an NVD-matchable cpe:2.3 string, or None if this owner/repo is not
    in the curated map or the version is not safe to embed in a cpe:2.3 URI."""
    parsed = _parse_github(purl)
    if not parsed:
        return None
    owner, repo, version = parsed
    if not _CPE_SAFE_VERSION.match(version):
        return None
    entry = GITHUB_CPE_MAP.get((owner.lower(), repo.lower()))
    if not entry:
        return None
    vendor, product = entry
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[github-cpe] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return
    components = doc.get("components")
    if not isinstance(components, list):
        return

    n = 0
    for c in components:
        purl = c.get("purl", "")
        if not purl.startswith("pkg:github/"):
            continue  # not a github-coordinate component
        if c.get("cpe"):
            continue  # a cpe is already present; never overwrite it
        cpe = derive_cpe(purl)
        if not cpe:
            continue
        c["cpe"] = cpe
        props = [p for p in (c.get("properties") or []) if p.get("name") != "bomlens:cpeSource"]
        props.append({"name": "bomlens:cpeSource", "value": "github-curated"})
        c["properties"] = props
        n += 1

    if n:
        with open(path, "w") as f:
            json.dump(doc, f, ensure_ascii=False)
        print(f"[github-cpe] attached an NVD-matchable cpe:2.3 to {n} github-coordinate "
              f"component(s) for CPE-based CVE matching.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-github-cpe.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
