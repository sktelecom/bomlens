#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-staleness.py — OPT-IN version-currency enrichment from deps.dev.
#
# Usage: enrich-staleness.py <sbom.json>
#
# Why: enrich-eol.sh already flags end-of-life and "behind the latest patch in
# your cycle" OFFLINE. This step adds the ABSOLUTE currency signals that need a
# live registry — the newest version across all cycles, how many releases you are
# behind, and when the newest one shipped — by querying deps.dev (Google's public
# package metadata) per component.
#
# OPT-IN by design: unlike EOL, this makes one network call per package, so it is
# gated by STALENESS_ENRICH (default off; the entrypoint only runs it when true)
# and trades the scan's offline determinism for freshness. It is best-effort: any
# failure (offline, rate-limit, unknown package) leaves the component untouched
# and never aborts the scan. Bounded by a per-request timeout, an overall wall-
# clock budget, and bounded concurrency so a large SBOM cannot stall.
#
# Emits, per component that resolves on deps.dev:
#   bomlens:staleness:latest         newest version across all release lines
#   bomlens:staleness:releasesBehind releases published after the installed one
#   bomlens:staleness:lastReleased   publish date (ISO) of the newest version
#   bomlens:staleness:source         "deps.dev@<date>"
#
# Testable offline: set STALENESS_FIXTURE_DIR to a directory of
# "<system>_<name>.json" files (the deps.dev package response shape) and no
# network is used. purl->deps.dev name uses '/' -> '_' and '@' -> '%40' escaping
# in the fixture filename.

import concurrent.futures
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.deps.dev/v3/systems/{system}/packages/{name}"
REQUEST_TIMEOUT = 12
TOTAL_BUDGET = 90
MAX_WORKERS = 8

# purl type -> deps.dev system. Only ecosystems deps.dev actually indexes.
SYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "golang": "go",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "rubygems",
}


def parse_purl(purl):
    """(system, deps.dev-name, version) from a purl, or None if unsupported.

    pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.0?type=jar
      -> ("maven", "org.springframework.boot:spring-boot-starter-web", "3.2.0")
    pkg:npm/%40angular/core@17.0.0 -> ("npm", "@angular/core", "17.0.0")
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    system = SYSTEMS.get(ptype.lower())
    if not system:
        return None
    if "@" not in rest:
        return None
    coord, version = rest.rsplit("@", 1)
    version = urllib.parse.unquote(version)
    parts = [urllib.parse.unquote(s) for s in coord.split("/")]
    if system == "maven":
        # namespace is the group; joined to the artifact with ':'
        if len(parts) < 2:
            return None
        name = ".".join(parts[:-1]) + ":" + parts[-1]
    else:
        # npm scoped packages keep the '@scope/name' form
        name = "/".join(parts)
    if not version:
        return None
    return system, name, version


def fetch_package(system, name):
    fixture_dir = os.environ.get("STALENESS_FIXTURE_DIR")
    if fixture_dir:
        safe = name.replace("/", "_").replace("@", "%40")
        path = os.path.join(fixture_dir, f"{system}_{safe}.json")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    url = API.format(system=system, name=urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
            return json.load(resp)
    except (urllib.error.URLError, OSError, ValueError):
        return None


def currency(pkg, installed):
    """(latest, releases_behind, last_released) from a deps.dev package payload.

    latest = the default version (the registry's current release). releases_behind
    = versions published strictly after the installed one, excluding deprecated —
    a publish-time proxy for "N releases behind" that avoids cross-ecosystem semver
    sorting. Returns None if the payload is unusable or the installed version is
    unknown to deps.dev.
    """
    versions = (pkg or {}).get("versions") or []
    if not versions:
        return None
    installed_at = None
    default = None
    for v in versions:
        ver = (v.get("versionKey") or {}).get("version")
        if ver == installed:
            installed_at = v.get("publishedAt")
        if v.get("isDefault"):
            default = v
    if default is None:
        return None
    latest = (default.get("versionKey") or {}).get("version")
    last_released = default.get("publishedAt")
    if installed_at is None:
        # Installed version not in deps.dev — report latest, but not a behind count
        # we cannot trust.
        return latest, None, last_released
    behind = sum(
        1
        for v in versions
        if not v.get("isDeprecated")
        and v.get("publishedAt")
        and v.get("publishedAt") > installed_at
    )
    return latest, behind, last_released


def enrich_one(comp, snap):
    parsed = parse_purl(comp.get("purl") or "")
    if not parsed:
        return None
    system, name, installed = parsed
    pkg = fetch_package(system, name)
    if pkg is None:
        return None
    result = currency(pkg, installed)
    if result is None:
        return None
    latest, behind, last_released = result
    props = [{"name": "bomlens:staleness:source", "value": f"deps.dev@{snap}"}]
    if latest is not None:
        props.append({"name": "bomlens:staleness:latest", "value": str(latest)})
    if behind is not None:
        props.append(
            {"name": "bomlens:staleness:releasesBehind", "value": str(behind)}
        )
    if last_released:
        props.append(
            {"name": "bomlens:staleness:lastReleased", "value": str(last_released)}
        )
    return props


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: enrich-staleness.py <sbom.json>\n")
        return 2
    sbom_path = sys.argv[1]
    try:
        with open(sbom_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        sys.stderr.write("[staleness] SBOM missing or invalid; skipping\n")
        return 0

    comps = data.get("components")
    if not isinstance(comps, list):
        return 0

    snap = datetime.date.today().isoformat()
    deadline = time.monotonic() + TOTAL_BUDGET

    # Strip any prior staleness props first (idempotent re-runs).
    for c in comps:
        props = c.get("properties")
        if isinstance(props, list):
            c["properties"] = [
                p
                for p in props
                if not str(p.get("name", "")).startswith("bomlens:staleness")
            ]

    enriched = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for c in comps:
            if time.monotonic() > deadline:
                break
            futures[pool.submit(enrich_one, c, snap)] = c
        for fut in concurrent.futures.as_completed(futures):
            try:
                new_props = fut.result()
            except Exception:  # noqa: BLE001 — best-effort, never abort
                new_props = None
            if new_props:
                c = futures[fut]
                c.setdefault("properties", [])
                c["properties"].extend(new_props)
                enriched += 1

    try:
        tmp = sbom_path + ".staleness.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, sbom_path)
    except OSError:
        sys.stderr.write("[staleness] could not write SBOM; leaving unchanged\n")
        return 0

    sys.stderr.write(
        f"[staleness] added deps.dev currency to {enriched} component(s) "
        f"(source deps.dev@{snap}).\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
