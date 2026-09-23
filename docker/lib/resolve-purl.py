#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# resolve-purl.py — OPT-IN check that a submitted PURL names a package that
# exists, by asking deps.dev for the coordinate.
#
# Usage: resolve-purl.py <sbom> <out-prefix>
# Writes: <out-prefix>_purl-resolution.json, which validate-sbom.sh reads to
# add one advisory row to the conformance report. The submitted document is
# never modified: conformance judges the original input, so the answer goes in
# a sidecar rather than into the SBOM.
#
# What this catches that no format check can. An identifier can be well formed,
# carry the namespace its type requires, and still name nothing:
#
#   pkg:maven/org.drools/org.drools.drools-core-dynamic@7.67.2.Final-redhat-00054
#       the groupId is repeated inside the artifactId
#   pkg:maven/The%2BApache%2BSoftware%2BFoundation/poi@5.4.1
#       a vendor display name sits in the groupId slot
#
# Both are produced by a generator that rebuilds identifiers from a component's
# display name instead of reading the package manager. Only a repository knows
# they resolve to nothing.
#
# The coordinate is checked, not the version. A version that a repository does
# not have is usually a vendor rebuild ("7.67.2.Final-redhat-00054") or an
# internal build, both of which are legitimate; checking it would report a
# correct component as missing. Every defect this step is meant to find shows
# up at the coordinate.
#
# A coordinate that does not resolve is reported, never failed. A package
# published only to a company-internal repository gives exactly the same
# answer, so this cannot be a requirement. PURL_RESOLVE_IGNORE drops known
# internal namespaces from the query entirely.
#
# Environment:
#   PURL_RESOLVE_IGNORE       space- or comma-separated namespace prefixes to
#                             skip (e.g. "com.acme com.acme.internal")
#   PURL_RESOLVE_BUDGET       total seconds for the whole step (default 240)
#   PURL_RESOLVE_FIXTURE_DIR  read "<system>_<name>.json" files from this
#                             directory instead of the network (tests)

import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.deps.dev/v3/systems/{system}/packages/{name}"
REQUEST_TIMEOUT = 12
MAX_WORKERS = 8
# Measured against deps.dev with eight requests in flight: 91 Maven coordinates
# answered in 3.2s, about 1,700 a minute. A large submission carries a few
# thousand distinct identifiers, so 240s leaves several times the margin that
# needs. What does not fit is reported as unchecked, never as missing.
DEFAULT_BUDGET = 240
MISSING_CAP = 50

# purl type -> deps.dev system. Only ecosystems deps.dev indexes; everything
# else (OS packages, composer, swift, cocoapods) is left unchecked and said to
# be unchecked.
SYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "golang": "go",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "rubygems",
}

TAGVALUE_PURL = re.compile(
    r"^ExternalRef:\s*PACKAGE-MANAGER\s+purl\s+(\S+)\s*$", re.MULTILINE
)


def coordinate(purl):
    """(system, deps.dev name) for a purl, or None when it cannot be asked.

    pkg:maven/org.slf4j/jcl-over-slf4j@2.0.15 -> ("maven", "org.slf4j:jcl-over-slf4j")
    pkg:npm/%40angular/core@17.0.0            -> ("npm", "@angular/core")
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
    coord = rest.rsplit("@", 1)[0] if "@" in rest else rest
    parts = [urllib.parse.unquote(s) for s in coord.split("/") if s]
    if not parts:
        return None
    if system == "maven":
        # The namespace is the group, joined to the artifact with ':'. Without a
        # namespace there is no coordinate to ask about; the purl-namespace
        # check already fails that identifier.
        if len(parts) < 2:
            return None
        return system, ".".join(parts[:-1]) + ":" + parts[-1]
    return system, "/".join(parts)


def ignored(purl, prefixes):
    if not prefixes:
        return False
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    rest = body.split("/", 1)[1] if "/" in body else ""
    name = urllib.parse.unquote(rest.rsplit("@", 1)[0] if "@" in rest else rest)
    return any(name.startswith(p) for p in prefixes)


def fetch(system, name):
    """True when the coordinate exists, False when it does not, None on error.

    The three answers are kept apart on purpose: a transient failure must not
    read as "this package does not exist".
    """
    fixture_dir = os.environ.get("PURL_RESOLVE_FIXTURE_DIR")
    if fixture_dir:
        safe = name.replace("/", "_").replace("@", "%40").replace(":", "_")
        path = os.path.join(fixture_dir, f"{system}_{safe}.json")
        if not os.path.isfile(path):
            return False
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            return None
        return bool(payload)
    url = API.format(system=system, name=urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
            json.load(resp)
            return True
    except urllib.error.HTTPError as exc:
        # 404 is the answer "no such package"; every other status is an error
        # on deps.dev's side and says nothing about the coordinate.
        return False if exc.code == 404 else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def purls_from(path):
    """Every purl in the submitted document, in document order, deduplicated."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return []
    if head.lstrip()[:1] == b"<":
        path = to_json(path) or path
    found = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for comp in data.get("components") or []:
            if isinstance(comp, dict) and isinstance(comp.get("purl"), str):
                found.append(comp["purl"])
        for pkg in data.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            for ref in pkg.get("externalRefs") or []:
                if (
                    isinstance(ref, dict)
                    and ref.get("referenceType") == "purl"
                    and isinstance(ref.get("referenceLocator"), str)
                ):
                    found.append(ref["referenceLocator"])
    else:
        found.extend(TAGVALUE_PURL.findall(text))
    seen = set()
    unique = []
    for p in found:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def to_json(path):
    """A CycloneDX XML submission read through the converter this image ships."""
    conv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdx-xml-to-json.py")
    if not os.path.isfile(conv):
        return None
    out = path + ".resolve-purl.json"
    try:
        rc = subprocess.run(
            [sys.executable, conv, path, out],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    except OSError:
        return None
    return out if rc == 0 and os.path.isfile(out) else None


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: resolve-purl.py <sbom> <out-prefix>\n")
        return 2
    sbom_path, out_prefix = sys.argv[1], sys.argv[2]
    prefixes = [
        p
        for p in re.split(r"[,\s]+", os.environ.get("PURL_RESOLVE_IGNORE", "").strip())
        if p
    ]
    try:
        budget = float(os.environ.get("PURL_RESOLVE_BUDGET", DEFAULT_BUDGET))
    except ValueError:
        budget = DEFAULT_BUDGET

    purls = purls_from(sbom_path)
    if not purls:
        sys.stderr.write("[resolve-purl] no PURLs to look up\n")

    # One question per coordinate, however many components share it.
    by_coordinate = {}
    unchecked = {"unsupported-type": 0, "ignored": 0}
    for purl in purls:
        if ignored(purl, prefixes):
            unchecked["ignored"] += 1
            continue
        coord = coordinate(purl)
        if coord is None:
            unchecked["unsupported-type"] += 1
            continue
        by_coordinate.setdefault(coord, []).append(purl)

    deadline = time.monotonic() + budget
    results = {}
    skipped = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for coord in by_coordinate:
            if time.monotonic() > deadline:
                skipped.append(coord)
                continue
            futures[pool.submit(fetch, *coord)] = coord
        for fut in concurrent.futures.as_completed(futures):
            try:
                results[futures[fut]] = fut.result()
            except Exception:  # noqa: BLE001 — best-effort, never abort a scan
                results[futures[fut]] = None

    found = missing = errored = 0
    missing_purls = []
    skipped_set = set(skipped)
    for coord, group in by_coordinate.items():
        if coord in skipped_set:
            continue
        verdict = results.get(coord)
        if verdict is True:
            found += len(group)
        elif verdict is False:
            missing += len(group)
            missing_purls.extend(group)
        else:
            errored += len(group)

    unchecked["lookup-failed"] = errored
    unchecked["budget-reached"] = sum(len(by_coordinate[c]) for c in skipped)

    report = {
        "source": "deps.dev" if not os.environ.get("PURL_RESOLVE_FIXTURE_DIR") else "fixture",
        "checkedAt": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "coordinateCount": len(by_coordinate),
        "counts": {
            "found": found,
            "missing": missing,
            "unchecked": sum(unchecked.values()),
        },
        "uncheckedReasons": {k: v for k, v in unchecked.items() if v},
        "missing": missing_purls[:MISSING_CAP],
        "missingMore": max(len(missing_purls) - MISSING_CAP, 0),
    }
    out_path = f"{out_prefix}_purl-resolution.json"
    try:
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, out_path)
    except OSError:
        sys.stderr.write("[resolve-purl] could not write the result; skipping\n")
        return 1
    sys.stderr.write(
        f"[resolve-purl] {found} identified, {missing} not found in the repository, "
        f"{report['counts']['unchecked']} unchecked "
        f"({len(by_coordinate)} coordinate(s), source {report['source']}).\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
