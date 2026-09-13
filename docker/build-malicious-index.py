#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# build-malicious-index.py — bundle a compact OSV malicious-package snapshot for
# OFFLINE flagging (enrich-malicious.sh).
#
# Usage: build-malicious-index.py <out.json>
#
# Why: a package published to attack whoever installs it is a different problem
# from a vulnerability in an honest one. Trivy answers the second. This answers
# the first, and it must do so without a network call at scan time (air-gapped
# scans, and no per-scan latency), so the data is baked in at image BUILD time.
#
# Source: OSV's per-ecosystem archives. Malicious packages carry a "MAL-" id,
# which is how they are told apart from ordinary advisories in the same archive.
#
# Size: the raw archives are ~275 MB and their malicious entries alone expand to
# ~345 MB, which is why this reduces them to what the check actually needs: a
# PURL keyed to its MAL id, the affected versions when the advisory names them,
# and the affected SEMVER/ECOSYSTEM ranges (introduced/fixed/last_affected)
# when it gives those instead. Measured 2026-07-28 (before ranges were kept):
# 232,687 PURLs across eight ecosystems, 10.8 MB of JSON. Most entries name no
# versions and no ranges because every published version of the package is
# malicious, which is also why a name match alone is usually enough for those.
#
# Best-effort, exactly like build-eol-index.py: an ecosystem whose fetch fails is
# skipped with a warning. If NOTHING is fetched (no network in the build), no
# file is written and enrich-malicious.sh cleanly skips at scan time — the check
# is optional, never a build or scan blocker.

import datetime
import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile

ARCHIVE = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"

# The ecosystems whose PURLs a BomLens SBOM can actually carry. Ordered cheapest
# first so a spent time budget costs the least coverage; npm is last because it
# is ~200 MB on its own — larger than the other seven combined.
ECOSYSTEMS = (
    "NuGet",
    "crates.io",
    "RubyGems",
    "Maven",
    "Packagist",
    "Go",
    "PyPI",
    "npm",
)

# A single ecosystem archive can be 200 MB, so the per-request timeout is far
# larger than the EOL builder's and the whole fetch is still bounded.
REQUEST_TIMEOUT = 300
TOTAL_BUDGET = 900


def fetch_ecosystem(name):
    """Return {purl: mal_id}, {purl: [versions]} and {purl: [ranges]} for one
    OSV archive.

    Versions are kept only when the advisory lists them explicitly. When an
    advisory instead gives a SEMVER/ECOSYSTEM range (introduced/fixed/
    last_affected), that range is kept too: without it, a package with a fixed
    release (most CVE-style malicious-version-range advisories, not "every
    version is malicious" typosquats) would be flagged on every version
    including the ones released after the fix. GIT-type ranges are dropped:
    they bound commits, not the released versions an SBOM carries.
    """
    url = ARCHIVE.format(name)
    req = urllib.request.Request(url, headers={"Accept": "application/zip"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310 (https only)
        blob = resp.read()
    ids, versions, ranges = {}, {}, {}
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for entry in zf.namelist():
            if not entry.startswith("MAL-"):
                continue
            try:
                adv = json.loads(zf.read(entry))
            except (ValueError, KeyError):
                continue
            for affected in adv.get("affected", []):
                purl = (affected.get("package") or {}).get("purl")
                if not purl:
                    continue
                ids.setdefault(purl, adv.get("id"))
                vers = affected.get("versions") or []
                if vers:
                    versions.setdefault(purl, sorted(set(vers))[:200])
                    continue
                for rng in affected.get("ranges", []):
                    if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                        continue
                    events = [
                        {k: v for k, v in ev.items() if k in ("introduced", "fixed", "last_affected", "limit")}
                        for ev in rng.get("events", [])
                    ]
                    # A block that only ever says "introduced 0" (OSV's spelling
                    # for "affected from the first release") and never closes
                    # verdicts identically to the plain "no versions, no ranges"
                    # fallback (every version malicious) for every comparable
                    # version, so keeping it would only grow the index for a
                    # range that can never change the answer. Any other block,
                    # even an unclosed one with a nonzero "introduced" (affected
                    # from THAT version on, not from the start), does change the
                    # answer for versions before it and must be kept.
                    trivial = events == [{"introduced": "0"}] or events == [{"introduced": "0.0.0"}]
                    if events and not trivial:
                        ranges.setdefault(purl, []).append(events)
    return ids, versions, ranges


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: build-malicious-index.py <out.json>\n")
        return 2

    out_path = sys.argv[1]
    packages, versions, ranges = {}, {}, {}
    ok, failed, skipped = 0, [], []
    deadline = time.monotonic() + TOTAL_BUDGET
    for eco in ECOSYSTEMS:
        if time.monotonic() > deadline:
            skipped.append(eco)
            continue
        try:
            ids, vers, rngs = fetch_ecosystem(eco)
        except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as exc:
            failed.append(eco)
            sys.stderr.write(f"[mal-index] WARN: could not fetch {eco}: {exc}\n")
            continue
        packages.update(ids)
        versions.update(vers)
        ranges.update(rngs)
        ok += 1
    if skipped:
        sys.stderr.write(
            f"[mal-index] WARN: time budget ({TOTAL_BUDGET}s) spent; "
            f"skipped {len(skipped)}: {skipped}\n"
        )

    if ok == 0:
        sys.stderr.write(
            "[mal-index] WARN: fetched 0 ecosystems; not writing bundle. "
            "Malicious-package flagging will be skipped at scan time.\n"
        )
        return 0

    out = {
        "_snapshot": datetime.date.today().isoformat(),
        "_ecosystems": [e for e in ECOSYSTEMS if e not in failed and e not in skipped],
        "packages": packages,
        "versions": versions,
        "ranges": ranges,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"), sort_keys=True)
    sys.stderr.write(
        f"[mal-index] bundled {len(packages)} malicious package(s) "
        f"({len(versions)} version-limited, {len(ranges)} range-limited) from {ok} "
        f"ecosystem(s) into {out_path} (snapshot {out['_snapshot']}); "
        f"{len(failed)} failed: {failed}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
