#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# build-eol-index.py — bundle a compact endoflife.date snapshot for OFFLINE EOL
# flagging (enrich-eol.sh).
#
# Usage: build-eol-index.py <eol-purl-map.json> <out.json>
#
# Why: enrich-eol.sh must decide "is this release cycle past its end-of-life?"
# without a network call (air-gapped scans, and no per-scan latency). So at image
# BUILD time we fetch, once, the endoflife.date data for exactly the products the
# map references and bake it into the image. The result (out.json) is a few KB.
#
# Attribution: end-of-life dates are sourced from https://endoflife.date. Its code
# is MIT; the lifecycle dates are factual data. The snapshot date is recorded in
# out.json under "_snapshot" and surfaced on each flagged component by
# enrich-eol.sh (bomlens:eol:source).
#
# Best-effort: a product whose fetch fails is skipped with a warning; the build is
# not aborted. If NOTHING is fetched (e.g. no network), no file is written and
# enrich-eol.sh cleanly skips at scan time — EOL flagging is optional, never a
# blocker.

import datetime
import json
import sys
import urllib.error
import urllib.request

API = "https://endoflife.date/api/{}.json"
# Only the fields enrich-eol.sh (and later staleness) actually reads, to keep the
# bundle small.
KEEP = ("cycle", "eol", "releaseDate", "latest", "latestReleaseDate")


def distinct_products(map_path):
    with open(map_path, encoding="utf-8") as fh:
        data = json.load(fh)
    seen = []
    for rule in data.get("rules", []):
        product = rule.get("product")
        if product and product not in seen:
            seen.append(product)
    return seen


def fetch(product):
    url = API.format(product)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https only)
        cycles = json.load(resp)
    return [{k: c[k] for k in KEEP if k in c} for c in cycles]


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: build-eol-index.py <eol-purl-map.json> <out.json>\n")
        return 2

    map_path, out_path = sys.argv[1], sys.argv[2]
    products = distinct_products(map_path)
    out = {"_snapshot": datetime.date.today().isoformat()}
    ok, failed = 0, []
    for product in products:
        try:
            out[product] = fetch(product)
            ok += 1
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            failed.append(product)
            sys.stderr.write(f"[eol-index] WARN: could not fetch {product}: {exc}\n")

    if ok == 0:
        sys.stderr.write(
            "[eol-index] WARN: fetched 0 products; not writing bundle. "
            "EOL flagging will be skipped at scan time.\n"
        )
        return 0

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"), sort_keys=True)
    sys.stderr.write(
        f"[eol-index] bundled {ok} product(s) into {out_path} "
        f"(snapshot {out['_snapshot']}); {len(failed)} failed: {failed}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
