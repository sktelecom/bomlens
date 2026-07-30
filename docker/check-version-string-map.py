#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Build gate: every CPE in version-string-map.json must exist in the bundled index.

Usage: check-version-string-map.py <version-string-map.json> <cpe_match.sqlite>

A CPE that names a vendor:product the index has never heard of matches nothing,
so the entry silently reverts to a name-and-version judgement while the table
claims otherwise. A misspelling would do it, and so would upstream renaming a
product between index rebuilds. Checked at build time, next to the index, so the
table cannot drift away from what it is matched against.

Entries with a null CPE are the deliberate case — no identifier is safe for them
— and are reported, not failed.
"""
import json
import sqlite3
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    table_path, index_path = sys.argv[1], sys.argv[2]

    entries = json.load(open(table_path)).get("entries") or []
    db = sqlite3.connect(index_path)
    missing, unmapped = [], []

    for e in entries:
        cpe = e.get("cpe")
        name = e.get("name", "?")
        if not cpe:
            unmapped.append(name)
            continue
        fields = cpe.split(":")
        if len(fields) < 5 or fields[0] != "cpe" or fields[1] != "2.3":
            missing.append(f"{name} (not a CPE 2.3 string: {cpe})")
            continue
        vendor, product = fields[3], fields[4]
        n = db.execute(
            "SELECT count(*) FROM cpe_match WHERE vendor = ? AND product = ?",
            (vendor, product),
        ).fetchone()[0]
        print(f"[build]   {name}: {vendor}:{product} -> {n} row(s)")
        if n == 0:
            missing.append(f"{name} ({vendor}:{product})")

    if unmapped:
        print(f"[build]   no CPE by design (name and version only): {', '.join(unmapped)}")
    if missing:
        print("[build] ERROR: version-string-map names a CPE the index does not have: "
              + ", ".join(missing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
