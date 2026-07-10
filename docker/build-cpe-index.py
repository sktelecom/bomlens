#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# build-cpe-index.py — distill a compact CPE->CVE applicability index from the
# fkie-cad/nvd-json-data-feeds NVD 2.0 JSON tree.
#
# Usage: build-cpe-index.py <feed_dir> <out_sqlite>
#
# Why: firmware binaries carry only a CPE (no purl), and Trivy cannot match CVEs
# by CPE. cve-bin-tool can, but building its full ~1.5 GB cve.db needs the NVD
# api2 detail fetch, which NVD rate-limits into multi-hour stalls. The NVD data
# itself is available in bulk (fkie-cad, a plain git clone, no rate limit), so we
# distill just the application-part CPE applicability rows we actually match on
# into a small SQLite index. firmware-cpe-match.py reads it at scan time.
#
# We keep ONLY part 'a' (applications) — firmware binaries map to cpe:2.3:a:... —
# which drops OS/hardware rows and shrinks the index. Each row is one vulnerable
# cpeMatch: its vendor/product plus the version bounds, tagged with the CVE and
# its severity/score so the matcher can emit findings without a second lookup.

import json
import os
import sqlite3
import sys

SCHEMA = """
CREATE TABLE cpe_match (
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    exact_version TEXT,            -- set when the CPE pins a version (field 5 != * / -)
    version_start TEXT,            -- versionStartIncluding/Excluding
    vs_incl       INTEGER,         -- 1 = Including, 0 = Excluding
    version_end   TEXT,            -- versionEndIncluding/Excluding
    ve_incl       INTEGER,
    cve_id        TEXT NOT NULL,
    severity      TEXT,
    cvss_version  TEXT,            -- "3" or "2"
    cvss_score    REAL
);
"""


def severity_of(cve):
    """Pick the best CVSS metric: v3.1 > v3.0 > v2. Returns (severity, majorver, score)."""
    metrics = cve.get("metrics", {})
    for key, major in (("cvssMetricV31", "3"), ("cvssMetricV30", "3"), ("cvssMetricV2", "2")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        entry = arr[0]
        data = entry.get("cvssData", {})
        sev = entry.get("baseSeverity") or data.get("baseSeverity")
        score = data.get("baseScore")
        return sev, major, score
    return None, None, None


def iter_cve_files(feed_dir):
    """Yield every CVE JSON path under <feed>/CVE-*/*/CVE-*.json using scandir (fast)."""
    for year_entry in os.scandir(feed_dir):
        if not year_entry.is_dir() or not year_entry.name.startswith("CVE-"):
            continue
        for bucket in os.scandir(year_entry.path):
            if not bucket.is_dir():
                continue
            for f in os.scandir(bucket.path):
                if f.name.startswith("CVE-") and f.name.endswith(".json"):
                    yield f.path


def rows_from_cve(path):
    """Extract application-part vulnerable cpeMatch rows from one CVE JSON."""
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return
    cve = doc.get("cve", doc)
    cid = cve.get("id")
    if not cid:
        return
    sev, cvss_ver, score = severity_of(cve)
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                fields = (m.get("criteria") or "").split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(fields) < 6 or fields[1] != "2.3" or fields[2] != "a":
                    continue
                vendor, product, ver = fields[3], fields[4], fields[5]
                vsi = m.get("versionStartIncluding")
                vse = m.get("versionStartExcluding")
                vei = m.get("versionEndIncluding")
                vee = m.get("versionEndExcluding")
                yield (
                    vendor,
                    product,
                    None if ver in ("*", "-") else ver,
                    vsi if vsi is not None else vse,
                    1 if vsi is not None else 0,
                    vei if vei is not None else vee,
                    1 if vei is not None else 0,
                    cid,
                    sev,
                    cvss_ver,
                    score,
                )


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-cpe-index.py <feed_dir> <out_sqlite>")
    feed_dir, out_path = sys.argv[1], sys.argv[2]
    if os.path.exists(out_path):
        os.remove(out_path)

    conn = sqlite3.connect(out_path)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.executescript(SCHEMA)

    files = cves = rows = 0
    batch = []
    for path in iter_cve_files(feed_dir):
        files += 1
        got = False
        for row in rows_from_cve(path):
            batch.append(row)
            rows += 1
            got = True
        if got:
            cves += 1
        if len(batch) >= 5000:
            conn.executemany("INSERT INTO cpe_match VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            batch = []
    if batch:
        conn.executemany("INSERT INTO cpe_match VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)

    conn.execute("CREATE INDEX ix_vp ON cpe_match (vendor, product)")
    conn.commit()
    conn.close()

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"[cpe-index] scanned {files} CVE files, {cves} with app CPEs, {rows} rows, {size_mb:.0f} MB")


if __name__ == "__main__":
    main()
