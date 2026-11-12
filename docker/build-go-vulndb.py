#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# build-go-vulndb.py: bundle a snapshot of the Go vulnerability database for
# the OFFLINE Go advisory match (scan-go-vulndb.py, run by scan-security.sh).
#
# Usage: build-go-vulndb.py <out.zip>
#
# Source: https://vuln.go.dev/vulndb.zip, the database's own offline export
# (index/db.json, index/modules.json, index/vulns.json and one ID/GO-*.json
# OSV record per advisory). About 3.6 MB, 4,800 records (2026-11). It is kept
# as published: scan-go-vulndb.py reads the records from the archive in place.
#
# License: the Go vulnerability database is CC-BY-4.0 (https://go.dev/security/
# vuln/database#license); its attribution is in THIRD_PARTY_LICENSES.md, and
# the snapshot date (index/db.json "modified") is named in each security
# report that used it.
#
# Best-effort, like build-eol-index.py: if the download fails or the archive
# is not a valid export, no file is written and the go-vulndb step is skipped
# at scan time (not_installed); the image build goes on.

import io
import json
import os
import re
import sys
import urllib.request
import zipfile

URL = "https://vuln.go.dev/vulndb.zip"
REQUEST_TIMEOUT = 120
MAX_BYTES = 256 * 1024 * 1024
RECORD_NAME = re.compile(r"^ID/GO-[0-9]{4}-[0-9]+\.json$")
ALLOWED_NAME = re.compile(r"^(index/(db|modules|vulns)\.json|ID/GO-[0-9]{4}-[0-9]+\.json)$")


def main():
    if len(sys.argv) != 2:
        print("usage: build-go-vulndb.py <out.zip>", file=sys.stderr)
        return 2
    out = sys.argv[1]
    req = urllib.request.Request(URL, headers={"Accept": "application/zip"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310 (https only)
        blob = resp.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        print("[build] Go vulnerability database export is larger than %d bytes; not bundled" % MAX_BYTES)
        return 1
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        bad = [n for n in names if not ALLOWED_NAME.match(n)]
        if bad:
            print("[build] unexpected entries in the Go vulnerability database export (%s); not bundled" % bad[:3])
            return 1
        records = [n for n in names if RECORD_NAME.match(n)]
        modified = json.loads(z.read("index/db.json")).get("modified", "")
        if not records or not modified:
            print("[build] the Go vulnerability database export has no records or no date; not bundled")
            return 1
        if z.testzip() is not None:
            print("[build] the Go vulnerability database export is corrupt; not bundled")
            return 1
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, out)
    print("[build] Go vulnerability database snapshot: %d records, modified %s, %d bytes -> %s"
          % (len(records), modified, len(blob), out))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # best-effort: never fail the image build
        print("[build] Go vulnerability database snapshot skipped: %s" % exc)
        sys.exit(1)
