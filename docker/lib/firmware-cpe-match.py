#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# firmware-cpe-match.py — match a firmware component SBOM against the distilled
# NVD CPE index (build-cpe-index.py) and emit cve-bin-tool-shaped CVE rows.
#
# Usage: firmware-cpe-match.py <component_sbom.cdx.json> <cpe_match.sqlite>
#   prints, to stdout, a JSON array of flat rows:
#     [ { "cve_number", "product", "version", "severity", "score", "cvss_version" } ]
#   which match-cpe-index.sh reshapes into the Trivy-style sidecar that
#   scan-security.sh merges.
#
# cve-bin-tool identifies firmware binaries and writes a CycloneDX SBOM whose
# components carry a CPE (2.2 URI form, e.g. cpe:/a:haxx:curl:8.14.1). We parse
# vendor/product/version out of that CPE, look up the vendor/product in the index,
# and apply the NVD version-range logic. No network, no cve-bin-tool DB.

import json
import re
import sqlite3
import sys

# Prefer cve-bin-tool's own version comparator so our matching agrees with how
# cve-bin-tool reads NVD ranges (it handles openssl letter releases like
# 1.1.1 < 1.1.1a < 1.1.1k and pre-release suffixes, which naive parsing gets
# wrong). Falls back to a self-contained comparator when cve-bin-tool is not
# installed, as in the base image.
try:
    from cve_bin_tool.version_compare import Version as _CBTVersion
except Exception:  # pragma: no cover - only when run outside the firmware image
    _CBTVersion = None


def parse_cpe(cpe):
    """Return (vendor, product, version) from a CPE 2.2 URI or 2.3 string, else None."""
    if not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        f = cpe.split(":")
        if len(f) >= 6 and f[2] == "a":
            return f[3], f[4], f[5]
        return None
    if cpe.startswith("cpe:/"):
        f = cpe[len("cpe:/"):].split(":")
        if len(f) >= 4 and f[0] == "a":
            return f[1], f[2], f[3]
    return None


_part_re = re.compile(r"(\d+|[a-zA-Z]+)")

# Words that mark a release before the version they follow (2.0.0rc1 < 2.0.0).
_PRE_RELEASE = {"pre", "rc", "alpha", "beta", "dev"}


def _tokens(v):
    """Split a version into numeric and alphabetic tokens: 1.0.2h -> [1, 0, 2, 'h']."""
    out = []
    for chunk in re.split(r"[^0-9A-Za-z]+", str(v)):
        for tok in _part_re.findall(chunk):
            out.append(int(tok) if tok.isdigit() else tok.lower())
    return out


def _fallback_cmp(a, b):
    """Compare two versions without cve-bin-tool (the base image has none).

    Same reading as the firmware image's comparator for the release forms NVD
    records: a letter after the last number is a later release (OpenSSL's
    1.0.2 < 1.0.2h < 1.0.2i, OpenSSH's 6.2 < 6.2p2), and a pre-release word
    is an earlier one (2.0.0rc1 < 2.0.0). At one position a number is later
    than a letter, so 1.0.2h < 1.0.3. Trailing zero components do not count,
    so 1.0 == 1.0.0 and 5.4.0 == 5.4, while 5.4.0rc1 < 5.4 < 5.4.0.1.
    """
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        xn, yn = isinstance(x, int), isinstance(y, int)
        if xn and yn:
            return (x > y) - (x < y)
        if xn != yn:
            return 1 if xn else -1
        xp, yp = x in _PRE_RELEASE, y in _PRE_RELEASE
        if xp != yp:
            return -1 if xp else 1
        return (x > y) - (x < y)
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    rest = longer[min(len(ta), len(tb)):]
    # Zero components the shorter version leaves out are equal to it.
    while rest and rest[0] == 0 and isinstance(rest[0], int):
        rest = rest[1:]
    if not rest:
        return 0
    nxt = rest[0]
    if isinstance(nxt, str) and nxt in _PRE_RELEASE:
        return -sign
    return sign


# Release prefixes that are not part of the number. The Go toolchain writes
# `go1.25.6` and Go modules write `v0.37.0`; NVD records both bounds as plain
# numbers, so the prefix is dropped before comparing.
#
# Only these two, and only immediately before a digit. A version is not a
# free-text field to normalize — dropping more would match releases that are
# genuinely different.
_VERSION_PREFIX_RE = re.compile(r"^(?:go|v)(?=[0-9])")


def _strip_version_prefix(v):
    return _VERSION_PREFIX_RE.sub("", v.strip()) if isinstance(v, str) else v


def vcmp(a, b):
    a, b = _strip_version_prefix(a), _strip_version_prefix(b)
    if _CBTVersion is not None:
        try:
            va, vb = _CBTVersion(a), _CBTVersion(b)
            return (va > vb) - (va < vb)
        except Exception:
            pass
    return _fallback_cmp(a, b)


# Whether a string can be compared as a version at all. A version has to contain
# a digit, which admits every real release form (letter suffixes like 1.0.2h,
# Debian epochs like 2:9.1) and rejects the placeholders this pipeline uses when
# no version was recovered: UNKNOWN, -, * and the empty string.
#
# A comparison that cannot be made is never a match. Both the version and the
# bound must be comparable for a bound to hold.
_HAS_DIGIT_RE = re.compile(r"[0-9]")


def usable_version(v):
    return isinstance(v, str) and _HAS_DIGIT_RE.search(v) is not None


def in_range(v, exact, vstart, vs_incl, vend, ve_incl):
    if not usable_version(v):
        return False
    if exact is not None:
        return usable_version(exact) and vcmp(v, exact) == 0
    ok = True
    if vstart is not None:
        if not usable_version(vstart):
            return False
        ok = ok and (vcmp(v, vstart) >= 0 if vs_incl else vcmp(v, vstart) > 0)
    if vend is not None:
        if not usable_version(vend):
            return False
        ok = ok and (vcmp(v, vend) <= 0 if ve_incl else vcmp(v, vend) < 0)
    # No exact version and no bounds -> the CPE marks every version vulnerable.
    return ok


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: firmware-cpe-match.py <sbom.json> <cpe_match.sqlite>")
    sbom_path, db_path = sys.argv[1], sys.argv[2]

    try:
        with open(sbom_path) as fh:
            sbom = json.load(fh)
    except (OSError, ValueError):
        print("[]")
        return

    conn = sqlite3.connect(db_path)
    out = []
    for comp in sbom.get("components", []):
        parsed = parse_cpe(comp.get("cpe"))
        if not parsed:
            continue
        vendor, product, cpe_ver = parsed
        # Prefer the component's own version; fall back to the CPE's version field.
        version = comp.get("version") or (cpe_ver if cpe_ver not in ("*", "-", "") else None)
        # A placeholder is not a version, so a presence-only judgement (reported
        # without one) is matched against nothing.
        if not usable_version(version):
            continue
        seen = set()
        for row in conn.execute(
            "SELECT exact_version, version_start, vs_incl, version_end, ve_incl, "
            "cve_id, severity, cvss_version, cvss_score "
            "FROM cpe_match WHERE vendor=? AND product=?",
            (vendor, product),
        ):
            exact, vstart, vs_incl, vend, ve_incl, cve_id, sev, cvss_ver, score = row
            if cve_id in seen:
                continue
            try:
                hit = in_range(version, exact, vstart, vs_incl, vend, ve_incl)
            except Exception:
                hit = False
            if not hit:
                continue
            seen.add(cve_id)
            out.append({
                "cve_number": cve_id,
                "product": product,
                "version": version,
                "severity": sev or "UNKNOWN",
                "score": score,
                "cvss_version": cvss_ver or "3",
            })
    conn.close()
    print(json.dumps(out))


if __name__ == "__main__":
    main()
