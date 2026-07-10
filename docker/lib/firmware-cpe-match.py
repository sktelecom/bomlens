#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# firmware-cpe-match.py — match a firmware component SBOM against the distilled
# NVD CPE index (build-cpe-index.py) and emit cve-bin-tool-shaped CVE rows.
#
# Usage: firmware-cpe-match.py <component_sbom.cdx.json> <cpe_match.sqlite>
#   prints, to stdout, a JSON array of flat rows:
#     [ { "cve_number", "product", "version", "severity", "score", "cvss_version" } ]
#   which is the exact shape scan-firmware.sh step ⑤ reshapes into the Trivy-style
#   sidecar, so nothing downstream changes.
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
# wrong). Falls back to a self-contained comparator if the import ever changes.
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


def _key(v):
    """Split a version into a comparable list of (is_num, value) tokens.

    Handles dotted-numeric with alpha suffixes (1.30.1, 8.14.1, 1.1.1k, 2.0.0rc1)
    without depending on PEP 440. Numeric tokens sort below alpha of the same
    position so 1.1.1 < 1.1.1k.
    """
    toks = []
    for chunk in re.split(r"[.\-_+~]", str(v)):
        for tok in _part_re.findall(chunk):
            if tok.isdigit():
                toks.append((1, int(tok), ""))
            else:
                toks.append((0, 0, tok.lower()))
    return toks


def vcmp(a, b):
    if _CBTVersion is not None:
        try:
            va, vb = _CBTVersion(a), _CBTVersion(b)
            return (va > vb) - (va < vb)
        except Exception:
            pass
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    ka += [(1, 0, "")] * (n - len(ka))
    kb += [(1, 0, "")] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def in_range(v, exact, vstart, vs_incl, vend, ve_incl):
    if exact is not None:
        return vcmp(v, exact) == 0
    ok = True
    if vstart is not None:
        ok = ok and (vcmp(v, vstart) >= 0 if vs_incl else vcmp(v, vstart) > 0)
    if vend is not None:
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
        if not version:
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
