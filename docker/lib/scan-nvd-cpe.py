#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# scan-nvd-cpe.py — run grype's CPE matcher against a CPE-enriched SBOM and emit
# the NVD-only findings as a Trivy-shaped sidecar for scan-security.sh to merge.
#
# Usage: scan-nvd-cpe.py <sbom.json> <out_prefix>
#   writes <out_prefix>_security_grype.json  (Trivy-shaped .Results[].Vulnerabilities[])
#
# Why: enrich-maven-cpe.py attaches an NVD-matchable cpe:2.3 to maven components,
# but attaching a CPE does nothing on its own — a CPE-matching engine has to run.
# Trivy's SBOM scan ignores component.cpe; grype does honor it (with
# GRYPE_MATCH_JAVA_USING_CPES). So we run grype for its CPE matches only and hand
# them to the existing sidecar-merge path. This recovers the NVD-only CVEs of
# older Apache/maven libraries that GitHub Security Advisory (Trivy's maven
# source) lacks — measured recovery: maven recall 14% -> ~79% on a supplier SBOM.
#
# Only grype's nvd:cpe matches are emitted: Trivy already covers the GHSA maven
# CVEs, so taking grype's GHSA matches too would just duplicate. The sidecar merge
# and the report's dedup handle any residual overlap by (purl, cve).
#
# NVD version filter (opt-in, SECURITY_NVD_VERIFY, default on in this image):
# grype's bundled DB drops the lower version bound on some NVD CPE ranges, so a
# fixed-in-9.0.104 Tomcat CVE (really >= 9.0.0) matches a 7.0.50 module. We
# re-check each finding against the live NVD range (lower AND upper bound) and drop
# the ones the component version falls outside. Needs network + NVD_API_KEY; when
# unreachable (air-gapped) the filter is skipped and every kept finding is flagged
# bomlens:cpeVersionUnverified so the report can show the caveat instead of hiding
# possible false positives.
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import urllib.request
    import urllib.parse
    import urllib.error
    _HAVE_NET = True
except Exception:  # pragma: no cover
    _HAVE_NET = False

GRYPE = os.environ.get("GRYPE_BIN", "grype")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# grype's vulnerability.fix.state -> Trivy's Status string. "unknown" and a
# missing fix object both map to "leave the key out" (see build_sidecar).
GRYPE_FIX_STATE_TO_STATUS = {"fixed": "fixed", "not-fixed": "affected", "wont-fix": "will_not_fix"}

# grype's nvd:cpe severity string -> Trivy's VendorSeverity integer scale.
GRYPE_SEVERITY_TO_VENDOR = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---- version comparison (maven/NVD, best-effort numeric) -------------------
def _ver_tuple(v):
    v = re.sub(r"[^0-9.].*$", "", str(v))  # 1.8.7-r2 / 5.0.0.RELEASE -> numeric head
    out = []
    for x in v.split("."):
        try:
            out.append(int(x))
        except ValueError:
            out.append(0)
    return tuple(out) or (0,)


def _cmp(a, b):
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _in_range(ver, m):
    """Is `ver` inside this NVD cpeMatch's version range?"""
    if m.get("versionStartIncluding") and _cmp(ver, m["versionStartIncluding"]) < 0:
        return False
    if m.get("versionStartExcluding") and _cmp(ver, m["versionStartExcluding"]) <= 0:
        return False
    if m.get("versionEndIncluding") and _cmp(ver, m["versionEndIncluding"]) > 0:
        return False
    if m.get("versionEndExcluding") and _cmp(ver, m["versionEndExcluding"]) >= 0:
        return False
    bounded = any(m.get(k) for k in (
        "versionStartIncluding", "versionStartExcluding",
        "versionEndIncluding", "versionEndExcluding"))
    if not bounded:
        parts = m["criteria"].split(":")
        cver = parts[5] if len(parts) > 5 else "*"
        if cver not in ("*", "-") and _cmp(ver, cver) != 0:
            return False
    return True


# ---- NVD lookup (cached) ----------------------------------------------------
def _nvd_matches(cve, key, cache):
    if cve in cache:
        return cache[cve]
    if not _HAVE_NET:
        cache[cve] = None
        return None
    params = urllib.parse.urlencode({"cveId": cve})
    req = urllib.request.Request(f"{NVD_API}?{params}")
    if key:
        req.add_header("apiKey", key)
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.load(resp)
            break
        except Exception:
            time.sleep(6)
    else:
        cache[cve] = None
        return None
    vulns = data.get("vulnerabilities", [])
    matches = []
    if vulns:
        for cfg in vulns[0]["cve"].get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        matches.append(m)
    cache[cve] = matches
    return matches


def _cpe_product(cpe):
    parts = (cpe or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def _nvd_cpe_vendor_severity(m, vuln, is_nvd):
    """Trivy-shaped VendorSeverity (e.g. {"nvd": 3}) from grype's nvd:cpe rating.

    When the primary match namespace already is nvd:cpe, use its severity
    directly. Otherwise look for the nvd:cpe entry among relatedVulnerabilities
    (the common case: grype's primary match comes from a different namespace).
    """
    if is_nvd:
        sev = vuln.get("severity")
    else:
        sev = next((r.get("severity") for r in (m.get("relatedVulnerabilities") or [])
                    if r.get("namespace") == "nvd:cpe"), None)
    n = GRYPE_SEVERITY_TO_VENDOR.get((sev or "").lower())
    return {"nvd": n} if n is not None else None


def _grype_db_path():
    """Path to grype's local sqlite vulnerability DB, or None if unavailable."""
    try:
        p = subprocess.run([GRYPE, "db", "status", "-o", "json"],
                            capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            return None
        data = json.loads(p.stdout)
        path = data.get("path")
        if path and os.path.exists(path):
            return path
    except Exception:
        pass
    return None


def _to_iso8601(raw):
    """Best-effort conversion of a sqlite date string to Trivy-shaped ISO 8601."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).strip())
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _published_date(conn, cve):
    """CVE published date from grype's local DB (nvd provider), Trivy-shaped."""
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT published_date FROM vulnerability_handles "
            "WHERE provider_id = 'nvd' AND name = ? LIMIT 1",
            (cve,)).fetchone()
    except Exception:
        return None
    if not row:
        return None
    return _to_iso8601(row[0])


# ---- main -------------------------------------------------------------------
def run_grype(sbom):
    print("[nvd-cpe] grype CPE matching started")
    env = dict(os.environ, GRYPE_MATCH_JAVA_USING_CPES="true")
    try:
        p = subprocess.run(
            [GRYPE, f"sbom:{sbom}", "--by-cve", "-o", "json"],
            capture_output=True, text=True, env=env, timeout=600)
    except FileNotFoundError:
        print("[nvd-cpe] WARN: grype not installed in this image; skipping", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[nvd-cpe] WARN: grype timed out; skipping", file=sys.stderr)
        return None
    if p.returncode != 0:
        print(f"[nvd-cpe] WARN: grype exited {p.returncode}; skipping", file=sys.stderr)
        return None
    try:
        return json.loads(p.stdout)
    except ValueError:
        print("[nvd-cpe] WARN: grype output unparseable; skipping", file=sys.stderr)
        return None


def build_sidecar(sbom_path, out_prefix):
    g = run_grype(sbom_path)
    if g is None:
        return
    # Default off: the base behavior stays offline (air-gap safe). When on it needs
    # network + NVD_API_KEY and adds minutes per scan, so it is opt-in; without it
    # nvd:cpe findings are kept and flagged bomlens:cpeVersionUnverified.
    verify = os.environ.get("SECURITY_NVD_VERIFY", "false") == "true"
    nvd_key = os.environ.get("NVD_API_KEY", "")
    cache = {}

    # Best-effort: grype's local vulnerability DB carries published dates that
    # grype's own JSON output doesn't. Missing/unreadable DB (air-gapped image
    # without a bundled DB) just means PublishedDate is omitted below.
    db_conn = None
    try:
        db_path = _grype_db_path()
        if db_path:
            db_conn = sqlite3.connect(db_path)
    except Exception:
        db_conn = None

    grype_matches = g.get("matches", [])
    # The verify loop is the only part of this script with a known total, so it
    # is also the only part that reports [deep-cve-progress]. Count up front how
    # many findings will actually hit the NVD lookup (nvd:cpe CVE matches) so the
    # percentage reflects that work, not the full grype match list.
    to_verify = sum(
        1 for m in grype_matches
        if m.get("vulnerability", {}).get("id", "").startswith("CVE-")
        and m.get("vulnerability", {}).get("namespace") == "nvd:cpe"
    ) if verify else 0
    verified_so_far = 0
    last_percent = None

    kept, dropped, unverified = [], 0, 0
    for m in grype_matches:
        vuln = m.get("vulnerability", {})
        cve = vuln.get("id", "")
        if not cve.startswith("CVE-"):
            # grype's primary vulnerability id is sometimes a non-CVE alias
            # from a non-NVD advisory source (e.g. "BIT-kafka-2024-27309",
            # built from an Apache mailing-list thread) with the actual CVE
            # listed only in relatedVulnerabilities. Fall back to the first
            # CVE-prefixed alias there rather than silently dropping a real
            # match.
            cve = next(
                (r.get("id", "") for r in (m.get("relatedVulnerabilities") or [])
                 if r.get("id", "").startswith("CVE-")),
                "",
            )
            if not cve:
                continue
        is_nvd = vuln.get("namespace") == "nvd:cpe"
        art = m.get("artifact", {})
        ver = art.get("version", "")
        purl = art.get("purl", "")
        cpes = art.get("cpes") or []
        product = _cpe_product(cpes[0]) if cpes else ""

        # Take grype's GHSA matches too (its Java matcher catches maven CVEs Trivy
        # misses); the sidecar merge dedups against Trivy's findings by (purl, cve).
        # Only the nvd:cpe matches carry the loose-version-range risk, so only they
        # go through the NVD version filter — GHSA advisories are version-accurate.
        flag_unverified = False
        if is_nvd:
            if verify:
                nvd_ms = _nvd_matches(cve, nvd_key, cache)
                verified_so_far += 1
                percent = min(100, (verified_so_far * 100) // to_verify) if to_verify else 100
                if percent != last_percent:
                    print(f"[deep-cve-progress] {percent}%")
                    last_percent = percent
                if nvd_ms is None:
                    flag_unverified = True  # network down: keep but flag
                else:
                    prod_m = [x for x in nvd_ms if f":{product}:" in x["criteria"].lower()]
                    if prod_m and not any(_in_range(ver, x) for x in prod_m):
                        dropped += 1
                        continue  # version outside every NVD range -> false positive
            else:
                flag_unverified = True

        rec = {
            "VulnerabilityID": cve,
            "PkgName": art.get("name", ""),
            "InstalledVersion": ver,
            "PkgIdentifier": {"PURL": purl} if purl else {},
            "Severity": (vuln.get("severity") or "UNKNOWN").upper(),
            "PrimaryURL": (vuln.get("urls") or [None])[0] or vuln.get("dataSource", ""),
            "CVSS": {"grype": {"V3Score": (vuln.get("cvss") or [{}])[0].get("metrics", {}).get("baseScore")}}
            if vuln.get("cvss") else {},
            "source": "grype-nvd-cpe",
        }
        status = GRYPE_FIX_STATE_TO_STATUS.get((vuln.get("fix") or {}).get("state"))
        if status is not None:
            rec["Status"] = status
        vendor_severity = _nvd_cpe_vendor_severity(m, vuln, is_nvd)
        if vendor_severity is not None:
            rec["VendorSeverity"] = vendor_severity
        published = _published_date(db_conn, cve)
        if published is not None:
            rec["PublishedDate"] = published
        if flag_unverified:
            rec["bomlens:cpeVersionUnverified"] = True
            unverified += 1
        kept.append(rec)

    if db_conn is not None:
        try:
            db_conn.close()
        except Exception:
            pass

    sidecar = {"Results": [{
        "Target": "maven (grype nvd:cpe)",
        "Class": "lang-pkgs",
        "Type": "jar",
        "Vulnerabilities": kept,
    }]}
    out = f"{out_prefix}_security_grype.json"
    with open(out, "w") as f:
        json.dump(sidecar, f, ensure_ascii=False)
    msg = f"[nvd-cpe] grype NVD-CPE findings: {len(kept)} kept"
    if verify:
        msg += f", {dropped} dropped by NVD version filter"
    if unverified:
        msg += f", {unverified} version-unverified (network unavailable)"
    print(msg + f" -> {os.path.basename(out)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: scan-nvd-cpe.py <sbom.json> <out_prefix>", file=sys.stderr)
        sys.exit(2)
    build_sidecar(sys.argv[1], sys.argv[2])
