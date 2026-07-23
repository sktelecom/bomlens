#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
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
import subprocess
import sys
import time

try:
    import urllib.request
    import urllib.parse
    import urllib.error
    _HAVE_NET = True
except Exception:  # pragma: no cover
    _HAVE_NET = False

GRYPE = os.environ.get("GRYPE_BIN", "grype")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


# ---- main -------------------------------------------------------------------
def run_grype(sbom):
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
    verify = os.environ.get("SECURITY_NVD_VERIFY", "true") != "false"
    nvd_key = os.environ.get("NVD_API_KEY", "")
    cache = {}

    kept, dropped, unverified = [], 0, 0
    for m in g.get("matches", []):
        vuln = m.get("vulnerability", {})
        cve = vuln.get("id", "")
        if not cve.startswith("CVE-"):
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
                matches = _nvd_matches(cve, nvd_key, cache)
                if matches is None:
                    flag_unverified = True  # network down: keep but flag
                else:
                    prod_m = [x for x in matches if f":{product}:" in x["criteria"].lower()]
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
        if flag_unverified:
            rec["bomlens:cpeVersionUnverified"] = True
            unverified += 1
        kept.append(rec)

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
