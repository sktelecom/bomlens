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
#
# Database age: grype refuses a database built more than 5 days ago, and the
# deep-cve image bakes its database in at build time. A database older than
# BOMLENS_GRYPE_DB_MAX_AGE_DAYS (7) days is updated first with `grype db update`
# (into a temporary folder when the image's cache cannot be written), unless the
# scan is offline (TRIVY_OFFLINE_SCAN or TRIVY_SKIP_DB_UPDATE). A database that
# is not updated is still read, with grype's own age limit raised to accept it,
# and the step is reported as degraded with the database's age. The outcome goes
# to the file BOMLENS_DEEP_CVE_STATUS_FILE names, when set, as JSON
# {"status": "ok"|"degraded"|"failed", "detail": ...} for entrypoint.sh.
import atexit
import fcntl
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
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
OS_PURL = re.compile(r"^pkg:(deb|rpm|apk|alpm)/")


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


_CPE_FIELD_SPLIT = re.compile(r"(?<!\\):")
_CPE_UNESCAPE = re.compile(r"\\(.)")


def _cpe_product(cpe):
    """Product field of a cpe:2.3 string, unescaped and lowercased so a grype
    CPE ("jackson\\-databind") and an NVD criteria string compare equal."""
    parts = _CPE_FIELD_SPLIT.split(cpe or "")
    return _CPE_UNESCAPE.sub(r"\1", parts[4]).lower() if len(parts) > 4 else ""


def _matched_products(m):
    """Products of the NVD CPEs this grype match was found through
    (matchDetails[].found.cpes), so the version filter checks the record that
    actually matched, whichever of the component's CPEs (primary or an
    alternate) grype searched. Falls back to the component's first CPE when
    grype reports no found CPE."""
    out = set()
    for d in m.get("matchDetails") or []:
        found = d.get("found") if isinstance(d, dict) else None
        if isinstance(found, dict):
            for c in found.get("cpes") or []:
                prod = _cpe_product(c)
                if prod:
                    out.add(prod)
    if not out:
        cpes = (m.get("artifact") or {}).get("cpes") or []
        prod = _cpe_product(cpes[0]) if cpes else ""
        if prod:
            out.add(prod)
    return out


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


# The environment every grype call of this run uses: the database location and
# age limit _prepare_grype_db settled on.
_GRYPE_ENV = None


def _grype_env():
    return _GRYPE_ENV if _GRYPE_ENV is not None else dict(os.environ)


def _grype_db_status(env):
    """`grype db status -o json` as a dict, or None when it cannot be read.

    grype exits 1 for a database it considers invalid (too old, for one) but
    still prints the status, so the exit code is not checked here."""
    try:
        p = subprocess.run([GRYPE, "db", "status", "-o", "json"],
                           capture_output=True, text=True, env=env, timeout=30)
        data = json.loads(p.stdout)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _grype_db_path():
    """Path to grype's local sqlite vulnerability DB, or None if unavailable."""
    data = _grype_db_status(_grype_env()) or {}
    path = data.get("path")
    if path and os.path.exists(path):
        return path
    return None


def _db_age_days(status):
    """Whole days since the database in `status` was built, or None."""
    raw = str((status or {}).get("built") or "").strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", raw)
    if not m:
        return None
    try:
        built = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if built.year < 2000:
        # A zero time: no database to date.
        return None
    return max(0, int((datetime.now(timezone.utc) - built).total_seconds() // 86400))


def _max_age_days():
    raw = os.environ.get("BOMLENS_GRYPE_DB_MAX_AGE_DAYS", "")
    return int(raw) if raw.isdigit() else 7


def _offline():
    """True when the scan was set up not to update vulnerability databases."""
    return any(os.environ.get(n, "").lower() == "true"
               for n in ("TRIVY_OFFLINE_SCAN", "TRIVY_SKIP_DB_UPDATE"))


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _stderr_cause(text, lines=3):
    """The last few lines grype wrote to stderr, without colours or log
    prefixes, joined into one line for a step detail."""
    out = []
    for line in _ANSI.sub("", text or "").splitlines():
        line = re.sub(r"^\[\d+\]\s+(ERROR|WARN|INFO|DEBUG)\s+", "", line.strip())
        if line:
            out.append(line)
    return " | ".join(out[-lines:])[:300]


def _writable_tree(path):
    """True when this user can write `path` and every folder under it."""
    if not path or not os.path.isdir(path):
        return False
    for root, _dirs, _files in os.walk(path):
        if not os.access(root, os.W_OK | os.X_OK):
            return False
    return True


def _update_grype_db(env):
    """Run `grype db update`. Returns (env to use, None) when the database was
    updated, or (None, cause) when it was not. The image's cache folder is used
    when this user can write it, one update at a time (scans in one container
    share it); otherwise a temporary folder, removed at exit."""
    cache = env.get("GRYPE_DB_CACHE_DIR", "")
    if _writable_tree(cache):
        try:
            lock = open(os.path.join(cache, ".bomlens-update.lock"), "a")
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            lock = None
        try:
            # Another scan may have updated it while this one waited.
            st = _grype_db_status(env)
            age = _db_age_days(st)
            if (st or {}).get("valid") and age is not None and age <= _max_age_days():
                return dict(env), None
            return _run_grype_db_update(env, cache)
        finally:
            if lock is not None:
                lock.close()
    else:
        try:
            cache = tempfile.mkdtemp(prefix="bomlens-grype-db.")
        except OSError as e:
            return None, f"no writable folder for the update: {e}"
        atexit.register(shutil.rmtree, cache, True)
        return _run_grype_db_update(env, cache)


def _run_grype_db_update(env, cache):
    new_env = dict(env, GRYPE_DB_CACHE_DIR=cache)
    new_env.pop("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", None)
    try:
        # grype's own limits: up to 30 s to check for an update, 300 s to download.
        p = subprocess.run([GRYPE, "db", "update"], capture_output=True, text=True,
                           env=new_env, timeout=400)
    except subprocess.TimeoutExpired:
        return None, "grype db update timed out"
    except OSError as e:
        return None, str(e)
    if p.returncode != 0:
        return None, _stderr_cause(p.stderr) or f"grype db update exited {p.returncode}"
    st = _grype_db_status(new_env)
    if not (st or {}).get("valid"):
        return None, (st or {}).get("error") or "the updated database is not valid"
    return new_env, None


def _prepare_grype_db():
    """Settle which grype database this run reads. Returns (env, degraded)
    where degraded is None, or the reason the result is incomplete."""
    env = dict(os.environ, GRYPE_MATCH_JAVA_USING_CPES="true")
    status = _grype_db_status(env)
    age = _db_age_days(status)
    if age is None:
        # No status to judge by: grype reports any problem when it runs.
        return env, None
    max_days = _max_age_days()
    print(f"[nvd-cpe] grype database: built {status.get('built')} ({age} day(s) old)")
    if age <= max_days and status.get("valid"):
        return env, None
    why = ""
    if age > max_days:
        if _offline():
            why = "not updated, the scan is offline (TRIVY_OFFLINE_SCAN or TRIVY_SKIP_DB_UPDATE)"
        else:
            print(f"[nvd-cpe] the grype database is {age} days old (over {max_days}); updating it")
            new_env, cause = _update_grype_db(env)
            if new_env is not None:
                built = (_grype_db_status(new_env) or {}).get("built")
                print(f"[nvd-cpe] grype database updated (built {built})")
                return new_env, None
            why = f"the update failed: {cause}"
            print(f"[nvd-cpe] WARN: grype db update failed: {cause}", file=sys.stderr)
    # Read the database there is: grype's own limit (5 days) would refuse it.
    env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = f"{(age + 1) * 24}h"
    if age <= max_days:
        return env, None
    print(f"[nvd-cpe] WARN: the grype database is {age} days old; "
          "vulnerabilities published since are not reported.", file=sys.stderr)
    return env, f"the grype database is {age} days old (over {max_days}); {why}"


def _write_status(status, detail=None):
    """Tell entrypoint.sh how the step went (see the header)."""
    path = os.environ.get("BOMLENS_DEEP_CVE_STATUS_FILE", "")
    if not path:
        return
    try:
        with open(path, "w") as f:
            json.dump({"status": status, "detail": detail}, f)
    except OSError:
        pass


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
def _sbom_alternates(doc):
    """Return [(component, [alt_cpe, ...])] for every component
    enrich-maven-cpe.py tagged with bomlens:cpeAlternates: the curated
    alternates of a project NVD splits across more than one CPE vendor, and
    the package-style candidates (vendor = groupId, product = artifactId,
    target_sw = maven). A component's single cpe field cannot carry them."""
    out = []
    for c in doc.get("components") or []:
        if not isinstance(c, dict):
            continue
        props = c.get("properties") or []
        raw = next((p.get("value") for p in props
                    if isinstance(p, dict) and p.get("name") == "bomlens:cpeAlternates"), None)
        if not raw:
            continue
        try:
            alt_cpes = json.loads(raw)
        except ValueError:
            continue
        if isinstance(alt_cpes, list):
            alt_cpes = [a for a in alt_cpes if isinstance(a, str) and a.startswith("cpe:2.3:")]
            if alt_cpes:
                out.append((c, alt_cpes))
    return out


def grype_input(sbom_path):
    """Path of the SBOM grype should scan, and whether it is a temporary copy.

    grype reads a CycloneDX component's cpe plus every property named
    syft:cpe23 as that package's CPEs (syft's CycloneDX decoder), and its CPE
    matcher searches all of them. So the alternates are written as syft:cpe23
    properties into a temporary copy: one grype run then searches
    every candidate with the component's own purl, type and version, instead
    of one bare-CPE grype run per alternate. The SBOM itself is not changed."""
    try:
        with open(sbom_path) as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return sbom_path, False
    tagged = _sbom_alternates(doc) if isinstance(doc, dict) else []
    if not tagged:
        return sbom_path, False
    for c, alt_cpes in tagged:
        props = c.setdefault("properties", [])
        have = {c.get("cpe")} | {p.get("value") for p in props
                                 if isinstance(p, dict) and p.get("name") == "syft:cpe23"}
        for alt in alt_cpes:
            if alt not in have:
                props.append({"name": "syft:cpe23", "value": alt})
                have.add(alt)
    try:
        fd, tmp = tempfile.mkstemp(prefix="bomlens-grype-", suffix=".json")
    except OSError:
        return sbom_path, False
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, ensure_ascii=False)
    except (OSError, TypeError, ValueError):
        try:
            os.remove(tmp)
        except OSError:
            pass
        return sbom_path, False
    return tmp, True


def run_grype(sbom):
    """grype's JSON result, or None after writing the cause to the status file."""
    print("[nvd-cpe] grype CPE matching started")
    try:
        p = subprocess.run(
            [GRYPE, f"sbom:{sbom}", "--by-cve", "-o", "json"],
            capture_output=True, text=True, env=_grype_env(), timeout=600)
    except FileNotFoundError:
        print("[nvd-cpe] WARN: grype not installed in this image; skipping", file=sys.stderr)
        _write_status("failed", "grype is not installed")
        return None
    except subprocess.TimeoutExpired:
        print("[nvd-cpe] WARN: grype timed out; skipping", file=sys.stderr)
        _write_status("failed", "grype timed out")
        return None
    if p.returncode != 0:
        cause = _stderr_cause(p.stderr)
        print(f"[nvd-cpe] WARN: grype exited {p.returncode}; skipping"
              + (f": {cause}" if cause else ""), file=sys.stderr)
        _write_status("failed", f"grype exited {p.returncode}" + (f": {cause}" if cause else ""))
        return None
    try:
        return json.loads(p.stdout)
    except ValueError:
        print("[nvd-cpe] WARN: grype output unparseable; skipping", file=sys.stderr)
        _write_status("failed", "grype output could not be read")
        return None


def build_sidecar(sbom_path, out_prefix):
    global _GRYPE_ENV
    _GRYPE_ENV, degraded = _prepare_grype_db()
    scan_path, is_tmp = grype_input(sbom_path)
    try:
        g = run_grype(scan_path)
    finally:
        if is_tmp:
            try:
                os.remove(scan_path)
            except OSError:
                pass
    if g is None:
        return
    grype_matches = g.get("matches", [])
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
    seen = set()  # (purl-or-name, cve): keep the first hit only, in case
    # grype reports the same CVE for a component more than once.
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
        # Distribution packages are Trivy's: it matches them against the
        # distribution's own advisories, which know what the distribution
        # patched. A CPE match on one compares the distribution's version with
        # upstream NVD ranges and reports CVEs the distribution already fixed,
        # so this pass leaves them out entirely.
        if OS_PURL.match(purl):
            continue
        products = _matched_products(m)
        dedup_key = (purl or art.get("name", ""), cve)
        if dedup_key in seen:
            continue

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
                    prod_m = [x for x in nvd_ms if _cpe_product(x.get("criteria", "")) in products]
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
        seen.add(dedup_key)

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
    _write_status("degraded" if degraded else "ok", degraded)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: scan-nvd-cpe.py <sbom.json> <out_prefix>", file=sys.stderr)
        sys.exit(2)
    # A cancelled scan ends with SIGTERM; exit through sys.exit so the atexit
    # cleanup of a temporary database folder runs.
    signal.signal(signal.SIGTERM, lambda _sig, _frame: sys.exit(143))
    build_sidecar(sys.argv[1], sys.argv[2])
