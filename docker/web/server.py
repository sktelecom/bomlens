#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# server.py — local web UI backend for sbom-tools (Python stdlib only).
# Runs inside the scanner image and drives /usr/local/bin/run-scan.
#   GET  /                -> index.html (React SPA)
#   GET  /capabilities    -> {firmware, docker}: which input types are usable here
#   GET  /results         -> JSON list of generated artifacts
#   GET  /download-all    -> zip of every generated artifact
#   GET  /file?name=...   -> serve one artifact (path-traversal guarded)
#   POST /upload?kind=... -> store an uploaded file, return a {token}
#   GET  /scan-stream?... -> Server-Sent Events: live scan log + final summary
#
# Input types (the `source` query param on /scan-stream):
#   current-dir   -> MODE=SOURCE  (syft dir scan of /src)
#   rootfs-dir    -> MODE=ROOTFS  (syft dir scan of <target>, a subfolder of /src)
#   git-url       -> clone <target> then MODE=SOURCE
#   zip-upload    -> extract uploaded zip then MODE=SOURCE
#   sbom-upload   -> MODE=ANALYZE on the uploaded SBOM
#   firmware-upload -> MODE=FIRMWARE (only when unblob is present in this image)
#   ai-model      -> MODE=AIBOM on <model id> (only in the bomlens-aibom image)
#   docker-image  -> MODE=IMAGE on <target>
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(WEB_DIR, "dist")  # built React SPA (Vite output)
# /host-output inside the container; overridable so the server can run standalone
# (e.g. the No-Docker UI contract test points it at a temp dir).
OUTPUT_DIR = os.environ.get("SBOM_OUTPUT_DIR", "/host-output")
SRC_DIR = "/src"
UPLOAD_DIR = os.path.join(OUTPUT_DIR, ".uploads")  # uploaded files + extracted/cloned trees
PORT = int(os.environ.get("UI_PORT", "8080"))
FIRMWARE_IMAGE = os.environ.get(
    "SBOM_FIRMWARE_IMAGE", "ghcr.io/sktelecom/sbom-scanner-firmware:latest"
)
AIBOM_IMAGE = os.environ.get(
    "SBOM_AIBOM_IMAGE", "ghcr.io/sktelecom/bomlens-aibom:latest"
)

# Per-kind upload size caps (bytes).
MAX_BYTES = {
    "sbom": 25 * 1024 * 1024,        # 25 MB
    "zip": 500 * 1024 * 1024,        # 500 MB
    "firmware": 500 * 1024 * 1024,   # 500 MB
}
# Accepted extensions per upload kind (lowercased).
UPLOAD_EXTS = {
    "sbom": (".json", ".xml", ".spdx", ".cdx.json", ".spdx.json"),
    "zip": (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar"),
    "firmware": (".bin", ".img", ".squashfs", ".sqsh", ".ubi", ".ubifs",
                 ".trx", ".chk", ".fw", ".rom", ".dlf",
                 # Compressed firmware images (unblob unpacks these), e.g. the
                 # OpenWRT *.img.gz releases.
                 ".gz", ".tgz", ".tar", ".xz", ".bz2", ".lzma", ".zst"),
}

# Content types for the static SPA bundle.
STATIC_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".map": "application/json",
    ".webmanifest": "application/manifest+json",
}

ARTIFACT_SUFFIXES = (
    "_bom.json", "_NOTICE.txt", "_NOTICE.html", "_NOTICE.pdf",
    "_security.json", "_security.md", "_security.html",
    "_conformance.json", "_conformance.md", "_conformance.html",
    "_risk-report.md", "_risk-report.html",
    "_bom.json.sig", "_scancode.json",
    # Source file tree (ScanCode-shaped, structure-only). Emitted by the scanner
    # for source-having modes so the UI's source-tree view works without the
    # opt-in ScanCode deep-license scan; the frontend prefers _scancode (which
    # carries licenses) when both exist.
    "_files.json",
)

# Recent-scans sidebar shows the newest N; older scans stay on disk but are not
# listed (the user deletes via the UI or the output folder).
RECENT_SCANS_CAP = 20


def safe_name(s):
    """Mirror entrypoint.sh filename normalization."""
    s = re.sub(r"[^a-zA-Z0-9.-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def output_prefix(project, version):
    """The {project}_{version} filename prefix every artifact of a scan shares."""
    return "%s_%s" % (safe_name(project), safe_name(version))


def safe_output_path(name):
    """Resolve a filename strictly inside OUTPUT_DIR (block path traversal)."""
    base = os.path.basename(name)
    if base != name or not base:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, base))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


def safe_prefix_path(prefix, suffix):
    """Resolve OUTPUT_DIR/<prefix><suffix> strictly inside OUTPUT_DIR. The prefix
    is normally already sanitized (output_prefix / scan_id_ok), but the summary
    helpers take it as a parameter, so re-check here: reject separators/traversal
    and confirm the realpath stays in OUTPUT_DIR. Returns None on a bad prefix."""
    if not isinstance(prefix, str) or not prefix or "/" in prefix or "\\" in prefix or ".." in prefix:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, prefix + suffix))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


# Directories the UI is allowed to scan as a ROOTFS target. Only /src is mounted
# into the UI container today; a future `--ui --mount <host-path>` would append
# its container path here, and the boundary check below extends to it for free.
ALLOWED_SCAN_ROOTS = [SRC_DIR]


def safe_scan_dir(rel):
    """Resolve a user-supplied directory path strictly inside an allowed scan
    root (block path traversal and symlink escape). Returns the real path on
    success, or None. Used by the rootfs-dir input — a relative path under /src.
    """
    if not rel or any(c in rel for c in ("\x00", "\n", "\r")):
        return None
    # Treat input as relative to /src: stripping any leading '/' folds an
    # absolute path like /etc back under /src, so it can't escape the boundary.
    rel = rel.lstrip("/")
    real = os.path.realpath(os.path.join(SRC_DIR, rel))
    for root in ALLOWED_SCAN_ROOTS:
        r = os.path.realpath(root)
        if (real == r or real.startswith(r + os.sep)) and os.path.isdir(real):
            return real
    return None


def firmware_capable():
    """The firmware tools (unblob) are only built into the firmware image."""
    return shutil.which("unblob") is not None


def scanoss_capable():
    """Vendored-OSS identification (scanoss-py) is only built in with SBOM_SCANOSS."""
    return shutil.which("scanoss-py") is not None


def aibom_capable():
    """AI-model SBOM generation (OWASP AIBOM Generator) lives only in the opt-in
    bomlens-aibom image — mirror scan-aibom.sh's detection."""
    aibom_dir = os.environ.get("AIBOM_DIR", "/opt/aibom-generator")
    return os.path.isfile(os.path.join(aibom_dir, "src", "cli.py")) or shutil.which("aibom") is not None


def docker_capable():
    return os.path.exists("/var/run/docker.sock")


def docker_cli_present():
    """A docker CLI in THIS image lets the base UI container launch a sibling
    firmware/aibom container via the mounted host socket (same pattern as the
    cdxgen language images in entrypoint.sh)."""
    return shutil.which("docker") is not None


def firmware_usable():
    """Firmware analysis is offered when either the tools are built into THIS
    image (run in-process) OR we can launch the firmware image as a sibling
    container (docker CLI + host socket). The sibling path is how the desktop
    app's permissive-only base UI image reaches the GPL-isolated firmware image."""
    return firmware_capable() or (docker_cli_present() and docker_capable())


def aibom_usable():
    """AI-model SBOMs are offered when the generator is in THIS image OR we can
    launch the aibom image as a sibling container (docker CLI + host socket)."""
    return aibom_capable() or (docker_cli_present() and docker_capable())


def list_results(prefix=None):
    """Generated artifacts in OUTPUT_DIR. With a prefix, only that scan's files
    ({prefix}_*) — used when re-opening a past scan."""
    out = []
    if os.path.isdir(OUTPUT_DIR):
        for name in sorted(os.listdir(OUTPUT_DIR)):
            p = os.path.join(OUTPUT_DIR, name)
            if not (os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES)):
                continue
            if prefix and not name.startswith(prefix + "_"):
                continue
            out.append({"name": name, "size": os.path.getsize(p)})
    return out


def scan_id_ok(sid):
    """A scan id is a filename prefix; allow only the safe_name charset (no
    path separators / traversal)."""
    return bool(sid) and re.fullmatch(r"[A-Za-z0-9._-]+", sid) is not None


# Row caps so a huge SBOM/scan can't bloat the SSE 'done' payload. The counts
# (sbom.components, severity totals) stay exact; only the detail lists are capped.
MAX_COMPONENT_ROWS = 2000
MAX_VULN_ROWS = 2000
MAX_VULN_REFS = 12  # reference links per CVE in the detail view
MAX_VULN_DESC = 600  # description chars per CVE (keeps the SSE payload bounded)
MAX_CONFORMANCE_MISSING = 50  # missing items per conformance check

# Severity ranking for picking a component's worst vulnerability.
_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}


def _component_licenses(c):
    """SPDX ids / names / expressions for one CycloneDX component (notice parity)."""
    out = []
    for lic in (c.get("licenses") or []):
        node = lic.get("license") or {}
        val = node.get("id") or node.get("name") or lic.get("expression")
        if val:
            out.append(val)
    return out


def _cvss_best(v):
    """Highest CVSS score and its vector across Trivy's sources (V3, fallback V2).

    Mirrors scan-security.sh so the web detail view and the rendered report agree.
    Returns (score, vector) with score None when no source carries a score.
    """
    best_score = None
    best_vector = ""
    for src in (v.get("CVSS") or {}).values():
        if not isinstance(src, dict):
            continue
        score = src.get("V3Score")
        vector = src.get("V3Vector") or ""
        if score is None:
            score = src.get("V2Score")
            vector = src.get("V2Vector") or ""
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = vector
    return best_score, best_vector


def _epss_kev_map(prefix):
    """Per-CVE EPSS probability + CISA KEV flag, written by scan-security.sh as a
    sidecar (Trivy's _security.json carries neither). Empty when absent/offline."""
    p = safe_prefix_path(prefix, "_security_epss.json")
    if not p or not os.path.isfile(p):
        return {}
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def security_summary(prefix):
    p = safe_prefix_path(prefix, "_security.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    priority = _epss_kev_map(prefix)
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            s = (v.get("Severity") or "UNKNOWN").upper()
            if s not in sev:
                s = "UNKNOWN"
            sev[s] += 1
            if len(vulns) < MAX_VULN_ROWS:
                score, vector = _cvss_best(v)
                desc = (v.get("Description") or "")[:MAX_VULN_DESC]
                cid = v.get("VulnerabilityID") or ""
                pr = priority.get(cid) or {}
                row = {
                    "id": cid,
                    "severity": s,
                    "pkg": v.get("PkgName") or "",
                    "installed": v.get("InstalledVersion") or "",
                    "fixed": v.get("FixedVersion") or "",
                    "title": v.get("Title") or "",
                    "cvss": score,
                    "cvssVector": vector,
                    "description": desc,
                    "url": v.get("PrimaryURL") or "",
                    "refs": (v.get("References") or [])[:MAX_VULN_REFS],
                }
                # EPSS (exploit probability, 0..1) + CISA KEV (actively exploited).
                epss = pr.get("epss")
                if isinstance(epss, (int, float)):
                    row["epss"] = epss
                if pr.get("kev"):
                    row["kev"] = True
                vulns.append(row)
    sev["TOTAL"] = sum(sev.values())
    sev["vulnerabilities"] = vulns
    return sev


def _norm_purl(purl):
    """purl without qualifiers/subpath, lowercased — a stable join key across the
    SBOM (cdxgen) and the security report (Trivy), which may differ in qualifiers."""
    if not purl:
        return ""
    return purl.split("?", 1)[0].split("#", 1)[0].strip().lower()


def _component_risk_index(prefix):
    """Join the Trivy security report to packages: worst severity + count per
    package, keyed by normalized purl and by (name, version). Uncapped (unlike
    the detail list) so a component's Risk reflects every finding against it.
    Returns (by_purl, by_nv); both empty when there is no security report."""
    p = safe_prefix_path(prefix, "_security.json")
    by_purl, by_nv = {}, {}
    if not p or not os.path.isfile(p):
        return by_purl, by_nv
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return by_purl, by_nv

    def bump(index, key, sev):
        cur = index.get(key)
        if cur is None:
            index[key] = {"sev": sev, "count": 1}
        else:
            cur["count"] += 1
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(cur["sev"], 0):
                cur["sev"] = sev

    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev not in _SEV_RANK:
                sev = "UNKNOWN"
            ident = v.get("PkgIdentifier")
            purl = ident.get("PURL") if isinstance(ident, dict) else None
            if purl:
                bump(by_purl, _norm_purl(purl), sev)
            name = (v.get("PkgName") or "").lower()
            if name:
                bump(by_nv, (name, v.get("InstalledVersion") or ""), sev)
    return by_purl, by_nv


def _scope_index(data):
    """Per-ref dependency scope from CycloneDX dependencies[]: 'direct' (the root
    component depends on it) vs 'transitive'. Mirrors the client sbomGraph: roots
    are the metadata component's dependsOn, or refs nothing depends on when the
    root has no entry. Returns (scope_by_ref, has_dependencies)."""
    deps = data.get("dependencies") or []
    adjacency, depended_on = {}, set()
    for d in deps:
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            continue
        targets = [t for t in (d.get("dependsOn") or []) if isinstance(t, str)]
        adjacency[d["ref"]] = targets
        depended_on.update(targets)
    if not any(adjacency.values()):
        return {}, False

    meta_comp = (data.get("metadata") or {}).get("component") or {}
    meta_ref = meta_comp.get("bom-ref") or meta_comp.get("purl")
    if meta_ref and meta_ref in adjacency:
        roots = adjacency[meta_ref]
    else:
        roots = [r for r in adjacency if r not in depended_on]
    direct = set(roots)

    refs = set(adjacency)
    for targets in adjacency.values():
        refs.update(targets)
    return {ref: ("direct" if ref in direct else "transitive") for ref in refs}, True


def sbom_summary(prefix):
    p = safe_prefix_path(prefix, "_bom.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    comps = data.get("components") or []
    risk_by_purl, risk_by_nv = _component_risk_index(prefix)
    scope_by_ref, has_deps = _scope_index(data)
    rows = []
    for c in comps[:MAX_COMPONENT_ROWS]:
        props = c.get("properties") or []
        vendored = any(
            p.get("name") == "bomlens:layer" and p.get("value") == "vendored"
            for p in props
        )
        # SCANOSS match confidence, surfaced read-only so a reviewer can eyeball it
        # (no accept/reject workflow — match triage belongs to TRUSCA).
        match = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:scanoss:match"),
            "",
        )
        # AI-relevant restrictive license class (behavioral-use / non-commercial),
        # set by normalize-sbom.sh via the shared license-flags.jq classifier.
        review = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:licenseReview"),
            "",
        )
        refs = c.get("externalReferences") or []
        source = next(
            (
                r.get("url")
                for r in refs
                if isinstance(r.get("url"), str)
                and r.get("type") in ("vcs", "distribution", "website")
            ),
            "",
        )
        row = {
            "name": c.get("name") or "",
            "version": c.get("version") or "",
            "group": c.get("group") or "",
            "purl": c.get("purl") or "",
            "type": c.get("type") or "",
            "licenses": _component_licenses(c),
            "vendored": vendored,
            "matchConfidence": match,
            "source": source,
            "copyright": c.get("copyright") or "",
        }

        # Scope: direct/transitive from the dependency graph (a component may be
        # addressed by bom-ref or purl). Omitted when the SBOM has no graph.
        if has_deps:
            scope = scope_by_ref.get(c.get("bom-ref")) or scope_by_ref.get(c.get("purl"))
            if scope:
                row["scope"] = scope

        # Risk: worst severity + count of vulnerabilities hitting this component.
        # Prefer the purl join; fall back to (name, version). Use one index only
        # so the count is not doubled.
        npurl = _norm_purl(c.get("purl"))
        risk = risk_by_purl.get(npurl) if npurl else None
        if risk is None:
            risk = risk_by_nv.get(((c.get("name") or "").lower(), c.get("version") or ""))
        if risk:
            row["maxSeverity"] = risk["sev"]
            row["vulnCount"] = risk["count"]

        if review:
            row["licenseReview"] = review

        rows.append(row)
    # suggest-identify-vendored: set by suggest-vendored.sh when the scan looks like
    # C/C++ embedded source with no package manager. Drives the result banner.
    meta_props = (data.get("metadata") or {}).get("properties") or []
    suggest = any(
        p.get("name") == "bomlens:suggest-identify-vendored" and p.get("value") == "true"
        for p in meta_props
    )
    return {
        "components": len(comps),
        "componentList": rows,
        "truncated": len(comps) > MAX_COMPONENT_ROWS,
        "suggestIdentifyVendored": suggest,
    }


def scanoss_status(prefix):
    """SCANOSS vendored-ID outcome for the UI, read from the vendored SBOM's
    metadata: 'unavailable' (search failed — rate limit / no network / no token),
    'no-match' (ran clean but found nothing vendored), or 'matched'. None when
    vendored identification wasn't run (no vendored artifact)."""
    p = safe_prefix_path(prefix, "_vendored.cdx.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    props = (data.get("metadata") or {}).get("properties") or []
    status = next(
        (x.get("value") for x in props if x.get("name") == "bomlens:scanoss:status"),
        None,
    )
    return {"status": status, "count": len(data.get("components") or [])}


def conformance_summary(prefix):
    """Supplier-SBOM conformance verdict (ANALYZE mode only)."""
    p = safe_prefix_path(prefix, "_conformance.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    # Per-check results drive the conformance / G7 section. The report is ours
    # (validate-sbom.sh), so it is trusted and already bounded, but normalize
    # defensively to a known shape and cap the missing lists.
    checks = []
    for c in (data.get("checks") or []):
        if not isinstance(c, dict):
            continue
        checks.append({
            "id": str(c.get("id") or ""),
            "label": str(c.get("label") or ""),
            "required": bool(c.get("required")),
            "status": str(c.get("status") or "warn"),
            "detail": str(c.get("detail") or ""),
            "missing": [str(m) for m in (c.get("missing") or [])][:MAX_CONFORMANCE_MISSING],
            "evidence": [str(e) for e in (c.get("evidence") or [])][:MAX_CONFORMANCE_MISSING],
        })
    return {
        "result": data.get("result", "unknown"),
        "format": data.get("format", ""),
        "checks": checks,
    }


def _max_severity(security):
    """Highest severity with a non-zero count in a security summary, else None."""
    if not security:
        return None
    for s in SEVERITY_ORDER:
        if security.get(s, 0) > 0:
            return s
    return None


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def list_scans():
    """Past scans in OUTPUT_DIR — one per {prefix}_bom.json, newest first. The
    real project/version come from the SBOM's metadata.component. Local files
    only; no account, no database."""
    scans = []
    if not os.path.isdir(OUTPUT_DIR):
        return scans
    for name in os.listdir(OUTPUT_DIR):
        if not name.endswith("_bom.json"):
            continue
        prefix = name[: -len("_bom.json")]
        p = os.path.join(OUTPUT_DIR, name)
        try:
            mtime = int(os.path.getmtime(p))
            with open(p) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        comps = data.get("components") or []
        meta = (data.get("metadata") or {}).get("component") or {}
        # The OWASP AIBOM generator names the root metadata.component after its
        # job id (job-<timestamp>), which is meaningless in the Recent list. For
        # AI scans, label by the model component instead.
        model = next(
            (c for c in comps if c.get("type") == "machine-learning-model"), None
        )
        if model:
            project = model.get("name") or prefix
            version = model.get("version") or ""
        else:
            project = meta.get("name") or prefix
            version = meta.get("version") or ""
        scans.append({
            "id": prefix,
            "project": project,
            "version": version,
            "components": len(comps),
            "maxSeverity": _max_severity(security_summary(prefix)),
            "isAiScan": any(c.get("type") == "machine-learning-model" for c in comps),
            "generatedAt": mtime,
        })
    scans.sort(key=lambda s: s["generatedAt"], reverse=True)
    return scans[:RECENT_SCANS_CAP]


def scan_detail(prefix):
    """A past scan as a done-event payload (its own artifacts only)."""
    sbom = sbom_summary(prefix)
    if sbom is None:
        return None
    return {
        "ok": True,
        "mode": None,
        "id": prefix,
        "results": list_results(prefix),
        "sbom": sbom,
        "security": security_summary(prefix),
        "conformance": conformance_summary(prefix),
        "scanoss": scanoss_status(prefix),
    }


# --------------------------------------------------------------------------
# Upload handling
# --------------------------------------------------------------------------
def upload_token_dir(token):
    """Resolve UPLOAD_DIR/<token> for a well-formed token only, traversal-safe."""
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        return None
    base = os.path.realpath(os.path.join(UPLOAD_DIR, token))
    if not base.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        return None
    return base


def resolve_upload(token):
    """Return the single uploaded file inside UPLOAD_DIR/<token>, traversal-safe."""
    base = upload_token_dir(token)
    if base is None:
        return None
    if not os.path.isdir(base):
        return None
    for name in os.listdir(base):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return p
    return None


def _parse_boundary(content_type):
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return None
    b = m.group(1).strip().strip('"')
    return b.encode("latin-1") if b else None


def extract_file_part(rfile, length, boundary, dest_path):
    """Stream the single `file` part of a multipart body to dest_path.

    One pass, bounded memory (the pending window never exceeds ~64 KB + the
    boundary length). Returns the original client filename. Raises ValueError on
    a malformed body."""
    delim = b"--" + boundary
    remaining = length

    def read_chunk(n):
        nonlocal remaining
        n = min(n, remaining)
        if n <= 0:
            return b""
        d = rfile.read(n)
        remaining -= len(d)
        return d

    # Accumulate until we have the FILE part's header terminator. Other parts
    # (e.g. a text "kind" field) may precede it, so locate `filename=` first,
    # then the \r\n\r\n that closes that part's headers.
    buf = b""
    header_blob = rest = None
    while True:
        fpos = buf.find(b"filename=")
        if fpos != -1:
            term = buf.find(b"\r\n\r\n", fpos)
            if term != -1:
                header_blob = buf[:term]
                rest = buf[term + 4:]
                break
        chunk = read_chunk(8192)
        if not chunk:
            raise ValueError("no file part found")
        buf += chunk
        if len(buf) > (1 << 20):  # 1 MB of headers = abuse
            raise ValueError("multipart headers too large")

    fm = re.search(rb'filename="([^"]*)"', header_blob)
    filename = (fm.group(1).decode("utf-8", "replace") if fm else "upload.bin")

    closing = b"\r\n" + delim
    pending = rest
    with open(dest_path, "wb") as f:
        while True:
            idx = pending.find(closing)
            if idx != -1:
                f.write(pending[:idx])
                return filename
            # Flush all but a tail that might hold a partial boundary.
            if len(pending) > len(closing):
                safe = len(pending) - len(closing)
                f.write(pending[:safe])
                pending = pending[safe:]
            chunk = read_chunk(65536)
            if not chunk:
                f.write(pending)  # malformed; flush what we have
                return filename
            pending += chunk


def safe_extract_zip(zip_path, dest_dir):
    """Extract a zip, rejecting absolute/traversal members (zip-slip)."""
    dest_real = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise ValueError("unsafe path in archive: %s" % member)
        zf.extractall(dest_dir)


def scan_root_of(extract_dir):
    """If the extracted tree is a single wrapping dir, descend into it."""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


def host_path_of(container_path):
    """Map a path inside THIS container to the equivalent host path.

    The UI launches with `-v $(pwd):/src -v $(pwd):/host-output`, so both mount
    points resolve to the same host dir (SBOM_UI_HOST_DIR). The entrypoint needs
    the host path to bind-mount the scanned tree into the sibling cdxgen
    container. Returns "" when SBOM_UI_HOST_DIR is unset or the path falls
    outside the known mounts (the entrypoint then falls back to syft).
    """
    hostdir = os.environ.get("SBOM_UI_HOST_DIR", "")
    if not hostdir:
        return ""
    p = os.path.normpath(container_path)
    for base in (OUTPUT_DIR, SRC_DIR):
        b = os.path.normpath(base)
        if p == b:
            return hostdir
        if p.startswith(b + os.sep):
            return os.path.join(hostdir, os.path.relpath(p, b))
    return ""


# Allowlist charsets for every value interpolated into the sibling docker-run
# command line. Each is enforced as an inline `re.fullmatch(<const>, value)`
# barrier in run_sibling_scan, in the same scope as the flow it gates: string
# substitution (re.sub) does NOT break command-injection taint, but a full-match
# guard the value must pass to reach the sink does. None of these admit a leading
# '-', whitespace, ':' (which would split a -v mount), or a shell metacharacter.
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*")          # image ref
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?")
_HOSTPATH_RE = re.compile(r"/[A-Za-z0-9._@/-]*")                # absolute bind-mount path
_BASENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")       # in-sibling file name

# Modes this dispatcher may launch as a sibling. A fixed allowlist (not the raw
# caller string) is interpolated into the docker-run command line, so the MODE
# argument can only ever be one of these literals.
_SIBLING_MODES = ("FIRMWARE", "AIBOM")


def _valid_image_ref(ref):
    """True for a plain image reference (registry/name[:tag][@digest]).

    The image comes from server env (SBOM_FIRMWARE_IMAGE / SBOM_AIBOM_IMAGE),
    not user input, but we still allowlist the charset so a misconfigured env
    can't smuggle a docker-run flag (no leading '-', no whitespace/separators).
    run_sibling_scan re-applies the same _REF_RE inline as the taint barrier."""
    return bool(ref) and _REF_RE.fullmatch(ref) is not None


def _valid_model_id(mid):
    """True for a HuggingFace model id (owner/name; owner optional).

    Shares _MODEL_RE with the inline barrier in run_sibling_scan, so the value
    that reaches the command line is charset-constrained (no leading '-', no
    whitespace, no path traversal) regardless of call site."""
    return bool(mid) and _MODEL_RE.fullmatch(mid) is not None


def _env_flag_value(value):
    """Sanitize a free-text value (project name/version) for a docker-run
    `-e KEY=<value>` argument.

    It is already a single argv element (subprocess is invoked with a list and
    shell=False, so it can never split into a new flag), but we additionally
    strip control characters and the few shell-significant bytes so the value
    that reaches the command line is a plain, bounded token."""
    return re.sub(r"[^\w.+:/ @=-]", "", (value or ""))[:256]


def run_sibling_scan(image, mode, host_out, on_log, *, host_file=None, model_id=None,
                     extra_env=None):
    """Run a firmware/aibom SBOM scan in a SIBLING container.

    The desktop app's base UI image is permissive-only (no GPL firmware tools,
    no heavy aibom deps), so when the user picks firmware/AI we hand the job to
    the dedicated firmware/aibom image launched via the mounted host Docker
    socket — the same sibling pattern entrypoint.sh uses for cdxgen language
    images. The sibling runs the FULL run-scan pipeline (generate + normalize +
    notice + security + sign) with MODE set, writing finished artifacts straight
    into the shared host output dir, which is also THIS container's OUTPUT_DIR.
    So the base container just streams the sibling's log and then summarizes the
    artifacts exactly as it does for an in-process scan.

    Mounts (host paths — the sibling is launched by the host daemon, which can
    only bind-mount host paths):
      host_out  -> /host-output  (shared artifacts; == our OUTPUT_DIR)
      host_file -> /input/<name> read-only (firmware upload)  [firmware only]
    The host socket is mounted so the firmware image can, in turn, do its own
    work; AIBOM needs only outbound network (HuggingFace).

    Returns the sibling's exit code, or -1 if docker could not be invoked.
    Streams every line (docker pull progress + scan log) through on_log so the
    SSE UX is identical to an in-process scan.
    """
    # Gate every user-influenced value with an inline full-match allowlist right
    # before it reaches the command line. Each `re.fullmatch(<const>, value)`
    # test is a barrier the value MUST pass to flow into the docker-run argv, so
    # only a charset-constrained token (no leading '-', whitespace, ':' or shell
    # metacharacter) can ever be interpolated. The guards sit in this scope (not
    # behind a helper) so the constraint is local to the flow.
    if not image or _REF_RE.fullmatch(image) is None:
        on_log("[ui] refusing to launch sibling: invalid image reference")
        return -1
    if mode not in _SIBLING_MODES:
        on_log("[ui] refusing to launch sibling: unsupported mode")
        return -1
    # Pin MODE to the exact matched literal (drops the caller's string identity).
    mode = _SIBLING_MODES[_SIBLING_MODES.index(mode)]
    if not host_out or _HOSTPATH_RE.fullmatch(host_out) is None:
        on_log("[ui] cannot launch sibling: host output dir unknown or unsafe "
               "(SBOM_UI_HOST_DIR unset — relaunch the UI via the desktop app or scan-sbom.sh --ui)")
        return -1
    if host_file is not None and _HOSTPATH_RE.fullmatch(host_file) is None:
        on_log("[ui] refusing to launch sibling: unsafe host input path")
        return -1
    if model_id is not None and _MODEL_RE.fullmatch(model_id) is None:
        on_log("[ui] refusing to launch sibling: invalid model id")
        return -1

    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)

    # Normalize the boolean-ish flags to exactly "true"/"false".
    def _bool_env(key):
        return "true" if env.get(key, "true") == "true" else "false"

    args = [
        "docker", "run", "--rm",
        "-v", "%s:/host-output" % host_out,  # host_out passed _HOSTPATH_RE above
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", "MODE=%s" % mode,  # mode ∈ _SIBLING_MODES (checked above)
        "-e", "PROJECT_NAME=%s" % _env_flag_value(env.get("PROJECT_NAME", "")),
        "-e", "PROJECT_VERSION=%s" % _env_flag_value(env.get("PROJECT_VERSION", "")),
        "-e", "HOST_OUTPUT_DIR=/host-output",
        "-e", "GENERATE_NOTICE=%s" % _bool_env("GENERATE_NOTICE"),
        "-e", "GENERATE_SECURITY=%s" % _bool_env("GENERATE_SECURITY"),
        "-e", "GENERATE_REPORT=%s" % _bool_env("GENERATE_REPORT"),
    ]
    if host_file is not None:
        # Mount the upload read-only under a fixed in-sibling path. Reduce to a
        # bare basename and re-gate it so the in-sibling path is a single
        # allowlisted file name (host_file itself passed _HOSTPATH_RE above).
        base = os.path.basename(host_file)
        if not base or _BASENAME_RE.fullmatch(base) is None:
            base = "upload.bin"
        args += ["-v", "%s:/input/%s:ro" % (host_file, base),
                 "-e", "TARGET_FILE=/input/%s" % base]
    if model_id is not None:
        # model_id passed _MODEL_RE above.
        args += ["-e", "MODEL_ID=%s" % model_id]
    # The sibling writes into /host-output; run-scan also cds there via cwd.
    args += ["-w", "/host-output", "--entrypoint", "/usr/local/bin/run-scan", image]

    # Pull progress first so the (heavy, one-time) firmware/aibom image download
    # shows up in the live log rather than as a silent stall.
    if not _sibling_image_present(image):
        on_log("[ui] pulling %s (first run is large; one-time download)..." % image)
        _stream_cmd(["docker", "pull", image], on_log)

    on_log("[ui] launching %s in a sibling container (%s)..." % (mode.lower(), image))
    return _stream_cmd(args, on_log)


def _sibling_image_present(image):
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except OSError:
        return False


def _stream_cmd(args, on_log):
    """Run a command, streaming combined stdout/stderr line-by-line to on_log.
    Returns the exit code, or -1 if the binary could not be launched."""
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as exc:
        on_log("[ui] failed to launch: %s" % exc)
        return -1
    for line in proc.stdout:
        on_log(line.rstrip("\n"))
    proc.wait()
    return proc.returncode


# Single-use private-repo tokens, stashed via POST /git-cred so the secret
# never travels in the scan-stream querystring (which could be logged/cached).
_GIT_CREDS = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # close-terminated; fine for one SSE per scan

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- GET ----
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/results":
            self._send(200, json.dumps(list_results()))
        elif path == "/download-all":
            self._download_all()
        elif path == "/capabilities":
            self._send(200, json.dumps({
                # `firmware`/`aibom` are the input-gating flags the frontend reads:
                # true when the input type is offerable here, whether the tools are
                # built into THIS image (run in-process) or reachable by launching
                # the firmware/aibom image as a SIBLING container (docker socket).
                "firmware": firmware_usable(),
                "scanoss": scanoss_capable(),
                "docker": docker_capable(),
                "aibom": aibom_usable(),
                # Whether the offer is satisfied by a sibling container (the desktop
                # app's permissive-only base UI image) — the frontend shows a
                # one-time "pulling the image" notice for the first sibling run.
                "firmwareSibling": not firmware_capable() and docker_cli_present() and docker_capable(),
                "aibomSibling": not aibom_capable() and docker_cli_present() and docker_capable(),
                "firmwareImage": FIRMWARE_IMAGE,
                "aibomImage": AIBOM_IMAGE,
                "hostDir": os.environ.get("SBOM_UI_HOST_DIR", ""),
            }))
        elif path == "/file":
            self._serve_file(urllib.parse.parse_qs(parsed.query))
        elif path == "/scans":
            self._send(200, json.dumps(list_scans()))
        elif path == "/scan":
            self._serve_scan(urllib.parse.parse_qs(parsed.query))
        elif path == "/scan-stream":
            self._scan_stream(urllib.parse.parse_qs(parsed.query))
        else:
            self._serve_static(path)

    # ---- POST ----
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/upload":
            self._upload(urllib.parse.parse_qs(parsed.query))
        elif parsed.path == "/git-cred":
            self._git_cred()
        elif parsed.path == "/scan-delete":
            self._scan_delete(urllib.parse.parse_qs(parsed.query))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def _scan_delete(self, qs):
        """Delete one past scan: remove every {id}_* artifact from OUTPUT_DIR.
        Local-only housekeeping (no account/db); the id is a validated prefix."""
        sid = (qs.get("id") or [""])[0]
        if not scan_id_ok(sid):
            self._send(400, json.dumps({"error": "bad scan id"}))
            return
        removed = 0
        for suf in ARTIFACT_SUFFIXES:
            # safe_prefix_path re-resolves {sid}{suf} with realpath and confirms
            # it stays inside OUTPUT_DIR, so the delete cannot escape even though
            # scan_id_ok already allowlisted the id. It also makes the boundary
            # explicit to static analysis (no taint reaches os.remove unchecked).
            p = safe_prefix_path(sid, suf)
            if p and os.path.isfile(p):
                try:
                    os.remove(p)
                    removed += 1
                except OSError:
                    pass
        self._send(200, json.dumps({"deleted": sid, "removed": removed}))

    def _git_cred(self):
        """Stash a private-repo token; return a single-use credId."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 8192:
            self._send(400, json.dumps({"error": "bad credential request"}))
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            token = (data.get("token") or "").strip()
        except (ValueError, OSError):
            self._send(400, json.dumps({"error": "invalid JSON"}))
            return
        if not token:
            self._send(400, json.dumps({"error": "token required"}))
            return
        cid = secrets.token_hex(16)
        _GIT_CREDS[cid] = token
        self._send(200, json.dumps({"credId": cid}))

    def _upload(self, qs):
        kind = (qs.get("kind") or [""])[0]
        if kind not in MAX_BYTES:
            self._send(400, json.dumps({"error": "unknown upload kind"}))
            return
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            self._send(400, json.dumps({"error": "expected multipart/form-data"}))
            return
        boundary = _parse_boundary(ctype)
        if not boundary:
            self._send(400, json.dumps({"error": "missing multipart boundary"}))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._send(411, json.dumps({"error": "Content-Length required"}))
            return
        if length > MAX_BYTES[kind]:
            self._send(413, json.dumps({"error": "file too large for %s" % kind}))
            return

        token = secrets.token_hex(16)
        dest_dir = os.path.join(UPLOAD_DIR, token)
        os.makedirs(dest_dir, exist_ok=True)
        tmp_path = os.path.join(dest_dir, "_incoming")
        try:
            filename = extract_file_part(self.rfile, length, boundary, tmp_path)
        except (ValueError, OSError) as exc:
            shutil.rmtree(dest_dir, ignore_errors=True)
            self._send(400, json.dumps({"error": "upload parse failed: %s" % exc}))
            return

        safe_fn = os.path.basename(filename) or "upload.bin"
        safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", safe_fn)
        lower = safe_fn.lower()
        if not lower.endswith(UPLOAD_EXTS[kind]):
            shutil.rmtree(dest_dir, ignore_errors=True)
            self._send(415, json.dumps({
                "error": "unsupported file type for %s (got %s)" % (kind, safe_fn)
            }))
            return
        final_path = os.path.join(dest_dir, safe_fn)
        os.replace(tmp_path, final_path)
        self._send(200, json.dumps({"token": token, "filename": safe_fn, "kind": kind}))

    def _serve_static(self, path):
        rel = path.lstrip("/") or "index.html"
        distroot = os.path.realpath(DIST_DIR)
        target = os.path.realpath(os.path.join(DIST_DIR, rel))
        inside = target == distroot or target.startswith(distroot + os.sep)
        if not inside or not os.path.isfile(target):
            target = os.path.join(DIST_DIR, "index.html")  # SPA fallback
        if not os.path.isfile(target):
            self._send(503, json.dumps({"error": "UI bundle not built"}))
            return
        ctype = STATIC_CTYPES.get(
            os.path.splitext(target)[1], "application/octet-stream"
        )
        with open(target, "rb") as f:
            self._send(200, f.read(), ctype)

    def _serve_file(self, qs):
        name = (qs.get("name") or [""])[0]
        path = safe_output_path(name)
        if not path or not os.path.isfile(path):
            self._send(404, json.dumps({"error": "not found"}))
            return
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif name.endswith(".json") or name.endswith(".sig"):
            ctype = "application/json"
        else:
            ctype = "text/plain; charset=utf-8"
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)

    def _serve_scan(self, qs):
        """Re-open a past scan by id (its {prefix}). Traversal-safe."""
        sid = (qs.get("id") or [""])[0]
        if not scan_id_ok(sid):
            self._send(400, json.dumps({"error": "invalid scan id"}))
            return
        detail = scan_detail(sid)
        if detail is None:
            self._send(404, json.dumps({"error": "not found"}))
            return
        self._send(200, json.dumps(detail))

    def _download_all(self):
        """Bundle every generated artifact into one in-memory zip.

        Artifacts are reports/JSON and stay small, so building the zip in a
        BytesIO and sending it with a fixed Content-Length fits the server's
        close-terminated model (no chunked transfer). Only files already
        whitelisted by list_results() are added — no new path is exposed.
        """
        files = list_results()
        if not files:
            self._send(404, json.dumps({"error": "no artifacts to download"}))
            return

        # Zip name from the shared "{project}_{version}" prefix; fall back to a
        # generic name if the artifacts don't share one.
        first = files[0]["name"]
        prefix = first
        for suf in ARTIFACT_SUFFIXES:
            if first.endswith(suf):
                prefix = first[: -len(suf)]
                break
        prefix = prefix.strip("._")
        zip_name = (prefix + "_sbom-artifacts.zip") if prefix else "sbom-artifacts.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                path = safe_output_path(f["name"])
                if path and os.path.isfile(path):
                    zf.write(path, arcname=f["name"])
        body = buf.getvalue()

        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header(
            "Content-Disposition", 'attachment; filename="%s"' % zip_name
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- scan stream (SSE) ----
    def _scan_stream(self, qs):
        def g(k, d=""):
            return (qs.get(k) or [d])[0]

        project = g("project").strip()
        version = g("version").strip()
        if not project or not version:
            self._send(400, json.dumps({"error": "project and version required"}))
            return

        source = g("source", "current-dir").strip() or "current-dir"
        target = g("target").strip()
        token = g("token").strip()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def sse(event, payload):
            try:
                self.wfile.write(("event: %s\ndata: %s\n\n" % (event, payload)).encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def fail(msg):
            sse("error", json.dumps(msg))
            sse("done", json.dumps({"ok": False, "results": list_results(),
                                    "sbom": None, "security": None, "conformance": None}))

        # Build the run-scan environment + working dir for the chosen source.
        env = os.environ.copy()
        env.update({
            "PROJECT_NAME": project,
            "PROJECT_VERSION": version,
            "UPLOAD_ENABLED": "false",
            "HOST_OUTPUT_DIR": OUTPUT_DIR,
            "GENERATE_NOTICE": "true" if g("notice", "true") == "true" else "false",
            "GENERATE_SECURITY": "true" if g("security", "true") == "true" else "false",
            "GENERATE_REPORT": "true",  # 오픈소스위험분석보고서: default-on (mirrors CLI)
            "DEEP_LICENSE": "true" if g("deep_license") == "true" else "false",
            # Vendored-OSS identification (SCANOSS). SCANOSS_API_URL/KEY, if set in
            # the server's environment, pass through via env.copy() above.
            "IDENTIFY_VENDORED": "true" if g("identify_vendored") == "true" else "false",
            "BYTE_STABLE": "true" if g("byte_stable") == "true" else "false",
        })
        # Optional SCANOSS token (single-use, stashed via POST /git-cred). Lets a
        # web-UI user supply their own OSSKB key, since the free anonymous endpoint
        # is heavily rate-limited. Overrides any key from the server environment.
        scanoss_cred = g("scanoss_cred").strip()
        if scanoss_cred:
            tok = _GIT_CREDS.pop(scanoss_cred, None)
            if tok:
                env["SCANOSS_API_KEY"] = tok
        cwd = OUTPUT_DIR
        cleanup_dir = None
        mode = None
        # When set, run the scan in a SIBLING container (firmware/aibom image)
        # instead of in-process run-scan. dict: {image, host_file?, model_id?}.
        sibling = None

        try:
            if source == "docker-image":
                if not target:
                    fail("Docker image name required"); return
                if not docker_capable():
                    fail("Docker socket not mounted (-v /var/run/docker.sock:...)"); return
                mode = "IMAGE"
                env["MODE"] = "IMAGE"
                env["TARGET_IMAGE"] = target

            elif source == "current-dir":
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = SRC_DIR

            elif source == "rootfs-dir":
                # Scan an OS rootfs (or any subfolder) under /src as a directory.
                # The path is validated to stay inside the mounted folder so it
                # can't reach /host-output uploads or container system paths.
                scan_dir = safe_scan_dir(target)
                if not scan_dir:
                    fail("Invalid or out-of-bounds directory path "
                         "(must be a folder inside the current folder)"); return
                mode = "ROOTFS"
                env["MODE"] = "ROOTFS"
                env["TARGET_DIR"] = scan_dir

            elif source == "git-url":
                if not target:
                    fail("Git URL required"); return
                if not re.match(r"^(https?://|git@|ssh://git@|file://)[A-Za-z0-9._~:@/+-]+$", target) \
                        or ".." in target or " " in target:
                    fail("Unsafe or unsupported git URL"); return
                if not shutil.which("git"):
                    fail("git not available in this image"); return
                # Optional private-repo token (single-use, via POST /git-cred).
                # Injected into the clone URL only; the log shows the bare URL.
                clone_url = target
                cred = g("cred").strip()
                if cred:
                    tok = _GIT_CREDS.pop(cred, None)
                    if tok and target.startswith("https://"):
                        clone_url = "https://x-access-token:%s@%s" % (tok, target[len("https://"):])
                cleanup_dir = os.path.join(UPLOAD_DIR, "git-" + secrets.token_hex(8))
                os.makedirs(cleanup_dir, exist_ok=True)
                clone_dest = os.path.join(cleanup_dir, "repo")
                sse("log", json.dumps("▶ Cloning %s ..." % target))
                cp = subprocess.run(
                    ["git", "clone", "--depth", "1", "--single-branch", "--", clone_url, clone_dest],
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                if cp.returncode != 0:
                    out = re.sub(r"x-access-token:[^@]*@", "x-access-token:***@", (cp.stdout or "").strip()[-500:])
                    fail("git clone failed: %s" % out); return
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = scan_root_of(clone_dest)

            elif source == "zip-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded archive not found (re-upload)"); return
                cleanup_dir = os.path.join(os.path.dirname(up), "extracted")
                os.makedirs(cleanup_dir, exist_ok=True)
                sse("log", json.dumps("▶ Extracting %s ..." % os.path.basename(up)))
                try:
                    if up.lower().endswith((".zip",)):
                        safe_extract_zip(up, cleanup_dir)
                    else:
                        # tarballs: shell out to tar (present in the image), traversal-guarded
                        listing = subprocess.run(["tar", "-tf", up], stdout=subprocess.PIPE, text=True)
                        if re.search(r"(^|\n)(/|.*\.\.(/|$))", listing.stdout or ""):
                            fail("unsafe path in archive"); return
                        subprocess.run(["tar", "-C", cleanup_dir, "--no-same-owner", "-xf", up], check=True)
                except (ValueError, OSError, subprocess.CalledProcessError) as exc:
                    fail("archive extraction failed: %s" % exc); return
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = scan_root_of(cleanup_dir)

            elif source == "sbom-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded SBOM not found (re-upload)"); return
                mode = "ANALYZE"
                env["MODE"] = "ANALYZE"
                env["ANALYZE_SBOM"] = up
                # ANALYZE needs license + vulnerability data for the risk report.
                env["GENERATE_NOTICE"] = "true"
                env["GENERATE_SECURITY"] = "true"

            elif source == "firmware-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded firmware not found (re-upload)"); return
                mode = "FIRMWARE"
                env["MODE"] = "FIRMWARE"
                env["TARGET_FILE"] = up
                if firmware_capable():
                    # Tools are in THIS image (UI launched from the firmware image):
                    # run in-process exactly as before.
                    pass
                elif docker_cli_present() and docker_capable():
                    # Permissive-only base UI image: hand the GPL-isolated firmware
                    # image the job as a sibling container. It needs the HOST path
                    # of the upload (the host daemon bind-mounts host paths only).
                    host_file = host_path_of(up)
                    if not host_file:
                        fail("Cannot reach the firmware image: host output dir unknown "
                             "(relaunch the UI via the desktop app or scan-sbom.sh --ui)."); return
                    sibling = {"image": FIRMWARE_IMAGE, "host_file": host_file}
                else:
                    fail("Firmware analysis requires Docker (to run the firmware image) "
                         "or relaunching the UI from the firmware image."); return

            elif source == "ai-model":
                # Generate an AI SBOM (CycloneDX 1.7 ML-BOM) for a HuggingFace
                # model via the OWASP AIBOM Generator (opt-in bomlens-aibom image).
                if not target:
                    fail("HuggingFace model id required (owner/name)"); return
                # owner/name (optional owner), HuggingFace charset only; no traversal.
                if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$", target):
                    fail("Unsupported model id (expected owner/name)"); return
                mode = "AIBOM"
                env["MODE"] = "AIBOM"
                env["MODEL_ID"] = target
                if aibom_capable():
                    pass  # in-process (UI launched from the aibom image)
                elif docker_cli_present() and docker_capable():
                    # Heavy aibom image runs as a sibling; needs only outbound net.
                    sibling = {"image": AIBOM_IMAGE, "model_id": target}
                else:
                    fail("AI-model SBOM generation requires Docker (to run the AIBOM image) "
                         "or relaunching the UI from the AIBOM image."); return

            else:
                fail("unknown input type: %s" % source); return

            # For a source scan, hand the entrypoint the HOST path of the scanned
            # tree so it can run a cdxgen language image as a sibling container
            # (transitive resolution). Empty -> entrypoint falls back to syft.
            if env.get("MODE") == "SOURCE" and env.get("SOURCE_ROOT"):
                host_root = host_path_of(env["SOURCE_ROOT"])
                if host_root:
                    env["SOURCE_ROOT_HOST"] = host_root

            sse("log", json.dumps("▶ Starting %s scan: %s %s" % (mode.lower(), project, version)))
            ok = False
            if sibling is not None:
                # Firmware / AI on the permissive-only base image: run the
                # dedicated image as a sibling container (host socket). It does
                # the full pipeline and writes artifacts into the shared host
                # output dir, which is also our OUTPUT_DIR — so the summary below
                # reads them just like an in-process scan.
                host_out = host_path_of(OUTPUT_DIR)
                rc = run_sibling_scan(
                    sibling["image"], env["MODE"], host_out,
                    lambda ln: sse("log", json.dumps(ln)),
                    host_file=sibling.get("host_file"),
                    model_id=sibling.get("model_id"),
                    extra_env=env,
                )
                ok = rc == 0
                if rc == -1:
                    sse("error", json.dumps("Failed to launch the %s sibling container." % mode.lower()))
            else:
                try:
                    proc = subprocess.Popen(
                        ["/usr/local/bin/run-scan"], env=env, cwd=cwd,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1,
                    )
                    for line in proc.stdout:
                        sse("log", json.dumps(line.rstrip("\n")))
                    proc.wait()
                    ok = proc.returncode == 0
                except Exception as exc:  # noqa: BLE001
                    sse("error", json.dumps("Failed to launch scan: %s" % exc))

            prefix = output_prefix(project, version)
            done = {
                "ok": ok,
                "mode": mode,
                "id": prefix,
                "results": list_results(prefix),
                "sbom": sbom_summary(prefix),
                "security": security_summary(prefix) if env["GENERATE_SECURITY"] == "true" else None,
                "conformance": conformance_summary(prefix),
                "scanoss": scanoss_status(prefix),
            }
            sse("done", json.dumps(done))
        finally:
            # Remove uploaded/cloned/extracted trees; keep generated artifacts
            # (entrypoint copied them to OUTPUT_DIR root).
            token_dir = upload_token_dir(token)
            if token_dir:
                shutil.rmtree(token_dir, ignore_errors=True)
            if cleanup_dir and source == "git-url":
                shutil.rmtree(cleanup_dir, ignore_errors=True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    print("[ui] BomLens Web UI listening on 0.0.0.0:%d" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
