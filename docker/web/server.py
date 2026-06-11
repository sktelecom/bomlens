#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# server.py — local web UI backend for sbom-tools (Python stdlib only).
# Runs inside the scanner image and drives /usr/local/bin/run-scan.
#   GET  /                -> index.html (React SPA)
#   GET  /capabilities    -> {firmware, docker}: which input types are usable here
#   GET  /results         -> JSON list of generated artifacts
#   GET  /file?name=...   -> serve one artifact (path-traversal guarded)
#   POST /upload?kind=... -> store an uploaded file, return a {token}
#   GET  /scan-stream?... -> Server-Sent Events: live scan log + final summary
#
# Input types (the `source` query param on /scan-stream):
#   current-dir   -> MODE=SOURCE  (syft dir scan of /src)
#   git-url       -> clone <target> then MODE=SOURCE
#   zip-upload    -> extract uploaded zip then MODE=SOURCE
#   sbom-upload   -> MODE=ANALYZE on the uploaded SBOM
#   firmware-upload -> MODE=FIRMWARE (only when unblob is present in this image)
#   docker-image  -> MODE=IMAGE on <target>
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
OUTPUT_DIR = "/host-output"
SRC_DIR = "/src"
UPLOAD_DIR = os.path.join(OUTPUT_DIR, ".uploads")  # uploaded files + extracted/cloned trees
PORT = int(os.environ.get("UI_PORT", "8080"))
FIRMWARE_IMAGE = os.environ.get(
    "SBOM_FIRMWARE_IMAGE", "ghcr.io/sktelecom/sbom-scanner-firmware:latest"
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
                 ".trx", ".chk", ".fw", ".rom", ".dlf"),
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
    "_bom.json", "_NOTICE.txt", "_NOTICE.html",
    "_security.json", "_security.md", "_security.html",
    "_conformance.json", "_conformance.md", "_conformance.html",
    "_risk-report.md", "_risk-report.html",
    "_bom.json.sig", "_scancode.json",
)


def safe_name(s):
    """Mirror entrypoint.sh filename normalization."""
    s = re.sub(r"[^a-zA-Z0-9.-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def safe_output_path(name):
    """Resolve a filename strictly inside OUTPUT_DIR (block path traversal)."""
    base = os.path.basename(name)
    if base != name or not base:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, base))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


def firmware_capable():
    """The firmware tools (unblob) are only built into the firmware image."""
    return shutil.which("unblob") is not None


def docker_capable():
    return os.path.exists("/var/run/docker.sock")


def list_results():
    out = []
    if os.path.isdir(OUTPUT_DIR):
        for name in sorted(os.listdir(OUTPUT_DIR)):
            p = os.path.join(OUTPUT_DIR, name)
            if os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES):
                out.append({"name": name, "size": os.path.getsize(p)})
    return out


# Row caps so a huge SBOM/scan can't bloat the SSE 'done' payload. The counts
# (sbom.components, severity totals) stay exact; only the detail lists are capped.
MAX_COMPONENT_ROWS = 2000
MAX_VULN_ROWS = 2000


def _component_licenses(c):
    """SPDX ids / names / expressions for one CycloneDX component (notice parity)."""
    out = []
    for lic in (c.get("licenses") or []):
        node = lic.get("license") or {}
        val = node.get("id") or node.get("name") or lic.get("expression")
        if val:
            out.append(val)
    return out


def security_summary(project, version):
    prefix = "%s_%s" % (safe_name(project), safe_name(version))
    p = os.path.join(OUTPUT_DIR, prefix + "_security.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            s = (v.get("Severity") or "UNKNOWN").upper()
            if s not in sev:
                s = "UNKNOWN"
            sev[s] += 1
            if len(vulns) < MAX_VULN_ROWS:
                vulns.append({
                    "id": v.get("VulnerabilityID") or "",
                    "severity": s,
                    "pkg": v.get("PkgName") or "",
                    "installed": v.get("InstalledVersion") or "",
                    "fixed": v.get("FixedVersion") or "",
                    "title": v.get("Title") or "",
                })
    sev["TOTAL"] = sum(sev.values())
    sev["vulnerabilities"] = vulns
    return sev


def sbom_summary(project, version):
    prefix = "%s_%s" % (safe_name(project), safe_name(version))
    p = os.path.join(OUTPUT_DIR, prefix + "_bom.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    comps = data.get("components") or []
    rows = []
    for c in comps[:MAX_COMPONENT_ROWS]:
        rows.append({
            "name": c.get("name") or "",
            "version": c.get("version") or "",
            "group": c.get("group") or "",
            "purl": c.get("purl") or "",
            "type": c.get("type") or "",
            "licenses": _component_licenses(c),
        })
    return {
        "components": len(comps),
        "componentList": rows,
        "truncated": len(comps) > MAX_COMPONENT_ROWS,
    }


def conformance_summary(project, version):
    """Supplier-SBOM conformance verdict (ANALYZE mode only)."""
    prefix = "%s_%s" % (safe_name(project), safe_name(version))
    p = os.path.join(OUTPUT_DIR, prefix + "_conformance.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return {"result": data.get("result", "unknown"), "format": data.get("format", "")}


# --------------------------------------------------------------------------
# Upload handling
# --------------------------------------------------------------------------
def resolve_upload(token):
    """Return the single uploaded file inside UPLOAD_DIR/<token>, traversal-safe."""
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        return None
    base = os.path.realpath(os.path.join(UPLOAD_DIR, token))
    if not base.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
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
        elif path == "/capabilities":
            self._send(200, json.dumps({
                "firmware": firmware_capable(),
                "docker": docker_capable(),
                "firmwareImage": FIRMWARE_IMAGE,
                "hostDir": os.environ.get("SBOM_UI_HOST_DIR", ""),
            }))
        elif path == "/file":
            self._serve_file(urllib.parse.parse_qs(parsed.query))
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
        else:
            self._send(404, json.dumps({"error": "not found"}))

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
            "BYTE_STABLE": "true" if g("byte_stable") == "true" else "false",
        })
        cwd = OUTPUT_DIR
        cleanup_dir = None
        mode = None

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
                if not firmware_capable():
                    fail("Firmware analysis requires the firmware image. Relaunch the UI with "
                         "SBOM_SCANNER_IMAGE=%s ./scan-sbom.sh --ui" % FIRMWARE_IMAGE)
                    return
                mode = "FIRMWARE"
                env["MODE"] = "FIRMWARE"
                env["TARGET_FILE"] = up

            else:
                fail("unknown input type: %s" % source); return

            sse("log", json.dumps("▶ Starting %s scan: %s %s" % (mode.lower(), project, version)))
            ok = False
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

            done = {
                "ok": ok,
                "mode": mode,
                "results": list_results(),
                "sbom": sbom_summary(project, version),
                "security": security_summary(project, version) if env["GENERATE_SECURITY"] == "true" else None,
                "conformance": conformance_summary(project, version),
            }
            sse("done", json.dumps(done))
        finally:
            # Remove uploaded/cloned/extracted trees; keep generated artifacts
            # (entrypoint copied them to OUTPUT_DIR root).
            if token:
                shutil.rmtree(os.path.join(UPLOAD_DIR, token), ignore_errors=True)
            if cleanup_dir and source == "git-url":
                shutil.rmtree(cleanup_dir, ignore_errors=True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    print("[ui] SBOM Generator Web UI listening on 0.0.0.0:%d" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
