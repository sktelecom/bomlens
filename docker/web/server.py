#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# server.py — local web UI backend for sbom-tools (Python stdlib only).
# Runs inside the scanner image and drives /usr/local/bin/run-scan.
#   GET  /                -> index.html
#   GET  /results         -> JSON list of generated artifacts
#   GET  /file?name=...   -> serve one artifact (path-traversal guarded)
#   GET  /scan-stream?... -> Server-Sent Events: live scan log + final summary
import json
import os
import re
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(WEB_DIR, "dist")  # built React SPA (Vite output)
OUTPUT_DIR = "/host-output"
SRC_DIR = "/src"
PORT = int(os.environ.get("UI_PORT", "8080"))

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


def list_results():
    out = []
    if os.path.isdir(OUTPUT_DIR):
        for name in sorted(os.listdir(OUTPUT_DIR)):
            p = os.path.join(OUTPUT_DIR, name)
            if os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES):
                out.append({"name": name, "size": os.path.getsize(p)})
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
    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            s = (v.get("Severity") or "UNKNOWN").upper()
            sev[s] = sev.get(s, 0) + 1
    sev["TOTAL"] = sum(sev.values())
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
    return {"components": len(data.get("components") or [])}


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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/results":
            self._send(200, json.dumps(list_results()))
        elif path == "/file":
            self._serve_file(urllib.parse.parse_qs(parsed.query))
        elif path == "/scan-stream":
            self._scan_stream(urllib.parse.parse_qs(parsed.query))
        else:
            # Everything else is the React SPA: serve the static asset if it
            # exists, else fall back to index.html (client-side routing).
            self._serve_static(path)

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

    def _scan_stream(self, qs):
        def g(k, d=""):
            return (qs.get(k) or [d])[0]

        project = g("project").strip()
        version = g("version").strip()
        if not project or not version:
            self._send(400, json.dumps({"error": "project and version required"}))
            return

        target = g("target").strip()
        mode = "IMAGE" if target else "SOURCE"
        env = os.environ.copy()
        env.update({
            "MODE": mode,
            "PROJECT_NAME": project,
            "PROJECT_VERSION": version,
            "UPLOAD_ENABLED": "false",
            "HOST_OUTPUT_DIR": OUTPUT_DIR,
            "GENERATE_NOTICE": "true" if g("notice") == "true" else "false",
            "GENERATE_SECURITY": "true" if g("security") == "true" else "false",
            "DEEP_LICENSE": "true" if g("deep_license") == "true" else "false",
            "BYTE_STABLE": "true" if g("byte_stable") == "true" else "false",
        })
        if mode == "IMAGE":
            env["TARGET_IMAGE"] = target
        cwd = SRC_DIR if mode == "SOURCE" else OUTPUT_DIR

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
            sse("log", json.dumps("Failed to launch scan: %s" % exc))

        done = {
            "ok": ok,
            "results": list_results(),
            "sbom": sbom_summary(project, version),
            "security": security_summary(project, version) if g("security") == "true" else None,
        }
        sse("done", json.dumps(done))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("[ui] SBOM Tools Web UI listening on 0.0.0.0:%d" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
