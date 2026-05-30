#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# server.py — minimal local web UI wrapper for sbom-tools.
# Uses only the Python standard library (no extra dependencies); runs inside the
# scanner Docker image and drives /usr/local/bin/run-scan. Bound to 0.0.0.0:8080
# so the host can reach it via `docker run -p`.
import json
import os
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = "/host-output"
SRC_DIR = "/src"
PORT = int(os.environ.get("UI_PORT", "8080"))


def safe_output_path(name: str):
    """Resolve a filename strictly inside OUTPUT_DIR (block path traversal)."""
    base = os.path.basename(name)
    if base != name or not base:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, base))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


class Handler(BaseHTTPRequestHandler):
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
        if parsed.path in ("/", "/index.html"):
            with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif parsed.path == "/results":
            self._send(200, json.dumps(self._list_results()))
        elif parsed.path == "/file":
            qs = urllib.parse.parse_qs(parsed.query)
            name = (qs.get("name") or [""])[0]
            path = safe_output_path(name)
            if not path or not os.path.isfile(path):
                self._send(404, json.dumps({"error": "not found"}))
                return
            ctype = "text/html; charset=utf-8" if name.endswith(".html") else "text/plain; charset=utf-8"
            if name.endswith(".json"):
                ctype = "application/json"
            with open(path, "rb") as f:
                self._send(200, f.read(), ctype)
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/scan":
            self._send(404, json.dumps({"error": "not found"}))
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, json.dumps({"error": "invalid JSON"}))
            return

        project = (payload.get("project") or "").strip()
        version = (payload.get("version") or "").strip()
        target = (payload.get("target") or "").strip()
        if not project or not version:
            self._send(400, json.dumps({"error": "project and version are required"}))
            return

        mode = "IMAGE" if target else "SOURCE"
        env = os.environ.copy()
        env.update({
            "MODE": mode,
            "PROJECT_NAME": project,
            "PROJECT_VERSION": version,
            "UPLOAD_ENABLED": "false",
            "HOST_OUTPUT_DIR": OUTPUT_DIR,
            "GENERATE_NOTICE": "true" if payload.get("notice") else "false",
            "GENERATE_SECURITY": "true" if payload.get("security") else "false",
            "DEEP_LICENSE": "true" if payload.get("deep_license") else "false",
            "BYTE_STABLE": "true" if payload.get("byte_stable") else "false",
        })
        if mode == "IMAGE":
            env["TARGET_IMAGE"] = target
        cwd = SRC_DIR if mode == "SOURCE" else OUTPUT_DIR

        try:
            proc = subprocess.run(
                ["/usr/local/bin/run-scan"],
                env=env, cwd=cwd,
                capture_output=True, text=True, timeout=1800,
            )
            ok = proc.returncode == 0
            log = (proc.stdout + "\n" + proc.stderr)[-12000:]
        except subprocess.TimeoutExpired:
            ok, log = False, "Scan timed out after 30 minutes."
        except Exception as exc:  # noqa: BLE001
            ok, log = False, f"Failed to launch scan: {exc}"

        self._send(200, json.dumps({"ok": ok, "log": log, "results": self._list_results()}))

    @staticmethod
    def _list_results():
        out = []
        if os.path.isdir(OUTPUT_DIR):
            for name in sorted(os.listdir(OUTPUT_DIR)):
                p = os.path.join(OUTPUT_DIR, name)
                if os.path.isfile(p) and (
                    name.endswith(("_bom.json", "_NOTICE.txt", "_NOTICE.html",
                                   "_security.json", "_security.md", "_security.html"))
                ):
                    out.append({"name": name, "size": os.path.getsize(p)})
        return out

    def log_message(self, *args):  # quiet default logging
        pass


if __name__ == "__main__":
    print(f"[ui] SBOM Tools Web UI listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
