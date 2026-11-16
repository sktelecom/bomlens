# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""The release workflow's view of bomlens-runner on PyPI.

check VERSION ENGINE [DEEP_LICENSE] [DEEP_CVE]
    Before publishing: when PyPI already has VERSION (a re-run), its wheel
    must name the same images, because PyPI keeps the first upload.

notes VERSION --dist DIR --body FILE
    After publishing: waits until PyPI lists every file in DIR, reads the
    images from the published wheel, and writes FILE (the release notes) back
    with the runner section added, or replaced when an earlier run added it.
"""

import argparse
import ast
import hashlib
import io
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

PROJECT = "bomlens-runner"
START = "<!-- bomlens-runner -->"
END = "<!-- /bomlens-runner -->"
FIELDS = ("ENGINE_IMAGE", "DEEP_LICENSE_IMAGE", "DEEP_CVE_IMAGE")
FILE_HOSTS = ("files.pythonhosted.org",)


def fetch(url: str, timeout: float = 60) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 (fixed https hosts)
        return response.read()


def release_json(version: str) -> dict | None:
    """PyPI's JSON for the version, or None when PyPI does not have it."""
    try:
        return json.loads(fetch(f"https://pypi.org/pypi/{PROJECT}/{version}/json"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def wheel_images(release: dict) -> tuple[str, str, str]:
    """The image references in the published wheel's _release.py."""
    wheels = [u for u in release["urls"] if u["filename"].endswith(".whl")]
    if len(wheels) != 1:
        raise SystemExit(f"[ERROR] PyPI lists {len(wheels)} wheels for {PROJECT}")
    url = wheels[0]["url"]
    if urllib.parse.urlsplit(url).scheme != "https" or urllib.parse.urlsplit(url).hostname not in FILE_HOSTS:
        raise SystemExit("[ERROR] the wheel is not on the PyPI file host")
    data = fetch(url)
    if hashlib.sha256(data).hexdigest() != wheels[0]["digests"]["sha256"]:
        raise SystemExit("[ERROR] the downloaded wheel does not match its PyPI hash")
    source = zipfile.ZipFile(io.BytesIO(data)).read("bomlens_runner/_release.py").decode("utf-8")
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            values[node.targets[0].id] = ast.literal_eval(node.value)
    return tuple(values.get(name, "") for name in FIELDS)


def section(version: str, release: dict, images: tuple[str, ...]) -> str:
    lines = [START, "### Engine runner", "", "```bash", f"pip install {PROJECT}=={version}", "```", "",
             "| File | SHA-256 |", "|---|---|"]
    lines += [f"| `{u['filename']}` | `{u['digests']['sha256']}` |" for u in sorted(release["urls"], key=lambda u: u["filename"])]
    lines += ["", "Images the runner uses by default:", ""]
    lines += [f"- `{ref}`" for ref in images if ref]
    lines.append(END)
    return "\n".join(lines)


def merge(body: str, new_section: str) -> str:
    """The notes with the runner section in place of an earlier one."""
    body = body.replace("\r\n", "\n")
    start = body.find(START)
    if start == -1:
        return body.rstrip("\n") + "\n\n" + new_section + "\n"
    end = body.find(END, start)
    after = body[end + len(END):] if end != -1 else ""
    return body[:start].rstrip("\n") + "\n\n" + new_section + after.rstrip("\n") + "\n"


def wait_for(version: str, filenames: set[str], tries: int, delay: float) -> dict:
    for attempt in range(tries):
        release = release_json(version)
        if release and filenames <= {u["filename"] for u in release["urls"]}:
            return release
        if attempt + 1 < tries:
            time.sleep(delay)
    raise SystemExit(f"[ERROR] PyPI does not list {', '.join(sorted(filenames))} for {PROJECT} {version}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("version")
    check.add_argument("images", nargs="+")
    notes = sub.add_parser("notes")
    notes.add_argument("version")
    notes.add_argument("--dist", type=Path, required=True)
    notes.add_argument("--body", type=Path, required=True)
    notes.add_argument("--tries", type=int, default=30)
    notes.add_argument("--delay", type=float, default=10)
    args = parser.parse_args(argv)

    if args.command == "check":
        release = release_json(args.version)
        if release is None:
            print(f"{PROJECT} {args.version} is not on PyPI yet")
            return 0
        wanted = tuple((args.images + ["", ""])[:3])
        published = wheel_images(release)
        if published != wanted:
            print(f"[ERROR] {PROJECT} {args.version} on PyPI names other images:", file=sys.stderr)
            for ref in published:
                print(f"  {ref}", file=sys.stderr)
            return 1
        print(f"{PROJECT} {args.version} is on PyPI with these images")
        return 0

    local = {p.name for p in args.dist.iterdir() if p.suffix in (".whl", ".gz")}
    release = wait_for(args.version, local, args.tries, args.delay)
    for path in sorted(args.dist.iterdir()):
        listed = [u for u in release["urls"] if u["filename"] == path.name]
        if listed and listed[0]["digests"]["sha256"] != hashlib.sha256(path.read_bytes()).hexdigest():
            print(f"::warning::{path.name} differs from the file on PyPI, which an earlier run uploaded")
    body = args.body.read_text(encoding="utf-8")
    args.body.write_text(merge(body, section(args.version, release, wheel_images(release))), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
