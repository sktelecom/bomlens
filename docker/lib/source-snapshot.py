#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# source-snapshot.py — capture the CONTENT of the scanned files for the web UI.
#
# Usage: source-snapshot.py <scanned_dir> <files.json> <out.json>
#
# Why: the result screens explain what a scan FOUND (components, licences,
# vulnerabilities) but never show what was scanned. source-file-tree.sh already
# writes the structure (`{prefix}_files.json`, a ScanCode-shaped path list); this
# adds the readable content behind it, so a reviewer can open a manifest or a
# licence file and confirm a finding against the real bytes.
#
# The scanned tree itself does not survive the scan — a source scan sees the
# container's /src, and the firmware unpacker extracts into a temp dir it deletes
# on exit — so the content is snapshotted here, while it exists, into an artifact
# that travels with the rest of the run.
#
# The file list is taken from files.json rather than re-walked, so the exclusions
# in source-file-tree.sh (VCS metadata, dependency caches, build outputs) apply
# here unchanged and cannot drift apart.
#
# Bounded on purpose — a snapshot must never dominate the output folder, and a
# firmware rootfs can be several GB:
#   * text only; binaries are counted, never embedded
#   * per file  SOURCE_SNAPSHOT_MAX_FILE   (default 256 KiB, longer files are cut)
#   * in total  SOURCE_SNAPSHOT_MAX_TOTAL  (default 8 MiB)
#   * at most   SOURCE_SNAPSHOT_MAX_FILES  (default 5000 entries)
# Files that document what the scan reports — licence texts and package
# manifests — are taken first, so the budget is spent on the evidence a reviewer
# actually opens. Every drop is counted in `totals` and logged, never silent.
#
# Best-effort: any failure leaves no snapshot and never breaks a scan. The output
# carries no timestamp, so a repeated scan of the same tree is byte-identical.

import json
import os
import sys

def cap(name, default):
    """A positive integer from the environment, or the default.

    The caller forwards these as `-e NAME=` whether or not the user set them, so
    an unset cap arrives as an empty string rather than as an absent variable.
    Anything that is not a positive integer falls back to the default: a cap is a
    safety limit, and a malformed one must not stop the capture or, worse, be
    read as zero and silently capture nothing."""
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_FILE_BYTES = cap("SOURCE_SNAPSHOT_MAX_FILE", 256 * 1024)
MAX_TOTAL_BYTES = cap("SOURCE_SNAPSHOT_MAX_TOTAL", 8 * 1024 * 1024)
MAX_FILES = cap("SOURCE_SNAPSHOT_MAX_FILES", 5000)

# Read in chunks so a huge file is never pulled into memory whole; only the first
# MAX_FILE_BYTES are kept anyway.
CHUNK = 64 * 1024

# Names that carry the evidence behind a finding: the licence texts a NOTICE is
# built from, and the manifests the component list is resolved from. Matched
# case-insensitively against the file name, by exact name or by prefix for the
# families that vary by suffix (LICENSE-MIT, COPYING.LESSER, …).
EVIDENCE_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile",
    "pipfile.lock", "setup.py", "setup.cfg",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "podfile", "podfile.lock", "package.swift", "pubspec.yaml",
    "dockerfile", "readme", "readme.md",
}
EVIDENCE_PREFIXES = ("license", "licence", "copying", "notice", "copyright")


def is_evidence(name):
    low = name.lower()
    return low in EVIDENCE_NAMES or low.startswith(EVIDENCE_PREFIXES)


def read_text(path, limit):
    """Return (text, size, truncated) for a text file, or None when binary.

    Binary detection is the usual heuristic: a NUL byte in the first chunk. It
    beats extension lists (a firmware rootfs is full of extension-less scripts
    and stripped ELF alike) and costs one read we need anyway. Undecodable bytes
    in an otherwise text file are replaced rather than dropping the file, so a
    latin-1 source comment cannot hide a manifest from the viewer."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        first = fh.read(min(CHUNK, limit) or 1)
        if b"\0" in first:
            return None
        raw = first
        while len(raw) < limit:
            chunk = fh.read(min(CHUNK, limit - len(raw)))
            if not chunk:
                break
            raw += chunk
    return raw.decode("utf-8", "replace"), size, size > limit


def main():
    if len(sys.argv) < 4:
        sys.exit(0)
    root, list_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]
    if not os.path.isdir(root) or not os.path.isfile(list_file):
        sys.exit(0)

    try:
        with open(list_file, encoding="utf-8") as fh:
            listing = json.load(fh)
    except (OSError, ValueError):
        sys.exit(0)

    entries = listing.get("files") if isinstance(listing, dict) else None
    if not isinstance(entries, list):
        sys.exit(0)

    real_root = os.path.realpath(root)
    paths, link_paths = [], []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel or os.path.isabs(rel):
            continue
        if entry.get("type") == "file":
            paths.append(rel)
        elif entry.get("type") == "symlink":
            link_paths.append(rel)

    # Evidence first, then the rest, each group by path so the output is stable.
    paths.sort(key=lambda p: (0 if is_evidence(os.path.basename(p)) else 1, p))

    files = []
    used = 0
    skipped_binary = skipped_budget = skipped_error = truncated_files = 0

    for rel in paths:
        full = os.path.realpath(os.path.join(root, rel))
        # Stay inside the scanned tree: the listing is ours, but a symlink in it
        # could still point outside, and a snapshot must not publish a file the
        # scan never looked at.
        if not full.startswith(real_root + os.sep) or os.path.islink(os.path.join(root, rel)):
            skipped_error += 1
            continue
        try:
            if not os.path.isfile(full):
                continue
            size = os.path.getsize(full)
        except OSError:
            skipped_error += 1
            continue
        # The total budget decides whether a file is taken at all — it never cuts
        # one short. Only the per-file cap truncates, so every entry in the
        # snapshot is either whole or cut at a size worth reading; the budget
        # cannot leave a trail of 40-byte fragments.
        if len(files) >= MAX_FILES or used + min(MAX_FILE_BYTES, size) > MAX_TOTAL_BYTES:
            skipped_budget += 1
            continue
        try:
            result = read_text(full, MAX_FILE_BYTES)
        except OSError:
            skipped_error += 1
            continue
        if result is None:
            skipped_binary += 1
            continue
        text, size, cut = result
        files.append({
            "path": rel,
            "size": size,
            "content": text,
            "truncated": cut,
        })
        if cut:
            truncated_files += 1
        used += len(text.encode("utf-8", "replace"))

    # Symlinks: record where each one points instead of its (never followed)
    # content. In a container image or a firmware rootfs most of /bin is links
    # into busybox, and "app -> /bin/busybox" is the whole answer to what that
    # entry is. Reading the link is a string operation — nothing outside the
    # tree is ever opened.
    links = []
    for rel in link_paths:
        full = os.path.join(root, rel)
        try:
            target = os.readlink(full)
        except OSError:
            continue
        links.append({"path": rel, "target": target})
    links.sort(key=lambda link: link["path"])

    files.sort(key=lambda f: f["path"])
    snapshot = {
        "links": links,
        "root": root,
        "limits": {
            "maxFileBytes": MAX_FILE_BYTES,
            "maxTotalBytes": MAX_TOTAL_BYTES,
            "maxFiles": MAX_FILES,
        },
        "totals": {
            "files": len(files),
            "links": len(links),
            "bytes": used,
            "truncatedFiles": truncated_files,
            "skippedBinary": skipped_binary,
            "skippedBudget": skipped_budget,
            "skippedUnreadable": skipped_error,
        },
        "files": files,
    }

    try:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, ensure_ascii=False, sort_keys=True)
    except OSError as exc:
        print("[WARN] source-snapshot: could not write %s (%s)." % (out_file, exc),
              file=sys.stderr)
        sys.exit(0)

    print("[INFO] source-snapshot: captured %d file(s), %d KiB."
          % (len(files), used // 1024))
    if skipped_budget:
        print("[WARN] source-snapshot: %d file(s) left out — the snapshot hit its "
              "size limit; the file view is partial." % skipped_budget)
    if truncated_files:
        print("[INFO] source-snapshot: %d file(s) shown only up to %d KiB."
              % (truncated_files, MAX_FILE_BYTES // 1024))
    if skipped_binary:
        print("[INFO] source-snapshot: %d binary file(s) listed without a preview."
              % skipped_binary)


if __name__ == "__main__":
    main()
