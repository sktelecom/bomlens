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
# Credentials in the captured text (a token in .npmrc, a password in a URL or
# in settings.xml) are masked before the snapshot is written, the same forms
# the scan log masks; a masked file carries "masked": true.
#
# Best-effort: any failure leaves no snapshot and never breaks a scan. The output
# carries no timestamp, so a repeated scan of the same tree is byte-identical.

import json
import os
import re
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


# Credential masking, applied to every text file before it is written. The
# first five rules are mask_log_stream in source-detect.sh, written for Python
# (tests/test-credential-masking.sh checks both give the same output): the user
# and password of a URL, an Authorization value, a Bearer or Basic credential,
# the value given to a token, password, secret, API key or npmrc _auth name, and
# a <password>, <passphrase>, <token> or <secret> element. Whitespace is matched
# within a line only, as sed sees it.
_WS = r"[ \t\r\f\v]"
_Q = "[\"']"
_LOG_RULES = [
    # The lookbehind starts a scheme only where a run of scheme characters
    # starts, as sed's leftmost match does, and keeps a long run linear.
    (re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*://)[^/\s\"']+@"), r"\1***@"),
    (re.compile(r"([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]" + _Q + "?"
                + _WS + "*[:=]" + _WS + "*" + _Q + r"?)([A-Za-z]+" + _WS + r"+)?[^\s\"',;]+"),
     r"\1\2***"),
    (re.compile(r"([Bb]earer|[Bb]asic)" + _WS + r"+[A-Za-z0-9._~+/=-]{8,}"), r"\1 ***"),
    (re.compile(r"((token|password|passwd|secret|api[_-]?key|_auth)" + _Q + "?" + _WS
                + "*[:=]" + _WS + "*" + _Q + r"?)[^\s\"',;&]+", re.IGNORECASE), r"\1***"),
    (re.compile(r"(<(password|passphrase|token|secret|Password|Passphrase|Token|Secret)>)"
                r"[^<]+(</)"), r"\1***\3"),
]

# Files that hold registry, index or service credentials get three more rules,
# for forms the log rules leave alone: a key whose name says it is a credential
# (npmAuthIdent, AWS_SECRET_ACCESS_KEY, mavenPassword; the name is bounded so a
# long line stays cheap; not a true/false/yes/no value, nor always-auth,
# auth-type, npmAlwaysAuth or npmAuthType), the password of a .netrc
# entry, and the value of a nuget.config <add key="...Password" value="..."/>.
_CREDENTIAL_FILE_NAMES = {
    ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc",
    "settings.xml", "settings-security.xml", "gradle.properties", ".netrc",
    "_netrc", "nuget.config", ".git-credentials", ".pgpass", "credentials",
}
# A key whose name says it is a credential is left alone when its value is a
# plain yes or no (always-auth=true, strict-ssl=false), or when it is a setting
# that names how to log in rather than the login itself.
_NOT_SECRET_VALUES = {"true", "false", "yes", "no"}
_NOT_SECRET_KEYS = {"always-auth", "auth-type", "npmalwaysauth", "npmauthtype"}


def _mask_credential_value(m):
    value = m.group("value").strip().strip("\"'").strip().lower()
    if value in _NOT_SECRET_VALUES or m.group("key").lower() in _NOT_SECRET_KEYS:
        return m.group(0)
    return m.group(1) + "***"


_CREDENTIAL_RULES = [
    (re.compile(r"^(" + _WS + r"*(?:export" + _WS + r"+)?[\"']?(?P<key>[A-Za-z0-9_.-]{0,128}?"
                r"(?:secret|token|password|passwd|pwd|credential|auth|api[_-]?key|"
                r"access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]{0,128})[\"']?" + _WS
                + r"*[=:]" + _WS + r"*)(?=\S)(?P<value>[^\n]*)$", re.IGNORECASE | re.MULTILINE),
     _mask_credential_value),
    (re.compile(r"(\b(?:password|passwd|account)" + _WS + r"+)\S+", re.IGNORECASE),
     r"\1***"),
    (re.compile(r"(key=" + _Q + r"[^\"']*(?:password|token|apikey|secret)[^\"']*" + _Q
                + _WS + r"+value=" + _Q + r")[^\"']+", re.IGNORECASE), r"\1***"),
]


def is_credential_file(rel):
    """A config file that can carry credentials: by name, any .env file, and a
    Docker client config.json."""
    name = os.path.basename(rel).lower()
    if name in _CREDENTIAL_FILE_NAMES or name == ".env" or name.startswith(".env."):
        return True
    return name == "config.json" and os.path.basename(os.path.dirname(rel)) == ".docker"


def mask_secrets(text, credential_file=False):
    """The text with what can identify a credential replaced by ***."""
    for pattern, repl in _LOG_RULES:
        text = pattern.sub(repl, text)
    if credential_file:
        for pattern, repl in _CREDENTIAL_RULES:
            text = pattern.sub(repl, text)
        # A Docker config.json "auth" holds base64 user:password.
        text = re.sub(r"(\"auth\"" + _WS + r"*:" + _WS + r"*\")[^\"]+", r"\1***", text)
    return text


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
    skipped_binary = skipped_budget = skipped_error = truncated_files = masked_files = 0

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
        masked = mask_secrets(text, is_credential_file(rel))
        entry = {
            "path": rel,
            "size": size,
            "content": masked,
            "truncated": cut,
        }
        if masked != text:
            entry["masked"] = True
            masked_files += 1
        text = masked
        files.append(entry)
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
            "maskedFiles": masked_files,
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
    if masked_files:
        print("[INFO] source-snapshot: credentials masked in %d file(s)."
              % masked_files)
    if skipped_binary:
        print("[INFO] source-snapshot: %d binary file(s) listed without a preview."
              % skipped_binary)


if __name__ == "__main__":
    main()
