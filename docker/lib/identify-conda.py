#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Identify conda/pip dependencies from a project's environment.yml.

Usage: identify-conda.py <source_dir> <output.json> [project_version]

cdxgen has no conda cataloger (confirmed: neither `--type conda` against a
plain environment.yml, nor against a synthesized conda-meta/ install
directory, produces anything -- this image carries no conda/mamba binary for
it to shell out to). Left alone, a project that ships only environment.yml
scans through cdxgen's python auto-detection instead: if a setup.py or
requirements.txt happens to sit in the same tree, cdxgen reads THAT and
ignores environment.yml entirely. Measured on CompVis/stable-diffusion: its
setup.py declares three UNPINNED install_requires (torch, numpy, tqdm); cdxgen
resolved them to that day's PyPI latest and pulled in the latest torch's own
transitive dependencies, for 32 components with zero overlap with the 24 the
project's real environment.yaml actually pins. No degraded signal marks this,
because cdxgen did not fail -- it silently used the wrong manifest.

This script reads environment.yml the same structural way identify-modelica.py
reads a `uses()` annotation: a narrow, known shape, not a general YAML parser.
Only the two-level shape conda projects actually use is recognized --

    dependencies:
      - python=3.11
      - numpy=1.26.4
      - pip:
        - requests==2.31.0

-- with `dependencies:` at column 0, each entry at exactly 2 spaces, and the
one `- pip:` entry's own items at exactly 4 spaces. Anything the file does
that this shape does not cover (different indent width, deeper nesting, a
flow-style `dependencies: [...]`, a tab) fails the WHOLE file, not just the
offending line: a partial read of a file whose shape turned out to be
different from what was assumed would leave callers unable to tell truncated
output from a complete one, so this only ever returns everything it found or
nothing. Best-effort like identify-modelica.py: no environment.yml, or one
that fails this shape check, degrades to an empty CycloneDX envelope rather
than aborting the scan.

Why this script is invoked from build-prep.sh (stage 1, before cdxgen runs)
and not only from entrypoint.sh's post-processing (stage 2, like Modelica):
the setup.py leak above can only be prevented by telling cdxgen not to run
its python cataloger at all (`--exclude-type python`), and that has to happen
before cdxgen is invoked, not after. build-prep.sh runs this script, and
--exclude-type python is only added when it actually produced components --
if environment.yml does not match the known shape, cdxgen's python cataloger
is left running exactly as before, since an inaccurate python-derived SBOM is
still better than an empty one.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CDX_SPEC_VERSION = "1.6"

# Generous but bounded: a real environment.yml is a few dozen lines. Anything
# far larger than that is not a project manifest this shape applies to, and
# reading unbounded input to look for a hostile file is not worth the risk.
MAX_BYTES = 64 * 1024
MAX_LINES = 2000

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# A conda-safe version after the build string (if any) has been split off.
# Same safe-character set enrich-cpe.sh uses for a cpe version: letters,
# digits, and the punctuation an actual package version uses.
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+~-]*$")
# Ordered longest-operator-first so ">=" is not mis-read as ">" + "=".
CONDA_OPERATORS = ("~=", "!=", ">=", "<=", "==", "=", ">", "<")
# Same idea for a pip requirement line, minus conda's bare "=" (pip's exact-pin
# spelling is "=="). A real environment.yml's pip: section uses range
# specifiers too (e.g. "streamlit>=0.73.1"), not just "=="; -- covered below,
# never as a fixed version, since a range does not name one.
PIP_OPERATORS = ("~=", "!=", ">=", "<=", "==", ">", "<")


def read_environment_file(source_dir):
    """The first of environment.yml / environment.yaml found at the project
    root. Not searched recursively: conda's own convention puts this file at
    the project root, and a nested one (a vendored example, a subproject) is
    not what this scan is being asked about."""
    for name in ("environment.yml", "environment.yaml"):
        path = source_dir / name
        if path.is_file():
            try:
                if path.stat().st_size > MAX_BYTES:
                    return None
                return path.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeDecodeError):
                return None
    return None


def parse_conda_entry(item):
    """"name", "name=version", "name=version=build", or a range/no-op
    operator (unpinned). Returns (name, version_or_None) or None if item is
    not this shape at all."""
    for op in CONDA_OPERATORS:
        idx = item.find(op)
        if idx <= 0:
            continue
        name, rest = item[:idx], item[idx + len(op):]
        if not NAME_RE.match(name) or not rest:
            return None
        if op != "=":
            return (name, None)  # range/inequality: not a fixed version
        parts = rest.split("=")
        if len(parts) > 2:
            return None  # more than one embedded "=" is not a shape we know
        version = parts[0]
        if not VERSION_RE.match(version):
            return None
        return (name, version)
    if not NAME_RE.match(item):
        return None
    return (item, None)


def parse_pip_entry(item):
    """"name==version" (exact pin), "name<op>version" for a range/inequality
    (unpinned -- a range does not name one fixed version), a bare "name", or a
    recognized-but-unrepresentable editable/VCS install (kept as a known
    shape, just not turned into a purl -- these are a normal part of a real
    environment.yml's pip section, not a sign the file itself is malformed)."""
    if item.startswith(("-e ", "--editable")) or re.match(r"^[a-z+]+://", item):
        return ("skip", None)
    for op in PIP_OPERATORS:
        idx = item.find(op)
        if idx <= 0:
            continue
        name, rest = item[:idx], item[idx + len(op):]
        if not NAME_RE.match(name) or not rest:
            return None
        if op != "==":
            return (name, None)
        if not VERSION_RE.match(rest):
            return None
        return (name, rest)
    if not NAME_RE.match(item):
        return None
    return (item, None)


def indent_of(line):
    # Strip BOTH space and tab to find the whitespace run, then check whether
    # a tab was in it -- stripping only " " first (as the original version of
    # this function did) leaves a tab-led line's "leading whitespace" empty,
    # so the tab itself is never in the slice being checked and goes
    # undetected (measured: a line that starts with a bare tab reads as
    # indent 0, "end of the dependencies block", not "unknown shape").
    stripped = line.lstrip(" \t")
    leading = line[: len(line) - len(stripped)]
    if "\t" in leading:
        return None  # a tab in the leading whitespace is not the known shape
    return len(leading)


def parse_dependencies(text):
    """Returns (conda_entries, pip_entries) -- each a list of (name, version)
    -- or None if the file does not match the known shape anywhere in its
    dependencies: block. conda_entries/pip_entries use version=None for an
    unpinned or range-pinned declaration."""
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        return None
    start = None
    for i, line in enumerate(lines):
        if line == "dependencies:":
            start = i + 1
            break
    if start is None:
        return ([], [])  # no dependencies: key at all -- nothing to read, not a failure

    conda_entries, pip_entries = [], []
    in_pip = False
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "" or line.lstrip(" ").startswith("#"):
            i += 1
            continue
        indent = indent_of(line)
        if indent is None:
            return None
        if indent == 0:
            break  # back to a top-level key: the dependencies: block is over
        stripped = line[indent:]
        if in_pip and indent == 2 and stripped.startswith("- "):
            in_pip = False
            continue  # re-examine this line as a conda-level entry
        if not stripped.startswith("- "):
            return None
        item = stripped[2:].rstrip()
        if not in_pip:
            if indent != 2:
                return None
            if item == "pip:":
                in_pip = True
                i += 1
                continue
            parsed = parse_conda_entry(item)
            if parsed is None:
                return None
            conda_entries.append(parsed)
        else:
            if indent != 4:
                return None
            parsed = parse_pip_entry(item)
            if parsed is None:
                return None
            if parsed[0] != "skip":
                pip_entries.append(parsed)
        i += 1
    return (conda_entries, pip_entries)


def detect_channel(text):
    """The single declared channel, or None if there is zero or more than
    one -- a purl channel qualifier is only safe to attach when there is no
    ambiguity about which channel a package actually came from."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line == "channels:") + 1
    except StopIteration:
        return None
    channels = []
    for line in lines[start:]:
        indent = indent_of(line)
        if indent is None or indent == 0:
            break
        stripped = line[indent:]
        if indent == 2 and stripped.startswith("- "):
            channels.append(stripped[2:].strip())
        else:
            break
    return channels[0] if len(channels) == 1 else None


def conda_component(name, version, channel):
    props = [{"name": "bomlens:layer", "value": "conda"}]
    if version is None:
        props.append({"name": "bomlens:versionUnpinned", "value": "true"})
        return {
            "type": "library", "name": name,
            "bom-ref": f"conda:{name}",
            "properties": props,
        }
    purl = f"pkg:conda/{name}@{version}"
    if channel:
        purl += f"?channel={channel}"
    return {
        "type": "library", "name": name, "version": version,
        "purl": purl, "bom-ref": purl,
        "properties": props,
    }


def pip_component(name, version):
    props = [{"name": "bomlens:layer", "value": "conda"}]
    if version is None:
        props.append({"name": "bomlens:versionUnpinned", "value": "true"})
        return {
            "type": "library", "name": name,
            "bom-ref": f"pypi:{name}",
            "properties": props,
        }
    purl = f"pkg:pypi/{name}@{version}"
    return {
        "type": "library", "name": name, "version": version,
        "purl": purl, "bom-ref": purl,
        "properties": props,
    }


def build(components, project_version):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": "conda", "version": project_version},
        },
        "components": components,
    }


def main():
    if len(sys.argv) < 3:
        print("usage: identify-conda.py <source_dir> <output.json> [version]", file=sys.stderr)
        return 2
    source_dir = Path(sys.argv[1])
    output = sys.argv[2]
    project_version = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    components = []
    if source_dir.is_dir():
        text = read_environment_file(source_dir)
        if text is not None:
            parsed = parse_dependencies(text)
            if parsed is None:
                print("[conda] environment.yml did not match the known shape; leaving it unread", file=sys.stderr)
            else:
                conda_entries, pip_entries = parsed
                channel = detect_channel(text)
                seen = set()
                for name, version in conda_entries:
                    if name in seen:
                        continue
                    seen.add(name)
                    components.append(conda_component(name, version, channel))
                seen = set()
                for name, version in pip_entries:
                    if name in seen:
                        continue
                    seen.add(name)
                    components.append(pip_component(name, version))
    else:
        print(f"[conda] source directory not found: {source_dir}", file=sys.stderr)

    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(build(components, project_version), fh, indent=2)
    except OSError as err:
        print(f"[conda] ERROR: could not write {output}: {err}", file=sys.stderr)
        return 1

    print(f"[conda] environment.yml dependencies identified: {len(components)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
