#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# detect-project-license.py — read the outbound licence a project declares in its
# own build manifest.
#
# The licence-conflict check needs to know what the project ships under, and a
# source scan does not supply it: cdxgen fills metadata.component.licenses for
# npm only, leaving Maven, Gradle, Python, Rust and PHP trees empty. Until now
# the only way to switch the check on was `--license`, so a project that had
# already declared its licence the standard way — a <licenses> block in pom.xml —
# was still told "no outbound license was declared".
#
# Prints one SPDX id on stdout, or nothing. Printing nothing is a normal result
# and leaves the check off; a wrong guess would be worse than no answer, since it
# would produce conflict verdicts against a licence the project never chose.
#
# Usage: detect-project-license.py <source-dir>

import json
import os
import re
import sys
import xml.etree.ElementTree as ET

# Free-text licence names seen in real manifests, mapped to their SPDX id. Only
# unambiguous spellings belong here: anything not matched is left undetected
# rather than guessed. Keys are compared lowercased with runs of non-alphanumeric
# characters collapsed, so "Apache License, Version 2.0" and "Apache-License 2.0"
# both land on the same key.
NAME_TO_SPDX = {
    "apache license version 2 0": "Apache-2.0",
    "the apache license version 2 0": "Apache-2.0",
    "apache software license version 2 0": "Apache-2.0",
    "apache 2 0": "Apache-2.0",
    "apache license 2 0": "Apache-2.0",
    "mit license": "MIT",
    "the mit license": "MIT",
    "bsd 2 clause license": "BSD-2-Clause",
    "bsd 3 clause license": "BSD-3-Clause",
    "the bsd 3 clause license": "BSD-3-Clause",
    "gnu general public license version 2": "GPL-2.0-only",
    "gnu general public license version 3": "GPL-3.0-only",
    "gnu lesser general public license version 2 1": "LGPL-2.1-only",
    "gnu lesser general public license version 3": "LGPL-3.0-only",
    "eclipse public license version 1 0": "EPL-1.0",
    "eclipse public license version 2 0": "EPL-2.0",
    "mozilla public license version 2 0": "MPL-2.0",
    "isc license": "ISC",
}

# A value already written as an SPDX id (or a simple expression) is taken as-is.
# Deliberately narrow: identifiers, plus AND/OR/WITH expressions and a trailing
# "+", which is what a manifest that already speaks SPDX will contain.
SPDX_LIKE = re.compile(r"^[A-Za-z0-9.+-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*$")


def normalize(value):
    """Map a manifest's licence string to an SPDX id, or None when unsure."""
    if not value:
        return None
    text = " ".join(str(value).split())
    if SPDX_LIKE.match(text) and " " not in text:
        return text
    if SPDX_LIKE.match(text):  # an expression such as "MIT OR Apache-2.0"
        return text
    key = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    return NAME_TO_SPDX.get(key)


def from_pom(path):
    """Maven: the first <licenses><license><name> (or <url> as a fallback)."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    # POMs are namespaced; match on the local tag name instead of hardcoding it.
    def local(el):
        return el.tag.rsplit("}", 1)[-1]

    for licenses in (e for e in root if local(e) == "licenses"):
        for lic in (e for e in licenses if local(e) == "license"):
            fields = {local(c): (c.text or "").strip() for c in lic}
            found = normalize(fields.get("name"))
            if found:
                return found
            # Some POMs give only a URL. apache.org/licenses/LICENSE-2.0 is
            # unambiguous; anything else is left undetected.
            url = fields.get("url", "").lower()
            if "apache.org/licenses/license-2.0" in url:
                return "Apache-2.0"
    return None


def from_json_manifest(path, key="license"):
    """npm / Composer: a "license" string, or the first entry of a list."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    value = data.get(key)
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, dict):  # Composer's older object form
        value = value.get("type") or value.get("name")
    return normalize(value)


def from_toml(path):
    """Rust / Python: a top-level or [project] `license = "..."` line.

    Read line-wise rather than with a TOML parser: tomllib is Python 3.11+ and
    this has to run on whatever interpreter the image carries. The pattern is
    anchored to a bare `license` key so a dependency's own key cannot match.
    """
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    section = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]")
            continue
        if section not in ("", "package", "project", "tool.poetry"):
            continue
        m = re.match(r'^license\s*=\s*"([^"]+)"', stripped)
        if m:
            return normalize(m.group(1))
        # PEP 621 also allows license = { text = "MIT" }
        m = re.match(r'^license\s*=\s*\{[^}]*text\s*=\s*"([^"]+)"', stripped)
        if m:
            return normalize(m.group(1))
    return None


# Manifest filename -> reader. Ordered: the first manifest found at the shallowest
# depth wins, so a repository's own manifest beats one inside a vendored copy.
READERS = [
    ("pom.xml", from_pom),
    ("package.json", from_json_manifest),
    ("pyproject.toml", from_toml),
    ("Cargo.toml", from_toml),
    ("composer.json", from_json_manifest),
]

# Directories that hold other people's code; a licence found in there describes a
# dependency, not this project.
SKIP_DIRS = {
    "node_modules", "vendor", "target", "build", "dist", ".git", "venv",
    ".venv", "__pycache__", "site-packages", "third_party", "thirdparty",
}


def detect(root):
    """Search the tree breadth-first, shallowest manifest first."""
    for depth in range(0, 3):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                           and not d.startswith(".")]
            rel = os.path.relpath(dirpath, root)
            current = 0 if rel == "." else rel.count(os.sep) + 1
            if current != depth:
                continue
            for name, reader in READERS:
                if name in filenames:
                    found = reader(os.path.join(dirpath, name))
                    if found:
                        return found
    return None


def main():
    if len(sys.argv) < 2:
        return 0
    root = sys.argv[1]
    if not os.path.isdir(root):
        return 0
    try:
        found = detect(root)
    except Exception:  # never let detection abort a scan
        return 0
    if found:
        print(found)
    return 0


if __name__ == "__main__":
    sys.exit(main())
