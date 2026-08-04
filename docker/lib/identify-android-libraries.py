#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read the libraries an Android app declares about itself.

Usage: identify-android-libraries.py <tree> > components.json

An app package holds no package database and, for an app written in Kotlin or
Java alone, no native library either — which is every source the firmware passes
read. Measured on one app: 964 files unpacked and nothing identified, while the
package carried a list of its own libraries the whole time.

Gradle writes that list. Each library that ships in the package leaves a file at
`META-INF/<group>_<artifact>.version` whose contents are its version, so the
coordinate is in the file name and the version is the file. That is a record of
what was built in, not a guess from a string found in a binary, and it maps
directly onto a Maven identifier the vulnerability step already knows how to use.

The reading is deliberately literal. A file whose name carries no `_` gives no
artifact, and contents that are not shaped like a version are not a version:
Gradle can leave its own task description in the file when a build is configured
in a way that never resolves it (`task ':arch:core:core-runtime:writeVersionFile'
property 'version'` on the app measured), and shipping that as a version would be
worse than leaving the library out.
"""
import json
import os
import re
import sys

VERSION_DIR = "META-INF"
SUFFIX = ".version"
# A version is one short token. Anything with a space in it is prose — a Gradle
# task description, an error — and not a version of anything.
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$")
# The same ceiling the other identification passes carry, for the same reason: a
# tree this large is not an app package and walking all of it costs the scan.
MAX_FILES = int(os.environ.get("FW_ANDROID_MAX_FILES", "200000"))


def read_version(path):
    """The version in a Gradle version file, or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(4096)
    except OSError:
        return None
    line = text.strip()
    return line if VERSION_RE.match(line) else None


def coordinate(filename):
    """`(group, artifact)` out of `<group>_<artifact>.version`, or None."""
    stem = filename[:-len(SUFFIX)]
    group, sep, artifact = stem.partition("_")
    if not sep or not group or not artifact:
        return None
    return group, artifact


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    tree = sys.argv[1]

    found = {}
    scanned = 0
    unread = 0
    capped = False
    for root, _dirs, files in os.walk(tree):
        if os.path.basename(root) != VERSION_DIR:
            continue
        for name in files:
            if not name.endswith(SUFFIX):
                continue
            if scanned >= MAX_FILES:
                capped = True
                break
            scanned += 1
            parsed = coordinate(name)
            if not parsed:
                continue
            version = read_version(os.path.join(root, name))
            if not version:
                unread += 1
                continue
            group, artifact = parsed
            found.setdefault((group, artifact, version),
                             os.path.join(root, name))
        if capped:
            break

    components = []
    for (group, artifact, version) in sorted(found):
        components.append({
            "bom-ref": f"android-library:{group}:{artifact}@{version}",
            "type": "library",
            "name": artifact,
            "version": version,
            "group": group,
            "purl": f"pkg:maven/{group}/{artifact}@{version}",
            "properties": [
                {"name": "bomlens:identifiedBy", "value": "android-version-file"},
            ],
            "evidence": {"occurrences": [{"location": found[(group, artifact, version)]}]},
        })

    print(json.dumps(components, ensure_ascii=False))
    print(f"[android] {scanned} version file(s) read; {len(components)} "
          f"library(ies) the package declares.", file=sys.stderr)
    if unread:
        # Said out loud rather than swallowed: the library is in the package and
        # this pass could not name its version, which is a different answer from
        # the library not being there.
        print(f"[android] {unread} version file(s) held no version and were left out.",
              file=sys.stderr)
    if capped:
        print(f"[android] WARN: stopped at {MAX_FILES} files; "
              f"raise FW_ANDROID_MAX_FILES to cover the rest.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
