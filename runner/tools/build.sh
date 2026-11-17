#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# build.sh - build the bomlens-runner sdist and wheel for a release.
#
# Usage: runner/tools/build.sh VERSION ENGINE [DEEP_LICENSE] [DEEP_CVE]
#
# Writes the version and image references into _release.py, builds into
# runner/dist with the hash-pinned setuptools in build-requirements.txt, and
# installs the wheel into a fresh virtual environment to check it. release.yml
# publishes what this builds; engine-runner.yml runs it on every change.
# SOURCE_DATE_EPOCH (default: the time of the commit checked out) makes the
# files the same on every build of one commit.

set -euo pipefail

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$RUNNER_DIR/.." && pwd)"
[ "$#" -ge 2 ] || { echo "usage: $0 VERSION ENGINE [DEEP_LICENSE] [DEEP_CVE]" >&2; exit 2; }
VERSION="$1"
PYTHON="${PYTHON:-python3}"

# The package carries the repository's licence and notice files.
for f in LICENSE NOTICE; do
    cmp -s "$ROOT_DIR/$f" "$RUNNER_DIR/$f" || { echo "[ERROR] runner/$f differs from $f; copy it again" >&2; exit 1; }
done

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

cd "$RUNNER_DIR"
rm -rf dist build src/*.egg-info
"$PYTHON" -m pip install --quiet --require-hashes --no-deps -r build-requirements.txt
"$PYTHON" tools/stamp_release.py "$@"
"$PYTHON" -c 'from setuptools import build_meta as b; b.build_sdist("dist"); b.build_wheel("dist")'

check="$(mktemp -d)"
trap 'rm -rf "$check"' EXIT
"$PYTHON" -m venv "$check/venv"
"$check/venv/bin/pip" install --quiet --no-deps --no-index dist/*.whl
installed="$("$check/venv/bin/bomlens-runner" --version)"
[ "$installed" = "$VERSION" ] || { echo "[ERROR] the wheel says $installed, not $VERSION" >&2; exit 1; }
"$check/venv/bin/python" -c 'import bomlens_runner as r; print(r.release_images())'
"$PYTHON" -c 'import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
missing = [n for n in ("LICENSE", "NOTICE") if not any(p.endswith("/licenses/" + n) for p in names)]
sys.exit("[ERROR] the wheel has no " + ", ".join(missing) if missing else 0)' dist/*.whl
ls -l dist
