#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# check-notice-sync.sh — prove the license files shipped inside the scanner
# image are byte-identical to the ones at the repository root.
#
# Why copies exist at all: Apache-2.0 section 4 requires a redistributor to
# carry a copy of the License and the NOTICE contents, and the image ships our
# own shell scripts. The image build context is ./docker (13 CI call sites and
# the user-facing `docker build ... ./docker` in the guides depend on that), so
# the root LICENSE is out of reach of any COPY. Placing the copies under
# docker/lib/notices/ gets them into the image through the existing
# `COPY lib/ /usr/local/lib/sbom/` with no Dockerfile change.
#
# The cost of a copy is drift, which is what this gate removes.
# No Docker needed.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHIPPED_DIR="$ROOT_DIR/docker/lib/notices"
FAILED=0

for name in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
    src="$ROOT_DIR/$name"
    shipped="$SHIPPED_DIR/$name"

    if [ ! -f "$src" ]; then
        echo "  MISS: $name is missing from the repository root"
        FAILED=1
        continue
    fi
    if [ ! -f "$shipped" ]; then
        echo "  MISS: docker/lib/notices/$name is missing — the image would ship without it"
        echo "        fix: cp $name docker/lib/notices/$name"
        FAILED=1
        continue
    fi
    if cmp -s "$src" "$shipped"; then
        echo "  ok:   $name matches docker/lib/notices/$name"
    else
        echo "  DIFF: $name and docker/lib/notices/$name have diverged"
        echo "        fix: cp $name docker/lib/notices/$name"
        FAILED=1
    fi
done

# Nothing else may live here: a stray file would be shipped as if it were one
# of our license documents.
while IFS= read -r path; do
    case "$(basename "$path")" in
        LICENSE|NOTICE|THIRD_PARTY_LICENSES.md) ;;
        *)
            echo "  EXTRA: docker/lib/notices/$(basename "$path") is not one of the three license documents"
            FAILED=1
            ;;
    esac
done < <(find "$SHIPPED_DIR" -mindepth 1 -maxdepth 1)

if [ "$FAILED" -ne 0 ]; then
    echo "[FAIL] the license files shipped in the image do not match the repository root"
    exit 1
fi

echo "[OK] the scanner image ships the repository's LICENSE, NOTICE, and THIRD_PARTY_LICENSES.md"
