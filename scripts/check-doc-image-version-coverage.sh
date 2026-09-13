#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-doc-image-version-coverage.sh: guard against the Docker image
# reference going stale when Renovate bumps a tool version.
#
# docs/reference/docker-image.md is the canonical place for the versions
# users see (docker/README.md and docs/concepts/architecture.md link to it
# instead of repeating numbers). Renovate bumps docker/Dockerfile's ARGs on
# its own schedule. Nothing else forces this page to follow; this script does.
#
# Only the tools this page's table already documents are checked; adding a
# new tool to the table is a separate editorial decision, not something this
# script should force. Bash 3.2 compatible (no associative arrays): macOS
# ships 3.2 at /bin/bash, and this runs there via the pre-push hook too.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="$ROOT/docker/Dockerfile"
DOC="$ROOT/docs/reference/docker-image.md"
DOC_KO="$ROOT/docs/reference/docker-image.ko.md"
fail=0

# ARG name : table row label. Extend this list if a row is added for another
# already-pinned tool; do not add a tool here that has no row yet.
PAIRS="
SYFT_VERSION:syft
TRIVY_VERSION:Trivy
COSIGN_VERSION:cosign
SCANCODE_VERSION:ScanCode Toolkit
DOCKER_CLI_VERSION:docker CLI
CDXGEN_VERSION:cdxgen
"

get_arg() {
    # First non-empty ARG assignment for the given name (Dockerfile ARGs are
    # not reassigned later in this file; grabbing the first match is enough).
    awk -v name="$1" '$0 ~ "^ARG " name "=" {
        sub("^ARG " name "=", "");
        print;
        exit
    }' "$DOCKERFILE"
}

while IFS=: read -r arg label; do
    [ -z "$arg" ] && continue
    version="$(get_arg "$arg")"
    if [ -z "$version" ]; then
        echo "ERROR: could not read ARG $arg from $DOCKERFILE"
        fail=1
        continue
    fi

    if ! grep -qF "| $label | $version |" "$DOC"; then
        echo "FAIL: $DOC's '$label' row does not show the pinned version ($version)."
        echo "      Dockerfile has: ARG $arg=$version"
        fail=1
    fi
    if ! grep -qF "| $label | $version |" "$DOC_KO"; then
        echo "FAIL: $DOC_KO's '$label' row does not show the pinned version ($version)."
        echo "      Dockerfile has: ARG $arg=$version"
        fail=1
    fi
done <<EOF
$PAIRS
EOF

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "docker/Dockerfile's ARGs are the version source of truth; the Docker image"
    echo "reference must be updated in the same PR that bumps one."
    exit 1
fi

echo "OK: every pinned tool version in docker-image.md matches docker/Dockerfile."
