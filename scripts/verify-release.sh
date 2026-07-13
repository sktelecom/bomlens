#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# verify-release.sh — gate a release before it is shown to users.
#
# A first-time visitor follows the release's two recommended entry points: the
# one-click desktop installer, and `docker pull` + the documented first-scan
# command. Those artifacts are produced by separate workflows (desktop.yml,
# docker-publish.yml) that finish after the release is created, so this script
# confirms both are actually ready and working for THIS release:
#   1. BomLens-Setup.exe and .dmg are attached to the release.
#   2. The published scanner image for this version is pullable.
#   3. The documented first-scan command produces a valid SBOM on that exact
#      published image (not a CI-built one).
#
# It only verifies (no publish/side effects), so the release-gate job can run it
# while the release is still a draft, and it can be dry-run on demand against an
# existing tag.
#
# Usage: verify-release.sh <tag>            e.g. verify-release.sh v1.5.1
# Env:   GH_TOKEN          token for `gh` (GITHUB_TOKEN in Actions)
#        VERIFY_TIMEOUT    seconds to wait for async artifacts (default 2100)
#        GITHUB_REPOSITORY owner/repo (default sktelecom/bomlens)
set -uo pipefail

TAG="${1:?usage: verify-release.sh <tag e.g. v1.5.1>}"
IMAGE_VERSION="${TAG#v}"
REPO="${GITHUB_REPOSITORY:-sktelecom/bomlens}"
OWNER="${REPO%%/*}"
IMAGE="ghcr.io/${OWNER}/bomlens:${IMAGE_VERSION}"
TIMEOUT="${VERIFY_TIMEOUT:-2100}"
MIN_BYTES=1000000   # a real installer is tens of MB; guard against 0-byte stubs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fail=0

echo "Verifying release $TAG (image $IMAGE)"

# ---------------------------------------------------------------------------
# 1) Desktop installers attached. desktop.yml builds and attaches these on the
#    tag; poll until both are present (or time out).
# ---------------------------------------------------------------------------
echo "1) Desktop installers attached to release $TAG"
deadline=$(( $(date +%s) + TIMEOUT ))
exe_size=""; dmg_size=""
while :; do
    assets="$(gh release view "$TAG" --repo "$REPO" --json assets \
        -q '.assets[] | .name + ":" + (.size|tostring)' 2>/dev/null || true)"
    exe_size="$(printf '%s\n' "$assets" | sed -n 's/^BomLens-Setup\.exe://p' | head -1)"
    dmg_size="$(printf '%s\n' "$assets" | sed -n 's/^BomLens-Setup\.dmg://p' | head -1)"
    if [ -n "$exe_size" ] && [ "$exe_size" -ge "$MIN_BYTES" ] 2>/dev/null \
       && [ -n "$dmg_size" ] && [ "$dmg_size" -ge "$MIN_BYTES" ] 2>/dev/null; then
        break
    fi
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 20
done
if [ -n "$exe_size" ] && [ "$exe_size" -ge "$MIN_BYTES" ] 2>/dev/null; then
    echo "  ✓ BomLens-Setup.exe attached (${exe_size} bytes)"
else
    echo "  ❌ BomLens-Setup.exe missing or too small (got '${exe_size:-none}')"; fail=1
fi
if [ -n "$dmg_size" ] && [ "$dmg_size" -ge "$MIN_BYTES" ] 2>/dev/null; then
    echo "  ✓ BomLens-Setup.dmg attached (${dmg_size} bytes)"
else
    echo "  ❌ BomLens-Setup.dmg missing or too small (got '${dmg_size:-none}')"; fail=1
fi

# ---------------------------------------------------------------------------
# 2) Published scanner image pullable. docker-publish.yml pushes it from the
#    tag; poll until the pull succeeds (or time out).
# ---------------------------------------------------------------------------
echo "2) Published scanner image $IMAGE pullable"
deadline=$(( $(date +%s) + TIMEOUT ))
while ! docker pull "$IMAGE" >/dev/null 2>&1; do
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 30
done
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "  ✓ pulled $IMAGE"
    # The walkthrough's published-image page (docs/reference/docker-image.md)
    # names the :latest tag, which docker-publish.yml only pushes from the
    # default branch — at tag time it may not exist yet, so that page would
    # silently SKIP. Alias the just-pulled release image locally (the same
    # trick heavy-e2e.yml uses) so the page actually runs against THIS release.
    docker tag "$IMAGE" "ghcr.io/${OWNER}/bomlens:latest"
else
    echo "  ❌ could not pull $IMAGE within ${TIMEOUT}s"; fail=1
fi

# ---------------------------------------------------------------------------
# 3) Documented first-scan command runs on the published image. The walkthrough
#    harness honours SBOM_SCANNER_IMAGE and runs the docs' runnable blocks.
# ---------------------------------------------------------------------------
echo "3) Documented first-scan command on the published image"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    if SBOM_SCANNER_IMAGE="$IMAGE" bash "$REPO_DIR/tests/test-docs-walkthrough.sh"; then
        echo "  ✓ documented walkthrough passed on $IMAGE"
    else
        echo "  ❌ documented walkthrough failed on $IMAGE"; fail=1
    fi
else
    echo "  ❌ skipped — published image not available"; fail=1
fi

echo ""
if [ "$fail" -ne 0 ]; then
    echo "❌ release $TAG is NOT ready (a recommended entry point is broken)"
    exit 1
fi
echo "✅ release $TAG verified: installers attached, image published, documented command works"
