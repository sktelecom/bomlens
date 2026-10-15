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
#   4. The four opt-in images (firmware/aibom/deep-cve/deep-license) are pullable too
#      (checked after step 3, not before -- see that step's own comment).
#
# It only verifies (no publish/side effects), so the release-gate job can run it
# while the release is still a draft, and it can be dry-run on demand against an
# existing tag.
#
# Usage: verify-release.sh <tag>            e.g. verify-release.sh v1.5.1
# Env:   GH_TOKEN          token for `gh` (GITHUB_TOKEN in Actions)
#        VERIFY_TIMEOUT    seconds to wait for the installers and the main
#                          image (default 2100)
#        VERIFY_SECONDARY_TIMEOUT  seconds for the WHOLE step checking the
#                          four opt-in images, shared rather than split four
#                          ways (default 5400 = 90 min): they do not take
#                          equal time to build (measured on a real run:
#                          firmware ~11min, deep-cve ~9min, aibom ~86min, all
#                          starting alongside the main image in the same
#                          docker-publish.yml call, not after it), and this
#                          job has no other way to learn docker-publish.yml
#                          finished -- release-upstream.yml's `release` and
#                          `images` jobs are not ordered by `needs:`, so this
#                          polling loop IS the synchronization. If the
#                          self-hosted runner ever serializes these image
#                          builds instead of running them concurrently, this
#                          default may need to grow again.
#        PUBLISH_REPO      owner/repo the release lives in (default sktelecom/bomlens)
#        GITHUB_REPOSITORY fallback for PUBLISH_REPO
set -uo pipefail

TAG="${1:?usage: verify-release.sh <tag e.g. v1.5.1>}"
IMAGE_VERSION="${TAG#v}"
# PUBLISH_REPO first: GITHUB_REPOSITORY is a reserved Actions variable that a
# workflow cannot override, so it always names the repository running the job.
# That is the wrong answer when the release being verified lives elsewhere.
REPO="${PUBLISH_REPO:-${GITHUB_REPOSITORY:-sktelecom/bomlens}}"
OWNER="${REPO%%/*}"
IMAGE="ghcr.io/${OWNER}/bomlens:${IMAGE_VERSION}"
TIMEOUT="${VERIFY_TIMEOUT:-2100}"
SECONDARY_TIMEOUT="${VERIFY_SECONDARY_TIMEOUT:-5400}"
MIN_BYTES=1000000   # a real installer is tens of MB; guard against 0-byte stubs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fail=0

# Resolve gh once, up front, rather than relying on it staying on PATH for the
# whole script. Observed on v1.11.4 (self-hosted runner): `gh` resolved fine
# at the start of this script but had silently dropped off PATH by the time
# step 3 ran, ~6 minutes and a `bash tests/test-docs-walkthrough.sh` later --
# the exact mechanism wasn't pinned down. A fixed path sidesteps whatever is
# mutating PATH mid-script instead of chasing it further.
GH_BIN="$(command -v gh || true)"
if [ -z "$GH_BIN" ]; then
    echo "❌ gh CLI not found on PATH; cannot verify the release" >&2
    exit 1
fi

# Pulls one image, retrying every $3 seconds (default 30; overridable only
# so tests/test-verify-release.sh doesn't have to wait out a real 30s) until
# the ABSOLUTE deadline $2 (epoch seconds, not a duration), then reports
# pass/fail and removes it again on success (step 4 below has no later use
# for it, unlike the main $IMAGE). An absolute deadline, not each image
# getting its own fresh budget: docker-publish.yml's opt-in images do not
# all take the same time to build (measured: firmware ~11min, deep-cve
# ~9min, aibom ~86min, all amd64-only builds except aibom which is also
# multi-arch), so step 4 below computes ONE shared deadline sized for the
# slowest of the three and gives each image whatever of it remains, rather
# than splitting one timeout three equal ways regardless of which image
# actually needs it. A function, not inlined into the step 4 loop, so that
# test can lift it out and drive it against a stubbed `docker` on PATH the
# same way tests/test-image-refresh.sh does for scan-sbom.sh's own functions.
check_secondary_image() {
    local img="$1" deadline="$2" retry_s="${3:-30}"
    local pulled=1
    while :; do
        if docker pull "$img" >/dev/null 2>&1; then
            pulled=0
            break
        fi
        [ "$(date +%s)" -ge "$deadline" ] && break
        sleep "$retry_s"
    done
    # Judge success by the pull's own exit status, not a follow-up `docker
    # image inspect`: on a non-ephemeral (self-hosted) runner, a prior run's
    # image can already sit in the local daemon, so inspect would report
    # success even though every pull attempt here actually failed.
    if [ "$pulled" -eq 0 ]; then
        echo "  ✓ pulled $img"
        docker rmi "$img" >/dev/null 2>&1 || true
        return 0
    fi
    echo "  ❌ could not pull $img before the shared deadline"
    return 1
}

echo "Verifying release $TAG (image $IMAGE)"

# ---------------------------------------------------------------------------
# 1) Desktop installers attached. desktop.yml builds and attaches these on the
#    tag; poll until both are present (or time out).
# ---------------------------------------------------------------------------
echo "1) Desktop installers attached to release $TAG"
deadline=$(( $(date +%s) + TIMEOUT ))
exe_size=""; dmg_size=""
while :; do
    assets="$("$GH_BIN" release view "$TAG" --repo "$REPO" --json assets \
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
#    Deliberately BEFORE step 4's opt-in-image check, not after: the opt-in
#    images build concurrently with the main one in the same docker-publish.yml
#    call (not after it), and aibom alone measures ~86 minutes to build vs. the
#    main image's ~24 -- so by the time this ~40-45 minute walkthrough finishes,
#    aibom has had that much longer to become pullable. Running step 4 first
#    would instead have this gate sit idle waiting on aibom, then only start
#    the walkthrough afterward, wasting on the order of 40 minutes per release
#    for no benefit (neither step's outcome depends on the other's).
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

# ---------------------------------------------------------------------------
# 4) The four opt-in images (firmware/aibom/deep-cve/deep-license) pullable at this
#    version. docker-publish.yml's build-firmware/build-aibom/build-deep-cve/
#    build-deep-license (the last one was missing from this check until v1.13.5,
#    when its build failed and the gate would still have published the release)
#    jobs run unconditionally alongside the main image on a real release, so
#    a broken push for one of them is exactly as release-blocking as the main
#    image being missing -- just harder to notice, since nothing else in this
#    gate ever pulls them. Pull-only, not a full scan: these are large --
#    measured compressed sizes: aibom ~3.8 GB (the biggest of the four
#    images, base included), deep-cve ~0.7 GB (its ~1.8 GB vulnerability DB is
#    built INTO the image, not fetched here), firmware ~0.4 GB -- and each
#    already gets its own Trivy scan inside docker-publish.yml. One shared
#    deadline for all three (see VERIFY_SECONDARY_TIMEOUT above), not a
#    separate budget each: aibom alone measures ~86 minutes to build, so
#    treating it the same as firmware's ~11 or deep-cve's ~9 would either
#    waste time three times over or starve the one that actually needs it.
#    Run AFTER step 3's walkthrough (see that step's comment): by now aibom
#    has had the walkthrough's own ~40-45 minutes of extra build time, so this
#    deadline mostly only needs to cover what remains, not the whole build.
#    Removed after each check, not kept like the main image: nothing later in
#    this script needs them. The main image, by contrast, is kept and tagged
#    :latest above (step 2) precisely so step 3's walkthrough reuses that
#    local copy instead of pulling it again -- these three have no such
#    later reader, so there is nothing to keep them for.
#    Only the bomlens-* names are checked, not the legacy sbom-scanner-*
#    aliases docker-publish.yml also signs: both names tag the exact same
#    DIGEST there, so a pull of one proves the other's manifest is just as
#    reachable, and checking it again here would only spend more of the
#    shared deadline on a second pull of bytes already confirmed present.
# ---------------------------------------------------------------------------
echo "4) Opt-in images (firmware/aibom/deep-cve/deep-license) pullable"
secondary_deadline=$(( $(date +%s) + SECONDARY_TIMEOUT ))
for suffix in firmware aibom deep-cve deep-license; do
    img="ghcr.io/${OWNER}/bomlens-${suffix}:${IMAGE_VERSION}"
    check_secondary_image "$img" "$secondary_deadline" || fail=1
done

# ---------------------------------------------------------------------------
# 5) The release describes itself. upload-assets attaches an SBOM for the
#    desktop dependency tree and one for the source bundles; a release that
#    quietly lost them would still install and scan, so nothing else notices.
# ---------------------------------------------------------------------------
echo "5) SBOM assets attached to release $TAG"
# A single one-shot `gh release view` here (unlike step 1's polling loop) had
# no resilience against a transient read failure -- observed on v1.11.4: the
# call silently came back empty (stderr swallowed by 2>/dev/null) even though
# the asset was already confirmed present, failing the gate after the ~40-
# minute walkthrough had already passed. Retry a few times before giving up.
sbom_size=""
for _ in 1 2 3 4 5; do
    sbom_assets="$("$GH_BIN" release view "$TAG" --repo "$REPO" --json assets \
        -q '.assets[] | .name + ":" + (.size|tostring)' 2>&1)"
    sbom_size="$(printf '%s\n' "$sbom_assets" | sed -n "s/^bomlens-source-${TAG}\.cdx\.json://p" | head -1)"
    if [ -n "$sbom_size" ] && [ "$sbom_size" -ge 100 ] 2>/dev/null; then
        break
    fi
    echo "  (retrying SBOM asset lookup: $sbom_assets)"
    sleep 5
done
if [ -n "$sbom_size" ] && [ "$sbom_size" -ge 100 ] 2>/dev/null; then
    echo "  ✓ bomlens-source-${TAG}.cdx.json attached (${sbom_size} bytes)"
else
    echo "  ❌ bomlens-source-${TAG}.cdx.json missing or empty (got '${sbom_size:-none}')"; fail=1
fi

echo ""
if [ "$fail" -ne 0 ]; then
    echo "❌ release $TAG is NOT ready (a recommended entry point is broken)"
    exit 1
fi
echo "✅ release $TAG verified: installers attached, all five images published, documented command works, SBOMs attached"
