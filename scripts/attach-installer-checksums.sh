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
# attach-installer-checksums.sh — add the desktop installers to SHA256SUMS.txt.
#
# The installers (BomLens-Setup.exe/.dmg) are attached by desktop.yml AFTER
# upload-assets wrote SHA256SUMS.txt, so the release gate calls this script
# once verify-release.sh has confirmed both installers are present. At that
# point every other writer of the release assets has finished, making this the
# single writer of SHA256SUMS.txt (no race). Re-runs are idempotent: existing
# installer lines are replaced, not duplicated.
#
# Usage: attach-installer-checksums.sh <tag>    e.g. attach-installer-checksums.sh v1.5.5
# Env:   GH_TOKEN          token for `gh` (GITHUB_TOKEN in Actions)
#        GITHUB_REPOSITORY owner/repo (default sktelecom/bomlens)
#        DRY_RUN=1         compute and print, but do not upload
set -euo pipefail

TAG="${1:?usage: attach-installer-checksums.sh <tag e.g. v1.5.5>}"
REPO="${GITHUB_REPOSITORY:-sktelecom/bomlens}"
INSTALLERS=(BomLens-Setup.exe BomLens-Setup.dmg)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Downloading installers and SHA256SUMS.txt from $REPO $TAG"
gh release download "$TAG" --repo "$REPO" \
    --pattern 'BomLens-Setup.exe' \
    --pattern 'BomLens-Setup.dmg' \
    --pattern 'SHA256SUMS.txt'

for f in "${INSTALLERS[@]}" SHA256SUMS.txt; do
    [ -f "$f" ] || { echo "❌ $f is not attached to release $TAG"; exit 1; }
done

# Replace any previous installer lines (idempotent when the gate re-runs).
grep -v 'BomLens-Setup\.' SHA256SUMS.txt > SHA256SUMS.new || true
sha256sum "${INSTALLERS[@]}" >> SHA256SUMS.new
mv SHA256SUMS.new SHA256SUMS.txt

# Self-check: every line whose file we have locally must verify.
sha256sum --check --ignore-missing SHA256SUMS.txt

echo ""
cat SHA256SUMS.txt

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "DRY_RUN=1 — skipping upload"
    exit 0
fi

gh release upload "$TAG" SHA256SUMS.txt --repo "$REPO" --clobber
echo "✅ SHA256SUMS.txt updated on release $TAG with installer checksums"
