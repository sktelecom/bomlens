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
# check-doc-links.sh — deterministic internal-link gate for the onboarding path.
#
# A first-time user clicks the links in the getting-started docs; a dangling
# relative link or a moved image sends them to a 404. Unlike external URLs
# (flaky, rate-limited — left to the informational link check), internal links
# resolve to files in this repo, so we can verify them offline and block on a
# break. External (http/https/mailto) and pure #anchor links are skipped.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

# Onboarding journey: the pages a newcomer actually follows. Extend as needed.
DOCS=(
  README.md
  docs/index.md docs/index.ko.md
  docs/start/first-scan.md docs/start/first-scan.ko.md
  docs/start/no-cli.md docs/start/no-cli.ko.md
  docs/guides/by-input.md docs/guides/by-input.ko.md
)

checked=0
for doc in "${DOCS[@]}"; do
  [ -f "$doc" ] || { echo "  ⚠ skip (missing): $doc"; continue; }
  dir="$(dirname "$doc")"
  # Extract every ](target) inline-link target.
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    # Drop an optional "title": ](path "Title")  ->  path
    target="${target%% \"*}"
    case "$target" in
      http://*|https://*|mailto:*|tel:*) continue ;;  # external — not our gate
    esac
    # Strip a trailing #anchor; skip pure-anchor links.
    path="${target%%#*}"
    [ -n "$path" ] || continue
    # Resolve: absolute from repo root, otherwise relative to the doc's dir.
    case "$path" in
      /*) resolved="${ROOT}${path}" ;;
      *)  resolved="${dir}/${path}" ;;
    esac
    checked=$((checked+1))
    if [ ! -e "$resolved" ]; then
      echo "  ❌ $doc → broken internal link: $target"
      fail=1
    fi
  done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\((.*)\)$/\1/')
done

echo ""
if [ "$fail" -ne 0 ]; then
  echo "❌ broken internal link(s) in the onboarding docs — fix the path or the target."
  exit 1
fi
echo "✅ onboarding internal links resolve ($checked checked across ${#DOCS[@]} pages)."
