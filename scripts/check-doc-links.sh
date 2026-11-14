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
# check-doc-links.sh — deterministic internal-link gate for the onboarding path,
# plus a repo-wide language-leak check for every .ko.md page.
#
# A first-time user clicks the links in the getting-started docs; a dangling
# relative link or a moved image sends them to a 404. Unlike external URLs
# (flaky, rate-limited — left to the informational link check), internal links
# resolve to files in this repo, so we can verify them offline and block on a
# break. External (http/https/mailto) and pure #anchor links are skipped.
#
# Separately, a .ko.md page that links to the English `foo.md` instead of its
# own `foo.ko.md` sibling is not a broken link, since the English target genuinely exists, but it sends a
# Korean reader clicking a Korean link straight to an English page. That check
# runs over every .ko.md under docs/, not just the onboarding list above.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

# Onboarding journey: the pages a newcomer actually follows. Extend as needed. The home
# pages (docs-site/home/*.mdx) are not listed: their links are relative to the docs root
# and are checked on the built site by docs-site/scripts/check-links.mjs.
DOCS=(
  README.md
  docs/concepts/what-is-sbom.md docs/concepts/what-is-sbom.ko.md
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

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "❌ broken internal link(s) in the onboarding docs — fix the path or the target."
  exit 1
fi
echo "✅ onboarding internal links resolve ($checked checked across ${#DOCS[@]} pages)."

echo ""
# Language-leak check: a .ko.md page whose relative link targets foo.md when
# foo.ko.md sits right beside it. Only flagged when the ko sibling actually
# exists — a link to a page with no Korean mirror (CONTRIBUTING.md, an image,
# a sample HTML report) is the correct, only-available target, not a leak.
leaked=0
leak_checked=0
while IFS= read -r -d '' doc; do
  doc_rel="${doc#"$ROOT/"}"
  dir="$(dirname "$doc")"
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    target="${target%% \"*}"
    case "$target" in
      http://*|https://*|mailto:*|tel:*) continue ;;
    esac
    path="${target%%#*}"
    [ -n "$path" ] || continue
    case "$path" in
      *.ko.md) continue ;;   # already points at a Korean page
      *.md)    ;;            # a plain .md target — check for a ko sibling below
      *)       continue ;;   # not a markdown page (image, sample html, ...)
    esac
    case "$path" in
      /*) resolved="${ROOT}${path}" ;;
      *)  resolved="${dir}/${path}" ;;
    esac
    ko_sibling="${resolved%.md}.ko.md"
    leak_checked=$((leak_checked+1))
    if [ -e "$ko_sibling" ]; then
      ko_sibling_rel="$(cd "$(dirname "$ko_sibling")" && pwd)/$(basename "$ko_sibling")"
      ko_sibling_rel="${ko_sibling_rel#"$ROOT/"}"
      echo "  ❌ $doc_rel → links to ${target} but ${ko_sibling_rel} exists"
      leaked=1
    fi
  done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\((.*)\)$/\1/')
done < <(find "$ROOT/docs" -name '*.ko.md' -print0)

if [ "$leaked" -ne 0 ]; then
  echo ""
  echo "❌ .ko.md page(s) link to the English page instead of their own Korean mirror."
  exit 1
fi
echo "✅ no language-leak links ($leak_checked .md links checked across every .ko.md page)."
