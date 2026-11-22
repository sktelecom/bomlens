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
# check-doc-coverage.sh — guard against documenting a new input form in some
# pages but not others.
#
# The authoritative list of scan modes lives in docker/entrypoint.sh (the
# "expected .../..." line). This script reads it and checks that every
# user-facing mode is (1) registered in the coverage manifest below and
# (2) mentioned in each page that should cover it. Adding a mode to the code
# but forgetting a page therefore fails CI. It also caps the length of the
# pages a first-time reader opens (LENGTH_CAPS below).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENTRYPOINT="$ROOT/docker/entrypoint.sh"
fail=0

doc_path() {
  case "$1" in
    by-input)          echo "docs/guides/by-input.md" ;;
    ui)                echo "docs/reference/ui.md" ;;
    cli)               echo "docs/reference/cli.md" ;;
    architecture)      echo "docs/concepts/architecture.md" ;;
    pipeline-by-input) echo "docs/concepts/pipeline-by-input.md" ;;
    readme)            echo "README.md" ;;
    *)                 echo "" ;;
  esac
}

# Korean mirror of doc_path(). README has none (no README.ko.md); every other
# key's .md has a same-named .ko.md sibling (the suffix
# convention the docs site reads), so the ko path is derived rather than duplicated here.
doc_path_ko() {
  [ "$1" = "readme" ] && { echo ""; return; }
  en="$(doc_path "$1")"
  [ -n "$en" ] && echo "${en%.md}.ko.md"
}

# Modes that are internal plumbing, not a user-facing input form. DIFF joins
# MERGE here for the same reason: it is reached by a flag operating on
# already-generated files (--diff), not a --target input form the by-input /
# architecture / pipeline-by-input pages walk through.
INTERNAL="MERGE POSTPROCESS UI DIFF"

# Coverage manifest — one line per user-facing mode:
#   MODE :: en pattern :: ko pattern :: comma-separated docs that must mention it
# When you add a mode to docker/entrypoint.sh, add a line here too.
#
# The ko pattern is NOT the en pattern reused: an English phrase like "docker
# image" or "binary" is translated away in prose ("Docker 이미지", "바이너리"),
# so checking for the literal English pattern in a .ko.md file finds nothing
# and the check would always fail. Each ko pattern below was chosen by reading
# what the Korean docs actually say for that mode; a bare CLI flag (--git,
# --firmware, ...) and a few loanwords/proper nouns (rootfs, ANALYZE, Figshare)
# survive translation unchanged and anchor both patterns.
COVERAGE="
SOURCE :: --git|GitHub URL|source folder :: --git|GitHub URL :: by-input,ui,cli,architecture,readme
IMAGE :: docker image|docker\.sock :: Docker 이미지|docker\.sock :: ui,cli,architecture
BINARY :: binary :: 바이너리 :: cli,architecture
ROOTFS :: rootfs|directory path :: rootfs|디렉터리 경로 :: cli,architecture
FIRMWARE :: --firmware|firmware :: --firmware|펌웨어 :: by-input,ui,cli,architecture,readme,pipeline-by-input
ANALYZE :: --analyze|ANALYZE :: --analyze|ANALYZE :: by-input,ui,cli,architecture,readme,pipeline-by-input
AIBOM :: --model|AI model :: --model|AI 모델 :: by-input,ui,cli,architecture,readme,pipeline-by-input
MODELFILE :: --model-file|model file :: --model-file|모델 파일 :: by-input,ui,cli,architecture,readme,pipeline-by-input
DATASET :: Figshare|figshare :: Figshare|figshare :: by-input,ui,cli,architecture,readme,pipeline-by-input
AIDECLARE :: --ai-declare|declaration :: --ai-declare|직접 입력 :: by-input,ui,cli,architecture,readme,pipeline-by-input
"

# 1) Pull the authoritative mode list from entrypoint.sh.
modes=$(grep -oE 'expected [A-Z/]+' "$ENTRYPOINT" | head -1 | sed 's/expected //; s#/# #g')
[ -n "$modes" ] || { echo "ERROR: could not read the mode list from $ENTRYPOINT"; exit 2; }

manifest_modes=$(printf '%s\n' "$COVERAGE" | awk -F ' :: ' 'NF>1 {print $1}')

# 2) Every user-facing mode must be registered in the manifest.
for m in $modes; do
  case " $INTERNAL " in *" $m "*) continue ;; esac
  if ! printf '%s\n' "$manifest_modes" | grep -qx "$m"; then
    echo "FAIL: mode '$m' is in entrypoint.sh but not in the coverage manifest."
    echo "      Add a line for it in scripts/check-doc-coverage.sh (pattern + docs)."
    fail=1
  fi
done

# 3) Each manifest pattern must appear in each listed doc, English and (where
#    a Korean mirror exists) Korean.
while IFS= read -r line; do
  [ -z "$line" ] && continue
  mode=$(printf '%s' "$line" | awk -F ' :: ' '{print $1}')
  pat=$(printf '%s' "$line" | awk -F ' :: ' '{print $2}')
  pat_ko=$(printf '%s' "$line" | awk -F ' :: ' '{print $3}')
  docs=$(printf '%s' "$line" | awk -F ' :: ' '{print $4}')
  oldIFS="$IFS"; IFS=','
  for d in $docs; do
    rel="$(doc_path "$d")"
    f="$ROOT/$rel"
    if [ ! -f "$f" ]; then echo "FAIL: doc key '$d' maps to a missing file ($rel)"; fail=1; continue; fi
    if ! grep -qiE -e "$pat" "$f"; then
      echo "FAIL: mode '$mode' (pattern: $pat) is missing in $rel"
      fail=1
    fi

    rel_ko="$(doc_path_ko "$d")"
    if [ -n "$rel_ko" ]; then
      f_ko="$ROOT/$rel_ko"
      if [ ! -f "$f_ko" ]; then echo "FAIL: doc key '$d' maps to a missing Korean mirror ($rel_ko)"; fail=1; continue; fi
      if ! grep -qiE -e "$pat_ko" "$f_ko"; then
        echo "FAIL: mode '$mode' (pattern: $pat_ko) is missing in $rel_ko"
        fail=1
      fi
    fi
  done
  IFS="$oldIFS"
done < <(printf '%s\n' "$COVERAGE")

# 4) Length caps for the pages a first-time reader opens. A page may only grow
#    past its cap by raising the number here, so the growth shows in review.
#    path :: max lines :: max words (0 = no word cap)
LENGTH_CAPS="
README.md :: 60 :: 700
docs/start/first-scan.md :: 170 :: 0
docs/start/first-scan.ko.md :: 172 :: 0
docs/start/no-cli.md :: 199 :: 0
docs/start/no-cli.ko.md :: 262 :: 0
docs/guides/supplier-sbom.md :: 246 :: 0
docs/guides/supplier-sbom.ko.md :: 248 :: 0
docs/guides/ai-model.md :: 464 :: 0
docs/guides/ai-model.ko.md :: 464 :: 0
docs/reference/ui.md :: 246 :: 0
docs/reference/ui.ko.md :: 246 :: 0
"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  rel=$(printf '%s' "$line" | awk -F ' :: ' '{print $1}')
  max_lines=$(printf '%s' "$line" | awk -F ' :: ' '{print $2}')
  max_words=$(printf '%s' "$line" | awk -F ' :: ' '{print $3}')
  f="$ROOT/$rel"
  if [ ! -f "$f" ]; then echo "FAIL: length cap names a missing file ($rel)"; fail=1; continue; fi
  lines=$(wc -l < "$f" | tr -d ' ')
  if [ "$lines" -gt "$max_lines" ]; then
    echo "FAIL: $rel has $lines lines, over its cap of $max_lines (scripts/check-doc-coverage.sh)"
    fail=1
  fi
  if [ "$max_words" -gt 0 ]; then
    words=$(wc -w < "$f" | tr -d ' ')
    if [ "$words" -gt "$max_words" ]; then
      echo "FAIL: $rel has $words words, over its cap of $max_words (scripts/check-doc-coverage.sh)"
      fail=1
    fi
  fi
done < <(printf '%s\n' "$LENGTH_CAPS")

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Documentation coverage check failed: a scan mode is missing from a page, or a page is over its length cap."
  exit 1
fi
echo "OK: every user-facing input form is documented across the key pages, and no capped page is over its length."
