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
# check-doc-coverage.sh — guard against documenting a new input form in some
# pages but not others.
#
# The authoritative list of scan modes lives in docker/entrypoint.sh (the
# "expected .../..." line). This script reads it and checks that every
# user-facing mode is (1) registered in the coverage manifest below and
# (2) mentioned in each page that should cover it. Adding a mode to the code
# but forgetting a page therefore fails CI.

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

# Modes that are internal plumbing, not a user-facing input form.
INTERNAL="MERGE POSTPROCESS UI"

# Coverage manifest — one line per user-facing mode:
#   MODE :: grep -iE pattern :: comma-separated docs that must mention it
# When you add a mode to docker/entrypoint.sh, add a line here too.
COVERAGE="
SOURCE :: --git|GitHub URL|source folder :: by-input,ui,cli,architecture,readme
IMAGE :: docker image|docker\.sock :: ui,cli,architecture
BINARY :: binary :: cli,architecture
ROOTFS :: rootfs|directory path :: cli,architecture
FIRMWARE :: --firmware|firmware :: by-input,ui,cli,architecture,readme,pipeline-by-input
ANALYZE :: --analyze|ANALYZE :: by-input,ui,cli,architecture,readme,pipeline-by-input
AIBOM :: --model|AI model :: by-input,ui,cli,architecture,readme,pipeline-by-input
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

# 3) Each manifest pattern must appear in each listed doc.
while IFS= read -r line; do
  [ -z "$line" ] && continue
  mode=$(printf '%s' "$line" | awk -F ' :: ' '{print $1}')
  pat=$(printf '%s' "$line" | awk -F ' :: ' '{print $2}')
  docs=$(printf '%s' "$line" | awk -F ' :: ' '{print $3}')
  oldIFS="$IFS"; IFS=','
  for d in $docs; do
    rel="$(doc_path "$d")"
    f="$ROOT/$rel"
    if [ ! -f "$f" ]; then echo "FAIL: doc key '$d' maps to a missing file ($rel)"; fail=1; continue; fi
    if ! grep -qiE -e "$pat" "$f"; then
      echo "FAIL: mode '$mode' (pattern: $pat) is missing in $rel"
      fail=1
    fi
  done
  IFS="$oldIFS"
done < <(printf '%s\n' "$COVERAGE")

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Documentation coverage check failed — a scan mode is missing from one or more pages."
  exit 1
fi
echo "OK: every user-facing input form is documented across the key pages."
