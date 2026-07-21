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
# check-ux-heuristics.sh — machine-checkable proxies for a friendly first run.
# These do not judge whether a message reads well (that needs a human); they
# catch the failure modes a beginner actually hits:
#   1. Silent exits   — every non-zero exit prints a reason the user can act on.
#   2. Setup parity   — check-setup.sh and check-setup.bat probe the same things,
#                       so Windows and macOS/Linux users get the same guidance.
#   3. Flag docs      — every flag the parser accepts is listed in --help, so no
#                       behavior is hidden from `scan-sbom.sh --help`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

note_fail() { echo "  ❌ $1"; fail=1; }
note_ok()   { echo "  ✓ $1"; }

# ----------------------------------------------------------------------------
# 1) No silent exits. For each non-zero exit, the same line or one of the few
#    preceding lines must print something (echo / printf / a *_error helper, or
#    `call :say` — the .bat message-table printer, which is how the Windows
#    launchers emit every translated line).
#    A bare `exit 1` leaves the user staring at a dead terminal.
# ----------------------------------------------------------------------------
echo "1) No silent error exits (scan-sbom.sh + Windows wrappers)"

check_silent_exits() {
  local file="$1" exit_re="$2"
  [ -f "$file" ] || { note_fail "missing $file"; return; }
  local n bad=0
  while IFS= read -r n; do
    # Look at the offending line plus the 3 lines above it for a user message.
    local ctx
    ctx="$(sed -n "$((n>3 ? n-3 : 1)),${n}p" "$file")"
    if ! printf '%s' "$ctx" | grep -qiE 'echo|printf|print_error|status |>&2|call :say'; then
      note_fail "$file:$n — exit without a user-facing message"
      bad=1
    fi
  done < <(grep -nE "$exit_re" "$file" | cut -d: -f1)
  [ "$bad" -eq 0 ] && note_ok "$file — every error exit explains itself"
}

check_silent_exits "scripts/scan-sbom.sh" 'exit[[:space:]]+1'
check_silent_exits "scripts/scan-sbom.bat" 'exit /b 1'
check_silent_exits "scripts/sbom-ui.bat" 'exit /b 1'

# ----------------------------------------------------------------------------
# 2) Setup-check parity. Both check-setup scripts must probe the same four
#    things, or one platform's users get a worse pre-flight.
# ----------------------------------------------------------------------------
echo "2) Setup-check parity (check-setup.sh ↔ check-setup.bat)"
declare -a CONCEPTS=(
  "Docker install:[Dd]ocker"
  "Docker engine:엔진|engine|running|info"
  "Scanner image:이미지|image"
  "UI port:포트|port|UI_PORT"
)
for f in scripts/check-setup.sh scripts/check-setup.bat; do
  [ -f "$f" ] || { note_fail "missing $f"; continue; }
  for c in "${CONCEPTS[@]}"; do
    label="${c%%:*}"; pat="${c#*:}"
    if grep -qiE "$pat" "$f"; then
      note_ok "$f probes ${label}"
    else
      note_fail "$f does not probe ${label}"
    fi
  done
done

# ----------------------------------------------------------------------------
# 3) Flag docs. Every option the argument parser handles must appear in the
#    --help body, so `--help` is a complete contract.
# ----------------------------------------------------------------------------
echo "3) Every parsed flag appears in --help (scan-sbom.sh)"
help_text="$(bash scripts/scan-sbom.sh --help 2>/dev/null || true)"
# Parser cases look like:  --foo)  or  --foo|--bar)  at the start of a line.
# Anchoring to the case branch avoids matching git options like --single-branch
# that appear mid-command elsewhere in the script.
parsed_flags="$(grep -oE '^[[:space:]]*--[a-z][a-z-]*(\|--[a-z][a-z-]*)*\)' scripts/scan-sbom.sh \
  | grep -oE -- '--[a-z][a-z-]+' | sort -u)"
undocumented=""
while IFS= read -r flag; do
  [ -n "$flag" ] || continue
  printf '%s' "$help_text" | grep -qE -- "(^|[^a-z])$flag([^a-z]|$)" || undocumented="$undocumented $flag"
done <<EOF
$parsed_flags
EOF
if [ -n "$undocumented" ]; then
  note_fail "parsed but absent from --help:$undocumented"
else
  note_ok "all parsed flags are listed in --help"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "❌ UX heuristics failed — see the items above."
  exit 1
fi
echo "✅ UX heuristics passed (no silent exits, setup parity, help is complete)."
