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
    # A comment-only line matching $exit_re (a hand-written explanation, e.g.
    # "exit 1 elsewhere in this script") is not a real exit call, so skip it
    # before checking for a preceding message -- otherwise prose that happens
    # to mention an exit code reads as a silent exit. Only the line's own
    # leading marker counts: "exit 1  # why" still starts with real code, so
    # it stays checked, matching sh's "#" and .bat's "REM " / "::" comments.
    local this_line
    this_line="$(sed -n "${n}p" "$file")"
    if printf '%s' "$this_line" | grep -qE '^[[:space:]]*(#|REM[[:space:]]|::)'; then
      continue
    fi
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
  "Engine memory:MemTotal"
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

# The message keys (M_...) are shared: the same set in both scripts, each defined
# once per language, so a message added to one platform cannot be forgotten on the
# other. Only keys that belong to one platform's mechanics are exempt
# (M_PRESS is the .bat's "press any key" line before its window closes).
echo "2b) Setup-check messages (same keys, both languages)"
PLATFORM_ONLY_KEYS=" M_PRESS "
sh_defs="$(grep -oE '^[[:space:]]+M_[A-Z0-9_]+=' scripts/check-setup.sh | tr -d ' \t=' | sort)"
bat_defs="$(grep -oE '^[[:space:]]*set "M_[A-Z0-9_]+=' scripts/check-setup.bat | sed -E 's/^[[:space:]]*set "//; s/=$//' | sort)"
for name in sh bat; do
  defs_var="${name}_defs"; defs="${!defs_var}"
  dup_ok=1
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    cnt="$(printf '%s\n' "$defs" | grep -cx "$key")"
    [ "$cnt" -eq 2 ] || { note_fail "check-setup.$name defines $key $cnt time(s), expected once per language (2)"; dup_ok=0; }
  done <<EOF2
$(printf '%s\n' "$defs" | sort -u)
EOF2
  [ "$dup_ok" -eq 1 ] && note_ok "check-setup.$name defines every message in both languages"
done
sh_keys="$(printf '%s\n' "$sh_defs" | sort -u)"
bat_keys="$(printf '%s\n' "$bat_defs" | sort -u)"
only_sh=""; only_bat=""
for k in $sh_keys; do
  printf '%s\n' "$bat_keys" | grep -qx "$k" || case "$PLATFORM_ONLY_KEYS" in *" $k "*) ;; *) only_sh="$only_sh $k" ;; esac
done
for k in $bat_keys; do
  printf '%s\n' "$sh_keys" | grep -qx "$k" || case "$PLATFORM_ONLY_KEYS" in *" $k "*) ;; *) only_bat="$only_bat $k" ;; esac
done
if [ -z "$only_sh$only_bat" ]; then
  note_ok "check-setup.sh and check-setup.bat carry the same $(printf '%s\n' "$sh_keys" | grep -c .) messages"
else
  note_fail "message keys differ between check-setup scripts: only in .sh:${only_sh:- (none)}; only in .bat:${only_bat:- (none)}"
fi

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
