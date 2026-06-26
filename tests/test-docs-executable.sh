#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-docs-executable.sh — run the commands the onboarding docs print, so a
# stale flag, image tag, or command in a getting-started page fails CI instead
# of the user.
#
# A doc author marks a runnable block with an HTML comment on the line above it:
#
#     <!-- ci:run -->
#     ```bash
#     ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --all --generate-only
#     ```
#
# For each marked scan-sbom command this harness:
#   - runs it against a known example project (so "the current directory" is a
#     real, scannable tree) using the repo's actual scan-sbom.sh, and
#   - asserts the artifacts the docs promise (e.g. MyApp_1.0.0_bom.json) appear.
# Only the script path and scan target are sandboxed; the flags come verbatim
# from the doc. Uploading commands are refused — a marked block must be
# --generate-only so CI never pushes anywhere.
#
# Usage:  ./tests/test-docs-executable.sh
# Env:    SBOM_SCANNER_IMAGE  scanner image (default: sbom-scanner:test)
#         VERBOSE=true        show scan logs on failure
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$REPO/scripts/scan-sbom.sh"
SANDBOX_SRC="$REPO/examples/nodejs"
SCANNER_IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"
VERBOSE="${VERBOSE:-false}"

# Onboarding pages whose ci:run blocks we execute.
DOCS=(
  "$REPO/docs/start/first-scan.md"
)

WORK_ROOT="$SCRIPT_DIR/test-workspace/docs-e2e"
rm -rf "$WORK_ROOT"; mkdir -p "$WORK_ROOT"

PASS=0; FAIL=0; SKIP=0
FAILED=()
c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); [ -n "${2:-}" ] && echo "        ↳ $2"; }
skip() { echo -e "  ${c_yellow}SKIP${c_reset} $1"; SKIP=$((SKIP+1)); }

have_docker=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then have_docker=1; fi
have_image=0
if [ "$have_docker" = 1 ] && docker image inspect "$SCANNER_IMG" >/dev/null 2>&1; then have_image=1; fi

echo "=================================================="
echo " sbom-tools executable-docs tests"
echo " image: $SCANNER_IMG (present=$have_image, docker=$have_docker)"
echo "=================================================="

# Pull the scan-sbom command lines out of every <!-- ci:run --> fenced block.
marked_commands() {
  local doc="$1"
  awk '
    /<!-- ci:run -->/ { armed=1; next }
    armed && /^```/    { infence=1; armed=0; next }
    infence && /^```/  { infence=0; next }
    infence            { print }
  ' "$doc" | grep -E 'scan-sbom\.(sh|bat)' | grep -vE '^[[:space:]]*#'
}

# proj/ver from a command string.
arg_value() { printf '%s\n' "$1" | sed -nE "s/.*$2[[:space:]]+\"?([^\" ]+)\"?.*/\1/p"; }

run_doc_command() {
  local doc="$1" cmd="$2"
  local label; label="$(basename "$doc"): $(printf '%s' "$cmd" | sed 's/^[[:space:]]*//' | cut -c1-70)"

  # Windows wrapper lines are exercised by test-windows.sh, not here.
  case "$cmd" in *scan-sbom.bat*) skip "$label (Windows .bat — see test-windows.sh)"; return ;; esac

  # Safety: a marked block must not upload.
  case "$cmd" in
    *--generate-only*) : ;;
    *) fail "$label" "marked command is missing --generate-only (would upload from CI)"; return ;;
  esac

  if [ "$have_image" != 1 ]; then skip "$label (scanner image unavailable)"; return; fi

  local proj ver; proj="$(arg_value "$cmd" --project)"; ver="$(arg_value "$cmd" --version)"
  if [ -z "$proj" ] || [ -z "$ver" ]; then fail "$label" "could not parse --project/--version"; return; fi

  # Sandbox: a real example project stands in for "the current directory".
  local work; work="$(mktemp -d "$WORK_ROOT/run.XXXXXX")"
  cp -R "$SANDBOX_SRC/." "$work/" 2>/dev/null

  # Run the doc's flags verbatim; only the script path is rewritten to the repo.
  local normalized; normalized="$(printf '%s' "$cmd" | sed -E 's#(\./)?scripts/scan-sbom\.sh#"'"$SCAN"'"#')"
  ( cd "$work" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" eval "$normalized" ) >"$work/_run.log" 2>&1
  local rc=$?

  if [ "$rc" -ne 0 ]; then
    fail "$label" "exit $rc"
    [ "$VERBOSE" = "true" ] && sed 's/^/        /' "$work/_run.log"
    return
  fi

  # Assert the artifacts the docs promise for these flags.
  local ok=1
  [ -f "$work/${proj}_${ver}_bom.json" ] || { ok=0; fail "$label" "missing ${proj}_${ver}_bom.json"; }
  case "$cmd" in *--all*|*--notice*) [ -f "$work/${proj}_${ver}_NOTICE.txt" ] || { ok=0; fail "$label" "missing NOTICE.txt"; }; esac
  case "$cmd" in *--all*|*--security*) [ -f "$work/${proj}_${ver}_security.json" ] || { ok=0; fail "$label" "missing security.json"; }; esac
  [ "$ok" = 1 ] && pass "$label"
}

found=0
for doc in "${DOCS[@]}"; do
  [ -f "$doc" ] || { fail "doc missing: $doc"; continue; }
  while IFS= read -r cmd; do
    [ -n "$cmd" ] || continue
    found=$((found+1))
    run_doc_command "$doc" "$cmd"
  done < <(marked_commands "$doc")
done

[ "$found" -eq 0 ] && fail "no <!-- ci:run --> commands found" "expected at least one marked block in the onboarding docs"

echo ""
echo "--------------------------------------------------"
echo -e " PASS=$PASS  ${c_red}FAIL=$FAIL${c_reset}  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] || { printf '   - %s\n' "${FAILED[@]}"; exit 1; }
exit 0
