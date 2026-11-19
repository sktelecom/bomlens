#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-swift-detect.sh: No-Docker checks for how a Swift or iOS tree is
# recognised and run.
#
#   - detect_lang names an Xcode project or a Swift package one or two folders
#     down "swift" (it used to say "unknown" and send the scan to the large
#     all-in-one image), but only when no other language was found.
#   - build-prep.sh drops SWIFT_SIGNING_KEY before cdxgen runs (cdxgen's
#     environment audit printed a "Credential Exposure" table for it) and gives
#     the cdxgen run on a Swift tree the resolver time limit.
#
# Fixtures: tests/fixtures/journey/swift-xcodeproj, swift-spm.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/journey"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

# shellcheck source=docker/lib/source-detect.sh
. "$LIB/source-detect.sh"

echo "== detect_lang =="
check "Package.swift and Package.resolved at the root" "$(detect_lang "$FIX/swift-spm")" "swift"
check "an Xcode project one folder down (App/App.xcodeproj)" "$(detect_lang "$FIX/swift-xcodeproj")" "swift"
mkdir -p "$WORK/root-xcode/App.xcodeproj"
check "an Xcode project at the root" "$(detect_lang "$WORK/root-xcode")" "swift"
mkdir -p "$WORK/pods/ios"; : > "$WORK/pods/ios/Podfile"
check "a Podfile in ios/ with nothing else" "$(detect_lang "$WORK/pods")" "swift"
mkdir -p "$WORK/rn/ios"; : > "$WORK/rn/ios/Podfile"; echo '{"name":"rn","dependencies":{"react":"18.0.0"}}' > "$WORK/rn/package.json"
check "a Node.js app with an ios/Podfile stays node" "$(detect_lang "$WORK/rn")" "node"
mkdir -p "$WORK/deep/a/b/c/d/X.xcodeproj"; : > "$WORK/deep/a/b/c/d/X.xcodeproj/project.pbxproj"
check "an Xcode project four folders down is not searched for" "$(detect_lang "$WORK/deep")" "unknown"
mkdir -p "$WORK/empty"
check "an empty folder stays unknown" "$(detect_lang "$WORK/empty")" "unknown"
mkdir -p "$WORK/pods2/Pods/Foo"; : > "$WORK/pods2/Pods/Foo/Package.swift"
check "a vendored Pods/ folder does not count" "$(detect_lang "$WORK/pods2")" "unknown"

echo "== build-prep.sh =="
PREP="$LIB/build-prep.sh"
check "SWIFT_SIGNING_KEY is unset before anything runs" "$(grep -c '^unset SWIFT_SIGNING_KEY$' "$PREP")" "1"
check "the cdxgen run goes through run_cdxgen (3 images)" "$(grep -c '^    run_cdxgen ' "$PREP")" "3"
check "a Swift tree uses the resolver time limit" "$(grep -c '^        run_supervised_timeout "\$PREP_TIMEOUT_DEFAULT" "\$@"$' "$PREP")" "1"
check "git is told not to prompt on a Swift tree" "$(grep -c 'GIT_TERMINAL_PROMPT="\${GIT_TERMINAL_PROMPT:-0}"' "$PREP")" "1"
if sh -n "$PREP" 2>/dev/null; then pass "build-prep.sh is valid sh"; else fail "build-prep.sh is valid sh"; fi

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
