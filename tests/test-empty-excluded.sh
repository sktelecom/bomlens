#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-empty-excluded.sh: No-Docker check that a source scan whose declared
# dependencies were all left out as development-only (a Python project with a
# uv.lock whose only packages are in dependency groups) is not reported as
# "did not resolve" nor as complete.
#
#   - assess-completeness.sh reads bomlens:sbom-empty-all-excluded and reports
#     only-excluded-dependencies, grade partial, with a fix that names the switch.
#   - the unresolved case (bomlens:sbom-empty-with-manifests) is unchanged.
#   - an SBOM with no components and neither property is still no-components.
#
# Fixture: tests/fixtures/journey/python-uv-lock (pyproject.toml and a uv.lock
# with pytest, iniconfig and colorama reached only from dependency groups).
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is not installed"; exit 0; }

assess() {  # <name> <properties json array>
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"p","version":"1"},"properties":%s},"components":[]}\n' "$2" > "$WORK/$1.json"
    bash "$LIB/assess-completeness.sh" "$WORK/$1.json" "$WORK/$1" >/dev/null 2>&1
}

echo "== fixture =="
[ -f "$ROOT_DIR/tests/fixtures/journey/python-uv-lock/uv.lock" ] && pass "uv.lock fixture present" || fail "uv.lock fixture present"
check "the lock file lists no runtime dependency of the project" \
    "$(awk '/^name = "itsdang"/{f=1} f&&/^dependencies = /{print "has"; exit} /^\[\[package\]\]/&&f&&!/itsdang/{exit}' "$ROOT_DIR/tests/fixtures/journey/python-uv-lock/uv.lock")" ""

echo "== all declared dependencies left out =="
assess excl '[{"name":"bomlens:sbom-empty-all-excluded","value":"pyproject.toml, uv.lock"},{"name":"bomlens:excluded-components","value":"pkg:pypi/pytest@8.4.2"}]'
check "grade is partial" "$(jq -r .grade "$WORK/excl_completeness.json")" "partial"
check "one reason: only-excluded-dependencies" "$(jq -r '[.reasons[].code] | join(",")' "$WORK/excl_completeness.json")" "only-excluded-dependencies"
check "the detail names the manifests" "$(jq -r '.reasons[0].detail' "$WORK/excl_completeness.json")" "pyproject.toml, uv.lock"
case "$(jq -r '.reasons[0].fix.en' "$WORK/excl_completeness.json")" in *BOMLENS_INCLUDE_DEV_DEPENDENCIES=1*) pass "the fix names the switch" ;; *) fail "the fix names the switch" ;; esac
case "$(jq -r '.reasons[0].message.ko' "$WORK/excl_completeness.json")" in *"pyproject.toml, uv.lock"*) pass "the Korean message carries the detail" ;; *) fail "the Korean message carries the detail" ;; esac

echo "== unresolved dependencies stay unreliable =="
assess unres '[{"name":"bomlens:sbom-empty-with-manifests","value":"pyproject.toml, uv.lock"}]'
check "grade is unreliable" "$(jq -r .grade "$WORK/unres_completeness.json")" "unreliable"
check "reason is empty-with-manifests" "$(jq -r '[.reasons[].code] | join(",")' "$WORK/unres_completeness.json")" "empty-with-manifests"

echo "== nothing declared =="
assess none '[]'
check "reason is no-components" "$(jq -r '[.reasons[].code] | join(",")' "$WORK/none_completeness.json")" "no-components"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
