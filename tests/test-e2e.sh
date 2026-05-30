#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-e2e.sh — user-perspective end-to-end tests for sbom-tools.
# Exercises the CLI exactly as a user would: SBOM generation, notice, security
# report, byte-stable output, image scanning, the web UI, and helper libraries.
#
# Usage:
#   ./tests/test-e2e.sh
# Env:
#   SBOM_SCANNER_IMAGE   scanner image to test (default: sbom-scanner:test)
#   VERBOSE=true         show scan logs on failure
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$REPO/scripts/scan-sbom.sh"
LIB="$REPO/docker/lib"
EXAMPLES="$REPO/examples"
SCANNER_IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"
VERBOSE="${VERBOSE:-false}"

# Work under the repo (/Users/...) so Docker Desktop file sharing mounts it.
# macOS `mktemp -d` defaults to /var/folders, which Docker does not share.
WORK_ROOT="$SCRIPT_DIR/test-workspace/e2e"
rm -rf "$WORK_ROOT"; mkdir -p "$WORK_ROOT"

PASS=0; FAIL=0; SKIP=0
FAILED_TESTS=()

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); [ -n "${2:-}" ] && echo "        ↳ $2"; }
skip() { echo -e "  ${c_yellow}SKIP${c_reset} $1"; SKIP=$((SKIP+1)); }
section() { echo ""; echo "▶ $1"; }

have_docker=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then have_docker=1; fi
have_image=0
if [ "$have_docker" = 1 ] && docker image inspect "$SCANNER_IMG" >/dev/null 2>&1; then have_image=1; fi

# Run a source scan in an isolated copy of a project. Echoes the work dir.
run_source_scan() {
    local src="$1"; shift
    local work; work="$(mktemp -d "$WORK_ROOT/src.XXXXXX")"
    cp -R "$src/." "$work/" 2>/dev/null
    ( cd "$work" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
        --project "testapp" --version "1.0" "$@" --generate-only ) > "$work/_scan.log" 2>&1
    echo "$work"
}

show_log_if_verbose() { [ "$VERBOSE" = "true" ] && sed 's/^/        /' "$1/_scan.log"; }

echo "=================================================="
echo " sbom-tools E2E Tests"
echo " image: $SCANNER_IMG (present=$have_image, docker=$have_docker)"
echo "=================================================="

# --------------------------------------------------------
# Group 1: CLI contract (no Docker image required)
# --------------------------------------------------------
section "CLI contract"

if bash "$SCAN" --help 2>&1 | grep -q -- "--notice"; then
    pass "--help lists new flags"
else
    fail "--help lists new flags"
fi

if ! bash "$SCAN" --generate-only >/dev/null 2>&1; then
    pass "missing --project/--version exits non-zero"
else
    fail "missing --project/--version exits non-zero" "expected failure"
fi

if bash "$SCAN" --help 2>&1 | grep -q -- "--ui"; then
    pass "--ui documented in help"
else
    fail "--ui documented in help"
fi

# --------------------------------------------------------
# Group 2: helper libraries (host-side, no Docker)
# --------------------------------------------------------
section "Helper libraries (host)"

tmp="$(mktemp -d)"
cat > "$tmp/bom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:rand",
 "metadata":{"timestamp":"2026-01-01T00:00:00Z"},
 "components":[
   {"name":"z","version":"1","purl":"pkg:x/z@1","licenses":[{"license":{"id":"MIT"}}]},
   {"name":"a","version":"2","purl":"pkg:x/a@2","licenses":[{"license":{"id":"Apache-2.0"}}]},
   {"name":"n","version":"3","purl":"pkg:x/n@3"}]}
EOF

cp "$tmp/bom.json" "$tmp/b2.json"
bash "$LIB/normalize-sbom.sh" "$tmp/bom.json" --stable >/dev/null 2>&1
# mutate only non-semantic fields in b2, then normalize
jq '.serialNumber="urn:uuid:other" | .metadata.timestamp="2026-12-31T23:59:59Z"' "$tmp/b2.json" > "$tmp/b2b.json"
bash "$LIB/normalize-sbom.sh" "$tmp/b2b.json" --stable >/dev/null 2>&1
if diff -q "$tmp/bom.json" "$tmp/b2b.json" >/dev/null 2>&1; then
    pass "normalize --stable is byte-reproducible"
else
    fail "normalize --stable is byte-reproducible"
fi

if [ "$(jq 'has("serialNumber")' "$tmp/bom.json")" = "false" ] \
   && [ "$(jq -r '.metadata.timestamp' "$tmp/bom.json")" = "1970-01-01T00:00:00Z" ] \
   && [ "$(jq -r '.components[0].name' "$tmp/bom.json")" = "a" ]; then
    pass "normalize pins timestamp, drops serial, sorts components"
else
    fail "normalize pins timestamp, drops serial, sorts components"
fi

bash "$LIB/generate-notice.sh" "$tmp/bom.json" "$tmp/out" "Demo" >/dev/null 2>&1
if grep -q "Apache-2.0" "$tmp/out_NOTICE.txt" && grep -q "NOASSERTION" "$tmp/out_NOTICE.txt"; then
    pass "notice groups licenses incl. NOASSERTION"
else
    fail "notice groups licenses incl. NOASSERTION"
fi
if grep -q "<h2>MIT</h2>" "$tmp/out_NOTICE.html"; then
    pass "notice html renders license sections"
else
    fail "notice html renders license sections"
fi
rm -rf "$tmp"

# --------------------------------------------------------
# Group 3: full source-scan E2E (requires image)
# --------------------------------------------------------
section "Source scan E2E"

if [ "$have_image" != 1 ]; then
    skip "source scan group (scanner image '$SCANNER_IMG' not available)"
else
    # 3a: nodejs --all -> 6 artifacts, valid SBOM
    nodesrc="$EXAMPLES/nodejs"
    if [ -d "$nodesrc" ]; then
        w="$(run_source_scan "$nodesrc" --all)"
        ok=1
        [ -f "$w/testapp_1.0_bom.json" ] || { ok=0; }
        if [ "$ok" = 1 ] && jq -e '.bomFormat=="CycloneDX"' "$w/testapp_1.0_bom.json" >/dev/null 2>&1; then :; else ok=0; fi
        if [ "$ok" = 1 ]; then pass "nodejs --all: SBOM is valid CycloneDX"; else fail "nodejs --all: SBOM is valid CycloneDX" "$(tail -3 "$w/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w"; fi

        ncomp=$(jq '[.components[]?]|length' "$w/testapp_1.0_bom.json" 2>/dev/null || echo 0)
        if [ "${ncomp:-0}" -gt 0 ]; then pass "nodejs SBOM has components ($ncomp)"; else fail "nodejs SBOM has components" "got $ncomp"; fi

        [ -f "$w/testapp_1.0_NOTICE.txt" ] && [ -f "$w/testapp_1.0_NOTICE.html" ] \
            && pass "nodejs --all: notice files produced" || fail "nodejs --all: notice files produced"
        [ -f "$w/testapp_1.0_security.json" ] && [ -f "$w/testapp_1.0_security.md" ] && [ -f "$w/testapp_1.0_security.html" ] \
            && pass "nodejs --all: security files produced" || fail "nodejs --all: security files produced"

        if [ -f "$w/testapp_1.0_security.json" ] && jq -e '.Results' "$w/testapp_1.0_security.json" >/dev/null 2>&1; then
            pass "security json is valid Trivy output"
        else
            fail "security json is valid Trivy output"
        fi
        rm -rf "$w"
    else
        skip "nodejs example not found"
    fi

    # 3b: python --notice
    pysrc="$EXAMPLES/python"
    if [ -d "$pysrc" ]; then
        w="$(run_source_scan "$pysrc" --notice)"
        if [ -f "$w/testapp_1.0_NOTICE.txt" ] && [ -s "$w/testapp_1.0_NOTICE.txt" ]; then
            pass "python --notice: non-empty notice"
        else
            fail "python --notice: non-empty notice" "$(tail -3 "$w/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w"
        fi
        rm -rf "$w"
    else
        skip "python example not found"
    fi

    # 3c: byte-stable reproducibility across two independent scans
    gosrc="$EXAMPLES/go"
    if [ -d "$gosrc" ]; then
        w1="$(run_source_scan "$gosrc" --byte-stable)"
        w2="$(run_source_scan "$gosrc" --byte-stable)"
        if [ -f "$w1/testapp_1.0_bom.json" ] && [ -f "$w2/testapp_1.0_bom.json" ]; then
            if diff -q "$w1/testapp_1.0_bom.json" "$w2/testapp_1.0_bom.json" >/dev/null 2>&1; then
                pass "go --byte-stable: two scans byte-identical"
            else
                fail "go --byte-stable: two scans byte-identical"
            fi
        else
            fail "go --byte-stable: SBOMs generated" "$(tail -3 "$w1/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w1"
        fi
        rm -rf "$w1" "$w2"
    else
        skip "go example not found"
    fi
fi

# --------------------------------------------------------
# Group 4: image scan E2E (requires image + docker)
# --------------------------------------------------------
section "Image scan E2E"
if [ "$have_image" != 1 ]; then
    skip "image scan (scanner image not available)"
else
    w="$(mktemp -d "$WORK_ROOT/img.XXXXXX")"
    ( cd "$w" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
        --project "alpinetest" --version "3.19" --target "alpine:3.19" --notice --generate-only ) > "$w/_scan.log" 2>&1
    if [ -f "$w/alpinetest_3.19_bom.json" ] && jq -e '.bomFormat' "$w/alpinetest_3.19_bom.json" >/dev/null 2>&1; then
        pass "alpine image scan: valid SBOM"
    else
        fail "alpine image scan: valid SBOM" "$(tail -3 "$w/_scan.log" 2>/dev/null)"; [ "$VERBOSE" = true ] && sed 's/^/        /' "$w/_scan.log"
    fi
    [ -f "$w/alpinetest_3.19_NOTICE.txt" ] && pass "alpine image scan: notice produced" || fail "alpine image scan: notice produced"
    rm -rf "$w"
fi

# --------------------------------------------------------
# Group 5: web UI E2E (requires image + docker)
# --------------------------------------------------------
section "Web UI E2E"
if [ "$have_image" != 1 ]; then
    skip "web UI (scanner image not available)"
else
    port=18080
    cid="$(docker run -d --rm -p "${port}:8080" -e MODE=UI -e UI_PORT=8080 \
        -v /var/run/docker.sock:/var/run/docker.sock "$SCANNER_IMG" 2>/dev/null)"
    if [ -n "$cid" ]; then
        ready=0
        for _ in $(seq 1 15); do
            if curl -fsS "http://localhost:${port}/" >/dev/null 2>&1; then ready=1; break; fi
            sleep 1
        done
        if [ "$ready" = 1 ]; then
            pass "web UI serves index page"
            if curl -fsS "http://localhost:${port}/results" | jq -e 'type=="array"' >/dev/null 2>&1; then
                pass "web UI /results returns JSON array"
            else
                fail "web UI /results returns JSON array"
            fi
            # path traversal guard
            code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${port}/file?name=../../etc/passwd")
            [ "$code" = "404" ] && pass "web UI blocks path traversal" || fail "web UI blocks path traversal" "http=$code"
        else
            fail "web UI serves index page" "server did not become ready"
        fi
        docker stop "$cid" >/dev/null 2>&1
    else
        fail "web UI container starts"
    fi
fi

# --------------------------------------------------------
# Summary
# --------------------------------------------------------
echo ""
echo "=================================================="
echo -e " ${c_green}PASS=$PASS${c_reset}  ${c_red}FAIL=$FAIL${c_reset}  ${c_yellow}SKIP=$SKIP${c_reset}"
if [ "$FAIL" -gt 0 ]; then
    echo " Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do echo "   - $t"; done
fi
echo "=================================================="
[ "$FAIL" -eq 0 ]
