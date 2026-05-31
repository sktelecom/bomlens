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
FW_IMG="${SBOM_FIRMWARE_IMAGE:-sbom-scanner-firmware:test}"
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
have_fw_image=0
if [ "$have_docker" = 1 ] && docker image inspect "$FW_IMG" >/dev/null 2>&1; then have_fw_image=1; fi

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

if bash "$SCAN" --help 2>&1 | grep -q -- "--firmware"; then
    pass "--firmware documented in help"
else
    fail "--firmware documented in help"
fi

# --firmware with no target must fail fast with a clear message (needs docker daemon:
# the guard runs after docker_check in the orchestrator).
if [ "$have_docker" = 1 ]; then
    # Capture first (pipefail would otherwise see the intended non-zero exit as a failure).
    fw_err="$(bash "$SCAN" --project p --version 1 --firmware 2>&1 || true)"
    if printf '%s' "$fw_err" | grep -q -- "--firmware requires"; then
        pass "--firmware without --target errors clearly"
    else
        fail "--firmware without --target errors clearly"
    fi
else
    skip "--firmware without --target (docker daemon unavailable)"
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

# scan-firmware.sh: present + syntactically valid (host-side, no tools needed)
if [ -f "$LIB/scan-firmware.sh" ] && bash -n "$LIB/scan-firmware.sh" 2>/dev/null; then
    pass "scan-firmware.sh present and parses"
else
    fail "scan-firmware.sh present and parses"
fi
# Its component-merge/dedupe is the core jq logic — verify it standalone.
cat > "$tmp/pkg.cdx.json" <<'EOF'
{"components":[{"name":"zlib","version":"1.2.13","purl":"pkg:deb/zlib@1.2.13"},{"name":"busybox","version":"1.36"}]}
EOF
cat > "$tmp/bin.cdx.json" <<'EOF'
{"components":[{"name":"zlib","version":"1.2.13","purl":"pkg:deb/zlib@1.2.13"},{"name":"openssl","version":"3.0.1"}]}
EOF
pkgc=$(jq -c '[.components[]? | select(.name != null)]' "$tmp/pkg.cdx.json")
binc=$(jq -c '[.components[]? | select(.name != null)]' "$tmp/bin.cdx.json")
merged=$(jq -n --argjson a "$pkgc" --argjson b "$binc" '($a + $b) | group_by(.purl // ((.name // "") + "@" + (.version // ""))) | map(.[0]) | length')
if [ "$merged" = "3" ]; then
    pass "firmware merge dedupes by purl (3 unique of 4)"
else
    fail "firmware merge dedupes by purl (3 unique of 4)" "got $merged"
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
# Group 4b: firmware scan E2E (firmware image) + base-image regression
# --------------------------------------------------------
section "Firmware scan E2E"

# Regression: the base (permissive-only) image must NOT carry firmware tools.
if [ "$have_image" = 1 ]; then
    if docker run --rm --entrypoint sh "$SCANNER_IMG" -c 'command -v unblob || command -v cve-bin-tool' >/dev/null 2>&1; then
        fail "base image stays firmware-tool-free" "unblob/cve-bin-tool unexpectedly present"
    else
        pass "base image stays firmware-tool-free (GPL isolated to firmware image)"
    fi
else
    skip "base-image firmware regression (scanner image not available)"
fi

if [ "$have_fw_image" != 1 ]; then
    skip "firmware scan (firmware image '$FW_IMG' not available — build with --build-arg SBOM_FIRMWARE=true)"
else
    w="$(mktemp -d "$WORK_ROOT/fw.XXXXXX")"
    # Minimal rootfs with a dpkg status DB so syft catalogs at least one package.
    mkdir -p "$w/rootfs/var/lib/dpkg" "$w/rootfs/bin" "$w/rootfs/etc"
    cat > "$w/rootfs/var/lib/dpkg/status" <<'EOF'
Package: zlib1g
Status: install ok installed
Architecture: amd64
Version: 1:1.2.13.dfsg-1
Description: compression library - runtime
EOF
    echo "fixture" > "$w/rootfs/bin/busybox"
    echo "NAME=Fixture" > "$w/rootfs/etc/os-release"

    # Pack into a standard squashfs using the firmware image's mksquashfs.
    if docker run --rm -v "$w":/w --entrypoint mksquashfs "$FW_IMG" \
            /w/rootfs /w/fw.squashfs -noappend -no-progress >/dev/null 2>&1 && [ -f "$w/fw.squashfs" ]; then
        pass "firmware fixture: squashfs packed"
        ( cd "$w" && SBOM_FIRMWARE_IMAGE="$FW_IMG" bash "$SCAN" \
            --project "fwtest" --version "1.0" --target fw.squashfs --all --generate-only ) > "$w/_scan.log" 2>&1

        bom="$w/fwtest_1.0_bom.json"
        if [ -f "$bom" ] && jq -e '.bomFormat=="CycloneDX" and .metadata.component.type=="firmware"' "$bom" >/dev/null 2>&1; then
            pass "firmware scan: valid CycloneDX with firmware metadata"
        else
            fail "firmware scan: valid CycloneDX with firmware metadata" "$(tail -5 "$w/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w"
        fi

        ncomp=$(jq '[.components[]?]|length' "$bom" 2>/dev/null || echo 0)
        if [ "${ncomp:-0}" -gt 0 ]; then
            pass "firmware scan: components detected after unpack ($ncomp)"
        else
            fail "firmware scan: components detected after unpack" "got $ncomp (unpack/syft may have found nothing)"
        fi

        { [ -f "$w/fwtest_1.0_NOTICE.txt" ] && [ -f "$w/fwtest_1.0_security.json" ]; } \
            && pass "firmware scan: notice + security artifacts produced" \
            || fail "firmware scan: notice + security artifacts produced"
    else
        fail "firmware fixture: squashfs packed" "mksquashfs unavailable in $FW_IMG"
    fi
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
# Group 6: cosign signing E2E (requires image + docker)
# --------------------------------------------------------
section "Cosign signing E2E"
if [ "$have_image" != 1 ]; then
    skip "cosign signing (scanner image not available)"
else
    keydir="$(mktemp -d "$WORK_ROOT/keys.XXXXXX")"
    docker run --rm -v "$keydir":/keys -w /keys -e COSIGN_PASSWORD="" \
        --entrypoint cosign "$SCANNER_IMG" generate-key-pair >/dev/null 2>&1
    if [ -f "$keydir/cosign.key" ]; then
        pass "cosign keypair generated"
        w="$(mktemp -d "$WORK_ROOT/sign.XXXXXX")"
        cp -R "$EXAMPLES/go/." "$w/" 2>/dev/null
        ( cd "$w" && COSIGN_KEY="$keydir/cosign.key" COSIGN_PASSWORD="" SBOM_SCANNER_IMAGE="$SCANNER_IMG" \
            bash "$SCAN" --project signtest --version 1.0 --sign --generate-only ) > "$w/_scan.log" 2>&1
        if [ -f "$w/signtest_1.0_bom.json.sig" ]; then
            pass "cosign produced detached signature"
            if docker run --rm -v "$w":/w -v "$keydir":/keys -w /w --entrypoint cosign "$SCANNER_IMG" \
                verify-blob --key /keys/cosign.pub --signature signtest_1.0_bom.json.sig \
                --insecure-ignore-tlog signtest_1.0_bom.json >/dev/null 2>&1; then
                pass "cosign verify-blob succeeds"
            else
                fail "cosign verify-blob succeeds"
            fi
        else
            fail "cosign produced detached signature" "$(tail -3 "$w/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w"
        fi
        rm -rf "$w"
    else
        fail "cosign keypair generated"
    fi
    rm -rf "$keydir"
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
