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

if bash "$SCAN" --help 2>&1 | grep -q -- "--analyze"; then
    pass "--analyze documented in help"
else
    fail "--analyze documented in help"
fi

if bash "$SCAN" --help 2>&1 | grep -q -- "--git"; then
    pass "--git documented in help"
else
    fail "--git documented in help"
fi

if bash "$SCAN" --help 2>&1 | grep -q -- "--no-report"; then
    pass "--no-report documented in help"
else
    fail "--no-report documented in help"
fi

# --git + --target are mutually exclusive (validated after docker_check).
if [ "$have_docker" = 1 ]; then
    ge_err="$(bash "$SCAN" --project p --version 1 --git https://github.com/x/y --target z 2>&1 || true)"
    if printf '%s' "$ge_err" | grep -q "mutually exclusive"; then
        pass "--git + --target rejected (mutually exclusive)"
    else
        fail "--git + --target rejected (mutually exclusive)" "$ge_err"
    fi
else
    skip "--git/--target exclusivity (docker daemon unavailable)"
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
pkgc=$(jq -c '[.components[]? | select((.name // "") != "")]' "$tmp/pkg.cdx.json")
binc=$(jq -c '[.components[]? | select((.name // "") != "")]' "$tmp/bin.cdx.json")
merged=$(jq -n --argjson a "$pkgc" --argjson b "$binc" '($a + $b) | group_by(.purl // ((.name // "") + "@" + (.version // ""))) | map(.[0]) | length')
if [ "$merged" = "3" ]; then
    pass "firmware merge dedupes by purl (3 unique of 4)"
else
    fail "firmware merge dedupes by purl (3 unique of 4)" "got $merged"
fi
rm -rf "$tmp"

# --------------------------------------------------------
# Group 2b: supplier SBOM analysis libraries (host-side, no Docker)
# Exercises validate-sbom.sh / convert-to-cdx.sh / generate-risk-report.sh
# against tests/fixtures/, matching the design's host-verification plan.
# --------------------------------------------------------
section "Supplier SBOM analysis (host)"

FIX="$REPO/tests/fixtures"
atmp="$(mktemp -d)"

# Good CycloneDX -> pass
bash "$LIB/validate-sbom.sh" "$FIX/good-cyclonedx.json" "$atmp/gc" "demo" >/dev/null 2>&1
if [ "$(jq -r '.result' "$atmp/gc_conformance.json" 2>/dev/null)" = "pass" ]; then
    pass "validate: good CycloneDX -> pass"
else
    fail "validate: good CycloneDX -> pass" "$(jq -c '[.checks[]|select(.required and .status==\"fail\")|.id]' "$atmp/gc_conformance.json" 2>/dev/null)"
fi

# Good SPDX -> pass + conversion yields components + licenses
bash "$LIB/validate-sbom.sh" "$FIX/good-spdx.json" "$atmp/gs" "demo" >/dev/null 2>&1
[ "$(jq -r '.result' "$atmp/gs_conformance.json" 2>/dev/null)" = "pass" ] \
    && pass "validate: good SPDX -> pass" || fail "validate: good SPDX -> pass"
bash "$LIB/convert-to-cdx.sh" "$FIX/good-spdx.json" "$atmp/gs_bom.json" >/dev/null 2>&1
ncdx=$(jq '[.components[]?]|length' "$atmp/gs_bom.json" 2>/dev/null || echo 0)
if jq -e '.bomFormat=="CycloneDX"' "$atmp/gs_bom.json" >/dev/null 2>&1 && [ "${ncdx:-0}" -gt 0 ]; then
    pass "convert: SPDX -> CycloneDX with components ($ncdx)"
else
    fail "convert: SPDX -> CycloneDX with components" "got $ncdx"
fi
if [ "$(jq -r '[.components[].licenses[]?.license.id]|length' "$atmp/gs_bom.json" 2>/dev/null || echo 0)" -gt 0 ]; then
    pass "convert: SPDX licenses preserved"
else
    fail "convert: SPDX licenses preserved"
fi

# Defective SBOMs -> fail with the specific violated check + non-empty missing list where applicable
check_bad() {
    local fixture="$1" expect_id="$2" label="$3"
    bash "$LIB/validate-sbom.sh" "$FIX/$fixture" "$atmp/b" "demo" >/dev/null 2>&1
    local res fails
    res=$(jq -r '.result' "$atmp/b_conformance.json" 2>/dev/null)
    fails=$(jq -rc '[.checks[]|select(.required and .status=="fail")|.id]' "$atmp/b_conformance.json" 2>/dev/null)
    if [ "$res" = "fail" ] && printf '%s' "$fails" | grep -q "\"$expect_id\""; then
        pass "validate: $label -> fail ($expect_id)"
    else
        fail "validate: $label -> fail ($expect_id)" "result=$res fails=$fails"
    fi
}
check_bad bad-generic-cyclonedx.json no-generic  "pkg:generic"
check_bad bad-nopurl-cyclonedx.json  purl        "missing PURL"
check_bad bad-notools-cyclonedx.json tools       "no tools"
check_bad bad-nodeps-cyclonedx.json  transitive  "no dependencies"

# Missing list populated for the no-PURL case
bash "$LIB/validate-sbom.sh" "$FIX/bad-nopurl-cyclonedx.json" "$atmp/mp" "demo" >/dev/null 2>&1
if jq -e '.checks[]|select(.id=="purl")|.missing|index("mysterylib")' "$atmp/mp_conformance.json" >/dev/null 2>&1; then
    pass "validate: missing-PURL report lists the offending component"
else
    fail "validate: missing-PURL report lists the offending component"
fi

# Risk report: re-aggregate a fail-conformance + synthetic Trivy findings
bash "$LIB/validate-sbom.sh" "$FIX/bad-generic-cyclonedx.json" "$atmp/rr" "demo" >/dev/null 2>&1
cat > "$atmp/rr_security.json" <<'EOF'
{"Results":[{"Vulnerabilities":[
 {"VulnerabilityID":"CVE-2024-0001","PkgName":"express","InstalledVersion":"4.18.2","Severity":"CRITICAL","FixedVersion":"4.19.0"},
 {"VulnerabilityID":"CVE-2024-0002","PkgName":"lodash","InstalledVersion":"4.17.21","Severity":"HIGH","FixedVersion":""}
]}]}
EOF
printf 'License: MIT\n' > "$atmp/rr_NOTICE.txt"
bash "$LIB/generate-risk-report.sh" "$atmp/rr" "demo" >/dev/null 2>&1
if grep -q "7일" "$atmp/rr_risk-report.md" && grep -q "30일" "$atmp/rr_risk-report.md"; then
    pass "risk report: Critical-7d / High-30d deadlines present (md)"
else
    fail "risk report: Critical-7d / High-30d deadlines present (md)"
fi
if grep -q "7일" "$atmp/rr_risk-report.html" && grep -q "30일" "$atmp/rr_risk-report.html"; then
    pass "risk report: deadlines present (html)"
else
    fail "risk report: deadlines present (html)"
fi
if grep -qE "Critical \| High" "$atmp/rr_risk-report.md" && grep -q "CVE-2024-0001" "$atmp/rr_risk-report.md"; then
    pass "risk report: severity table + CVE rows present"
else
    fail "risk report: severity table + CVE rows present"
fi
if grep -q "반려" "$atmp/rr_risk-report.md"; then
    pass "risk report: surfaces conformance rejection reason"
else
    fail "risk report: surfaces conformance rejection reason"
fi
rm -rf "$atmp"

# Self-generated risk report (no conformance artifact) — the all-modes default.
# Without a *_conformance.json the report must drop the 포맷 검증 section and
# retitle to 오픈소스위험분석보고서 with sections renumbered from 1.
stmp="$(mktemp -d)"
cat > "$stmp/self_security.json" <<'EOF'
{"Results":[{"Vulnerabilities":[
 {"VulnerabilityID":"CVE-2025-0001","PkgName":"openssl","InstalledVersion":"3.0.0","Severity":"CRITICAL","FixedVersion":"3.0.1"}
]}]}
EOF
printf 'License: MIT\nLicense: Apache-2.0\n' > "$stmp/self_NOTICE.txt"
bash "$LIB/generate-risk-report.sh" "$stmp/self" "SelfApp" >/dev/null 2>&1
if grep -q "오픈소스위험분석보고서" "$stmp/self_risk-report.md" \
   && ! grep -q "포맷 검증" "$stmp/self_risk-report.md"; then
    pass "risk report (self): titled 오픈소스위험분석보고서, no 포맷 검증 section"
else
    fail "risk report (self): titled 오픈소스위험분석보고서, no 포맷 검증 section"
fi
if grep -q "## 1. 취약점" "$stmp/self_risk-report.md" \
   && grep -q "7일" "$stmp/self_risk-report.md" && grep -q "CVE-2025-0001" "$stmp/self_risk-report.md"; then
    pass "risk report (self): renumbered from 1, vuln table present"
else
    fail "risk report (self): renumbered from 1, vuln table present"
fi
if grep -q "<h1>오픈소스위험분석보고서</h1>" "$stmp/self_risk-report.html"; then
    pass "risk report (self): html titled 오픈소스위험분석보고서"
else
    fail "risk report (self): html titled 오픈소스위험분석보고서"
fi
rm -rf "$stmp"

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
        # Risk report is now generated in SOURCE mode too (not only ANALYZE).
        if [ -f "$w/testapp_1.0_risk-report.md" ] && [ -f "$w/testapp_1.0_risk-report.html" ] \
           && grep -q "오픈소스위험분석보고서" "$w/testapp_1.0_risk-report.md"; then
            pass "nodejs SOURCE: 오픈소스위험분석보고서 generated (all-modes default)"
        else
            fail "nodejs SOURCE: 오픈소스위험분석보고서 generated (all-modes default)"
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
# Group 3b: source ingestion E2E — ZIP archive + offline git clone
# --------------------------------------------------------
section "Source ingestion E2E (zip + git)"
if [ "$have_image" != 1 ]; then
    skip "ingestion scan (scanner image not available)"
else
    # ZIP: archive an example, then scan the .zip (auto-extract -> SOURCE).
    if command -v zip >/dev/null 2>&1 && [ -d "$EXAMPLES/nodejs" ]; then
        z="$(mktemp -d "$WORK_ROOT/zip.XXXXXX")"
        ( cd "$EXAMPLES" && zip -qr "$z/app.zip" nodejs )
        ( cd "$z" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
            --project ziptest --version 1.0 --target app.zip --all --generate-only ) > "$z/_scan.log" 2>&1
        if [ -f "$z/ziptest_1.0_bom.json" ] && jq -e '.bomFormat=="CycloneDX"' "$z/ziptest_1.0_bom.json" >/dev/null 2>&1; then
            pass "zip ingestion: extracted + scanned to valid SBOM"
        else
            fail "zip ingestion: extracted + scanned to valid SBOM" "$(tail -3 "$z/_scan.log" 2>/dev/null)"; show_log_if_verbose "$z"
        fi
        if [ -f "$z/ziptest_1.0_risk-report.md" ]; then
            pass "zip ingestion: risk-report produced"
        else
            fail "zip ingestion: risk-report produced"
        fi
        # the temp extraction dir must be cleaned up (only artifacts remain)
        if ! ls -d "$z"/.sbom-arc.* >/dev/null 2>&1; then
            pass "zip ingestion: temp extraction dir cleaned up"
        else
            fail "zip ingestion: temp extraction dir cleaned up"
        fi
        rm -rf "$z"
    else
        skip "zip ingestion (zip command or nodejs example unavailable)"
    fi

    # GIT: build a local bare repo (offline, no network) and clone via file://.
    if command -v git >/dev/null 2>&1 && [ -d "$EXAMPLES/nodejs" ]; then
        g="$(mktemp -d "$WORK_ROOT/git.XXXXXX")"
        ( cd "$g" && git init -q proj && cp -R "$EXAMPLES/nodejs/." proj/ \
          && cd proj && git config user.email t@t && git config user.name t \
          && git add -A && git commit -qm init )
        ( cd "$g" && git clone -q --bare proj fixture.git )
        ( cd "$g" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
            --project gittest --version 1.0 --git "file://$g/fixture.git" --all --generate-only ) > "$g/_scan.log" 2>&1
        if [ -f "$g/gittest_1.0_bom.json" ] && jq -e '.bomFormat=="CycloneDX"' "$g/gittest_1.0_bom.json" >/dev/null 2>&1; then
            pass "git ingestion: cloned + scanned to valid SBOM"
        else
            fail "git ingestion: cloned + scanned to valid SBOM" "$(tail -3 "$g/_scan.log" 2>/dev/null)"; show_log_if_verbose "$g"
        fi
        if [ -f "$g/gittest_1.0_risk-report.md" ]; then
            pass "git ingestion: risk-report produced"
        else
            fail "git ingestion: risk-report produced"
        fi
        rm -rf "$g"
    else
        skip "git ingestion (git command or nodejs example unavailable)"
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
# Group 4b2: vendored-OSS identification (SCANOSS). Network + opt-in image, so
# it is gated behind SCANOSS_E2E=1 and never part of the default/CI run (OSSKB
# is rate-limited and identification-only). The deterministic half (the
# off-by-default suggestion) runs whenever the image is available.
# --------------------------------------------------------
section "Vendored-OSS identification E2E"

have_scanoss=0
if [ "$have_image" = 1 ] && \
   docker run --rm --entrypoint sh "$SCANNER_IMG" -c 'command -v scanoss-py' >/dev/null 2>&1; then
    have_scanoss=1
fi

if [ "$have_image" != 1 ]; then
    skip "vendored-OSS identification (scanner image not available)"
else
    # Deterministic: a C/C++ tree with no package manager and a near-empty scan
    # must record the off-by-default suggestion (no SCANOSS needed for this).
    w="$(mktemp -d "$WORK_ROOT/vend.XXXXXX")"
    mkdir -p "$w/src"
    cat > "$w/src/main.c" <<'EOF'
int main(void) { return 0; }
EOF
    ( cd "$w" && bash "$SCAN" --project "vendtest" --version "1.0" \
        --generate-only ) > "$w/_suggest.log" 2>&1 || true
    sbom="$w/vendtest_1.0_bom.json"
    if [ -f "$sbom" ] && jq -e '.metadata.properties[]? | select(.name=="bomlens:suggest-identify-vendored" and .value=="true")' "$sbom" >/dev/null 2>&1; then
        pass "C/C++ source with no manifest records the identify-vendored suggestion"
    else
        fail "vendored suggestion not recorded for a bare C/C++ tree" "$(tail -5 "$w/_suggest.log" 2>/dev/null)"; show_log_if_verbose "$w"
    fi

    # Real identification needs scanoss-py in the image + OSSKB reachability.
    if [ "$have_scanoss" != 1 ]; then
        skip "vendored identification scan (image lacks scanoss-py — build --build-arg SBOM_SCANOSS=true)"
    elif [ "${SCANOSS_E2E:-0}" != "1" ]; then
        skip "vendored identification scan (set SCANOSS_E2E=1 to hit the OSSKB API)"
    else
        ( cd "$w" && bash "$SCAN" --project "vendtest2" --version "1.0" \
            --identify-vendored --all --generate-only ) > "$w/_identify.log" 2>&1 || true
        # Wiring check is deterministic; a specific match is not (depends on OSSKB).
        if grep -q "Identifying vendored open source" "$w/_identify.log" 2>/dev/null; then
            pass "--identify-vendored runs the SCANOSS step inside the container"
        else
            fail "--identify-vendored did not invoke the SCANOSS step" "$(tail -8 "$w/_identify.log" 2>/dev/null)"; show_log_if_verbose "$w"
        fi
        sbom2="$w/vendtest2_1.0_bom.json"
        if [ -f "$sbom2" ] && jq -e '.bomFormat=="CycloneDX"' "$sbom2" >/dev/null 2>&1; then
            pass "--identify-vendored produces a valid CycloneDX SBOM"
        else
            fail "--identify-vendored SBOM invalid/missing"
        fi

        # Over-detection guard (the scenario raised in review): enabling
        # --identify-vendored on a normal package-managed project must NOT balloon
        # the component count. Reconciliation drops SCANOSS matches that the npm
        # scan already declared, so the count stays ~equal to baseline.
        if [ -d "$EXAMPLES/nodejs" ]; then
            wb="$(run_source_scan "$EXAMPLES/nodejs" --all)"
            base_n=$(jq '[.components[]?]|length' "$wb/testapp_1.0_bom.json" 2>/dev/null || echo 0)
            wv="$(run_source_scan "$EXAMPLES/nodejs" --all --identify-vendored)"
            vend_n=$(jq '[.components[]?]|length' "$wv/testapp_1.0_bom.json" 2>/dev/null || echo 0)
            if [ "${base_n:-0}" -gt 0 ] && [ "${vend_n:-0}" -le "$((base_n + 3))" ]; then
                pass "managed project: --identify-vendored does not over-detect (base=$base_n, with=$vend_n)"
            else
                fail "managed project over-detection" "base=$base_n, with=$vend_n (expected with <= base+3)"
            fi
            rm -rf "$wb" "$wv"
        fi

        # False-positive probe: unique proprietary C must NOT match any OSS, so a
        # genuinely-private source tree gains no spurious vendored components.
        fp="$(mktemp -d "$WORK_ROOT/fp.XXXXXX")"; mkdir -p "$fp/src"
        cat > "$fp/src/widget.c" <<'EOF'
/* Proprietary, not open source. */
static int skt_widget_counter_xyz9f3a = 0;
int skt_widget_frobnicate_9f3a(int zorp){ skt_widget_counter_xyz9f3a += zorp*7+13; return skt_widget_counter_xyz9f3a ^ 0xC0FFEE; }
int main(void){ return skt_widget_frobnicate_9f3a(42); }
EOF
        wf="$(run_source_scan "$fp" --identify-vendored)"
        fpn=$(jq '[.components[]? | select(.properties[]?|select(.name=="bomlens:identifiedBy" and .value=="scanoss"))] | length' "$wf/testapp_1.0_bom.json" 2>/dev/null || echo 0)
        [ "${fpn:-0}" = "0" ] && pass "proprietary C tree -> no false vendored matches" || fail "false positive: $fpn vendored component(s) on proprietary code"
        rm -rf "$wf"

        # Graceful degrade: a bad SCANOSS endpoint must not abort the scan; a valid
        # SBOM is still produced (vendored step degrades to empty).
        wg="$(SCANOSS_API_URL=https://invalid.nonexistent.invalid run_source_scan "$fp" --identify-vendored 2>/dev/null)"
        if [ -f "$wg/testapp_1.0_bom.json" ] && jq -e '.bomFormat=="CycloneDX"' "$wg/testapp_1.0_bom.json" >/dev/null 2>&1; then
            pass "bad SCANOSS endpoint degrades gracefully (valid SBOM still produced)"
        else
            fail "bad SCANOSS endpoint did not degrade gracefully"
        fi
        rm -rf "$fp" "$wg"
    fi
    rm -rf "$w"
fi

# --------------------------------------------------------
# Group 4c: supplier SBOM analysis E2E through the container (requires image)
# --------------------------------------------------------
section "Supplier SBOM analysis E2E"
if [ "$have_image" != 1 ]; then
    skip "analyze scan (scanner image not available)"
else
    w="$(mktemp -d "$WORK_ROOT/analyze.XXXXXX")"
    cp "$REPO/tests/fixtures/good-spdx.json" "$w/" 2>/dev/null
    ( cd "$w" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
        --project "supplier" --version "2.3.1" --analyze good-spdx.json --generate-only ) > "$w/_scan.log" 2>&1

    if jq -e '.result=="pass"' "$w/supplier_2.3.1_conformance.json" >/dev/null 2>&1; then
        pass "analyze: SPDX conformance pass (container)"
    else
        fail "analyze: SPDX conformance pass (container)" "$(tail -5 "$w/_scan.log" 2>/dev/null)"; show_log_if_verbose "$w"
    fi
    nbom=$(jq '[.components[]?]|length' "$w/supplier_2.3.1_bom.json" 2>/dev/null || echo 0)
    if jq -e '.bomFormat=="CycloneDX"' "$w/supplier_2.3.1_bom.json" >/dev/null 2>&1 && [ "${nbom:-0}" -gt 0 ]; then
        pass "analyze: SPDX converted to CycloneDX with components ($nbom)"
    else
        fail "analyze: SPDX converted to CycloneDX with components" "got $nbom"
    fi
    { [ -f "$w/supplier_2.3.1_risk-report.md" ] && grep -q "7일" "$w/supplier_2.3.1_risk-report.md" && grep -q "30일" "$w/supplier_2.3.1_risk-report.md"; } \
        && pass "analyze: risk report with 7d/30d deadlines (container)" \
        || fail "analyze: risk report with 7d/30d deadlines (container)"
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
            # /capabilities drives input-type gating (firmware tab etc.)
            if curl -fsS "http://localhost:${port}/capabilities" | jq -e 'has("firmware") and has("docker")' >/dev/null 2>&1; then
                pass "web UI /capabilities reports firmware/docker support"
            else
                fail "web UI /capabilities reports firmware/docker support"
            fi
            # base image has no firmware tools -> firmware capability is false
            if [ "$(curl -fsS "http://localhost:${port}/capabilities" | jq -r '.firmware')" = "false" ]; then
                pass "web UI: firmware disabled on base image"
            else
                fail "web UI: firmware disabled on base image"
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
