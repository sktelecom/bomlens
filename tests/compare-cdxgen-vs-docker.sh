#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# compare-cdxgen-vs-docker.sh
# Empirically compares "cdxgen alone (no build tools)" vs "sbom-tools Docker image
# (build tools + dependency resolution)" across a set of fixture projects.
# Measures three metrics per project: component count, vulnerability count, scan time.
#
# Baseline A : official cdxgen image (no language build tools) -> manifest parsing only
# Variant  B : sbom-tools scanner image -> installs deps, then cdxgen
#
# Usage:
#   ./tests/compare-cdxgen-vs-docker.sh
# Env:
#   SBOM_FIXTURES_DIR   project root to scan (default: ~/projects/bd-scan/tests/fixtures/projects,
#                       falls back to ./examples)
#   SBOM_SCANNER_IMAGE  sbom-tools image (default: ghcr.io/sktelecom/sbom-scanner:latest)
#   CDXGEN_IMAGE        baseline cdxgen image (default: ghcr.io/cyclonedx/cdxgen:latest)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/test-workspace"
RESULT_CSV="$WORKSPACE/compare-result.csv"
mkdir -p "$WORKSPACE"

SCANNER_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/sbom-scanner:latest}"
CDXGEN_IMAGE="${CDXGEN_IMAGE:-ghcr.io/cyclonedx/cdxgen:latest}"
FIXTURES_DIR="${SBOM_FIXTURES_DIR:-$HOME/projects/bd-scan/tests/fixtures/projects}"

if [ ! -d "$FIXTURES_DIR" ]; then
    echo "[WARN] fixtures dir not found: $FIXTURES_DIR — falling back to examples/"
    FIXTURES_DIR="$SCRIPT_DIR/../examples"
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker is required and must be running."
    exit 1
fi

# Discover project directories that contain a recognized manifest.
mapfile -t PROJECT_DIRS < <(find "$FIXTURES_DIR" -maxdepth 2 -type f \
    \( -name pom.xml -o -name build.gradle -o -name build.gradle.kts \
       -o -name package.json -o -name requirements.txt -o -name pyproject.toml \
       -o -name go.mod -o -name Cargo.toml -o -name Gemfile -o -name composer.json \
       -o -name '*.csproj' \) -exec dirname {} \; 2>/dev/null | sort -u)

if [ "${#PROJECT_DIRS[@]}" -eq 0 ]; then
    echo "[ERROR] No projects with a known manifest found under $FIXTURES_DIR"
    exit 1
fi

echo "Fixtures dir : $FIXTURES_DIR"
echo "Projects     : ${#PROJECT_DIRS[@]}"
echo "Baseline (A) : $CDXGEN_IMAGE"
echo "Variant  (B) : $SCANNER_IMAGE"
echo ""

comp_count() { jq '([.components[]?] | length)' "$1" 2>/dev/null || echo 0; }

vuln_count() {
    # Run Trivy from inside the scanner image (trivy is pinned there).
    local bom="$1" dir; dir="$(dirname "$bom")"
    docker run --rm -v "$dir":/w --entrypoint trivy "$SCANNER_IMAGE" \
        sbom --quiet --format json "/w/$(basename "$bom")" 2>/dev/null \
        | jq '([.Results[]?.Vulnerabilities[]?] | length)' 2>/dev/null || echo 0
}

echo "project,cdxgen_only_comp,docker_comp,comp_delta,comp_pct,cdxgen_only_cve,docker_cve,cdxgen_sec,docker_sec" > "$RESULT_CSV"

for projdir in "${PROJECT_DIRS[@]}"; do
    name="$(basename "$projdir")"
    printf '  [%-22s] ' "$name"

    # ----- Baseline A: cdxgen alone -----
    tmpA="$(mktemp -d)"; cp -R "$projdir/." "$tmpA/" 2>/dev/null
    sA=$(date +%s)
    docker run --rm -v "$tmpA":/app "$CDXGEN_IMAGE" -r -o /app/out_bom.json /app >/dev/null 2>&1
    eA=$(date +%s)
    compA=$(comp_count "$tmpA/out_bom.json"); secA=$((eA - sA))
    cveA=$([ -f "$tmpA/out_bom.json" ] && vuln_count "$tmpA/out_bom.json" || echo 0)

    # ----- Variant B: sbom-tools image -----
    tmpB="$(mktemp -d)"; cp -R "$projdir/." "$tmpB/" 2>/dev/null
    sB=$(date +%s)
    docker run --rm -v "$tmpB":/src -v "$tmpB":/host-output \
        -e MODE=SOURCE -e PROJECT_NAME=cmp -e PROJECT_VERSION=0 \
        -e UPLOAD_ENABLED=false -e HOST_OUTPUT_DIR=/host-output \
        "$SCANNER_IMAGE" >/dev/null 2>&1
    eB=$(date +%s)
    compB=$(comp_count "$tmpB/cmp_0_bom.json"); secB=$((eB - sB))
    cveB=$([ -f "$tmpB/cmp_0_bom.json" ] && vuln_count "$tmpB/cmp_0_bom.json" || echo 0)

    delta=$((compB - compA))
    if [ "$compA" -gt 0 ]; then pct="$(awk "BEGIN{printf \"%.1f\", ($delta/$compA)*100}")"; else pct="inf"; fi

    echo "$name,$compA,$compB,$delta,$pct,$cveA,$cveB,$secA,$secB" >> "$RESULT_CSV"
    echo "cdxgen=$compA docker=$compB (Δ$delta, ${pct}%) cve:$cveA→$cveB time:${secA}s→${secB}s"

    rm -rf "$tmpA" "$tmpB"
done

echo ""
echo "[DONE] Results written to: $RESULT_CSV"
echo ""
column -s, -t "$RESULT_CSV"
