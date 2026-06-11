#!/bin/bash

# SBOM Generator - Examples Test Script
# 각 예제 디렉토리에 스캔 대상 매니페스트가 갖춰져 있는지 검증합니다.
# 실제 SBOM 생성(scan-sbom.sh)은 Docker와 언어 이미지가 필요하므로
# tests/test-scan.sh에서 다루고, 여기서는 Docker 없이 빠르게 예제 구성을 확인합니다.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0
SKIP=0

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "  SBOM Generator - Examples Test Suite"
echo "========================================"
echo ""

# 예제 디렉토리와 감지 매니페스트(scan-sbom.sh가 언어를 식별하는 파일) 매핑.
# 값은 공백으로 구분한 후보 목록이며, 하나라도 있으면 통과한다.
# glob 패턴(*.csproj 등)은 그대로 두면 매칭 검사에서 확장된다.
examples=(
    "java-maven:pom.xml"
    "java-gradle:build.gradle build.gradle.kts"
    "nodejs:package.json"
    "python:requirements.txt pyproject.toml"
    "go:go.mod"
    "ruby:Gemfile"
    "php:composer.json"
    "rust:Cargo.toml"
    "dotnet:*.csproj"
    "swift:Package.swift"
    "docker:Dockerfile"
)

# 예제 디렉토리에 기대 매니페스트가 있는지 검사.
test_example() {
    local name="$1" patterns="$2"
    local dir="${SCRIPT_DIR}/${name}"

    if [ ! -d "${dir}" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC}: ${name} (directory not found)"
        SKIP=$((SKIP + 1))
        return
    fi

    local found=""
    for pat in ${patterns}; do
        # 후보별로 glob 확장(매칭 실패 시 패턴 문자열 그대로 남으므로 실제 파일인지 확인).
        for f in "${dir}"/${pat}; do
            [ -e "${f}" ] && { found="$(basename "${f}")"; break; }
        done
        [ -n "${found}" ] && break
    done

    if [ -n "${found}" ]; then
        echo -e "${GREEN}✓ PASS${NC}: ${name} (${found})"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ FAIL${NC}: ${name} (no manifest among: ${patterns})"
        FAIL=$((FAIL + 1))
    fi
}

for entry in "${examples[@]}"; do
    test_example "${entry%%:*}" "${entry#*:}"
done
echo ""

# 결과 출력
echo "========================================"
echo "  Test Results"
echo "========================================"
echo -e "${GREEN}Passed${NC}: ${PASS}"
echo -e "${RED}Failed${NC}: ${FAIL}"
echo -e "${YELLOW}Skipped${NC}: ${SKIP}"
echo ""

total=$((PASS + FAIL))
if [ ${total} -gt 0 ]; then
    success_rate=$((PASS * 100 / total))
    echo "Success Rate: ${success_rate}%"
fi

# 실패가 있으면 exit 1
if [ ${FAIL} -gt 0 ]; then
    exit 1
fi
