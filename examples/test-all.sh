#!/bin/bash

# SBOM Generator - Examples Test Script
# 모든 예제를 순차적으로 테스트합니다.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0
SKIP=0

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "========================================"
echo "  SBOM Generator - Examples Test Suite"
echo "========================================"
echo ""

# 테스트 함수
test_example() {
    local example_dir="$1"
    local example_name=$(basename "${example_dir}")
    
    if [ ! -d "${example_dir}" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC}: ${example_name} (directory not found)"
        ((SKIP++))
        return
    fi
    
    if [ ! -f "${example_dir}/run.sh" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC}: ${example_name} (run.sh not found)"
        ((SKIP++))
        return
    fi
    
    echo -e "${BLUE}Testing${NC}: ${example_name}..."
    
    cd "${example_dir}"
    
    if ./run.sh > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}: ${example_name}"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: ${example_name}"
        ((FAIL++))
    fi
    
    # SBOM 파일 정리
    rm -f *_bom.json
    
    cd "${SCRIPT_DIR}"
}

# 각 예제 테스트
examples=(
    "java-maven"
    "python-pip"
    "nodejs-npm"
    "docker-image"
)

for example in "${examples[@]}"; do
    test_example "${SCRIPT_DIR}/${example}"
    echo ""
done

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
