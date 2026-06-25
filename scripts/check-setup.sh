#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.

# check-setup.sh — SBOM Generator를 쓰기 전 환경이 준비됐는지 점검한다.
# Docker 설치·실행 여부, 스캐너 이미지 보유 여부, UI 포트 사용 가능 여부를
# 차례로 확인하고, 막힌 항목마다 한국어로 다음에 할 일을 알려준다.

set -u

DOCKER_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"
UI_PORT="${UI_PORT:-8080}"

OK="✅"
NG="❌"
problems=0

note() { printf '   %s\n' "$1"; }

echo "=========================================="
echo "  SBOM Generator 설치 점검"
echo "=========================================="

# 1) Docker 설치
if docker version >/dev/null 2>&1; then
    echo "${OK} Docker 설치됨"
else
    echo "${NG} Docker가 설치되어 있지 않거나 PATH에 없습니다."
    note "Windows 무료 옵션: Rancher Desktop(GUI) https://rancherdesktop.io/"
    note "또는 WSL2 + docker-ce  https://docs.docker.com/engine/install/"
    note "설치 후 이 점검을 다시 실행하세요."
    echo "------------------------------------------"
    echo "점검 결과: 1개 이상 해결이 필요합니다."
    exit 1
fi

# 2) Docker 엔진 실행
if docker info >/dev/null 2>&1; then
    echo "${OK} Docker 엔진 실행 중"
else
    echo "${NG} Docker 엔진이 실행 중이 아닙니다."
    note "Rancher Desktop / Docker Desktop을 켠 뒤 다시 시도하세요."
    echo "------------------------------------------"
    echo "점검 결과: 1개 이상 해결이 필요합니다."
    exit 1
fi

# 3) 스캐너 이미지 보유
if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "${OK} 스캐너 이미지 보유: $DOCKER_IMAGE"
else
    echo "${NG} 스캐너 이미지가 아직 없습니다: $DOCKER_IMAGE"
    note "처음 실행할 때 약 3~4GB를 자동으로 내려받습니다. 지금 미리 받으려면:"
    note "  docker pull $DOCKER_IMAGE"
    problems=$((problems + 1))
fi

# 4) UI 포트 사용 가능 여부 (점검 실패가 치명적이지는 않음)
port_busy=0
if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$UI_PORT" -sTCP:LISTEN >/dev/null 2>&1 && port_busy=1
elif command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":${UI_PORT} " && port_busy=1
elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -q "[:.]${UI_PORT} .*LISTEN" && port_busy=1
fi
if [ "$port_busy" -eq 0 ]; then
    echo "${OK} UI 포트 ${UI_PORT} 사용 가능"
else
    echo "${NG} UI 포트 ${UI_PORT}이(가) 이미 사용 중입니다."
    note "다른 포트로 실행하려면 UI_PORT를 바꾸세요. 예: UI_PORT=9090 으로 다시 실행"
    problems=$((problems + 1))
fi

echo "------------------------------------------"
if [ "$problems" -eq 0 ]; then
    echo "점검 결과: 모두 준비됐습니다. 웹 UI를 실행해도 좋습니다."
    exit 0
else
    echo "점검 결과: ${problems}개 항목을 확인하세요(위 안내 참고)."
    exit 0
fi
