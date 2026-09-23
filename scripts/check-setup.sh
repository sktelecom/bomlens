#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.

# check-setup.sh - checks that the environment is ready before BomLens is used
# (macOS/Linux/WSL2; check-setup.bat is the Windows counterpart and probes the
# same things). It checks, in order: Docker installed, engine running, scanner
# image present, engine memory for Java builds, UI port free. Each blocked item
# says what to do next, in English or Korean.
#
# Language: SBOM_LANG=ko|en, else the locale (LC_ALL, LC_MESSAGES, LANG); Korean
# for ko*, English otherwise. The message keys (M_...) are the same as in
# check-setup.bat, and scripts/check-ux-heuristics.sh keeps the two sets equal.
#
# Exit code: 0 everything is ready; 1 a blocking problem (Docker missing or its
# engine not running, nothing else can be checked); 2 only non-blocking problems
# (image not downloaded yet, low engine memory, UI port busy), so a script can
# tell "usable, with things to review" from "ready". The number of such
# problems is printed in the result line.
#
# Not carried over from the .bat: its settings file (bomlens.settings.txt) and
# the Hyper-V/WSL reserved-port check exist for double-click Windows users;
# scan-sbom.sh reads neither.

set -u

DOCKER_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"
UI_PORT="${UI_PORT:-8080}"
# Engine memory below this is a hint for Maven/Gradle builds (3.5 GiB; a 4 GiB
# engine reports about 3.8 GiB), the same line as scan-sbom.sh's warning.
MIN_ENGINE_MB=3584

OK="✅"
NG="❌"
problems=0

lang="${SBOM_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}"
case "$lang" in ko*) SBOM_LANG=ko ;; *) SBOM_LANG=en ;; esac

if [ "$SBOM_LANG" = ko ]; then
    M_SEP="=========================================="
    M_SEP2="------------------------------------------"
    M_TITLE="  BomLens 설치 점검"
    M_O_INSTALLED="Docker 설치됨"
    M_O_ENGINE="Docker 엔진 실행 중"
    M_O_IMAGE="스캐너 이미지 보유:"
    M_O_MEM="Docker 엔진 메모리가 Java 빌드에 충분합니다:"
    M_O_PORT="UI 포트 사용 가능:"
    M_X_NO_DOCKER="Docker가 설치되어 있지 않거나 PATH에 없습니다."
    M_OPT_RANCHER="   Windows 무료 옵션: Rancher Desktop (GUI) https://rancherdesktop.io/"
    M_OPT_WSL="   또는 WSL2 + docker-ce  https://docs.docker.com/engine/install/"
    M_RERUN="   설치 후 이 점검을 다시 실행하세요."
    M_X_NO_ENGINE="Docker 엔진이 실행 중이 아닙니다. Rancher Desktop / Docker Desktop을 켜고 아이콘이 안정될 때까지 기다리세요."
    M_X_NO_IMAGE="스캐너 이미지가 아직 없습니다:"
    M_PREPULL="   처음 실행할 때 약 250MB를 자동으로 내려받습니다. 지금 미리 받으려면:"
    M_OFFLINE_HINT="   네트워크가 없나요? 다른 곳에서 docker save 로 만든 tar 파일을 docker load -i <파일> 로 설치할 수 있습니다."
    M_X_MEM="Docker 엔진 메모리가 부족합니다. Maven/Gradle 빌드에는 약 4GB가 필요합니다:"
    M_MEM_FIX="   Colima: colima stop && colima start --memory 4 / Docker Desktop: Settings > Resources > Memory / WSL2: %UserProfile%\\.wslconfig 의 memory=4GB 후 wsl --shutdown"
    M_X_PORT="UI 포트가 이미 사용 중입니다:"
    M_PORT_FIX="   다른 포트로 실행하려면 UI_PORT를 바꾸세요. 예: UI_PORT=9090 으로 다시 실행"
    M_ALL_GOOD="점검 결과: 모두 준비됐습니다. 웹 UI를 실행해도 좋습니다."
    M_SOME_BAD="점검 결과: 위에서 ❌ 표시된 항목을 확인하세요."
    M_PROBLEMS="확인할 항목 수:"
else
    M_SEP="=========================================="
    M_SEP2="------------------------------------------"
    M_TITLE="  BomLens setup check"
    M_O_INSTALLED="Docker is installed"
    M_O_ENGINE="Docker engine is running"
    M_O_IMAGE="Scanner image is present:"
    M_O_MEM="Docker engine memory is enough for Java builds:"
    M_O_PORT="UI port is available:"
    M_X_NO_DOCKER="Docker is not installed, or not on PATH."
    M_OPT_RANCHER="   Free on Windows: Rancher Desktop (GUI) https://rancherdesktop.io/"
    M_OPT_WSL="   or WSL2 + docker-ce  https://docs.docker.com/engine/install/"
    M_RERUN="   Install it, then run this check again."
    M_X_NO_ENGINE="The Docker engine is not running. Start Rancher Desktop or Docker Desktop and wait for its icon to settle."
    M_X_NO_IMAGE="The scanner image is not downloaded yet:"
    M_PREPULL="   The first run downloads about 250 MB automatically. To fetch it now:"
    M_OFFLINE_HINT="   No network? Make a tar elsewhere with docker save, then install it here with docker load -i <file>."
    M_X_MEM="The Docker engine has too little memory. A Maven or Gradle build needs about 4 GB:"
    M_MEM_FIX="   Colima: colima stop && colima start --memory 4 / Docker Desktop: Settings > Resources > Memory / WSL2: memory=4GB in %UserProfile%\\.wslconfig, then wsl --shutdown"
    M_X_PORT="The UI port is already in use:"
    M_PORT_FIX="   To run on another port, change UI_PORT. Example: run again with UI_PORT=9090"
    M_ALL_GOOD="Result: everything is ready. You can start the web UI."
    M_SOME_BAD="Result: please review the items marked ❌ above."
    M_PROBLEMS="Items to review:"
fi

note() { printf '%s\n' "$1"; }
ok()   { printf '%s %s\n' "$OK" "$1"; }
bad()  { printf '%s %s\n' "$NG" "$1"; }
fatal() {
    note "$M_SEP2"
    note "$M_SOME_BAD"
    exit 1
}

note "$M_SEP"
note "$M_TITLE"
note "$M_SEP"

# 1) Docker installed
if docker version >/dev/null 2>&1; then
    ok "$M_O_INSTALLED"
else
    bad "$M_X_NO_DOCKER"
    note "$M_OPT_RANCHER"
    note "$M_OPT_WSL"
    note "$M_RERUN"
    fatal
fi

# 2) Docker engine running
if docker info >/dev/null 2>&1; then
    ok "$M_O_ENGINE"
else
    bad "$M_X_NO_ENGINE"
    fatal
fi

# 3) Scanner image present
if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    ok "$M_O_IMAGE $DOCKER_IMAGE"
else
    bad "$M_X_NO_IMAGE $DOCKER_IMAGE"
    note "$M_PREPULL"
    note "     docker pull $DOCKER_IMAGE"
    note "$M_OFFLINE_HINT"
    problems=$((problems + 1))
fi

# 4) Engine memory for Maven/Gradle builds. A hint, like the warning scan-sbom.sh
# prints before such a build: an unreadable value is not a problem.
mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null)
mem_bytes=${mem_bytes%%$'\r'*}
case "$mem_bytes" in
    ''|*[!0-9]*) ;;
    *)
        mem_mb=$((mem_bytes / 1024 / 1024))
        if [ "$mem_mb" -gt 0 ] && [ "$mem_mb" -lt "$MIN_ENGINE_MB" ]; then
            bad "$M_X_MEM $(( (mem_mb + 512) / 1024 )) GB"
            note "$M_MEM_FIX"
            problems=$((problems + 1))
        elif [ "$mem_mb" -gt 0 ]; then
            ok "$M_O_MEM $(( (mem_mb + 512) / 1024 )) GB"
        fi ;;
esac

# 5) UI port free (a failure here is not blocking)
port_busy=0
if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$UI_PORT" -sTCP:LISTEN >/dev/null 2>&1 && port_busy=1
elif command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":${UI_PORT} " && port_busy=1
elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -q "[:.]${UI_PORT} .*LISTEN" && port_busy=1
fi
if [ "$port_busy" -eq 0 ]; then
    ok "$M_O_PORT $UI_PORT"
else
    bad "$M_X_PORT $UI_PORT"
    note "$M_PORT_FIX"
    problems=$((problems + 1))
fi

note "$M_SEP2"
if [ "$problems" -eq 0 ]; then
    note "$M_ALL_GOOD"
    exit 0
fi
note "$M_SOME_BAD"
note "$M_PROBLEMS $problems"
exit 2
