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
# image present, the Android SDK image (only Android scans need it), that the
# container can see the folder you scan (the current folder, or the one given as
# the first argument), engine memory for Java builds, UI port free. Each blocked
# item says what to do next, in English or Korean.
#
# Language: SBOM_LANG=ko|en, else the locale (LC_ALL, LC_MESSAGES, LANG); Korean
# for ko*, English otherwise. The message keys (M_...) are the same as in
# check-setup.bat, and scripts/check-ux-heuristics.sh keeps the two sets equal.
#
# Exit code: 0 everything is ready; 1 a blocking problem (Docker missing or its
# engine not running, nothing else can be checked); 2 only non-blocking problems
# (image not downloaded yet, a folder the container cannot see, low engine
# memory, UI port busy), so a script can
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
# The folder whose visibility inside the container is checked.
# An absolute path: docker run -v reads a name that is not a path as a named
# volume, which is empty (a false "cannot see this folder") and is left behind.
SCAN_DIR="${1:-$PWD}"
if [ -d "$SCAN_DIR" ]; then
    SCAN_DIR="$(cd "$SCAN_DIR" && pwd)"
fi
ANDROID_IMAGE_PREFIX="${ANDROID_IMAGE_PREFIX:-bomlens-android-sdk}"

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
    M_O_ANDROID="안드로이드 SDK 이미지 보유:"
    M_N_ANDROID="안드로이드(Gradle) 스캔에 쓰는 SDK 이미지가 아직 없습니다. 안드로이드 프로젝트를 스캔할 때만 필요하며, 없으면 스캔이 바로 멈추고 만드는 방법을 안내합니다. 미리 만들려면:"
    M_O_SHARE="스캐너 컨테이너가 이 폴더를 볼 수 있습니다:"
    M_X_SHARE="스캐너 컨테이너가 이 폴더를 보지 못합니다(컨테이너 안에서 비어 보임):"
    M_SHARE_FIX="   Docker는 일부 폴더만 공유합니다. Colima는 홈 폴더, Docker Desktop은 Settings > Resources > File sharing 입니다. 프로젝트를 홈 폴더 아래로 옮기거나 그 위치를 공유하세요."
    M_S_SHARE="이 폴더가 비어 있거나 스캐너 이미지가 없어 컨테이너 공유 점검을 건너뜁니다:"
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
    M_MEM_NOTE="   4GB로 설정한 엔진은 약 3.8 GiB로 표시되며, 이 점검은 3.5 GiB부터 통과합니다."
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
    M_O_ANDROID="Android SDK image is present:"
    M_N_ANDROID="The Android SDK image (for Android Gradle scans) is not built yet. Only Android projects need it; without it a scan stops at once and says how to build it. To build it ahead of time:"
    M_O_SHARE="The scanner container can see this folder:"
    M_X_SHARE="The scanner container cannot see this folder (it looks empty inside):"
    M_SHARE_FIX="   Docker shares only some folders: your home folder on Colima, Settings > Resources > File sharing on Docker Desktop. Move the project under your home folder, or share its location."
    M_S_SHARE="Skipping the shared-folder check, because this folder is empty or the scanner image is missing:"
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
    M_MEM_NOTE="   An engine set to 4 GB shows as about 3.8 GiB; this check passes from 3.5 GiB."
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
if command -v docker >/dev/null 2>&1; then
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

# 3b) Android SDK image. Not published (its SDK terms bar redistribution), so it
# is built on this machine, and only Android scans use it: a missing image is a
# note, not a problem.
android_imgs=$(docker image ls --format '{{.Repository}}' 2>/dev/null | grep -E "^${ANDROID_IMAGE_PREFIX}[0-9]+$" | sort -u | tr '\n' ' ')
if [ -n "$android_imgs" ]; then
    ok "$M_O_ANDROID ${android_imgs% }"
else
    note "-  $M_N_ANDROID"
    note "     docker build --build-arg ANDROID_API=34 -t ${ANDROID_IMAGE_PREFIX}34:latest https://github.com/sktelecom/bomlens.git#main:docker/android"
fi

# 3c) Shared folder: a folder the engine's VM does not share (Colima shares only
# the home folder, so /tmp is not) is mounted as an empty one, and a scan of it
# would run for minutes and find nothing. Needs the scanner image to start a
# container, and a folder that has something in it to compare with.
if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1 && [ -d "$SCAN_DIR" ] && [ -n "$(ls -A "$SCAN_DIR" 2>/dev/null)" ]; then
    seen=$(docker run --rm --entrypoint sh -v "$SCAN_DIR":/probe:ro "$DOCKER_IMAGE" -c 'ls -A /probe | head -n 1' 2>/dev/null)
    if [ -n "$seen" ]; then
        ok "$M_O_SHARE $SCAN_DIR"
    else
        bad "$M_X_SHARE $SCAN_DIR"
        note "$M_SHARE_FIX"
        problems=$((problems + 1))
    fi
else
    note "-  $M_S_SHARE $SCAN_DIR"
fi

# 4) Engine memory for Maven/Gradle builds. A hint, like the warning scan-sbom.sh
# prints before such a build: an unreadable value is not a problem.
mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null)
mem_bytes=${mem_bytes%%$'\r'*}
case "$mem_bytes" in
    ''|*[!0-9]*) ;;
    *)
        mem_mb=$((mem_bytes / 1024 / 1024))
        # One decimal, as the engine reports it: rounding 3.8 up to "4" hid how
        # close to the line the engine was.
        mem_tenths=$(( (mem_bytes * 10 + 536870912) / 1073741824 ))
        mem_gib="$((mem_tenths / 10)).$((mem_tenths % 10)) GiB"
        if [ "$mem_mb" -gt 0 ] && [ "$mem_mb" -lt "$MIN_ENGINE_MB" ]; then
            bad "$M_X_MEM $mem_gib"
            note "$M_MEM_NOTE"
            note "$M_MEM_FIX"
            problems=$((problems + 1))
        elif [ "$mem_mb" -gt 0 ]; then
            ok "$M_O_MEM $mem_gib"
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
