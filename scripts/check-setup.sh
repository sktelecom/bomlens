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
# image present (the version of this CLI), the Android SDK image (only Android
# scans need it), that the container can see the folder you scan (the current
# folder, or the one given as the first argument), engine memory for Java
# builds, the images BomLens has downloaded with their total size and the free
# disk space of the engine (with how to clean up), UI port free. Each blocked
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

# The version of this CLI bundle, written in by the release build (an unreleased
# checkout keeps the placeholder). The default scanner image is the one of that
# version, as the desktop app uses, not whatever :latest is on this machine.
BOMLENS_CLI_VERSION="@BOMLENS_VERSION@"
case "$BOMLENS_CLI_VERSION" in
    @*) DEFAULT_IMAGE_TAG="latest"; CLI_VERSION_KNOWN=0 ;;
    *)  DEFAULT_IMAGE_TAG="$BOMLENS_CLI_VERSION"; CLI_VERSION_KNOWN=1 ;;
esac
DOCKER_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:$DEFAULT_IMAGE_TAG}"
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
    M_PREPULL="   처음 실행할 때 약 1.4GB를 자동으로 내려받습니다. 지금 미리 받으려면:"
    M_OFFLINE_HINT="   네트워크가 없나요? 다른 곳에서 docker save 로 만든 tar 파일을 docker load -i <파일> 로 설치할 수 있습니다."
    M_X_MEM="Docker 엔진 메모리가 부족합니다. Maven/Gradle 빌드에는 약 4GB가 필요합니다:"
    M_MEM_FIX="   Colima: colima stop && colima start --memory 4 / Docker Desktop: Settings > Resources > Memory / WSL2: %UserProfile%\\.wslconfig 의 memory=4GB 후 wsl --shutdown"
    M_MEM_NOTE="   4GB로 설정한 엔진은 약 3.8 GiB로 표시되며, 이 점검은 3.5 GiB부터 통과합니다."
    M_X_PORT="UI 포트가 이미 사용 중입니다:"
    M_O_PORT_OWN="이 포트는 실행 중인 BomLens 웹 UI가 쓰고 있습니다(문제 아님):"
    M_PORT_FIX="   다른 포트로 실행하려면 UI_PORT를 바꾸세요. 예: UI_PORT=9090 으로 다시 실행"
    M_O_IMAGES="이 컴퓨터의 BomLens 이미지(디스크 차지 크기):"
    M_O_TOTAL="이 이미지들의 합계:"
    M_O_DISK="Docker 엔진의 디스크 여유 공간:"
    M_X_DISK="Docker 엔진의 디스크 여유 공간이 적습니다:"
    M_DISK_NEED="   처음 스캔할 때 언어별 이미지 하나를 3~16GB 내려받습니다(.NET은 약 15GB). 명령줄 도구는 여유 공간이 이미지 크기에 2GB를 더한 값보다 적으면 내려받기 전에 멈추며, BOMLENS_SKIP_DISK_CHECK=1 을 지정하면 그대로 스캔합니다."
    M_CLEAN="   필요 없는 이미지 삭제: docker image rm <이미지>. 어느 컨테이너도 쓰지 않는 이미지 전체 삭제: docker image prune -a"
    M_CLEAN2="   지운 뒤에도 공간이 모자라면 Docker Desktop이나 Rancher Desktop의 Settings에서 디스크를 압축하거나, Colima는 colima ssh -- sudo fstrim -av 를 실행하세요."
    M_N_LATEST="latest 태그 이미지도 있지만 이 명령줄 도구는 위의 버전 태그를 쓰므로 그 이미지는 쓰이지 않습니다. 이 도구의 버전:"
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
    M_PREPULL="   The first run downloads about 1.4 GB automatically. To fetch it now:"
    M_OFFLINE_HINT="   No network? Make a tar elsewhere with docker save, then install it here with docker load -i <file>."
    M_X_MEM="The Docker engine has too little memory. A Maven or Gradle build needs about 4 GB:"
    M_MEM_FIX="   Colima: colima stop && colima start --memory 4 / Docker Desktop: Settings > Resources > Memory / WSL2: memory=4GB in %UserProfile%\\.wslconfig, then wsl --shutdown"
    M_MEM_NOTE="   An engine set to 4 GB shows as about 3.8 GiB; this check passes from 3.5 GiB."
    M_X_PORT="The UI port is already in use:"
    M_O_PORT_OWN="This port is used by BomLens's own web UI, which is running (not a problem):"
    M_PORT_FIX="   To run on another port, change UI_PORT. Example: run again with UI_PORT=9090"
    M_O_IMAGES="BomLens images on this machine (size on disk):"
    M_O_TOTAL="Total size of these images:"
    M_O_DISK="Free disk space in the Docker engine:"
    M_X_DISK="Free disk space in the Docker engine is low:"
    M_DISK_NEED="   A first scan downloads one language image of 3 to 16 GB (.NET about 15 GB). The CLI stops before downloading when the free space is smaller than the image plus 2 GB; BOMLENS_SKIP_DISK_CHECK=1 scans anyway."
    M_CLEAN="   Remove an image you no longer need: docker image rm <image>. All images no container uses: docker image prune -a"
    M_CLEAN2="   Space still short afterwards: compact the disk in Docker Desktop or Rancher Desktop (Settings), or on Colima run: colima ssh -- sudo fstrim -av"
    M_N_LATEST="An image tagged latest is also here, but this CLI uses the version tag above, so it is not used. This CLI is version:"
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
    # The version tag is not here but a :latest is (an older install): say it
    # is not the image this CLI runs.
    if [ "$CLI_VERSION_KNOWN" = 1 ] && [ -z "${SBOM_SCANNER_IMAGE:-}" ] \
       && docker image inspect "ghcr.io/sktelecom/bomlens:latest" >/dev/null 2>&1; then
        note "-  $M_N_LATEST $BOMLENS_CLI_VERSION"
    fi
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

# 4b) Images BomLens has downloaded and the engine's free disk. A first scan of a
# language downloads 3 to 16 GB; the sizes here are what the images take on disk
# (docker image inspect), each image counted once however many tags it has.
# Free space is read with a short container, as scan-sbom.sh does; an engine
# whose value cannot be read is not a problem.
img_total_mb=0; img_seen=" "; img_lines=""
while IFS= read -r row; do
    [ -n "$row" ] || continue
    img_id="${row%% *}"; img_ref="${row#* }"
    case "$img_seen" in *" $img_id "*) continue ;; esac
    img_seen="$img_seen$img_id "
    img_bytes=$(docker image inspect --format '{{.Size}}' "$img_id" 2>/dev/null)
    img_bytes=${img_bytes%%$'\r'*}
    case "$img_bytes" in ''|*[!0-9]*) continue ;; esac
    img_mb=$((img_bytes / 1000000))
    img_total_mb=$((img_total_mb + img_mb))
    img_lines="$img_lines$(awk -v r="$img_ref" -v m="$img_mb" 'BEGIN { printf "     %-60s %6.1f GB\n", r, m / 1000 }')
"
done <<EOF_IMGS
$(docker image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E ' (ghcr\.io/cdxgen/|ghcr\.io/sktelecom/(bomlens|sbom-)|bomlens-android-sdk)' | grep -v ':<none>$')
EOF_IMGS
if [ -n "$img_lines" ]; then
    note "-  $M_O_IMAGES"
    printf '%s' "$img_lines"
    note "   $M_O_TOTAL $(awk -v m="$img_total_mb" 'BEGIN { printf "%.1f", m / 1000 }') GB"
fi
probe_img="$DOCKER_IMAGE"
docker image inspect "$probe_img" >/dev/null 2>&1 || probe_img=$(docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | head -n 1)
free_mb=""
if [ -n "${BOMLENS_FAKE_FREE_MB:-}" ]; then
    free_mb="$BOMLENS_FAKE_FREE_MB"
elif [ -n "$probe_img" ]; then
    free_mb=$(docker run --rm --pull never --entrypoint df "$probe_img" -Pm / 2>/dev/null | tr -d '\r' | awk 'NR==2 {print $4}')
fi
case "$free_mb" in
    ''|*[!0-9]*) ;;
    *)
        free_gb=$(awk -v m="$free_mb" 'BEGIN { printf "%.1f", m / 1000 }')
        # 5 GB: the smallest language image (2.9 GB) plus the 2 GB the CLI keeps free.
        if [ "$free_mb" -lt 5000 ]; then
            bad "$M_X_DISK $free_gb GB"
            note "$M_DISK_NEED"
            note "$M_CLEAN"
            note "$M_CLEAN2"
            problems=$((problems + 1))
        else
            ok "$M_O_DISK $free_gb GB"
            note "$M_DISK_NEED"
            note "$M_CLEAN"
            note "$M_CLEAN2"
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
# A busy port may be BomLens's own web UI container: that is the UI working.
own_ui=""
if [ "$port_busy" -eq 1 ] && command -v docker >/dev/null 2>&1; then
    own_ui=$(docker ps --filter "publish=$UI_PORT" --format '{{.Image}}' 2>/dev/null | grep -E 'bomlens|sbom-generator|sbom-scanner' | head -n 1)
fi
if [ "$port_busy" -eq 0 ]; then
    ok "$M_O_PORT $UI_PORT"
elif [ -n "$own_ui" ]; then
    ok "$M_O_PORT_OWN $UI_PORT ($own_ui)"
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
