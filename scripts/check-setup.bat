@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM SPDX-License-Identifier: Apache-2.0
REM Licensed under the Apache License, Version 2.0.
REM
REM check-setup.bat - BomLens environment check (Windows).
REM Double-click to see whether Docker, the scanner image and the UI port are ready.
REM
REM Encoding contract: UTF-8 WITHOUT BOM, CRLF. Message strings contain no "%" and no "!".

chcp 65001 >nul
setlocal

call :cfg_load

if not defined SBOM_SCANNER_IMAGE set "SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens:latest"
set "DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%"
if not defined UI_PORT set "UI_PORT=8080"
if not defined ANDROID_IMAGE_PREFIX set "ANDROID_IMAGE_PREFIX=bomlens-android-sdk"
REM The folder whose visibility inside the container is checked: the first
REM argument, else the current folder.
set "SCAN_DIR=%~1"
if not defined SCAN_DIR set "SCAN_DIR=%CD%"
set "IMAGE_OK="
set /a PROBLEMS=0

call :detect_lang
call :load_msgs

call :say M_SEP
call :say M_TITLE
call :say M_SEP

REM 1) Docker installed
docker version >nul 2>&1
if not errorlevel 1 goto :ok_installed
where docker >nul 2>&1
if not errorlevel 1 goto :engine_down
call :say M_X_NO_DOCKER
call :say M_OPT_RANCHER
call :say M_OPT_WSL
call :say M_RERUN
goto :fatal

:ok_installed
call :say M_O_INSTALLED

REM 2) Docker engine running
docker info >nul 2>&1
if errorlevel 1 goto :engine_down
call :say M_O_ENGINE
goto :check_image

:engine_down
call :say M_X_NO_ENGINE
goto :fatal

REM 3) scanner image present
:check_image
docker image inspect "%DOCKER_IMAGE%" >nul 2>&1
if errorlevel 1 goto :image_missing
call :say M_O_IMAGE
call :sayval DOCKER_IMAGE
set "IMAGE_OK=1"
goto :check_android_step

:image_missing
call :say M_X_NO_IMAGE
call :sayval DOCKER_IMAGE
call :say M_PREPULL
echo   docker pull %DOCKER_IMAGE%
call :say M_OFFLINE_HINT
set /a PROBLEMS+=1

REM 3b) Android SDK image. Not published (its SDK terms bar redistribution), so it
REM is built on this machine, and only Android scans use it: a missing image is a
REM note, not a problem.
:check_android_step
set "ANDROID_IMGS="
for /f "delims=" %%i in ('docker image ls --format "{{.Repository}}" 2^>nul ^| findstr /R /C:"^%ANDROID_IMAGE_PREFIX%[0-9][0-9]*$"') do set "ANDROID_IMGS=%%i"
if not defined ANDROID_IMGS goto :android_missing
call :say M_O_ANDROID
call :sayval ANDROID_IMGS
goto :check_share_step

:android_missing
call :say M_N_ANDROID
echo   docker build --build-arg ANDROID_API=34 -t %ANDROID_IMAGE_PREFIX%34:latest https://github.com/sktelecom/bomlens.git#main:docker/android

REM 3c) Shared folder: a folder Docker does not share is mounted as an empty one,
REM and a scan of it would run for minutes and find nothing. Needs the scanner
REM image to start a container, and a folder that has something in it.
:check_share_step
set "HAS_FILES="
for /f "delims=" %%x in ('dir /b /a "%SCAN_DIR%" 2^>nul') do set "HAS_FILES=1"
if not defined IMAGE_OK goto :share_skipped
if not defined HAS_FILES goto :share_skipped
set "SEEN="
for /f "delims=" %%x in ('docker run --rm --entrypoint sh -v "%SCAN_DIR%":/probe:ro "%DOCKER_IMAGE%" -c "ls -A /probe" 2^>nul') do set "SEEN=1"
if not defined SEEN goto :share_hidden
call :say M_O_SHARE
call :sayval SCAN_DIR
goto :check_mem_step

:share_hidden
call :say M_X_SHARE
call :sayval SCAN_DIR
call :say M_SHARE_FIX
set /a PROBLEMS+=1
goto :check_mem_step

:share_skipped
call :say M_S_SHARE
call :sayval SCAN_DIR

REM 4) Docker engine memory for Maven/Gradle builds. A hint only: an unreadable
REM value is skipped. docker info prints bytes; the last six digits are dropped
REM to get decimal megabytes, so set /a never sees a number past 32 bits. The
REM line is 3.5 GiB (a 4 GiB engine reports about 3.8), as in scan-sbom.sh.
:check_mem_step
set "MEM_BYTES="
for /f "delims=" %%m in ('docker info --format "{{.MemTotal}}" 2^>nul') do set "MEM_BYTES=%%m"
if not defined MEM_BYTES goto :check_port_step
for /f "delims=0123456789" %%x in ("%MEM_BYTES%") do goto :check_port_step
if "%MEM_BYTES:~7,1%"=="" goto :check_port_step
set "MEM_MB=%MEM_BYTES:~0,-6%"
set "MEM_MBN=0"
set /a "MEM_MBN=%MEM_MB%" 2>nul
REM Decimal megabytes to GiB with one decimal, like check-setup.sh (rounding 3.8
REM up to 4 hid how close to the line the engine was): MB*10000/1074 is tenths.
set /a "MEM_T=(MEM_MBN*10000+537)/1074"
set /a "MEM_W=MEM_T/10"
set /a "MEM_F=MEM_T %% 10"
if %MEM_MBN% LSS 3758 goto :mem_low
call :say M_O_MEM
echo   %MEM_W%.%MEM_F% GiB
goto :check_port_step

:mem_low
call :say M_X_MEM
echo   %MEM_W%.%MEM_F% GiB
call :say M_MEM_NOTE
call :say M_MEM_FIX
set /a PROBLEMS+=1

REM 5) UI port available
:check_port_step
set "PORT_BUSY="
call :cache_ranges
call :check_port %UI_PORT%
call :cleanup
if defined PORT_BUSY goto :port_busy
call :say M_O_PORT
echo   %UI_PORT%
goto :summary

:port_busy
call :say M_X_PORT
echo   %UI_PORT%
REM The old advice was "set UI_PORT=9090", which a double-click user can never
REM apply. Point at the settings file instead — and note the launcher now moves
REM to a free port on its own, so this is informational rather than blocking.
call :say M_PORT_FIX
set /a PROBLEMS+=1

:summary
call :say M_SEP2
if "%PROBLEMS%"=="0" call :say M_ALL_GOOD
if not "%PROBLEMS%"=="0" call :say M_SOME_BAD
if not "%PROBLEMS%"=="0" call :say M_PROBLEMS
if not "%PROBLEMS%"=="0" echo   %PROBLEMS%
call :say M_PRESS
pause >nul
endlocal & exit /b 0

:fatal
call :say M_SEP2
call :say M_SOME_BAD
call :say M_PRESS
pause >nul
endlocal & exit /b 1

REM ==========================================================================
REM Helpers (kept identical to sbom-ui.bat — see the comments there)
REM ==========================================================================
:say
setlocal EnableDelayedExpansion
echo(!%~1!
endlocal & goto :eof

:sayval
setlocal EnableDelayedExpansion
echo   !%~1!
endlocal & goto :eof

REM Snapshot the reserved ranges once — see the note in sbom-ui.bat: re-running
REM netsh per candidate port cost about six seconds per check.
:cache_ranges
set "RANGE_FILE=%TEMP%\bomlens-ranges-%RANDOM%%RANDOM%.txt"
netsh int ipv4 show excludedportrange protocol=tcp > "%RANGE_FILE%" 2>nul
goto :eof

:cleanup
if defined RANGE_FILE del "%RANGE_FILE%" >nul 2>&1
goto :eof

:check_port
netstat -an | findstr /R /C:":%~1 .*LISTENING" >nul 2>&1
if not errorlevel 1 set "PORT_BUSY=1"
if defined PORT_BUSY goto :eof
if not exist "%RANGE_FILE%" goto :eof
for /f "usebackq tokens=1,2" %%a in ("%RANGE_FILE%") do call :check_range "%%a" "%%b" %~1
goto :eof

REM Reserved ranges (Hyper-V/WSL) are the common false green light: nothing is
REM LISTENING, yet docker still cannot bind. netsh output is localized, so a row
REM counts only when BOTH tokens are numeric — `set /a` avoids spawning findstr
REM per row.
:check_range
set "A=%~1"
set "B=%~2"
set /a "NA=A" 2>nul
set /a "NB=B" 2>nul
if not "%NA%"=="%A%" goto :eof
if not "%NB%"=="%B%" goto :eof
if %~3 LSS %A% goto :eof
if %~3 GTR %B% goto :eof
set "PORT_BUSY=1"
goto :eof

:cfg_load
set "CFG_FILE=%~dp0bomlens.settings.txt"
if not exist "%CFG_FILE%" set "CFG_FILE=%USERPROFILE%\.bomlens\settings.txt"
if not exist "%CFG_FILE%" goto :eof
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%CFG_FILE%") do call :cfg_set "%%a" "%%b"
goto :eof

:cfg_set
set "K=%~1"
set "V=%~2"
if not defined K goto :eof
set "OK="
for %%w in (SBOM_LANG UI_PORT UI_BIND_ADDRESS SBOM_SCANNER_IMAGE SBOM_OUTPUT_DIR SBOM_UI_MOUNT_DIR SBOM_PULL SBOM_IMAGE_TAR) do if /i "%K%"=="%%w" set "OK=1"
if not defined OK goto :eof
if defined %K% goto :eof
call :cfg_rtrim
REM Reject a value carrying a shell metacharacter — see sbom-ui.bat's :cfg_set
REM for why (a whitelisted setting is read back later as a bare %VAR%, so an
REM unfiltered "UI_PORT=1234 & <anything>" runs <anything> on expansion).
set "BAD="
if not "%V:!=%"=="%V%" set "BAD=1"
if not "%V:&=%"=="%V%" set "BAD=1"
if not "%V:|=%"=="%V%" set "BAD=1"
if not "%V:<=%"=="%V%" set "BAD=1"
if not "%V:>=%"=="%V%" set "BAD=1"
if not "%V:^=%"=="%V%" set "BAD=1"
if defined BAD goto :eof
set "%K%=%V%"
goto :eof

:cfg_rtrim
if not defined V goto :eof
if not "%V:~-1%"==" " goto :eof
set "V=%V:~0,-1%"
goto :cfg_rtrim

:detect_lang
if defined SBOM_LANG goto :lang_norm
for /f "tokens=1,2,3" %%a in ('reg query "HKCU\Control Panel\International" /v LocaleName 2^>nul') do if /i "%%a"=="LocaleName" set "SBOM_LANG=%%c"
:lang_norm
if not defined SBOM_LANG set "SBOM_LANG=en"
if /i "%SBOM_LANG:~0,2%"=="ko" (set "SBOM_LANG=ko") else (set "SBOM_LANG=en")
goto :eof

:load_msgs
if "%SBOM_LANG%"=="ko" goto :msgs_ko

set "M_SEP==========================================="
set "M_SEP2=------------------------------------------"
set "M_TITLE=  BomLens setup check"
set "M_O_INSTALLED=[O] Docker is installed"
set "M_O_ENGINE=[O] Docker engine is running"
set "M_O_IMAGE=[O] Scanner image is present:"
set "M_O_MEM=[O] Docker engine memory is enough for Java builds:"
set "M_O_ANDROID=[O] Android SDK image is present:"
set "M_N_ANDROID=[-] The Android SDK image (for Android Gradle scans) is not built yet. Only Android projects need it; without it a scan stops at once and says how to build it. To build it ahead of time:"
set "M_O_SHARE=[O] The scanner container can see this folder:"
set "M_X_SHARE=[X] The scanner container cannot see this folder (it looks empty inside):"
set "M_SHARE_FIX=    Docker shares only some folders: Settings, Resources, File sharing on Docker Desktop. Move the project to a shared folder, or share its location."
set "M_S_SHARE=[-] Skipping the shared-folder check, because this folder is empty or the scanner image is missing:"
set "M_O_PORT=[O] UI port is available:"
set "M_X_NO_DOCKER=[X] Docker is not installed, or not on PATH."
set "M_OPT_RANCHER=    Free on Windows: Rancher Desktop (GUI) https://rancherdesktop.io/"
set "M_OPT_WSL=    or WSL2 + docker-ce  https://docs.docker.com/engine/install/"
set "M_RERUN=    Install it, then run this check again."
set "M_X_NO_ENGINE=[X] The Docker engine is not running. Start Rancher Desktop or Docker Desktop and wait for its icon to settle."
set "M_X_NO_IMAGE=[X] The scanner image is not downloaded yet:"
set "M_PREPULL=    The first run downloads about 250 MB automatically. To fetch it now:"
set "M_OFFLINE_HINT=    No network at the venue? See bomlens.settings.example.txt (SBOM_IMAGE_TAR) to install from a file."
set "M_X_MEM=[X] The Docker engine has too little memory. A Maven or Gradle build needs about 4 GB:"
set "M_MEM_FIX=    Docker Desktop: Settings, Resources, Memory. With the WSL 2 backend or Rancher Desktop: set memory=4GB in .wslconfig in your user folder, then run wsl --shutdown."
set "M_MEM_NOTE=    An engine set to 4 GB shows as about 3.8 GiB; this check passes from 3.5 GiB."
set "M_X_PORT=[X] UI port is already in use or reserved:"
set "M_PORT_FIX=    sbom-ui.bat will move to the next free port by itself. To pin a port, set UI_PORT in bomlens.settings.txt next to these scripts."
set "M_ALL_GOOD=Result: everything is ready. You can run sbom-ui.bat"
set "M_SOME_BAD=Result: please review the items marked [X] above."
set "M_PROBLEMS=Items to review:"
set "M_PRESS=Press any key to close this window."
goto :eof

:msgs_ko
set "M_SEP==========================================="
set "M_SEP2=------------------------------------------"
set "M_TITLE=  BomLens 설치 점검"
set "M_O_INSTALLED=[O] Docker 설치됨"
set "M_O_ENGINE=[O] Docker 엔진 실행 중"
set "M_O_IMAGE=[O] 스캐너 이미지 보유:"
set "M_O_MEM=[O] Docker 엔진 메모리가 Java 빌드에 충분합니다:"
set "M_O_ANDROID=[O] 안드로이드 SDK 이미지 보유:"
set "M_N_ANDROID=[-] 안드로이드(Gradle) 스캔에 쓰는 SDK 이미지가 아직 없습니다. 안드로이드 프로젝트를 스캔할 때만 필요하며, 없으면 스캔이 바로 멈추고 만드는 방법을 안내합니다. 미리 만들려면:"
set "M_O_SHARE=[O] 스캐너 컨테이너가 이 폴더를 볼 수 있습니다:"
set "M_X_SHARE=[X] 스캐너 컨테이너가 이 폴더를 보지 못합니다(컨테이너 안에서 비어 보임):"
set "M_SHARE_FIX=    Docker는 일부 폴더만 공유합니다. Docker Desktop은 Settings, Resources, File sharing 입니다. 프로젝트를 공유된 폴더로 옮기거나 그 위치를 공유하세요."
set "M_S_SHARE=[-] 이 폴더가 비어 있거나 스캐너 이미지가 없어 컨테이너 공유 점검을 건너뜁니다:"
set "M_O_PORT=[O] UI 포트 사용 가능:"
set "M_X_NO_DOCKER=[X] Docker가 설치되어 있지 않거나 PATH에 없습니다."
set "M_OPT_RANCHER=    Windows 무료 옵션: Rancher Desktop (GUI) https://rancherdesktop.io/"
set "M_OPT_WSL=    또는 WSL2 + docker-ce  https://docs.docker.com/engine/install/"
set "M_RERUN=    설치 후 이 점검을 다시 실행하세요."
set "M_X_NO_ENGINE=[X] Docker 엔진이 실행 중이 아닙니다. Rancher Desktop / Docker Desktop을 켜고 아이콘이 안정될 때까지 기다리세요."
set "M_X_NO_IMAGE=[X] 스캐너 이미지가 아직 없습니다:"
set "M_PREPULL=    처음 실행할 때 약 250MB를 자동으로 내려받습니다. 지금 미리 받으려면:"
set "M_OFFLINE_HINT=    현장에 네트워크가 없나요? 파일로 설치하려면 bomlens.settings.example.txt의 SBOM_IMAGE_TAR을 참고하세요."
set "M_X_MEM=[X] Docker 엔진 메모리가 부족합니다. Maven/Gradle 빌드에는 약 4GB가 필요합니다:"
set "M_MEM_FIX=    Docker Desktop: Settings, Resources, Memory. WSL 2 백엔드나 Rancher Desktop은 사용자 폴더의 .wslconfig 에 memory=4GB 를 적고 wsl --shutdown 을 실행하세요."
set "M_MEM_NOTE=    4GB로 설정한 엔진은 약 3.8 GiB로 표시되며, 이 점검은 3.5 GiB부터 통과합니다."
set "M_X_PORT=[X] UI 포트가 이미 사용 중이거나 예약되어 있습니다:"
set "M_PORT_FIX=    sbom-ui.bat이 알아서 비어 있는 다음 포트로 옮깁니다. 포트를 고정하려면 스크립트 옆 bomlens.settings.txt에 UI_PORT를 지정하세요."
set "M_ALL_GOOD=점검 결과: 모두 준비됐습니다. sbom-ui.bat 을 실행해도 좋습니다."
set "M_SOME_BAD=점검 결과: 위에서 [X] 표시된 항목을 확인하세요."
set "M_PROBLEMS=확인할 항목 수:"
set "M_PRESS=아무 키나 누르면 창이 닫힙니다."
goto :eof
