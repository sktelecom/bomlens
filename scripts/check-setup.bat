@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
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
goto :check_port_step

:image_missing
call :say M_X_NO_IMAGE
call :sayval DOCKER_IMAGE
call :say M_PREPULL
echo   docker pull %DOCKER_IMAGE%
call :say M_OFFLINE_HINT
set /a PROBLEMS+=1

REM 4) UI port available
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
for %%w in (SBOM_LANG UI_PORT SBOM_SCANNER_IMAGE SBOM_OUTPUT_DIR SBOM_UI_MOUNT_DIR SBOM_PULL SBOM_IMAGE_TAR) do if /i "%K%"=="%%w" set "OK=1"
if not defined OK goto :eof
if defined %K% goto :eof
call :cfg_rtrim
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
set "M_O_PORT=[O] UI port is available:"
set "M_X_NO_DOCKER=[X] Docker is not installed, or not on PATH."
set "M_OPT_RANCHER=    Free on Windows: Rancher Desktop (GUI) https://rancherdesktop.io/"
set "M_OPT_WSL=    or WSL2 + docker-ce  https://docs.docker.com/engine/install/"
set "M_RERUN=    Install it, then run this check again."
set "M_X_NO_ENGINE=[X] The Docker engine is not running. Start Rancher Desktop or Docker Desktop and wait for its icon to settle."
set "M_X_NO_IMAGE=[X] The scanner image is not downloaded yet:"
set "M_PREPULL=    The first run downloads about 3-4 GB automatically. To fetch it now:"
set "M_OFFLINE_HINT=    No network at the venue? See bomlens.settings.example.txt (SBOM_IMAGE_TAR) to install from a file."
set "M_X_PORT=[X] UI port is already in use or reserved:"
set "M_PORT_FIX=    sbom-ui.bat will move to the next free port by itself. To pin a port, set UI_PORT in bomlens.settings.txt next to these scripts."
set "M_ALL_GOOD=Result: everything is ready. You can run sbom-ui.bat"
set "M_SOME_BAD=Result: please review the items marked [X] above."
set "M_PRESS=Press any key to close this window."
goto :eof

:msgs_ko
set "M_SEP==========================================="
set "M_SEP2=------------------------------------------"
set "M_TITLE=  BomLens 설치 점검"
set "M_O_INSTALLED=[O] Docker 설치됨"
set "M_O_ENGINE=[O] Docker 엔진 실행 중"
set "M_O_IMAGE=[O] 스캐너 이미지 보유:"
set "M_O_PORT=[O] UI 포트 사용 가능:"
set "M_X_NO_DOCKER=[X] Docker가 설치되어 있지 않거나 PATH에 없습니다."
set "M_OPT_RANCHER=    Windows 무료 옵션: Rancher Desktop (GUI) https://rancherdesktop.io/"
set "M_OPT_WSL=    또는 WSL2 + docker-ce  https://docs.docker.com/engine/install/"
set "M_RERUN=    설치 후 이 점검을 다시 실행하세요."
set "M_X_NO_ENGINE=[X] Docker 엔진이 실행 중이 아닙니다. Rancher Desktop / Docker Desktop을 켜고 아이콘이 안정될 때까지 기다리세요."
set "M_X_NO_IMAGE=[X] 스캐너 이미지가 아직 없습니다:"
set "M_PREPULL=    처음 실행할 때 약 3~4GB를 자동으로 내려받습니다. 지금 미리 받으려면:"
set "M_OFFLINE_HINT=    현장에 네트워크가 없나요? 파일로 설치하려면 bomlens.settings.example.txt의 SBOM_IMAGE_TAR을 참고하세요."
set "M_X_PORT=[X] UI 포트가 이미 사용 중이거나 예약되어 있습니다:"
set "M_PORT_FIX=    sbom-ui.bat이 알아서 비어 있는 다음 포트로 옮깁니다. 포트를 고정하려면 스크립트 옆 bomlens.settings.txt에 UI_PORT를 지정하세요."
set "M_ALL_GOOD=점검 결과: 모두 준비됐습니다. sbom-ui.bat 을 실행해도 좋습니다."
set "M_SOME_BAD=점검 결과: 위에서 [X] 표시된 항목을 확인하세요."
set "M_PRESS=아무 키나 누르면 창이 닫힙니다."
goto :eof
