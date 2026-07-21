@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM Licensed under the Apache License, Version 2.0.
REM
REM sbom-ui.bat - launch the BomLens local web UI on Windows.
REM Double-click this file to start the browser-based interface.
REM
REM Encoding contract: UTF-8 WITHOUT BOM, CRLF line endings. A BOM breaks the
REM first line (@echo off) and LF-only endings break goto label seeking.
REM Message strings must contain no "%" and no "!" (see :say below).

chcp 65001 >nul
setlocal

REM --- settings file -------------------------------------------------------
REM Environment variables do not survive a double-click, so the same knobs are
REM readable from a plain text file next to this script. Precedence is
REM real environment variable > settings file > built-in default.
call :cfg_load

REM --- defaults ------------------------------------------------------------
if not defined SBOM_SCANNER_IMAGE set "SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens:latest"
set "DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%"
if not defined UI_PORT set "UI_PORT=8080"
REM missing = pull only when absent (default), always = refresh, never = offline
if not defined SBOM_PULL set "SBOM_PULL=missing"

REM Results land in a dedicated folder under the user's home directory, which
REM both Rancher Desktop and Docker Desktop share by default. Double-clicking
REM this .bat would otherwise dump artifacts next to the script. Each scan goes
REM into a <project>_<version>/ subfolder under here (created by server.py).
REM Override the base with SBOM_OUTPUT_DIR.
set "OUTDIR=%SBOM_OUTPUT_DIR%"
if not defined OUTDIR set "OUTDIR=%USERPROFILE%\sbom-output"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

call :detect_lang
call :load_msgs

REM --- optional extra scan folder ------------------------------------------
REM Point SBOM_UI_MOUNT_DIR at a folder and it shows up in the web UI as a
REM read-only scan target (e.g. an extracted Linux rootfs). Same idea as
REM scan-sbom.sh --ui --mount, reachable by double-click.
set "MOUNT_V="
set "SCAN_ROOTS="
if not defined SBOM_UI_MOUNT_DIR goto :mount_done
REM Strip a trailing backslash: "D:\rootfs\" would emit "D:\rootfs\":/... and the
REM backslash escapes the closing quote, mangling the whole mount spec.
if "%SBOM_UI_MOUNT_DIR:~-1%"=="\" set "SBOM_UI_MOUNT_DIR=%SBOM_UI_MOUNT_DIR:~0,-1%"
if not exist "%SBOM_UI_MOUNT_DIR%\" goto :err_mount_missing
REM Reject shell metacharacters rather than trying to quote around them: this
REM value is expanded into a command line, and making that bullet-proof in cmd
REM is a losing battle. A clear sentence beats a cryptic Docker error.
call :check_mount_chars
if defined BAD_CHAR goto :err_mount_badchar
set "MOUNT_V=-v "%SBOM_UI_MOUNT_DIR%":/scan-targets/mounted:ro"
set "SCAN_ROOTS=/scan-targets/mounted|%SBOM_UI_MOUNT_DIR%"
:mount_done

REM --- Docker checks (the real prerequisite) -------------------------------
REM `docker version` also talks to the daemon, so it fails when the engine is
REM merely stopped. Distinguish the two with `where`, otherwise a user whose
REM engine is off is told to go install Docker they already have.
docker version >nul 2>&1
if not errorlevel 1 goto :docker_ok
where docker >nul 2>&1
if errorlevel 1 goto :err_no_docker
goto :err_no_engine
:docker_ok
docker info >nul 2>&1
if errorlevel 1 goto :err_no_engine

REM --- scanner image: local -> offline tar -> registry ----------------------
if /i "%SBOM_PULL%"=="always" goto :do_pull
docker image inspect "%DOCKER_IMAGE%" >nul 2>&1
if not errorlevel 1 goto :image_ready
if not defined SBOM_IMAGE_TAR if exist "%~dp0bomlens-image.tar" set "SBOM_IMAGE_TAR=%~dp0bomlens-image.tar"
if defined SBOM_IMAGE_TAR goto :do_load
if /i "%SBOM_PULL%"=="never" goto :err_no_image
goto :do_pull

:do_load
call :say M_LOAD_TAR
call :sayval SBOM_IMAGE_TAR
docker load -i "%SBOM_IMAGE_TAR%"
if errorlevel 1 goto :err_load_failed
goto :image_ready

:do_pull
call :say M_SEP
call :say M_PULL_1
call :say M_PULL_2
call :say M_PULL_3
call :sayval DOCKER_IMAGE
call :say M_SEP
docker pull "%DOCKER_IMAGE%"
if errorlevel 1 goto :err_pull_failed
:image_ready

REM --- pick a free port ----------------------------------------------------
REM A busy or reserved port used to fail inside docker run, after the browser
REM had already been opened, and the window then closed with no message.
call :cache_ranges
set "PORT_START=%UI_PORT%"
set /a PORT_TRIES=0
:port_scan
set "PORT_BUSY="
call :check_port %UI_PORT%
if not defined PORT_BUSY goto :port_ok
set /a PORT_TRIES+=1
if %PORT_TRIES% GEQ 20 goto :err_no_port
set /a UI_PORT+=1
goto :port_scan
:port_ok
if not "%UI_PORT%"=="%PORT_START%" call :say M_PORT_MOVED
if not "%UI_PORT%"=="%PORT_START%" echo   %PORT_START% -^> %UI_PORT%

call :say M_SEP
call :say M_TITLE
call :say M_URL
echo   http://localhost:%UI_PORT%
call :say M_OUTDIR
call :sayval OUTDIR
call :say M_CLOSE_HINT
call :say M_SEP

REM Open the browser shortly after the server comes up. The port was verified
REM free above, so the bind below is very likely to succeed.
start "" cmd /c "timeout /t 4 >nul & start http://localhost:%UI_PORT%"

docker run --rm -it ^
    -p %UI_PORT%:8080 ^
    -v "%OUTDIR%":/src ^
    -v "%OUTDIR%":/host-output ^
    %MOUNT_V% ^
    -v /var/run/docker.sock:/var/run/docker.sock ^
    -e MODE=UI ^
    -e UI_PORT=8080 ^
    -e SBOM_SCANNER_IMAGE="%DOCKER_IMAGE%" ^
    -e SBOM_UI_HOST_DIR="%OUTDIR%" ^
    -e SBOM_UI_SCAN_ROOTS="%SCAN_ROOTS%" ^
    "%DOCKER_IMAGE%"
set "RC=%ERRORLEVEL%"

REM Always report and hold the window. Without this, a bind failure or a
REM container crash closed the console instantly and left no clue at all.
echo.
if not "%RC%"=="0" call :say M_RUN_FAILED
call :say M_STOPPED
echo   exit code: %RC%
call :say M_PRESS
pause >nul
call :cleanup
endlocal & exit /b %RC%

REM ==========================================================================
REM Failure paths. Each one prints an explanation and holds the window open.
REM ==========================================================================
:err_no_docker
call :say M_ERR_NO_DOCKER
call :say M_OPT_HEAD
call :say M_OPT_RANCHER
call :say M_OPT_WSL
call :say M_OPT_DD
echo.
call :say M_HINT_CHECK
goto :die

:err_no_engine
call :say M_ERR_NO_ENGINE
goto :die

:err_mount_missing
call :say M_ERR_MOUNT_MISSING
call :sayval SBOM_UI_MOUNT_DIR
goto :die

:err_mount_badchar
call :say M_ERR_MOUNT_BADCHAR
call :sayval SBOM_UI_MOUNT_DIR
goto :die

:err_no_image
call :say M_ERR_NO_IMAGE
call :sayval DOCKER_IMAGE
goto :die

:err_load_failed
call :say M_ERR_LOAD_FAILED
call :sayval SBOM_IMAGE_TAR
goto :die

:err_pull_failed
call :say M_ERR_PULL_1
call :say M_ERR_PULL_2
call :say M_ERR_PULL_3
call :say M_ERR_PULL_4
call :say M_ERR_PULL_5
goto :die

:err_no_port
call :say M_ERR_NO_PORT
echo   %PORT_START% - %UI_PORT%
goto :die

:die
echo.
call :say M_PRESS
pause >nul
call :cleanup
endlocal & exit /b 1

REM ==========================================================================
REM Helpers
REM ==========================================================================

REM Print a message by variable NAME. Delayed expansion is enabled only inside
REM this routine: `echo %VAR%` re-parses "&", "|" and ">" out of the message and
REM would run them as commands (a message containing "&" hangs the script), while
REM turning delayed expansion on globally would corrupt paths containing "!".
REM Cost of this trade: message strings must not contain "!".
REM Remove the reserved-range snapshot written by :cache_ranges.
:cleanup
if defined RANGE_FILE del "%RANGE_FILE%" >nul 2>&1
goto :eof

:say
setlocal EnableDelayedExpansion
echo(!%~1!
endlocal & goto :eof

REM Print an indented VALUE (a path, an image ref) by variable NAME. Same reason
REM as :say — `echo   %SOMEPATH%` on a folder called "a&b" prints "a" and then
REM tries to run "b" as a command.
:sayval
setlocal EnableDelayedExpansion
echo   !%~1!
endlocal & goto :eof

REM Reject characters that break cmd command-line construction. Works on the
REM variable directly: passing the value as an argument and echoing it would
REM re-parse the very metacharacters we are trying to detect.
:check_mount_chars
set "BAD_CHAR="
if not "%SBOM_UI_MOUNT_DIR:!=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
if not "%SBOM_UI_MOUNT_DIR:&=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
if not "%SBOM_UI_MOUNT_DIR:|=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
if not "%SBOM_UI_MOUNT_DIR:<=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
if not "%SBOM_UI_MOUNT_DIR:>=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
if not "%SBOM_UI_MOUNT_DIR:^=%"=="%SBOM_UI_MOUNT_DIR%" set "BAD_CHAR=1"
goto :eof

REM Snapshot the Hyper-V/WSL reserved ranges ONCE. Running netsh per candidate
REM port cost ~6 seconds on a machine with a handful of ranges, which would be
REM added to every single launch. A netsh blocked by group policy just leaves the
REM file empty: that means "no reserved ranges known", not a blocked launch.
:cache_ranges
set "RANGE_FILE=%TEMP%\bomlens-ranges-%RANDOM%%RANDOM%.txt"
netsh int ipv4 show excludedportrange protocol=tcp > "%RANGE_FILE%" 2>nul
goto :eof

REM Busy if something is LISTENING on it, OR if it falls inside a reserved range.
REM The reserved-range case is the common false green light on Windows 11:
REM nothing is listening, yet docker still cannot bind.
:check_port
netstat -an | findstr /R /C:":%~1 .*LISTENING" >nul 2>&1
if not errorlevel 1 set "PORT_BUSY=1"
if defined PORT_BUSY goto :eof
if not exist "%RANGE_FILE%" goto :eof
for /f "usebackq tokens=1,2" %%a in ("%RANGE_FILE%") do call :check_range "%%a" "%%b" %~1
goto :eof

REM netsh output is localized (Japanese headers on a Japanese laptop), so a row
REM counts only when BOTH tokens are numeric — never match on header text.
REM The numeric test uses `set /a` rather than findstr so that no process is
REM spawned per row; with several ranges that was the whole cost of the check.
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

REM --- settings file -------------------------------------------------------
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
REM Whitelist: never `set` an arbitrary name out of a text file.
set "OK="
for %%w in (SBOM_LANG UI_PORT SBOM_SCANNER_IMAGE SBOM_OUTPUT_DIR SBOM_UI_MOUNT_DIR SBOM_PULL SBOM_IMAGE_TAR) do if /i "%K%"=="%%w" set "OK=1"
if not defined OK goto :eof
REM A real environment variable always wins over the file.
if defined %K% goto :eof
call :cfg_rtrim
set "%K%=%V%"
goto :eof

:cfg_rtrim
if not defined V goto :eof
if not "%V:~-1%"==" " goto :eof
set "V=%V:~0,-1%"
goto :cfg_rtrim

REM --- language ------------------------------------------------------------
REM Mirrors electron/lib/i18n.mjs resolveLang(): SBOM_LANG wins, otherwise the
REM system locale, and anything that is not Korean falls back to English.
REM English default is also the fix for mojibake on a Japanese console: the
REM console FONT has no Hangul glyphs, so no codepage can render Korean there.
:detect_lang
if defined SBOM_LANG goto :lang_norm
for /f "tokens=1,2,3" %%a in ('reg query "HKCU\Control Panel\International" /v LocaleName 2^>nul') do if /i "%%a"=="LocaleName" set "SBOM_LANG=%%c"
REM No console-codepage fallback here: chcp 65001 above already replaced the
REM original codepage, so it can no longer tell us anything about the system.
:lang_norm
if not defined SBOM_LANG set "SBOM_LANG=en"
if /i "%SBOM_LANG:~0,2%"=="ko" (set "SBOM_LANG=ko") else (set "SBOM_LANG=en")
goto :eof

REM --- messages ------------------------------------------------------------
REM Two flat blocks instead of per-message if/else: inside a parenthesized block
REM every ")" in a message is a parser hazard, while `set "K=V"` neutralizes all
REM metacharacters. Keep the two blocks key-for-key identical (tests enforce it).
:load_msgs
if "%SBOM_LANG%"=="ko" goto :msgs_ko

set "M_SEP==========================================="
set "M_TITLE=  BomLens web UI"
set "M_URL=  Address:"
set "M_OUTDIR=  Results folder:"
set "M_CLOSE_HINT=  (closing this window stops the UI)"
set "M_PULL_1=  First run: downloading the scanner image (about 250 MB)."
set "M_PULL_2=  The first scan of a project also fetches a language image (0.6-1.7 GB)."
set "M_PULL_3=  Image:"
set "M_LOAD_TAR=Loading the scanner image from a local file (no network needed):"
set "M_PORT_MOVED=Port was busy or reserved, moved to a free one:"
set "M_RUN_FAILED=[error] The UI container did not start correctly."
set "M_STOPPED=BomLens has stopped."
set "M_PRESS=Press any key to close this window."
set "M_ERR_NO_DOCKER=[error] Docker is not installed, or not on PATH."
set "M_OPT_HEAD=  Free options on Windows:"
set "M_OPT_RANCHER=    - Rancher Desktop (GUI, works with this launcher): https://rancherdesktop.io/"
set "M_OPT_WSL=    - WSL2 + docker-ce (run scan-sbom.sh inside WSL): https://docs.docker.com/engine/install/"
set "M_OPT_DD=  Docker Desktop also works (larger organisations need a paid licence): https://www.docker.com/products/docker-desktop/"
set "M_HINT_CHECK=  For a summary of what is missing, double-click check-setup.bat"
set "M_ERR_NO_ENGINE=[error] The Docker engine is not running. Start Rancher Desktop or Docker Desktop, wait for its icon to settle, then try again."
set "M_ERR_MOUNT_MISSING=[error] SBOM_UI_MOUNT_DIR folder does not exist:"
set "M_ERR_MOUNT_BADCHAR=[error] SBOM_UI_MOUNT_DIR contains a character that cannot be passed to Docker safely. Please use a path without & ^ | < > percent or exclamation marks:"
set "M_ERR_NO_IMAGE=[error] The scanner image is not present and SBOM_PULL is set to never:"
set "M_ERR_LOAD_FAILED=[error] Could not load the scanner image from the file:"
set "M_ERR_PULL_1=[error] Downloading the scanner image failed."
set "M_ERR_PULL_2=  If you are on a corporate network this is most likely a proxy."
set "M_ERR_PULL_3=  Note: the image is downloaded by the Docker daemon, not by this window, so setting HTTP_PROXY here has no effect."
set "M_ERR_PULL_4=  Configure the proxy in Docker Desktop: Settings - Resources - Proxies, or Rancher Desktop: Preferences - WSL - Proxy."
set "M_ERR_PULL_5=  No network at all? Ask your organiser for the offline image file and see bomlens.settings.example.txt (SBOM_IMAGE_TAR)."
set "M_ERR_NO_PORT=[error] Could not find a free port in this range:"
goto :eof

:msgs_ko
set "M_SEP==========================================="
set "M_TITLE=  BomLens 웹 UI"
set "M_URL=  주소:"
set "M_OUTDIR=  결과 저장 폴더:"
set "M_CLOSE_HINT=  (이 창을 닫으면 중지됩니다)"
set "M_PULL_1=  처음 실행이라 스캐너 이미지를 내려받습니다 (약 250MB)."
set "M_PULL_2=  프로젝트를 처음 스캔할 때 언어별 이미지(0.6~1.7GB)를 한 번 더 내려받습니다."
set "M_PULL_3=  이미지:"
set "M_LOAD_TAR=로컬 파일에서 스캐너 이미지를 불러옵니다 (네트워크 불필요):"
set "M_PORT_MOVED=포트가 사용 중이거나 예약되어 있어 비어 있는 포트로 옮겼습니다:"
set "M_RUN_FAILED=[오류] UI 컨테이너가 정상적으로 시작되지 않았습니다."
set "M_STOPPED=BomLens가 종료되었습니다."
set "M_PRESS=아무 키나 누르면 창이 닫힙니다."
set "M_ERR_NO_DOCKER=[오류] Docker가 설치되어 있지 않거나 PATH에 없습니다."
set "M_OPT_HEAD=  Windows에서 쓸 수 있는 무료 옵션:"
set "M_OPT_RANCHER=    - Rancher Desktop (GUI, 이 런처와 바로 동작): https://rancherdesktop.io/"
set "M_OPT_WSL=    - WSL2 + docker-ce (WSL 안에서 scan-sbom.sh 실행): https://docs.docker.com/engine/install/"
set "M_OPT_DD=  Docker Desktop도 동작합니다 (규모가 큰 조직은 유료 라이선스 필요): https://www.docker.com/products/docker-desktop/"
set "M_HINT_CHECK=  무엇이 문제인지 한눈에 보려면 check-setup.bat 을 더블클릭하세요."
set "M_ERR_NO_ENGINE=[오류] Docker 엔진이 실행 중이 아닙니다. Rancher Desktop / Docker Desktop을 켜고 아이콘이 안정된 뒤 다시 시도하세요."
set "M_ERR_MOUNT_MISSING=[오류] SBOM_UI_MOUNT_DIR 폴더가 없습니다:"
set "M_ERR_MOUNT_BADCHAR=[오류] SBOM_UI_MOUNT_DIR에 Docker로 안전하게 넘길 수 없는 문자가 있습니다. & ^ | < > 퍼센트 느낌표가 없는 경로를 사용해 주세요:"
set "M_ERR_NO_IMAGE=[오류] 스캐너 이미지가 없고 SBOM_PULL이 never로 설정되어 있습니다:"
set "M_ERR_LOAD_FAILED=[오류] 파일에서 스캐너 이미지를 불러오지 못했습니다:"
set "M_ERR_PULL_1=[오류] 스캐너 이미지 다운로드에 실패했습니다."
set "M_ERR_PULL_2=  사내 네트워크라면 프록시 때문일 가능성이 높습니다."
set "M_ERR_PULL_3=  참고: 이미지는 이 창이 아니라 Docker 데몬이 내려받으므로, 여기서 HTTP_PROXY를 설정해도 효과가 없습니다."
set "M_ERR_PULL_4=  Docker Desktop은 Settings - Resources - Proxies, Rancher Desktop은 Preferences - WSL - Proxy 에서 프록시를 설정하세요."
set "M_ERR_PULL_5=  네트워크가 아예 없나요? 오프라인 이미지 파일을 받아 bomlens.settings.example.txt의 SBOM_IMAGE_TAR을 참고하세요."
set "M_ERR_NO_PORT=[오류] 이 범위에서 비어 있는 포트를 찾지 못했습니다:"
goto :eof
