@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM Licensed under the Apache License, Version 2.0.
REM
REM sbom-ui.bat - launch the SBOM Generator local web UI on Windows.
REM Double-click this file to start the browser-based interface.

chcp 65001 >nul
setlocal

set DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%
if "%DOCKER_IMAGE%"=="" set DOCKER_IMAGE=ghcr.io/sktelecom/bomlens:latest
set UI_PORT=%UI_PORT%
if "%UI_PORT%"=="" set UI_PORT=8080

REM Results land in a dedicated folder under the user's home directory, which
REM both Rancher Desktop and Docker Desktop share by default. Double-clicking
REM this .bat would otherwise dump artifacts next to the script. Each scan goes
REM into a <project>_<version>/ subfolder under here (created by server.py).
REM Override the base with SBOM_OUTPUT_DIR.
set OUTDIR=%SBOM_OUTPUT_DIR%
if "%OUTDIR%"=="" set OUTDIR=%USERPROFILE%\sbom-output
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

REM --- 추가 스캔 대상 폴더 (선택) ---
REM SBOM_UI_MOUNT_DIR에 폴더를 지정하면 웹 UI의 "루트 파일시스템" 입력에
REM 읽기 전용 스캔 대상으로 나타난다 (예: 추출해 둔 리눅스 rootfs 폴더).
REM scan-sbom.sh --ui --mount 와 같은 기능의 더블클릭용 통로다.
set "MOUNT_V="
set "SCAN_ROOTS="
if "%SBOM_UI_MOUNT_DIR%"=="" goto :mount_done
if not exist "%SBOM_UI_MOUNT_DIR%\" (
    echo [오류] SBOM_UI_MOUNT_DIR 폴더가 없습니다: %SBOM_UI_MOUNT_DIR%
    pause
    exit /b 1
)
set "MOUNT_V=-v "%SBOM_UI_MOUNT_DIR%":/scan-targets/mounted:ro"
set "SCAN_ROOTS=/scan-targets/mounted|%SBOM_UI_MOUNT_DIR%"
:mount_done

REM --- Docker 점검 (진짜 사전 요구사항) ---
docker version >nul 2>&1
if errorlevel 1 (
    echo [오류] Docker가 설치되어 있지 않거나 PATH에 없습니다.
    echo   Windows에서 쓸 수 있는 무료 옵션:
    echo     - Rancher Desktop ^(GUI, 이 런처와 바로 동작^): https://rancherdesktop.io/
    echo     - WSL2 + docker-ce ^(WSL 안에서 scan-sbom.sh 실행^): https://docs.docker.com/engine/install/
    echo   Docker Desktop도 동작합니다 ^(규모가 큰 조직은 유료 라이선스 필요^): https://www.docker.com/products/docker-desktop/
    echo.
    echo   무엇이 문제인지 한눈에 보려면 check-setup.bat 을 더블클릭하세요.
    pause
    exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
    echo [오류] Docker 엔진이 실행 중이 아닙니다. Rancher Desktop / Docker Desktop을 켠 뒤 다시 시도하세요.
    pause
    exit /b 1
)

REM --- 첫 실행이면 스캐너 이미지를 미리 내려받는다 (진행률 표시) ---
docker image inspect "%DOCKER_IMAGE%" >nul 2>&1
if errorlevel 1 (
    echo ==========================================
    echo   처음 실행이라 스캐너 이미지를 내려받습니다 ^(약 3~4GB^).
    echo   네트워크 상황에 따라 수 분 걸릴 수 있어요. 잠시 기다려 주세요.
    echo   이미지: %DOCKER_IMAGE%
    echo ==========================================
    docker pull "%DOCKER_IMAGE%"
    if errorlevel 1 (
        echo [오류] 이미지 다운로드에 실패했습니다. 인터넷 연결을 확인하고 다시 시도하세요.
        pause
        exit /b 1
    )
)

echo ==========================================
echo   SBOM Generator 웹 UI
echo   주소: http://localhost:%UI_PORT%
echo   결과 저장 폴더: %OUTDIR%
echo   ^(이 창을 닫으면 중지됩니다^)
echo ==========================================

REM 서버가 뜬 직후 브라우저를 연다.
start "" cmd /c "timeout /t 2 >nul & start http://localhost:%UI_PORT%"

docker run --rm -it ^
    -p %UI_PORT%:8080 ^
    -v "%OUTDIR%":/src ^
    -v "%OUTDIR%":/host-output ^
    %MOUNT_V% ^
    -v /var/run/docker.sock:/var/run/docker.sock ^
    -e MODE=UI ^
    -e UI_PORT=8080 ^
    -e SBOM_UI_HOST_DIR="%OUTDIR%" ^
    -e SBOM_UI_SCAN_ROOTS="%SCAN_ROOTS%" ^
    "%DOCKER_IMAGE%"

endlocal
