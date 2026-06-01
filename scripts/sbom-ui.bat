@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM Licensed under the Apache License, Version 2.0.
REM
REM sbom-ui.bat - launch the SBOM Generator local web UI on Windows.
REM Double-click this file to start the browser-based interface.

setlocal

set DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%
if "%DOCKER_IMAGE%"=="" set DOCKER_IMAGE=ghcr.io/sktelecom/sbom-scanner:latest
set UI_PORT=%UI_PORT%
if "%UI_PORT%"=="" set UI_PORT=8080

REM --- Docker checks (the real prerequisite) ---
docker version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not in PATH.
    echo   Install Docker Desktop: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running. Please start it and retry.
    echo   Download: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

echo ==========================================
echo   SBOM Generator Web UI
echo   URL: http://localhost:%UI_PORT%
echo   (Close this window to stop)
echo ==========================================

REM Open the browser shortly after the server starts.
start "" cmd /c "timeout /t 2 >nul & start http://localhost:%UI_PORT%"

docker run --rm -it ^
    -p %UI_PORT%:8080 ^
    -v "%CD%":/src ^
    -v "%CD%":/host-output ^
    -v \\.\pipe\docker_engine:\\.\pipe\docker_engine ^
    -e MODE=UI ^
    -e UI_PORT=8080 ^
    "%DOCKER_IMAGE%"

endlocal
