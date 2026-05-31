@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM Licensed under the Apache License, Version 2.0.
REM
REM scan-sbom.bat - Windows wrapper.
REM
REM The full 2-stage orchestration (language detection -> cdxgen language image
REM -> build-prep -> post-process image) lives in scan-sbom.sh. To avoid
REM duplicating that logic in batch, we run it via Git Bash (Git for Windows),
REM which ships a POSIX bash. Docker Desktop must be installed and running.

setlocal

where bash >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git Bash not found.
    echo   scan-sbom on Windows runs through Git Bash. Install Git for Windows:
    echo     https://git-scm.com/download/win
    echo   ^(or run scan-sbom.sh under WSL^). For the no-CLI UI, double-click sbom-ui.bat.
    exit /b 1
)

docker version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not running.
    echo   Install/start Docker Desktop: https://www.docker.com/products/docker-desktop/
    exit /b 1
)

bash "%~dp0scan-sbom.sh" %*

endlocal
