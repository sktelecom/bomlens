@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM
REM     http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.

setlocal enabledelayedexpansion

REM ========================================================
REM SBOM Scan Script (Windows)
REM ========================================================

set DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%
if "%DOCKER_IMAGE%"=="" set DOCKER_IMAGE=ghcr.io/sktelecom/sbom-scanner:latest
set SERVER_URL=http://host.docker.internal:8081
set DEFAULT_API_KEY=%API_KEY%
if "%DEFAULT_API_KEY%"=="" set DEFAULT_API_KEY=odt_YOUR_REAL_API_KEY_HERE

set GENERATE_ONLY=false
set TARGET=
set PROJECT_NAME=
set PROJECT_VERSION=
set GENERATE_NOTICE=false
set GENERATE_SECURITY=false
set DEEP_LICENSE=false
set SIGN_SBOM=false
set BYTE_STABLE=false

REM ========================================================
REM Parse arguments
REM ========================================================
:parse_args
if "%~1"=="" goto validate_args
if "%~1"=="--project" (
    set PROJECT_NAME=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--version" (
    set PROJECT_VERSION=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--target" (
    set TARGET=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--generate-only" (
    set GENERATE_ONLY=true
    shift
    goto parse_args
)
if "%~1"=="--notice" (
    set GENERATE_NOTICE=true
    shift
    goto parse_args
)
if "%~1"=="--security" (
    set GENERATE_SECURITY=true
    shift
    goto parse_args
)
if "%~1"=="--all" (
    set GENERATE_NOTICE=true
    set GENERATE_SECURITY=true
    shift
    goto parse_args
)
if "%~1"=="--deep-license" (
    set DEEP_LICENSE=true
    shift
    goto parse_args
)
if "%~1"=="--byte-stable" (
    set BYTE_STABLE=true
    shift
    goto parse_args
)
if "%~1"=="--sign" (
    set SIGN_SBOM=true
    shift
    goto parse_args
)
if "%~1"=="--help" (
    call :show_help
    exit /b 0
)
echo [ERROR] Unknown option: %~1
exit /b 1

:show_help
echo Usage: %~nx0 --project ^<name^> --version ^<ver^> [OPTIONS]
echo.
echo Options:
echo   --project ^<name^>       Project name (required)
echo   --version ^<ver^>        Version (required)
echo   --target ^<target^>      Analysis target:
echo                          - Not specified: Current directory source code
echo                          - Image name (e.g., nginx:latest): Docker image
echo                          - File path (e.g., firmware.bin): Binary file
echo                          - Directory (e.g., .\rootfs\): RootFS directory
echo   --generate-only        Save locally without uploading
echo   --notice               Also generate open-source NOTICE (txt + html)
echo   --security             Also generate Trivy security report (json + md + html)
echo   --all                  Shorthand for --notice --security
echo   --deep-license         Deep 1st-party license detection via scancode (opt-in)
echo   --byte-stable          Deterministic SBOM output
echo   --sign                 Sign the SBOM with cosign (requires COSIGN_KEY)
echo   --help                 Show this help message
echo.
echo Environment Variables:
echo   SBOM_SCANNER_IMAGE     Docker image to use (default: latest)
echo                          Examples:
echo                            ghcr.io/sktelecom/sbom-scanner:latest (default)
echo                            ghcr.io/sktelecom/sbom-scanner:v1
echo                            ghcr.io/sktelecom/sbom-scanner:v1.0.0
echo.
echo Examples:
echo   # Scan source code (current directory)
echo   %~nx0 --project MyApp --version 1.0.0 --generate-only
echo.
echo   # Scan Docker image
echo   %~nx0 --project MyImage --version 1.0 --target nginx:latest --generate-only
echo.
echo   # Scan binary file
echo   %~nx0 --project RouterOS --version 2.0 --target firmware.bin --generate-only
echo.
echo   # Scan RootFS directory
echo   %~nx0 --project DeviceOS --version 1.0 --target .\rootfs\ --generate-only
exit /b 0

:validate_args
REM ========================================================
REM Validate input
REM ========================================================
if "%PROJECT_NAME%"=="" (
    echo [ERROR] --project and --version are required.
    echo Run '%~nx0 --help' for usage.
    exit /b 1
)
if "%PROJECT_VERSION%"=="" (
    echo [ERROR] --project and --version are required.
    echo Run '%~nx0 --help' for usage.
    exit /b 1
)

REM ========================================================
REM Auto-detect target type
REM ========================================================
set MODE=SOURCE
set TARGET_IMAGE=
set TARGET_FILE=
set TARGET_DIR=
set SOURCE_DIR=%CD%

if not "%TARGET%"=="" (
    REM Check file
    if exist "%TARGET%" (
        if exist "%TARGET%\*" (
            REM Directory
            set MODE=ROOTFS
            set TARGET_DIR=%TARGET%
            echo [INFO] Detected directory: !TARGET_DIR!
        ) else (
            REM File
            set MODE=BINARY
            set TARGET_FILE=%TARGET%
            echo [INFO] Detected binary file: !TARGET_FILE!
        )
    ) else (
        REM Assume Docker image
        set MODE=IMAGE
        set TARGET_IMAGE=%TARGET%
        echo [INFO] Detected Docker image: !TARGET_IMAGE!
    )
)

REM ========================================================
REM Verify Docker environment
REM ========================================================
docker version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not in PATH.
    exit /b 1
)

REM ========================================================
REM Configure volume mounts and environment variables
REM ========================================================
set CACHE_MOUNTS=
set VOLUME_MOUNTS=
set ENV_VARS=

if "%MODE%"=="SOURCE" (
    REM Source code mode
    set VOLUME_MOUNTS=-v "%SOURCE_DIR%":/src -v "%SOURCE_DIR%":/host-output
    
    REM Mount build caches if they exist
    if exist "%USERPROFILE%\.gradle" (
        set CACHE_MOUNTS=!CACHE_MOUNTS! -v "%USERPROFILE%\.gradle":/root/.gradle
    )
    if exist "%USERPROFILE%\.m2" (
        set CACHE_MOUNTS=!CACHE_MOUNTS! -v "%USERPROFILE%\.m2":/root/.m2
    )
)

if "%MODE%"=="IMAGE" (
    REM Docker image mode
    set VOLUME_MOUNTS=-v "%SOURCE_DIR%":/host-output -v \\.\pipe\docker_engine:\\.\pipe\docker_engine
    set ENV_VARS=!ENV_VARS! -e TARGET_IMAGE="%TARGET_IMAGE%"
)

if "%MODE%"=="BINARY" (
    REM Binary file mode
    for %%F in ("%TARGET_FILE%") do (
        set FILE_DIR=%%~dpF
        set FILE_NAME=%%~nxF
    )
    set VOLUME_MOUNTS=-v "!FILE_DIR!":/target -v "%SOURCE_DIR%":/host-output
    set ENV_VARS=!ENV_VARS! -e TARGET_FILE="/target/!FILE_NAME!"
)

if "%MODE%"=="ROOTFS" (
    REM RootFS directory mode
    set VOLUME_MOUNTS=-v "%TARGET_DIR%":/target -v "%SOURCE_DIR%":/host-output
    set ENV_VARS=!ENV_VARS! -e TARGET_DIR="/target"
)

REM Common environment variables
if "%GENERATE_ONLY%"=="true" (
    set UPLOAD_VAR=false
) else (
    set UPLOAD_VAR=true
)

REM ========================================================
REM Run Docker container
REM ========================================================
echo ==========================================
echo  Starting SBOM Analysis
echo  Mode: %MODE%
echo  Project: %PROJECT_NAME% (%PROJECT_VERSION%)
if not "%TARGET%"=="" echo  Target: %TARGET%
echo ==========================================

docker run --rm ^
    %VOLUME_MOUNTS% ^
    %CACHE_MOUNTS% ^
    --add-host=host.docker.internal:host-gateway ^
    -e MODE="%MODE%" ^
    %ENV_VARS% ^
    -e UPLOAD_ENABLED="%UPLOAD_VAR%" ^
    -e GENERATE_NOTICE="%GENERATE_NOTICE%" ^
    -e GENERATE_SECURITY="%GENERATE_SECURITY%" ^
    -e DEEP_LICENSE="%DEEP_LICENSE%" ^
    -e SIGN_SBOM="%SIGN_SBOM%" ^
    -e BYTE_STABLE="%BYTE_STABLE%" ^
    -e HOST_OUTPUT_DIR="/host-output" ^
    -e PROJECT_NAME="%PROJECT_NAME%" ^
    -e PROJECT_VERSION="%PROJECT_VERSION%" ^
    -e API_KEY="%DEFAULT_API_KEY%" ^
    -e API_URL="%SERVER_URL%" ^
    "%DOCKER_IMAGE%"

if errorlevel 1 (
    echo [ERROR] Scan failed. Check logs above.
    exit /b 1
)

echo ==========================================
echo  Analysis Complete!
if "%GENERATE_ONLY%"=="true" (
    REM Generate safe filename
    set SAFE_PROJECT=%PROJECT_NAME: =_%
    set SAFE_PROJECT=!SAFE_PROJECT:/=_!
    set SAFE_PROJECT=!SAFE_PROJECT:\=_!
    set SAFE_VERSION=%PROJECT_VERSION: =_%
    set SAFE_VERSION=!SAFE_VERSION:/=_!
    set SAFE_VERSION=!SAFE_VERSION:\=_!
    echo  SBOM saved: !SAFE_PROJECT!_!SAFE_VERSION!_bom.json
)
echo ==========================================

endlocal
