@echo off
REM Copyright 2026 SK Telecom Co., Ltd.
REM Licensed under the Apache License, Version 2.0.
REM
REM check-setup.bat - SBOM Generator 실행 전 환경 점검 (Windows).
REM 더블클릭하면 Docker 설치/실행, 스캐너 이미지, UI 포트 상태를 한국어로 알려줍니다.

chcp 65001 >nul
setlocal

set DOCKER_IMAGE=%SBOM_SCANNER_IMAGE%
if "%DOCKER_IMAGE%"=="" set DOCKER_IMAGE=ghcr.io/sktelecom/bomlens:latest
set UI_PORT=%UI_PORT%
if "%UI_PORT%"=="" set UI_PORT=8080
set PROBLEMS=0

echo ==========================================
echo   SBOM Generator 설치 점검
echo ==========================================

REM 1) Docker 설치
docker version >nul 2>&1
if errorlevel 1 (
    echo [X] Docker가 설치되어 있지 않거나 PATH에 없습니다.
    echo     Windows 무료 옵션: Rancher Desktop^(GUI^) https://rancherdesktop.io/
    echo     또는 WSL2 + docker-ce  https://docs.docker.com/engine/install/
    echo     설치 후 이 점검을 다시 실행하세요.
    echo ------------------------------------------
    echo 점검 결과: 1개 이상 해결이 필요합니다.
    pause
    exit /b 1
)
echo [O] Docker 설치됨

REM 2) Docker 엔진 실행
docker info >nul 2>&1
if errorlevel 1 (
    echo [X] Docker 엔진이 실행 중이 아닙니다.
    echo     Rancher Desktop / Docker Desktop을 켠 뒤 다시 시도하세요.
    echo ------------------------------------------
    echo 점검 결과: 1개 이상 해결이 필요합니다.
    pause
    exit /b 1
)
echo [O] Docker 엔진 실행 중

REM 3) 스캐너 이미지 보유
docker image inspect "%DOCKER_IMAGE%" >nul 2>&1
if errorlevel 1 (
    echo [X] 스캐너 이미지가 아직 없습니다: %DOCKER_IMAGE%
    echo     처음 실행할 때 약 3~4GB를 자동으로 내려받습니다. 지금 미리 받으려면:
    echo       docker pull %DOCKER_IMAGE%
    set /a PROBLEMS+=1
) else (
    echo [O] 스캐너 이미지 보유: %DOCKER_IMAGE%
)

REM 4) UI 포트 사용 가능 여부
netstat -an | findstr /R /C:":%UI_PORT% .*LISTENING" >nul 2>&1
if errorlevel 1 (
    echo [O] UI 포트 %UI_PORT% 사용 가능
) else (
    echo [X] UI 포트 %UI_PORT%이(가) 이미 사용 중입니다.
    echo     다른 포트로 실행하려면 UI_PORT를 바꾸세요. 예: set UI_PORT=9090 후 다시 실행
    set /a PROBLEMS+=1
)

echo ------------------------------------------
if "%PROBLEMS%"=="0" (
    echo 점검 결과: 모두 준비됐습니다. sbom-ui.bat 을 실행해도 좋습니다.
) else (
    echo 점검 결과: %PROBLEMS%개 항목을 확인하세요^(위 안내 참고^).
)
pause
endlocal
