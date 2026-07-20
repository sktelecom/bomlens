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
REM
REM IMPORTANT: a bare `bash` on a standard Windows PATH resolves to WSL's
REM C:\Windows\System32\bash.exe (or a WindowsApps app-execution alias), NOT Git
REM Bash. WSL bash reads C:\... as a path inside its own filesystem and fails to
REM find this script. So we locate Git Bash explicitly instead of trusting PATH.

setlocal EnableDelayedExpansion

REM --- Locate Git Bash (never WSL bash) ---
set "BASH_EXE="

REM 1) Explicit override.
if defined SBOM_BASH if exist "%SBOM_BASH%" set "BASH_EXE=%SBOM_BASH%"

REM 2) Derive from git on PATH: <root>\cmd\git.exe -> <root>\bin\bash.exe. Git for
REM    Windows puts cmd\ on PATH (so `where git` works) even when bin\ is not.
if not defined BASH_EXE (
    for /f "delims=" %%i in ('where git 2^>nul') do (
        if not defined BASH_EXE (
            for %%r in ("%%~dpi..") do set "GITROOT=%%~fr"
            if exist "!GITROOT!\bin\bash.exe" set "BASH_EXE=!GITROOT!\bin\bash.exe"
            if not defined BASH_EXE if exist "!GITROOT!\usr\bin\bash.exe" set "BASH_EXE=!GITROOT!\usr\bin\bash.exe"
        )
    )
)

REM 3) Known install locations.
if not defined BASH_EXE if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%ProgramW6432%\Git\bin\bash.exe" set "BASH_EXE=%ProgramW6432%\Git\bin\bash.exe"
if not defined BASH_EXE if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles(x86)%\Git\bin\bash.exe"

REM 4) Last resort: a bash on PATH that is neither the WSL launcher nor the
REM    WindowsApps alias stub.
if not defined BASH_EXE (
    for /f "delims=" %%i in ('where bash 2^>nul') do (
        if not defined BASH_EXE (
            echo %%i | find /i "\System32\" >nul
            if errorlevel 1 (
                echo %%i | find /i "\WindowsApps\" >nul
                if errorlevel 1 set "BASH_EXE=%%i"
            )
        )
    )
)

if not defined BASH_EXE (
    echo [ERROR] Git Bash not found.
    echo   scan-sbom on Windows must run through Git Bash, not WSL's bash.
    echo   The 'bash' on your PATH is likely C:\Windows\System32\bash.exe ^(WSL^)
    echo   or a WindowsApps alias, which cannot run this script.
    echo   Fix any one of:
    echo     - Install Git for Windows: https://git-scm.com/download/win
    echo     - Set SBOM_BASH to your Git bash.exe ^(e.g. C:\Program Files\Git\bin\bash.exe^)
    echo     - Run scan-sbom.sh inside WSL.
    echo   For the no-CLI UI, double-click sbom-ui.bat instead.
    exit /b 1
)

REM `docker version` talks to the daemon too, so it also fails when the engine is
REM merely stopped. Tell those apart with `where`, otherwise someone whose engine
REM is off is told to install Docker they already have.
docker version >nul 2>&1
if not errorlevel 1 goto :docker_ok
where docker >nul 2>&1
if not errorlevel 1 (
    echo [ERROR] Docker is installed but the engine is not running.
    echo   Start Rancher Desktop or Docker Desktop, wait for its icon to settle,
    echo   then run this again.
    exit /b 1
)
echo [ERROR] Docker is not installed or not on PATH.
echo   Free engines for Windows: Rancher Desktop ^(https://rancherdesktop.io/^)
echo   or WSL2 + docker-ce ^(run scan-sbom.sh inside WSL^). Docker Desktop also
echo   works ^(paid license for larger orgs^).
exit /b 1
:docker_ok
REM The engine can still be unreachable even when `docker version` succeeds
REM (permissions, a half-started daemon), so confirm before delegating to bash.
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] The Docker engine is not responding.
    echo   Start Rancher Desktop or Docker Desktop and wait for its icon to settle.
    echo   On Docker Desktop, check you are a member of the docker-users group.
    exit /b 1
)

REM Hand Git Bash a forward-slash script path; it takes those most reliably.
set "SCRIPT_SH=%~dp0scan-sbom.sh"
set "SCRIPT_SH=%SCRIPT_SH:\=/%"

"%BASH_EXE%" "%SCRIPT_SH%" %*
set "RC=%ERRORLEVEL%"

endlocal & exit /b %RC%
