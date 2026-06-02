<#
.SYNOPSIS
    Windows 자동 스모크 테스트 — SBOM Generator의 Windows 고유 위험을 헤드리스로 검증한다.

.DESCRIPTION
    GUI(더블클릭과 브라우저 업로드)는 자동화하지 않는다. 대신 Windows에서만 깨지기 쉬운
    부분을 비대화형으로 확인한다.
      - Docker 엔진 점검과 스캐너 이미지 프리풀
      - 명명 파이프 마운트(\\.\pipe\docker_engine)와 파일 공유 경로에서
        고지문(NOTICE)이 실제로 호스트 폴더에 생성되는지
      - 웹 UI 컨테이너가 떠서 http://localhost:8080 이 응답하는지
      - 공유되지 않은 경로에서는 산출물이 나타나지 않는 함정이 재현되는지

    자동화할 수 없는 단계는 조용히 넘기지 않고 SKIP으로 분명히 남긴다. 종료 코드는
    실패가 하나라도 있으면 1, 모두 통과/스킵이면 0 이다.

.NOTES
    실제 Windows + Rancher Desktop / Docker Desktop 에서 실행한다.
    실행: powershell -ExecutionPolicy Bypass -File tests\windows-smoke.ps1
#>

[CmdletBinding()]
param(
    [string]$Image = $(if ($env:SBOM_SCANNER_IMAGE) { $env:SBOM_SCANNER_IMAGE } else { 'ghcr.io/sktelecom/sbom-generator:latest' }),
    [int]$UiPort = $(if ($env:UI_PORT) { [int]$env:UI_PORT } else { 8080 })
)

$ErrorActionPreference = 'Stop'
$script:Fail = 0
$script:RepoRoot = Split-Path -Parent $PSScriptRoot

function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Skip($msg) { Write-Host "[SKIP] $msg" -ForegroundColor Yellow }
function Failed($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:Fail++ }
function Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# 1) Docker 엔진 점검
# ---------------------------------------------------------------------------
Section '1. Docker 엔진'
docker version *> $null
if ($LASTEXITCODE -ne 0) { Failed 'docker가 설치되어 있지 않거나 PATH에 없습니다. 더 진행할 수 없습니다.'; exit 1 }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Failed 'Docker 엔진이 실행 중이 아닙니다. Rancher/Docker Desktop을 켜고 다시 실행하세요.'; exit 1 }
Pass 'Docker 엔진 실행 중'

# ---------------------------------------------------------------------------
# 2) 스캐너 이미지 프리풀
# ---------------------------------------------------------------------------
Section '2. 스캐너 이미지 프리풀'
docker pull $Image
if ($LASTEXITCODE -ne 0) { Failed "이미지 pull 실패: $Image"; exit 1 }
Pass "이미지 준비됨: $Image"

# ---------------------------------------------------------------------------
# 3) CLI 스캔으로 명명 파이프 + 파일 공유 + 고지문 생성 검증
#    scan-sbom.bat 는 Git Bash 를 통해 동작한다. 없으면 이 단계는 SKIP.
# ---------------------------------------------------------------------------
Section '3. CLI 스캔 e2e (명명 파이프 + 파일 공유 + NOTICE)'
$bash = Get-Command bash -ErrorAction SilentlyContinue
$nodejsExample = Join-Path $script:RepoRoot 'examples\nodejs'
if (-not $bash) {
    Skip 'Git Bash(bash)가 없어 CLI 스캔 단계를 건너뜁니다. UI 흐름은 수동 체크리스트로 확인하세요.'
} elseif (-not (Test-Path $nodejsExample)) {
    Skip "examples\nodejs 예제를 찾지 못해 CLI 스캔을 건너뜁니다: $nodejsExample"
} else {
    # 파일 공유 기본 경로인 홈 디렉터리 아래에 작업 폴더를 만든다.
    $work = Join-Path $env:USERPROFILE ('sbom-smoke-' + (Get-Date -Format 'yyyyMMddHHmmss'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        Copy-Item -Path (Join-Path $nodejsExample '*') -Destination $work -Recurse -Force
        Push-Location $work
        try {
            $bat = Join-Path $script:RepoRoot 'scripts\scan-sbom.bat'
            & $bat --project SmokeApp --version 0.0.1 --notice --generate-only
        } finally {
            Pop-Location
        }
        $noticeTxt = Join-Path $work 'SmokeApp_0.0.1_NOTICE.txt'
        $noticeHtml = Join-Path $work 'SmokeApp_0.0.1_NOTICE.html'
        if ((Test-Path $noticeTxt) -and (Test-Path $noticeHtml)) {
            Pass "고지문이 호스트 폴더에 생성됨: $work"
        } else {
            Failed "고지문이 호스트 폴더에 나타나지 않았습니다. 파일 공유 또는 명명 파이프 마운트를 의심하세요: $work"
        }
    } finally {
        Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 4) 웹 UI 컨테이너 헬스체크 (HTTP 200)
# ---------------------------------------------------------------------------
Section '4. 웹 UI 헬스체크'
$uiOut = Join-Path $env:USERPROFILE ('sbom-ui-smoke-' + (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $uiOut -Force | Out-Null
$cid = $null
try {
    $cid = docker run -d --rm `
        -p "$($UiPort):8080" `
        -v "$($uiOut):/src" `
        -v "$($uiOut):/host-output" `
        -v '\\.\pipe\docker_engine:\\.\pipe\docker_engine' `
        -e MODE=UI -e UI_PORT=8080 -e "SBOM_UI_HOST_DIR=$uiOut" `
        $Image
    if ($LASTEXITCODE -ne 0 -or -not $cid) {
        Failed 'UI 컨테이너를 시작하지 못했습니다.'
    } else {
        $ok = $false
        foreach ($i in 1..30) {
            Start-Sleep -Seconds 2
            try {
                $resp = Invoke-WebRequest -Uri "http://localhost:$UiPort" -UseBasicParsing -TimeoutSec 5
                if ($resp.StatusCode -eq 200) { $ok = $true; break }
            } catch {
                # 아직 기동 중일 수 있다. 계속 폴링.
            }
        }
        if ($ok) { Pass "웹 UI 응답 200 OK (http://localhost:$UiPort)" }
        else { Failed "웹 UI가 시간 내에 200을 반환하지 않았습니다 (포트 $UiPort 충돌 여부 확인)." }
    }
} finally {
    if ($cid) { docker stop $cid *> $null }
    Remove-Item -Path $uiOut -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 5) 음성 테스트 — 공유되지 않은 경로에서는 산출물이 안 나타나는 함정 재현
#    공유 밖 경로를 일반적으로 정하기 어려우므로 best-effort. 정하지 못하면 SKIP.
# ---------------------------------------------------------------------------
Section '5. 비공유 경로 함정 재현 (best-effort)'
if (-not $bash) {
    Skip 'Git Bash가 없어 음성 테스트를 건너뜁니다.'
} else {
    # Docker Desktop 기본 공유는 보통 %USERPROFILE% 트리만 포함한다. 시스템 임시
    # 폴더(C:\Windows\Temp)는 공유 밖인 경우가 많아 함정 재현 후보로 쓴다.
    $unshared = Join-Path $env:SystemRoot ('Temp\sbom-unshared-' + (Get-Date -Format 'yyyyMMddHHmmss'))
    try {
        New-Item -ItemType Directory -Path $unshared -Force | Out-Null
        Copy-Item -Path (Join-Path $nodejsExample '*') -Destination $unshared -Recurse -Force
        Push-Location $unshared
        try {
            $bat = Join-Path $script:RepoRoot 'scripts\scan-sbom.bat'
            & $bat --project UnsharedApp --version 0.0.1 --notice --generate-only *> $null
        } finally {
            Pop-Location
        }
        if (Test-Path (Join-Path $unshared 'UnsharedApp_0.0.1_bom.json')) {
            Skip '이 경로가 파일 공유에 포함되어 함정이 재현되지 않았습니다. 환경에 따라 정상입니다.'
        } else {
            Pass '공유 밖 경로에서는 산출물이 나타나지 않음을 확인(scan-sbom.sh가 이 경우를 오류로 잡음).'
        }
    } catch {
        Skip "음성 테스트를 수행하지 못했습니다: $($_.Exception.Message)"
    } finally {
        Remove-Item -Path $unshared -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 결과
# ---------------------------------------------------------------------------
Section '결과'
if ($script:Fail -eq 0) {
    Write-Host '모든 자동 검증을 통과했습니다(스킵 제외). 나머지는 수동 체크리스트로 확인하세요.' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($script:Fail)개 항목이 실패했습니다. 위 로그를 확인하세요." -ForegroundColor Red
    exit 1
}
