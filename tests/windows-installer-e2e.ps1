<#
.SYNOPSIS
    릴리스된 BomLens-Setup.exe의 설치→기동→스캔 전 여정을 Windows에서 촘촘히 검증한다.

.DESCRIPTION
    docs/start/no-cli.md의 Path A(데스크톱 앱) 가이드 순서를 그대로 따라가며, 최종 사용자가
    실제로 겪는 경로를 비대화형으로 확인한다. 기존 windows-smoke.ps1이 .bat 런처 레이어만
    검증하는 것과 달리, 이 스크립트는 릴리스 산출물 exe 그 자체를 대상으로 한다.

      1) 릴리스 exe 획득(latest 다운로드 또는 -ExePath)
      2) 사일런트 설치(/S)와 설치 위치·언인스톨러·바로가기 확인
      3) 설치된 exe의 버전 메타데이터가 릴리스 태그와 일치하는지(태그→extraMetadata.version 주입)
      4) 부팅 스모크(SBOM_SMOKE=1, Docker 불필요) — startup.log의 "준비 완료" 도달
      5) 전 여정(Docker 필요, 없으면 SKIP) — 앱 실제 기동→이미지 풀→UI 컨테이너→실제 스캔
         산출물(CycloneDX/SPDX/NOTICE)→앱 종료 시 컨테이너 정리
      6) 언인스톨(/S)과 설치 폴더 제거
      7) 결과 요약

    자동화할 수 없는 GUI 단계(SmartScreen "실행" 클릭, ZIP 드래그드롭)는 조용히 넘기지 않고
    SKIP으로 분명히 남기고, windows-verify.ps1 -Capture로 보완하도록 안내한다. 종료 코드는
    실패가 하나라도 있으면 1, 모두 통과/스킵이면 0 이다.

.PARAMETER Version
    대상 릴리스 태그(예: v1.8.3). 미지정 시 latest를 내려받고, 버전 검증 기준은 원격 최신 태그.

.PARAMETER ExePath
    이미 받은(또는 CI 산출물) BomLens-Setup.exe 경로. 지정 시 다운로드 단계를 건너뛴다.

.PARAMETER ExpectedVersion
    버전 스탬프 엄격 검증값(예: 1.8.3). 미지정 시 대상 태그에서 'v'를 뗀 값.

.PARAMETER Image
    스캐너 이미지 override. 기본은 앱 내부 기본값과 동일한 ghcr.io/sktelecom/bomlens:latest.

.PARAMETER UserDataDir
    startup.log가 놓이는 폴더 override. 기본 %APPDATA%\sbom-generator-desktop.

.PARAMETER PullTimeoutMin
    첫 이미지 풀 포함 앱 기동 대기 한도(분). 기본 20.

.PARAMETER KeepInstalled
    디버깅용 — 마지막 언인스톨 단계를 생략한다.

.NOTES
    실제 Windows + Rancher Desktop / Docker Desktop 에서 실행한다. PowerShell 5.1/7+ 동작.
    실행: powershell -ExecutionPolicy Bypass -File tests\windows-installer-e2e.ps1
    사설 저장소라 익명 다운로드가 막히면 gh(로그인) 또는 -ExePath 를 쓴다.
#>

[CmdletBinding()]
param(
    [string]$Version,
    [string]$ExePath,
    [string]$ExpectedVersion,
    [string]$Image = $(if ($env:SBOM_SCANNER_IMAGE) { $env:SBOM_SCANNER_IMAGE } else { 'ghcr.io/sktelecom/bomlens:latest' }),
    [string]$UserDataDir,
    [int]$PullTimeoutMin = 20,
    [switch]$KeepInstalled
)

$ErrorActionPreference = 'Stop'
$script:Fail = 0
$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# --- 상수(코드베이스와 정렬) ---------------------------------------------------
# 저장소: origin 원격에서 owner/repo를 뽑되, 실패하면 알려진 값으로.
$script:Repo = 'sktelecom/bomlens'
$script:ExeName = 'BomLens-Setup.exe'
$script:InstallExe = Join-Path $env:LOCALAPPDATA 'Programs\BomLens\BomLens.exe'
$script:DesktopLabel = 'bomlens.desktop=1'          # container.mjs DESKTOP_LABEL
$script:ReadyEn = 'Ready. Opening the UI.'          # i18n.mjs en.ready
$script:ReadyKo = '준비 완료. UI를 엽니다.'          # i18n.mjs ko.ready

function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Skip($msg) { Write-Host "[SKIP] $msg" -ForegroundColor Yellow }
function Failed($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:Fail++ }
function Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# docker 등 네이티브 명령은 정상 동작 중에도 stderr로 경고를 낸다. PS 5.1에서
# $ErrorActionPreference='Stop'과 겹치면 그 stderr 한 줄이 종료 오류로 승격돼 엔진이
# 멀쩡한데도 스크립트가 멈춘다. 종료 코드만 보는 래퍼(windows-smoke.ps1과 동일 규약).
function Invoke-Native {
    param([Parameter(Mandatory)][scriptblock]$Script)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Script 2>&1 | Out-Null } finally { $ErrorActionPreference = $prev }
    return $LASTEXITCODE
}

# 네이티브 명령의 stdout을 문자열로 회수한다(git/docker ps/curl 출력 파싱용).
function Get-NativeOut {
    param([Parameter(Mandatory)][scriptblock]$Script)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = (& $Script 2>$null | Out-String) } finally { $ErrorActionPreference = $prev }
    return $out
}

# startup.log 경로 해석: -UserDataDir 우선 → 기본 %APPDATA%\sbom-generator-desktop →
# 못 찾으면 %APPDATA% 하위에서 startup.log 를 훑는다(패키지 name 변경 대비).
function Resolve-StartupLog {
    if ($UserDataDir) { return (Join-Path $UserDataDir 'startup.log') }
    $default = Join-Path (Join-Path $env:APPDATA 'sbom-generator-desktop') 'startup.log'
    if (Test-Path $default) { return $default }
    $hit = Get-ChildItem -Path $env:APPDATA -Filter 'startup.log' -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $default
}

# 로그 파일이 성공 패턴을 담을 때까지(또는 실패/타임아웃까지) 폴링한다.
# 반환: 'ok' | 'failed' | 'timeout'. 각 실행마다 앱이 로그를 새로 쓰므로 stale 걱정은 없다.
function Wait-ForLog {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$OkPatterns,
        [string[]]$FailPatterns = @('boot state: failed'),
        [int]$TimeoutSec = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $Path) {
            $text = Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($text) {
                foreach ($fp in $FailPatterns) { if ($text -match [regex]::Escape($fp)) { return 'failed' } }
                foreach ($ok in $OkPatterns) { if ($text -match [regex]::Escape($ok)) { return 'ok' } }
            }
        }
        Start-Sleep -Milliseconds 800
    }
    return 'timeout'
}

# 설치된 앱을 강제로 정리한다(그레이스풀 종료가 관측되지 않았을 때의 백스톱).
function Stop-App {
    Invoke-Native { taskkill /IM BomLens.exe /F /T } | Out-Null
}

# SSE 응답에서 마지막 `event: done` 다음의 data 페이로드(JSON 문자열)를 뽑는다.
function Get-DonePayload {
    param([Parameter(Mandatory)][string]$Raw)
    $lines = $Raw -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -eq 'event: done') {
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                $l = $lines[$j]
                if ($l -match '^data: (.*)$') { return $Matches[1] }
            }
        }
    }
    return $null
}

# 임시 소스 zip을 만든다. PowerShell Compress-Archive는 엔트리 경로에 역슬래시를 써서
# 컨테이너 unzip이 거부하므로(메모리: windows-ps51-verify-gotchas), 엔트리 이름을 직접
# 슬래시로 지정해 만든다. no-cli.md의 "ZIP 업로드" 경로를 그대로 재현한다.
function New-SourceZip {
    param([Parameter(Mandatory)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    try {
        $entry = $zip.CreateEntry('app/package.json')
        $sw = New-Object System.IO.StreamWriter($entry.Open())
        $sw.Write('{"name":"bomlens-e2e-fixture","version":"0.0.1","dependencies":{"left-pad":"1.3.0"}}')
        $sw.Dispose()
    } finally {
        $zip.Dispose()
    }
}

# ===========================================================================
# 0. 프리플라이트
# ===========================================================================
Section '0. 프리플라이트'
if ($env:OS -ne 'Windows_NT') { Failed '이 스크립트는 Windows 전용입니다.'; exit 1 }
Write-Host "PowerShell $($PSVersionTable.PSVersion) / $([System.Environment]::OSVersion.VersionString)"

# origin 원격에서 owner/repo 추출(있으면). 없으면 기본값 유지.
$originUrl = (Get-NativeOut { git -C $script:RepoRoot remote get-url origin }).Trim()
if ($originUrl -match 'github\.com[:/]+([^/]+/[^/.]+)') { $script:Repo = $Matches[1] }
Write-Host "대상 저장소: $script:Repo"

# 기대 버전 해석: ExpectedVersion > Version(태그) > 원격 최신 태그. 실패하면 null(버전 검증 SKIP).
if (-not $ExpectedVersion) {
    if ($Version) {
        $ExpectedVersion = ($Version -replace '^v', '')
    } else {
        $tagsRaw = Get-NativeOut { git -C $script:RepoRoot ls-remote --tags origin }
        $vers = @()
        foreach ($line in ($tagsRaw -split "`n")) {
            if ($line -match 'refs/tags/v(\d+\.\d+\.\d+)(?!\^)') { $vers += $Matches[1] }
        }
        if ($vers.Count -gt 0) {
            $ExpectedVersion = ($vers | Sort-Object { [version]$_ } | Select-Object -Last 1)
        }
    }
}
if ($ExpectedVersion) { Write-Host "기대 버전: $ExpectedVersion" } else { Skip '기대 버전을 해석하지 못했습니다(버전 스탬프 검증은 SKIP됩니다).' }

$scratch = Join-Path $env:TEMP ('bomlens-e2e-' + (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

# ===========================================================================
# 1. 릴리스 exe 획득
# ===========================================================================
Section '1. 릴리스 exe 획득'
$exe = $null
if ($ExePath) {
    if (-not (Test-Path $ExePath)) { Failed "지정한 -ExePath가 없습니다: $ExePath"; exit 1 }
    $exe = (Resolve-Path $ExePath).Path
    Pass "로컬 exe 사용: $exe"
} else {
    $exe = Join-Path $scratch $script:ExeName
    $tagRef = if ($Version) { $Version } else { 'latest' }
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    $downloaded = $false
    # 사설 저장소를 고려해 gh(로그인)를 먼저 시도한다.
    if ($gh) {
        $rc = Invoke-Native { gh release download $tagRef --repo $script:Repo --pattern $script:ExeName --dir $scratch --clobber }
        if ($rc -eq 0 -and (Test-Path $exe)) { $downloaded = $true; Pass "gh release download 성공: $tagRef" }
    }
    # 공개 저장소면 브라우저 URL로도 받힌다.
    if (-not $downloaded) {
        $url = if ($Version) {
            "https://github.com/$script:Repo/releases/download/$Version/$script:ExeName"
        } else {
            "https://github.com/$script:Repo/releases/latest/download/$script:ExeName"
        }
        try {
            Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -ErrorAction Stop
            if (Test-Path $exe) { $downloaded = $true; Pass "다운로드 성공: $url" }
        } catch {
            Failed "exe 다운로드 실패($url). 사설 저장소면 'gh auth login' 후 재시도하거나 -ExePath로 지정하세요. 원인: $($_.Exception.Message)"
            exit 1
        }
    }
    if (-not $downloaded) { Failed 'exe를 획득하지 못했습니다.'; exit 1 }
}
$exeSize = (Get-Item $exe).Length
if ($exeSize -lt 20MB) { Failed "설치 파일이 비정상적으로 작습니다($([math]::Round($exeSize/1MB,1)) MB). 손상/부분 다운로드 의심." }
else { Pass "설치 파일 크기 확인: $([math]::Round($exeSize/1MB,1)) MB" }

# ===========================================================================
# 2. 사일런트 설치
# ===========================================================================
Section '2. 사일런트 설치'
Skip '대화형 마법사 + SmartScreen "실행" 클릭은 자동화 불가 — windows-verify.ps1 -Capture smartscreen 로 별도 캡처하세요.'
$installRc = 0
try {
    $p = Start-Process -FilePath $exe -ArgumentList '/S' -Wait -PassThru
    $installRc = $p.ExitCode
} catch {
    Failed "사일런트 설치 실행 실패: $($_.Exception.Message)"
}
if ($installRc -ne 0) { Skip "인스톨러 종료 코드 $installRc (NSIS /S는 보통 0). 계속 진행해 설치 결과로 판정합니다." }

if (Test-Path $script:InstallExe) { Pass "설치 위치 확인: $script:InstallExe" }
else { Failed "설치된 실행 파일을 찾지 못했습니다: $script:InstallExe"; }

$installDir = Split-Path $script:InstallExe
$uninstaller = Join-Path $installDir 'Uninstall BomLens.exe'
if (Test-Path $uninstaller) { Pass "언인스톨러 확인: $uninstaller" }
else { Skip "언인스톨러를 예상 경로에서 찾지 못했습니다: $uninstaller" }

# 시작 메뉴 바로가기(사용자/전체). 없으면 SKIP.
$lnkRoots = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
)
$lnk = $null
foreach ($root in $lnkRoots) {
    if (Test-Path $root) {
        $hit = Get-ChildItem -Path $root -Filter 'BomLens.lnk' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $lnk = $hit.FullName; break }
    }
}
if ($lnk) { Pass "시작 메뉴 바로가기 확인: $lnk" } else { Skip '시작 메뉴 바로가기를 찾지 못했습니다(설치 옵션에 따라 정상일 수 있음).' }

# ===========================================================================
# 3. 버전 스탬프(태그 → extraMetadata.version 주입 확인)
# ===========================================================================
Section '3. 버전 스탬프'
if (Test-Path $script:InstallExe) {
    $vi = (Get-Item $script:InstallExe).VersionInfo
    $pv = ($vi.ProductVersion, $vi.FileVersion | Where-Object { $_ } | Select-Object -First 1)
    Write-Host "설치된 exe 버전 메타데이터: ProductVersion=$($vi.ProductVersion) FileVersion=$($vi.FileVersion)"
    if ($ExpectedVersion) {
        if ($pv -and ($pv -like "$ExpectedVersion*")) { Pass "버전 스탬프 일치: $pv (기대 $ExpectedVersion)" }
        else { Failed "버전 스탬프 불일치: 설치본 '$pv' vs 기대 '$ExpectedVersion' (태그→extraMetadata.version 주입 확인 필요)" }
    } else {
        Skip "기대 버전이 없어 스탬프 대조를 건너뜁니다(설치본: $pv)."
    }
} else {
    Skip '설치 파일이 없어 버전 검증을 건너뜁니다.'
}

# ===========================================================================
# 4. 부팅 스모크(SBOM_SMOKE=1, Docker 불필요)
# ===========================================================================
Section '4. 부팅 스모크(Docker 불필요)'
if (-not (Test-Path $script:InstallExe)) {
    Skip '설치 파일이 없어 부팅 스모크를 건너뜁니다.'
} else {
    Stop-App
    $logPath = Resolve-StartupLog
    if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
    $env:SBOM_SMOKE = '1'
    Remove-Item Env:\SBOM_LANG -ErrorAction SilentlyContinue
    try {
        Start-Process -FilePath $script:InstallExe | Out-Null
        # SBOM_SMOKE 경로는 Docker/컨테이너를 건너뛰고 상태 화면에서 t.ready만 찍고 멈춘다.
        $r = Wait-ForLog -Path $logPath -OkPatterns @($script:ReadyEn, $script:ReadyKo) -TimeoutSec 60
        switch ($r) {
            'ok'      { Pass "부팅 스모크 통과 — 상태 로그에 '준비 완료' 도달 ($logPath)" }
            'failed'  { Failed "부팅 스모크 중 실패 상태가 로그에 나타났습니다: $logPath" }
            'timeout' { Failed "부팅 스모크: 60초 내 '준비 완료'가 로그에 나타나지 않았습니다: $logPath" }
        }
    } finally {
        Stop-App
        Remove-Item Env:\SBOM_SMOKE -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# 5. 전 여정(Docker 필요, 없으면 이하 SKIP)
# ===========================================================================
Section '5. 전 여정(실제 기동→풀→UI 컨테이너→스캔→정리)'
$dockerOk = $false
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Skip 'docker가 PATH에 없습니다 — 전 여정을 건너뜁니다(Rancher/Docker Desktop 설치 후 재실행).'
} elseif ((Invoke-Native { docker info }) -ne 0) {
    Skip 'Docker 엔진이 실행 중이 아닙니다 — 전 여정을 건너뜁니다(엔진을 켜고 재실행).'
} else {
    $dockerOk = $true
    Pass 'Docker 엔진 실행 중'
}

if ($dockerOk -and (Test-Path $script:InstallExe)) {
    # 출력 폴더를 홈 트리 아래 임시 폴더로 지정한다 — 사용자의 실제 ~/sbom-output을
    # 건드리지 않고, Rancher/Docker Desktop이 기본 공유하는 경로라 마운트가 된다.
    $outDir = Join-Path $env:USERPROFILE ('bomlens-e2e-out-' + (Get-Date -Format 'yyyyMMddHHmmss'))
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $logPath = Resolve-StartupLog
    $cid = $null
    try {
        Stop-App
        if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
        Remove-Item Env:\SBOM_SMOKE -ErrorAction SilentlyContinue
        $env:SBOM_LANG = 'en'                       # 로그 문구를 영어로 고정해 결정론적으로 판정
        $env:SBOM_OUTPUT_DIR = $outDir
        $env:SBOM_SCANNER_IMAGE = $Image

        # 5a. 앱 실제 기동 — 로그로 부팅 상태 전이를 추적(첫 풀 포함이라 넉넉히 대기).
        Start-Process -FilePath $script:InstallExe | Out-Null
        $bootTimeout = [Math]::Max(60, $PullTimeoutMin * 60)
        $r = Wait-ForLog -Path $logPath -OkPatterns @($script:ReadyEn) -TimeoutSec $bootTimeout
        if ($r -ne 'ok') {
            $tail = if (Test-Path $logPath) { (Get-Content $logPath -Tail 15 -Encoding UTF8) -join "`n" } else { '(로그 없음)' }
            Failed "앱이 ${bootTimeout}초 내 준비 상태에 도달하지 못했습니다($r). 로그 tail:`n$tail"
        } else {
            Pass '앱 기동 완료 — 상태 로그가 준비 완료(READY)에 도달'

            # 5b. 앱이 띄운 UI 컨테이너와 게시 포트 탐지(DESKTOP_LABEL 기준).
            $port = $null
            foreach ($i in 1..15) {
                $ports = (Get-NativeOut { docker ps --filter "label=$script:DesktopLabel" --format '{{.Ports}}' }).Trim()
                if ($ports -match ':(\d+)->8080') { $port = [int]$Matches[1]; break }
                $ids = (Get-NativeOut { docker ps -q --filter "label=$script:DesktopLabel" }).Trim()
                if ($ids) { $cid = ($ids -split "`n")[0].Trim() }
                Start-Sleep -Seconds 1
            }
            $ids = (Get-NativeOut { docker ps -q --filter "label=$script:DesktopLabel" }).Trim()
            if ($ids) { $cid = ($ids -split "`n")[0].Trim() }

            if (-not $port) {
                Failed 'DESKTOP_LABEL이 붙은 UI 컨테이너의 게시 포트를 찾지 못했습니다.'
            } else {
                Pass "UI 컨테이너 탐지 — 호스트 포트 $port"

                # 5c. UI 헬스 200 + capabilities.hostDir가 드라이브 경로인지(windows-smoke와 동일 단언).
                $base = "http://127.0.0.1:$port"
                $healthy = $false
                foreach ($i in 1..15) {
                    try {
                        $resp = Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 5
                        if ($resp.StatusCode -eq 200) { $healthy = $true; break }
                    } catch { }
                    Start-Sleep -Seconds 2
                }
                if ($healthy) { Pass "웹 UI 응답 200 OK ($base)" } else { Failed "웹 UI가 200을 반환하지 않았습니다($base)." }

                try {
                    $caps = Invoke-RestMethod -Uri "$base/capabilities" -TimeoutSec 5
                    if ($caps.hostDir -match '^[A-Za-z]:[\\/]') { Pass "capabilities.hostDir가 드라이브 경로: $($caps.hostDir)" }
                    else { Failed "capabilities.hostDir가 드라이브 경로가 아닙니다(sibling 스캔 실패 우려): '$($caps.hostDir)'" }
                } catch {
                    Failed "capabilities 조회 실패: $($_.Exception.Message)"
                }

                # 5d. 실제 스캔(no-cli.md의 ZIP 업로드 경로) — upload → scan-stream(SPDX 포함).
                $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
                if (-not $curl -and $healthy) {
                    Skip 'curl.exe가 없어 스캔 e2e를 건너뜁니다(최신 Windows에는 기본 포함).'
                } elseif ($healthy) {
                    $proj = 'BomLensE2E'; $ver = '0.0.1'; $prefix = "${proj}_${ver}"
                    $zip = Join-Path $scratch 'e2e-src.zip'
                    New-SourceZip -ZipPath $zip
                    $upRaw = Get-NativeOut { curl.exe -fsS -F "kind=zip" -F "file=@$zip" "$base/upload?kind=zip" }
                    $token = $null
                    try { $token = ($upRaw | ConvertFrom-Json).token } catch { }
                    if (-not $token) {
                        Failed "업로드가 토큰을 반환하지 않았습니다: $upRaw"
                    } else {
                        Pass '소스 ZIP 업로드 성공(토큰 수신)'
                        $qs = "project=$proj&version=$ver&source=zip-upload&token=$token&spdx=true&security=false"
                        $sse = Get-NativeOut { curl.exe -fsS -N --max-time 300 "$base/scan-stream?$qs" }
                        $donePayload = Get-DonePayload -Raw $sse
                        if (-not $donePayload) {
                            Failed 'scan-stream에서 done 이벤트를 받지 못했습니다.'
                        } else {
                            $done = $null
                            try { $done = $donePayload | ConvertFrom-Json } catch { }
                            if (-not $done) {
                                Failed "done 페이로드 파싱 실패: $($donePayload.Substring(0, [Math]::Min(200, $donePayload.Length)))"
                            } elseif ($done.ok -ne $true) {
                                Failed "스캔이 ok=true로 끝나지 않았습니다(mode=$($done.mode))."
                            } else {
                                Pass "스캔 완료 — done.ok=true, mode=$($done.mode)"
                                $names = @($done.results | ForEach-Object { $_.name })
                                # 산출물 단언: CycloneDX SBOM(필수), SPDX(필수, spdx=true), NOTICE(기대).
                                if ($names -match '_bom\.json$') { Pass 'CycloneDX SBOM 산출물 확인(_bom.json)' } else { Failed "결과에 _bom.json이 없습니다: $($names -join ', ')" }
                                if ($names -match '_bom\.spdx\.json$') { Pass 'SPDX 산출물 확인(_bom.spdx.json)' } else { Failed "결과에 _bom.spdx.json이 없습니다(spdx=true인데): $($names -join ', ')" }
                                if ($names -match '_NOTICE\.') { Pass '고지문 산출물 확인(_NOTICE.*)' } else { Skip "결과에 _NOTICE가 없습니다: $($names -join ', ')" }

                                # 호스트 출력 폴더에 실제 파일이 떨어졌는지(마운트 왕복 검증).
                                $runDir = Join-Path $outDir $prefix
                                $hostBom = Join-Path $runDir "${prefix}_bom.json"
                                if (Test-Path $hostBom) {
                                    Pass "호스트 출력 폴더에 SBOM 파일 생성 확인: $hostBom"
                                    # SBOM 내용 최소 단언: CycloneDX 포맷.
                                    try {
                                        $bom = Get-Content $hostBom -Raw -Encoding UTF8 | ConvertFrom-Json
                                        if ($bom.bomFormat -eq 'CycloneDX') { Pass "SBOM bomFormat=CycloneDX (specVersion=$($bom.specVersion))" }
                                        else { Failed "SBOM bomFormat이 CycloneDX가 아닙니다: $($bom.bomFormat)" }
                                    } catch { Failed "호스트 SBOM 파싱 실패: $($_.Exception.Message)" }
                                    # SPDX 내용 최소 단언.
                                    $hostSpdx = Join-Path $runDir "${prefix}_bom.spdx.json"
                                    if (Test-Path $hostSpdx) {
                                        try {
                                            $spdx = Get-Content $hostSpdx -Raw -Encoding UTF8 | ConvertFrom-Json
                                            if ($spdx.spdxVersion -eq 'SPDX-2.3') { Pass "SPDX spdxVersion=SPDX-2.3" }
                                            else { Failed "SPDX spdxVersion이 SPDX-2.3이 아닙니다: $($spdx.spdxVersion)" }
                                        } catch { Failed "호스트 SPDX 파싱 실패: $($_.Exception.Message)" }
                                    } else { Skip "호스트에 SPDX 파일이 없습니다: $hostSpdx" }
                                } else {
                                    Failed "호스트 출력 폴더에 SBOM 파일이 없습니다(마운트/파일 공유 의심): $hostBom"
                                }
                            }
                        }
                    }
                }

                # 5e. 앱 종료 시 컨테이너 정리 — 그레이스풀 종료를 시도하고 컨테이너가 사라지는지.
                #     taskkill /F는 before-quit 정리를 건너뛰므로 먼저 창을 정상 종료시킨다.
                Invoke-Native { taskkill /IM BomLens.exe /T } | Out-Null
                $gone = $false
                foreach ($i in 1..20) {
                    Start-Sleep -Seconds 1
                    $ids = (Get-NativeOut { docker ps -q --filter "label=$script:DesktopLabel" }).Trim()
                    if (-not $ids) { $gone = $true; break }
                }
                if ($gone) { Pass '앱 종료 시 UI 컨테이너가 정리됨(고아 없음)' }
                else { Skip 'taskkill로 그레이스풀 종료가 관측되지 않았습니다 — 컨테이너 정리는 다음 기동의 cleanupOrphans/단위 테스트가 보장합니다.' }
            }
        }
    } finally {
        Stop-App
        if ($cid) { Invoke-Native { docker stop -t 3 $cid } | Out-Null }
        # 라벨이 붙은 잔여 컨테이너까지 정리.
        $leftover = (Get-NativeOut { docker ps -q --filter "label=$script:DesktopLabel" }).Trim()
        foreach ($id in ($leftover -split "`n")) { if ($id.Trim()) { Invoke-Native { docker stop -t 3 $id.Trim() } | Out-Null } }
        Remove-Item Env:\SBOM_LANG -ErrorAction SilentlyContinue
        Remove-Item Env:\SBOM_OUTPUT_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:\SBOM_SCANNER_IMAGE -ErrorAction SilentlyContinue
        Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} elseif ($dockerOk) {
    Skip '설치 파일이 없어 전 여정을 건너뜁니다.'
}

# ===========================================================================
# 6. 언인스톨
# ===========================================================================
Section '6. 언인스톨'
if ($KeepInstalled) {
    Skip '-KeepInstalled 지정 — 언인스톨을 건너뜁니다.'
} elseif (Test-Path $uninstaller) {
    try {
        $up = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru
        Start-Sleep -Seconds 3
        if (-not (Test-Path $script:InstallExe)) { Pass '언인스톨 완료 — 설치 실행 파일 제거 확인' }
        else { Failed "언인스톨 후에도 설치 파일이 남아 있습니다: $script:InstallExe" }
    } catch {
        Failed "언인스톨 실행 실패: $($_.Exception.Message)"
    }
} else {
    Skip '언인스톨러를 찾지 못해 언인스톨을 건너뜁니다.'
}

# ===========================================================================
# 정리 & 결과
# ===========================================================================
Remove-Item -Path $scratch -Recurse -Force -ErrorAction SilentlyContinue

Section '결과'
if ($script:Fail -eq 0) {
    Write-Host '모든 자동 검증을 통과했습니다(스킵 제외). GUI 항목(SmartScreen/드래그드롭)은 windows-verify.ps1 -Capture로 보완하세요.' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($script:Fail)개 항목이 실패했습니다. 위 로그를 확인하세요." -ForegroundColor Red
    exit 1
}
