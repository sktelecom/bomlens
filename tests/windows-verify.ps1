<#
.SYNOPSIS
    Windows 데스크톱 앱 e2e 검증 턴키 키트 — 자동 스모크 실행과 화면 캡처를 한 곳에서.

.DESCRIPTION
    실제 Windows PC에서 데스크톱 앱(SBOM-Generator-*.exe)을 검증할 때 쓴다. 두 가지 일을 한다.

      1) 자동 스모크: tests/windows-smoke.ps1을 실행해 명명 파이프 마운트, 파일 공유 경로,
         NOTICE 생성, UI 컨테이너 HTTP 200을 비대화형으로 확인한다.
      2) 화면 캡처: GUI/OS 전용 화면(SmartScreen 경고, Rancher 설치, 앱 실행, 결과 다운로드)을
         PNG로 저장한다. Claude Code(Windows)가 그대로 실행하거나 사람이 직접 실행한다.

    Claude는 명령 실행과 캡처, docs 반영, 커밋을 할 수 있다. 버튼 클릭과 드래그처럼 GUI를
    조작하는 순간은 사람이 화면을 띄워 두고, 그 상태에서 이 스크립트로 캡처한다.

.PARAMETER Smoke
    tests/windows-smoke.ps1 자동 스모크를 실행한다.

.PARAMETER Capture
    캡처할 화면 이름. 결과는 docs/images/<이름>.png 로 저장된다.
    추천 이름: smartscreen, rancher-install, app-running, app-results, bat-console

.PARAMETER Window
    전체 화면 대신 현재 맨 앞 창(foreground window)만 캡처한다.

.PARAMETER Delay
    캡처 전 대기 시간(초). 그동안 캡처할 창을 맨 앞으로 가져온다. 기본 5초.

.PARAMETER OutDir
    캡처 저장 폴더. 기본 docs/images.

.EXAMPLE
    # 자동 스모크 실행
    powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Smoke

.EXAMPLE
    # SmartScreen 경고를 띄운 뒤, 5초 안에 그 창을 맨 앞으로 두면 캡처된다
    powershell -ExecutionPolicy Bypass -File tests\windows-verify.ps1 -Capture smartscreen -Window

.NOTES
    Windows 전용. PowerShell 5.1 또는 7+ 에서 동작.
#>

[CmdletBinding()]
param(
    [switch]$Smoke,
    [string]$Capture,
    [switch]$Window,
    [int]$Delay = 5,
    [string]$OutDir
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

if ($env:OS -ne "Windows_NT") {
    Write-Host "[경고] 이 스크립트는 Windows 전용입니다. 현재 OS에서는 캡처가 동작하지 않습니다." -ForegroundColor Yellow
}

function Invoke-Smoke {
    $smoke = Join-Path $PSScriptRoot "windows-smoke.ps1"
    if (-not (Test-Path $smoke)) {
        Write-Host "[오류] windows-smoke.ps1을 찾을 수 없습니다: $smoke" -ForegroundColor Red
        exit 1
    }
    Write-Host "=== 자동 스모크 실행 (windows-smoke.ps1) ===" -ForegroundColor Cyan
    & $smoke
    Write-Host "스모크 종료 코드: $LASTEXITCODE"
}

function Save-Screenshot {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [switch]$ForegroundOnly,
        [int]$DelaySeconds = 5,
        [string]$Destination
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # 맨 앞 창만 캡처할 때 창 영역을 구하는 P/Invoke.
    if (-not ("SbomCapture.Win32" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace SbomCapture {
    public struct RECT { public int Left, Top, Right, Bottom; }
    public static class Win32 {
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    }
}
"@
    }

    if ($DelaySeconds -gt 0) {
        Write-Host "캡처할 창을 맨 앞으로 두세요. $DelaySeconds초 뒤 캡처합니다..." -ForegroundColor Yellow
        for ($i = $DelaySeconds; $i -gt 0; $i--) {
            Write-Host "  $i" -NoNewline; Start-Sleep -Seconds 1; Write-Host "`r" -NoNewline
        }
    }

    if ($ForegroundOnly) {
        $h = [SbomCapture.Win32]::GetForegroundWindow()
        $r = New-Object SbomCapture.RECT
        [void][SbomCapture.Win32]::GetWindowRect($h, [ref]$r)
        $x = $r.Left; $y = $r.Top
        $w = $r.Right - $r.Left; $hgt = $r.Bottom - $r.Top
    } else {
        $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $x = $vs.X; $y = $vs.Y; $w = $vs.Width; $hgt = $vs.Height
    }

    if ($w -le 0 -or $hgt -le 0) {
        Write-Host "[오류] 캡처 영역이 올바르지 않습니다 ($w x $hgt)." -ForegroundColor Red
        return $false
    }

    $bmp = New-Object System.Drawing.Bitmap $w, $hgt
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen($x, $y, 0, 0, (New-Object System.Drawing.Size $w, $hgt))
    $bmp.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose(); $bmp.Dispose()

    Write-Host "[저장됨] $Destination  ($w x $hgt)" -ForegroundColor Green
    return $true
}

# --- 본문 ---
$didSomething = $false

if ($Smoke) {
    Invoke-Smoke
    $didSomething = $true
}

if ($Capture) {
    $dir = if ($OutDir) { $OutDir } else { Join-Path $repoRoot "docs\images" }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $safe = ($Capture -replace '[^a-zA-Z0-9._-]', '-')
    $dest = Join-Path $dir "$safe.png"
    Save-Screenshot -Name $safe -ForegroundOnly:$Window -DelaySeconds $Delay -Destination $dest | Out-Null
    Write-Host "docs에서 참조하려면: ![설명](images/$safe.png)"
    $didSomething = $true
}

if (-not $didSomething) {
    Write-Host "할 일을 지정하세요. 예:" -ForegroundColor Yellow
    Write-Host "  -Smoke                         자동 스모크 실행"
    Write-Host "  -Capture smartscreen -Window   맨 앞 창을 docs/images/smartscreen.png 로 캡처"
    Write-Host "자세한 사용법: Get-Help tests\windows-verify.ps1 -Full"
}
