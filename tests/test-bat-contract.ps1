<#
.SYNOPSIS
    Windows .bat 진입점 계약 테스트 — 스텁 docker로 실제 cmd.exe에서 .bat을 실행한다.

.DESCRIPTION
    tests/test-windows.sh 는 bash 계층(scan-sbom.sh 오케스트레이션)을 검증하지만,
    사용자가 실제로 실행하는 .bat 계층 — cmd.exe 파싱, Git Bash 탐색, PATHEXT 해석,
    cmd→bash 인자 전달 — 은 어디서도 실행되지 않았다. 이 테스트는 그 계층을
    Docker 데몬 없이 검증한다: 가짜 docker.exe 를 PATH 맨 앞에 놓고 .bat 3종을
    진짜 cmd.exe 로 돌린다.

    스텁이 .exe 인 이유: cmd 배치 파일이 다른 배치 파일을 `call` 없이 부르면 제어가
    돌아오지 않으므로 docker.bat 스텁은 호출 지점에서 원본 스크립트를 끊어 버린다.
    실제 docker 와 같은 동작은 실행 파일이어야 하며, 모든 Windows 에 있는
    .NET Framework csc.exe 로 실행 시점에 컴파일한다.

    모든 케이스는 stdin 을 NUL 로 돌린다 — check-setup.bat / sbom-ui.bat 말미의
    무조건 pause 가 CI 를 영구 블록하는 것을 막는다. sbom-ui.bat 의 브라우저 오픈은
    cmd 내장 start 라 스텁할 수 없다(fire-and-forget 이고 종료 코드에 영향 없음).

    windows-smoke.ps1(실제 Docker 필요, 수동 전용)과 달리 이 테스트는 hosted
    windows runner 에서 매 PR 실행된다.

.NOTES
    실행: pwsh -File tests\test-bat-contract.ps1   (Windows 전용, Git for Windows 필요)
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Fail = 0
$script:CaseN = 0
$script:RepoRoot = Split-Path -Parent $PSScriptRoot

function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Skip($msg) { Write-Host "[SKIP] $msg" -ForegroundColor Yellow }
function Failed($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:Fail++ }
function Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

if ($env:OS -ne 'Windows_NT') {
    Skip 'Windows 가 아니므로 .bat 계약 테스트를 건너뜁니다.'
    exit 0
}

$script:Work = Join-Path $env:TEMP ('bat-contract-' + [System.Diagnostics.Process]::GetCurrentProcess().Id)
New-Item -ItemType Directory -Path $script:Work -Force | Out-Null
$StubBin = Join-Path $script:Work 'stubbin'
New-Item -ItemType Directory -Path $StubBin -Force | Out-Null

# ---------------------------------------------------------------------------
# 스텁 docker.exe 컴파일
#   - 모든 호출을 DOCKER_STUB_LOG 에 기록하고 0 을 반환한다.
#   - PROJECT_NAME/PROJECT_VERSION 을 실은 `docker run`(후처리/단발 스테이지)에는
#     실제 컨테이너가 남겼을 SBOM 을 /host-output 마운트의 호스트 경로에 써서
#     --generate-only 의 "산출물이 호스트에 도착했는가" 최종 검사를 통과시킨다.
#     (tests/test-windows.sh 의 bash 스텁과 같은 규약)
# ---------------------------------------------------------------------------
Section '0. 스텁 docker.exe 준비'
$stubSource = @'
using System;
using System.IO;

class DockerStub {
    static int Main(string[] args) {
        string log = Environment.GetEnvironmentVariable("DOCKER_STUB_LOG");
        if (!string.IsNullOrEmpty(log)) {
            try { File.AppendAllText(log, "docker " + string.Join(" ", args) + Environment.NewLine); }
            catch (IOException) { }
        }
        string pn = null, pv = null, hostout = null, prev = null;
        foreach (string a in args) {
            if (prev == "-v") {
                if (a.EndsWith(":/host-output")) hostout = a.Substring(0, a.Length - ":/host-output".Length);
                else if (a.EndsWith(":/out") && hostout == null) hostout = a.Substring(0, a.Length - ":/out".Length);
            }
            if (a.StartsWith("PROJECT_NAME=")) pn = a.Substring("PROJECT_NAME=".Length);
            if (a.StartsWith("PROJECT_VERSION=")) pv = a.Substring("PROJECT_VERSION=".Length);
            prev = a;
        }
        if (args.Length > 0 && args[0] == "run" && pn != null && pv != null) {
            string dest = hostout == null ? "." : hostout;
            // Git Bash 가 MSYS 형식(/c/Users/...)을 넘기면 드라이브 경로로 되돌린다.
            if (dest.Length > 3 && dest[0] == '/' && dest[2] == '/')
                dest = dest[1] + ":" + dest.Substring(2);
            try {
                Directory.CreateDirectory(dest);
                File.WriteAllText(Path.Combine(dest, pn + "_" + pv + "_bom.json"),
                    "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1," +
                    "\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\"" + pn +
                    "\",\"version\":\"" + pv + "\"}},\"components\":[]}\n");
            } catch (Exception) { }
        }
        return 0;
    }
}
'@
$stubCs = Join-Path $script:Work 'docker-stub.cs'
Set-Content -Path $stubCs -Value $stubSource -Encoding ASCII
$csc = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) {
    Skip '.NET Framework csc.exe 를 찾지 못해 스텁을 만들 수 없습니다.'
    exit 0
}
& $csc /nologo ("/out:" + (Join-Path $StubBin 'docker.exe')) $stubCs | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $StubBin 'docker.exe'))) {
    Failed '스텁 docker.exe 컴파일에 실패했습니다.'
    exit 1
}
# 러너의 진짜 docker(Windows 컨테이너)보다 먼저 잡히도록 PATH 맨 앞에 둔다.
$env:PATH = "$StubBin;$env:PATH"
Pass "스텁 docker.exe 준비됨: $StubBin"

# ---------------------------------------------------------------------------
# .bat 실행 헬퍼 — cmd /d /s /c 로 실제 cmd.exe 파싱을 태우고, stdin NUL 과
# 케이스별 타임아웃으로 pause/행이 잡 전체를 잡아먹지 않게 한다.
# ---------------------------------------------------------------------------
function Invoke-Bat {
    param(
        [Parameter(Mandatory)][string]$Bat,
        [string]$BatArgs = '',
        [string]$Cwd = $script:RepoRoot,
        [int]$TimeoutSec = 120
    )
    $script:CaseN++
    $out = Join-Path $script:Work ("case{0}.out" -f $script:CaseN)
    $env:DOCKER_STUB_LOG = Join-Path $script:Work ("case{0}.docker.log" -f $script:CaseN)
    New-Item -ItemType File -Path $env:DOCKER_STUB_LOG -Force | Out-Null
    $cmdline = "`"$Bat`" $BatArgs < NUL > `"$out`" 2>&1"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = "/d /s /c `"$cmdline`""
    $psi.WorkingDirectory = $Cwd
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
    if ($timedOut) { try { $p.Kill() } catch { } }
    return @{
        TimedOut = $timedOut
        ExitCode = $(if ($timedOut) { -1 } else { $p.ExitCode })
        Output   = $(if (Test-Path $out) { Get-Content $out -Raw } else { '' })
        StubLog  = $(Get-Content $env:DOCKER_STUB_LOG -Raw -ErrorAction SilentlyContinue)
    }
}

try {
    # -----------------------------------------------------------------------
    # 1) scan-sbom.bat --help : Git Bash 탐색 + bash 위임 + 인자 전달
    # -----------------------------------------------------------------------
    Section '1. scan-sbom.bat --help'
    $r = Invoke-Bat -Bat (Join-Path $script:RepoRoot 'scripts\scan-sbom.bat') -BatArgs '--help'
    if ($r.TimedOut) { Failed 'scan-sbom.bat --help 가 시간 안에 끝나지 않았습니다.' }
    elseif ($r.ExitCode -eq 0 -and $r.Output -match '--project') {
        Pass 'Git Bash 를 찾아 위임하고 사용법(--project)을 출력했습니다.'
    } else {
        Failed "scan-sbom.bat --help 실패 (exit=$($r.ExitCode)):`n$($r.Output)"
    }

    # -----------------------------------------------------------------------
    # 2) scan-sbom.bat 전 구간: cmd → Git Bash → scan-sbom.sh → (스텁) docker
    # -----------------------------------------------------------------------
    Section '2. scan-sbom.bat --generate-only (전 구간)'
    $proj = Join-Path $script:Work 'proj'
    New-Item -ItemType Directory -Path $proj -Force | Out-Null
    Set-Content -Path (Join-Path $proj 'package.json') `
        -Value '{"name":"demo-app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}' -Encoding ASCII
    $r = Invoke-Bat -Bat (Join-Path $script:RepoRoot 'scripts\scan-sbom.bat') `
        -BatArgs '--project WinApp --version 0.0.1 --generate-only' -Cwd $proj
    $bom = Join-Path $proj 'WinApp_0.0.1\WinApp_0.0.1_bom.json'
    if ($r.TimedOut) { Failed 'scan-sbom.bat 스캔이 시간 안에 끝나지 않았습니다.' }
    elseif ($r.ExitCode -eq 0 -and $r.Output -match 'Analysis Complete' -and (Test-Path $bom)) {
        Pass "cmd → bash → docker 전 구간 완주, SBOM 이 호스트에 생성됨: $bom"
    } else {
        Failed "scan-sbom.bat 스캔 실패 (exit=$($r.ExitCode), bom=$(Test-Path $bom)):`n$($r.Output)"
    }

    # -----------------------------------------------------------------------
    # 3) sbom-ui.bat : 더블클릭 UI 런처의 docker run 인자 계약
    # -----------------------------------------------------------------------
    Section '3. sbom-ui.bat (UI 런처 계약)'
    $uiOut = Join-Path $script:Work 'ui-out'
    $env:SBOM_OUTPUT_DIR = $uiOut
    $env:UI_PORT = '18093'
    $env:SBOM_SCANNER_IMAGE = 'ghcr.io/example/stub-image:test'
    try {
        $r = Invoke-Bat -Bat (Join-Path $script:RepoRoot 'scripts\sbom-ui.bat')
        if ($r.TimedOut) { Failed 'sbom-ui.bat 이 시간 안에 끝나지 않았습니다.' }
        elseif ($r.ExitCode -ne 0) { Failed "sbom-ui.bat 종료 코드 $($r.ExitCode):`n$($r.Output)" }
        else {
            $log = if ($r.StubLog) { $r.StubLog } else { '' }
            if ($log -match 'docker run ' -and $log -match '-p 18093:8080' -and $log -match 'MODE=UI') {
                Pass 'docker run 에 UI_PORT 포트 매핑과 MODE=UI 가 전달되었습니다.'
            } else {
                Failed "docker run 인자가 기대와 다릅니다:`n$log"
            }
            if (Test-Path $uiOut) { Pass "SBOM_OUTPUT_DIR 결과 폴더를 만들었습니다: $uiOut" }
            else { Failed "SBOM_OUTPUT_DIR 결과 폴더가 생성되지 않았습니다: $uiOut" }
        }
    } finally {
        Remove-Item Env:SBOM_OUTPUT_DIR, Env:UI_PORT, Env:SBOM_SCANNER_IMAGE -ErrorAction SilentlyContinue
    }

    # -----------------------------------------------------------------------
    # 4) check-setup.bat : 환경 점검이 pause 에 걸리지 않고 완주하는가
    #    단언은 ASCII 마커([O])와 종료 코드만 — chcp 65001 한국어 문구는
    #    리다이렉트 캡처 시 인코딩이 러너마다 달라 신뢰할 수 없다.
    # -----------------------------------------------------------------------
    Section '4. check-setup.bat (stdin NUL 로 완주)'
    $env:UI_PORT = '18094'
    try {
        $r = Invoke-Bat -Bat (Join-Path $script:RepoRoot 'scripts\check-setup.bat') -TimeoutSec 60
        $okMarks = [regex]::Matches("$($r.Output)", '\[O\]').Count
        if ($r.TimedOut) { Failed 'check-setup.bat 이 pause 에 걸려 끝나지 않았습니다.' }
        elseif ($r.ExitCode -eq 0 -and $okMarks -ge 3) {
            Pass "점검이 완주했고 [O] 항목 $okMarks 개를 보고했습니다."
        } else {
            Failed "check-setup.bat 실패 (exit=$($r.ExitCode), [O]=$okMarks):`n$($r.Output)"
        }
    } finally {
        Remove-Item Env:UI_PORT -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -Path $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 결과
# ---------------------------------------------------------------------------
Section '결과'
if ($script:Fail -eq 0) {
    Write-Host '.bat 계약 테스트를 모두 통과했습니다.' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($script:Fail)개 항목이 실패했습니다. 위 로그를 확인하세요." -ForegroundColor Red
    exit 1
}
