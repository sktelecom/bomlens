# Windows 종합 검증 절차 (Windows Verification)

> 성격: 실무 절차 문서 (메인테이너용). 실제 Windows PC + Rancher Desktop 환경에서
> CLI와 웹 UI 전체 흐름을 검증할 때 사용한다. 사람이 직접 수행하거나, Windows에서
> 실행한 코딩 에이전트에게 이 문서를 그대로 지시해도 된다. CI가 커버하지 못하는
> 영역(실제 Docker 스캔, 파일 공유 경로, GUI)을 대상으로 한다.

## 이번 회차 배경 (2026-07, SPDX 출력 출시 검증)

- PR #378: opt-in `--spdx` 플래그가 추가되어, 최종 CycloneDX SBOM을 변환한
  SPDX 2.3 JSON(`{프로젝트}_{버전}_bom.spdx.json`)을 추가 산출물로 생성한다.
  `--all`에도 포함되며, 웹 UI에는 Outputs 아래 "SPDX export"(한국어: "SPDX 내보내기")
  토글로 노출된다. 정본은 CycloneDX이고 SPDX는 변환본이다.
- 이미 검증된 것: macOS에서 CLI/웹 UI end-to-end, CI의 ubuntu 통합 테스트·Playwright·
  시각 회귀, windows-latest 러너의 No-Docker 계약 테스트.
- 이번 회차의 목적: **실제 Windows에서 Docker를 띄운 전체 스캔 흐름** 검증.
  SPDX 신기능과 함께 일반 기능(소스/이미지/ZIP/분석/웹 UI)도 회귀 확인한다.
  과거 Windows 결함은 모두 호스트 경로·마운트 계층(MSYS 드라이브 경로,
  `--volumes-from`)에서 나왔으므로(PR #345/#346/#348) 그 지점을 특히 본다.
- GHCR `:latest` 이미지는 머지 내용을 포함해 재게시 완료.
  **이미지를 로컬 빌드하지 말고 pull만 한다.**

## 사전 조건 (먼저 전부 확인하고, 하나라도 안 되면 보고 후 중단)

```
docker version          # Rancher Desktop(또는 Docker Desktop) 실행 중이어야 함
git pull                # main 최신화 (PR #378 포함 여부: git log --oneline | head)
docker pull ghcr.io/sktelecom/bomlens:latest
```

- Git bash가 설치되어 있어야 한다(`scan-sbom.bat`이 내부에서 사용).
- 테스트 산출물 폴더는 Docker 파일 공유가 되는 홈 아래 경로를 쓴다
  (예: `%USERPROFILE%\bomlens-wintest`). 끝나면 삭제한다.
- JSON 확인에 jq가 없을 수 있다. PowerShell `ConvertFrom-Json`을 쓴다.

## 지켜야 할 것

- 검증 중에는 저장소에 아무것도 커밋·푸시하지 않는다. 산출물은 전부 테스트 폴더에만 만든다.
- 실패가 나오면 추측으로 통과 처리하지 말고, 로그를 저장하고 실패로 기록한다.
  각 스캔은 로그를 파일로 남긴다(`... > scanlog-<항목>.txt 2>&1`).

## 검증 절차

### 0. 자동 게이트 2종 (Windows 고유 계층)

```
powershell -ExecutionPolicy Bypass -File tests\test-bat-contract.ps1
powershell -ExecutionPolicy Bypass -File tests\windows-smoke.ps1
```

- 전자는 docker 없이 `.bat` 계층(cmd.exe 파싱, Git bash 탐색, 인자 전달)을 검증한다.
- 후자는 명명 파이프 마운트, 파일 공유 경로의 산출물 생성, UI 컨테이너 HTTP 200을
  검증한다. SKIP은 실패가 아니다. 종료 코드 0이면 통과.

### 0.5 릴리스 exe 전 여정 검증 (설치→기동→스캔→언인스톨)

위 두 게이트는 `.bat` 런처 계층만 본다. 이 단계는 **최종 사용자에게 배포되는 릴리스
산출물 `BomLens-Setup.exe` 그 자체**를 대상으로, `docs/start/no-cli.md` Path A(데스크톱 앱)
가이드 순서를 그대로 따라간다.

```
powershell -ExecutionPolicy Bypass -File tests\windows-installer-e2e.ps1
```

- 기본은 **latest 릴리스**를 내려받아 검증한다. 사설 저장소라 익명 다운로드가 막히면
  `gh auth login` 후 재실행하거나, 이미 받은 파일을 `-ExePath` 로 지정한다.
  특정 버전은 `-Version v1.8.3`, 버전 스탬프 기대값은 `-ExpectedVersion 1.8.3`.
- 검증 항목: exe 획득 → 사일런트 설치(`/S`)와 설치 위치·언인스톨러·바로가기 →
  설치본 버전 메타데이터가 릴리스 태그와 일치(태그→`extraMetadata.version` 주입) →
  부팅 스모크(`SBOM_SMOKE=1`, Docker 불필요) → **전 여정**(앱 실제 기동 → 이미지 풀 →
  `MODE=UI` 컨테이너 → ZIP 업로드 스캔으로 CycloneDX/SPDX/NOTICE 산출물 → 앱 종료 시
  컨테이너 정리) → 언인스톨(`/S`). 첫 풀(약 3~4GB)로 수 분~십수 분 걸릴 수 있고,
  대기 한도는 `-PullTimeoutMin`(기본 20)으로 조정한다.
- **Docker가 없으면** 5단계 이후는 명시적 SKIP이다(부팅 스모크까지는 검증됨).
  SKIP은 실패가 아니며, 종료 코드 0이면 통과.
- **자동화 불가한 GUI 단계**(SmartScreen "실행" 클릭, ZIP 파일 드래그드롭)는 이 스크립트가
  SKIP으로 남긴다. 그 화면은 `windows-verify.ps1 -Capture smartscreen -Window` 등으로
  별도 캡처해 근거로 남긴다.
- 결과 로그는 기존 `windows-verification-*-results.md` 포맷을 따라 기록한다.

### 1. CLI 기본 소스 스캔 (examples/nodejs)

```
cd examples\nodejs
..\..\scripts\scan-sbom.bat --project WinTest --version 1.0 --generate-only -o %USERPROFILE%\bomlens-wintest
```

확인(산출물은 `%USERPROFILE%\bomlens-wintest\WinTest_1.0\` 아래):

- `WinTest_1.0_bom.json` 존재, `bomFormat`이 `CycloneDX`, components가 50개 이상
- `_NOTICE.txt/.html`, `_security.json/.md/.html`, `_risk-report.md/.html` 존재
- 스캔 로그에 cdxgen 형제 컨테이너 실행 흔적이 있는지. syft 폴백이면 직접 의존성만
  잡히므로 개수가 크게 준다(PR #345/#348 회귀 감시 지점).

### 2. SPDX 출력

```
..\..\scripts\scan-sbom.bat --project WinTest --version 1.0 --generate-only --spdx -o %USERPROFILE%\bomlens-wintest
```

PowerShell로 확인:

```powershell
$s = Get-Content "$env:USERPROFILE\bomlens-wintest\WinTest_1.0\WinTest_1.0_bom.spdx.json" -Raw | ConvertFrom-Json
$s.spdxVersion     # "SPDX-2.3" 이어야 함
$s.SPDXID          # "SPDXRef-DOCUMENT"
$s.name            # "WinTest-1.0" (문서명이 "unknown"이면 실패)
$s.packages.Count  # CycloneDX components 수 + 2 안팎
```

추가 확인:

- `--all`로도 한 번 돌려 `_bom.spdx.json`이 생기는지
- 바이트 안정성: `--byte-stable --spdx`로 두 번 스캔(사이에 결과 폴더를 지우고 사본
  보관), 두 SPDX 파일을 `fc /b`로 비교해 완전히 동일해야 함

### 3. Docker 이미지 스캔

```
..\..\scripts\scan-sbom.bat --project WinAlpine --version 1.0 --generate-only --spdx --target alpine:latest -o %USERPROFILE%\bomlens-wintest
```

- `bom.json`에 alpine 패키지(musl, busybox 등)가 들어 있고 SPDX 파일도 생성되는지.

### 4. ZIP 스캔

작은 프로젝트를 zip으로 묶어(`examples/nodejs`를 압축해도 됨) `--target app.zip --all`로
스캔한다. SBOM, 위험분석보고서, SPDX가 모두 생성되는지 확인한다.

### 5. 공급사 SBOM 분석 (ANALYZE, SPDX 입력 경로)

2단계에서 만든 `WinTest_1.0_bom.spdx.json`을 입력으로 사용한다:

```
..\..\scripts\scan-sbom.bat --project WinAnalyze --version 1.0 --generate-only --analyze <경로>\WinTest_1.0_bom.spdx.json -o %USERPROFILE%\bomlens-wintest
```

- SPDX 입력이 CycloneDX로 변환되어 분석되고 `_conformance.*`가 생성되는지.
  SPDX 출력을 다시 입력으로 넣는 왕복 검증을 겸한다.

### 6. 웹 UI

```
scripts\scan-sbom.bat --ui
```

http://localhost:8080 에서:

- Outputs 그룹에 "SPDX export" 토글이 보이는지(언어를 한국어로 바꾸면 "SPDX 내보내기")
- current-dir 소스 스캔을 SPDX 토글 켜고 실행하면 결과 화면 SBOM 카드에 "SPDX" 칩이
  붙고 다운로드가 되는지
- 완료된 스캔에서 "같은 설정으로 재스캔"을 열면 SPDX 토글이 켜진 상태로 복원되는지
- (회귀 감시) 소스 스캔이 cdxgen 형제 컨테이너로 도는지 스캔 로그 스트림에서 확인

브라우저 조작이 안 되는 환경이면 사람이 화면을 확인하도록 SKIP으로 남기고,
서버 응답만이라도 curl로 확인한다:

```
curl -N "http://localhost:8080/scan-stream?project=UiWin&version=1.0&source=current-dir&notice=false&security=false&spdx=true&deep_license=false&identify_vendored=false&includeOsv=false&byte_stable=false"
```

done 이벤트의 results에 `UiWin_1.0_bom.spdx.json`이 있어야 한다.

### 7. 정리

- UI 컨테이너 정지, `%USERPROFILE%\bomlens-wintest` 삭제, examples 폴더에 생긴
  부산물(`package-lock.json`, 산출물 폴더 등)은 `git status`로 확인해 원복한다.

## 보고 형식

항목별 표로 정리한다: 번호/항목/결과(통과·실패·SKIP)/비고(실패 시 로그 파일명과 핵심 오류).
마지막에 한 줄 결론(예: "Windows에서 SPDX 포함 전 기능 정상" 또는 실패 항목 요약)을 쓴다.
실패가 있으면 원인 추정과 재현 명령을 함께 남긴다.
