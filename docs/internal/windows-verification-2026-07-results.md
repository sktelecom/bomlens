# Windows 종합 검증 결과 — 2026-07 (SPDX 출력 출시)

[Windows 종합 검증 절차](windows-verification.md)를 실제 Windows PC에서 수행한 결과다. 이번 회차는
opt-in `--spdx` 출력(PR #378)을 실제 Docker 스캔 전체 흐름에서 검증하고, 그와 함께 일반 기능이
회귀하지 않았는지 확인하는 것이 목적이었다.

## 실행 환경

- Windows 11, Docker 엔진은 Rancher Desktop dockerd(Server 29.1.3).
- Git for Windows(`scan-sbom.bat`이 내부에서 쓰는 Git Bash 제공). PowerShell은 5.1이고 pwsh는
  설치돼 있지 않다.
- 스캐너 이미지 `ghcr.io/sktelecom/bomlens:latest`(digest `sha256:0b1662b4…`)를 로컬 빌드 없이
  pull해 최신본으로 갱신했다.
- 저장소 main은 `745b425`이며 PR #378을 포함한다.
- 산출물은 모두 `%USERPROFILE%\bomlens-wintest` 아래에만 만들고 끝나고 지웠다. 저장소에는 이
  결과 문서 외에 아무것도 커밋하지 않았다.

## 결과 요약

| # | 항목 | 결과 | 비고 |
|---|------|------|------|
| 0a | `.bat` 계약 테스트(`test-bat-contract.ps1`) | 통과 | 4개 케이스 모두 PASS. 실행에 인코딩 우회가 필요했다(아래 참고 1) |
| 0b | 자동 스모크(`windows-smoke.ps1`) | 통과 | Docker 엔진, 이미지, CLI NOTICE 생성, 웹 UI 200, `capabilities.hostDir` 드라이브 경로가 PASS. 5절만 SKIP(아래 참고 2) |
| 1 | CLI 소스 스캔(`examples/nodejs`) | 통과 | CycloneDX 1.6, components 119. NOTICE·security·risk-report 생성. cdxgen 형제 컨테이너가 production 118개를 해석해 syft 폴백이 아니었다 |
| 2 | SPDX 출력 | 통과 | `spdxVersion` `SPDX-2.3`, `SPDXID` `SPDXRef-DOCUMENT`, `name` `WinTest-1.0`, `packages` 121(=components+2). `--all`로도 `_bom.spdx.json`이 생겼다. 바이트 안정성은 아래에 따로 적는다 |
| 3 | Docker 이미지 스캔(`alpine:latest`) | 통과 | bom에 musl, busybox 등 96개 컴포넌트, SPDX 파일도 생성. 이미지 모드라 SPDX 문서명은 이미지 digest이고 `packages`는 17개다(파일형 컴포넌트가 SPDX 패키지에서 빠진 결과로 정상) |
| 4 | ZIP 스캔(`--all`) | 통과 | SBOM 119개, 위험분석보고서, SPDX(`name` `WinZip-1.0`, `packages` 121) 모두 생성 |
| 5 | 공급사 SBOM 분석(SPDX 입력) | 통과 | 2단계에서 만든 SPDX를 `--analyze`로 넣어 CycloneDX 121개로 변환·분석하고 `_conformance.json/.md/.html`을 만들었다. SPDX 출력을 다시 입력으로 넣는 왕복이 성립한다 |
| 6 | 웹 UI | 통과(시각 확인은 사람 몫) | 서버 응답으로 검증했다(아래) |
| 7 | 정리 | 완료 | UI 컨테이너 정지, 작업 폴더 삭제, `examples/nodejs`의 스캔 부산물(node_modules, package-lock.json) 제거. `git status`는 깨끗하고 잔여 컨테이너는 없다 |

## 바이트 안정성

`--byte-stable --spdx`가 재현 가능한 SPDX를 내는지 확인했다. 출력 디렉터리를 서로 다르게 두고
같은 소스를 두 번 완전 재생성한 뒤 두 SPDX 파일을 비교했다. 두 파일은 SHA256이 같았고
`fc /b`도 차이가 없다고 보고했다(각 147,672바이트). cdxgen이 락파일 없이는 비결정적이라는
경고를 내는데도 `--byte-stable`이 최종 SPDX를 결정적으로 만든다는 뜻이다.

이 검증은 `--no-report`를 함께 줘서 보안 스캔을 건너뛰고 SBOM과 SPDX 생성만 돌렸다. SPDX는
Trivy 단계 이전에 기록되므로 바이트 비교에는 영향이 없다.

## 웹 UI 검증 방법과 범위

이 환경에서는 브라우저 자동 조작을 쓸 수 없어, 절차 문서가 허용한 대로 서버 응답으로 확인하고
시각 확인은 사람 몫으로 남겼다. UI 컨테이너를 `examples/nodejs` 소스를 마운트해 띄운 뒤 다음을
봤다.

- `/capabilities`의 `hostDir`가 드라이브 경로로 잡혔다.
- 프런트엔드 번들(`/assets/index-*.js`)에 SPDX 토글 문구가 들어 있다. 영어 `SPDX export`,
  한국어 `SPDX 내보내기`와 설명 문구를 확인했다.
- `scan-stream`을 `spdx=true`로 호출하니 `event: done`의 `results`에
  `UiWin_1.0_bom.spdx.json`이 포함됐고, 로그 스트림에 `[spdx] SPDX ready:
  UiWin_1.0_bom.spdx.json (packages=121)`이 흘렀다. 소스 스캔은 cdxgen 형제 컨테이너로 돌아
  전이 의존성 119개를 채웠다.

결과 화면의 SPDX 칩, 다운로드 동작, "같은 설정으로 재스캔" 시 토글 복원처럼 눈으로 봐야 하는
항목은 이 회차에서 확인하지 못했다. 사람이 브라우저에서 이어서 봐야 한다.

## 결론

Windows(Rancher Desktop)에서 SPDX 출력을 포함한 CLI, 이미지, ZIP, 공급사 SBOM 분석, 웹 UI가
모두 정상 동작한다. 과거 Windows 결함이 나왔던 호스트 경로와 마운트 계층(드라이브 경로,
cdxgen 형제 컨테이너)에서 회귀는 없었다. 웹 UI의 시각 확인 세 가지만 사람 검증으로 남는다.

## 참고 — 제품 결함은 아니나 손보면 좋은 것

1. `tests\*.ps1`은 BOM 없는 UTF-8에 한국어가 섞여 있어, pwsh가 없는 이 환경의 Windows
   PowerShell 5.1이 cp949로 오독하면서 파싱이 깨졌다. 특히 `test-bat-contract.ps1`의 C#
   here-string이 열리지 않았다. 파일을 UTF-8 BOM으로 다시 인코딩한 사본으로 실행해 넘겼다.
   `test-bat-contract.ps1`은 이미 주석에서 pwsh 실행을 권하므로, pwsh가 없을 때의 우회를
   절차 문서에 한 줄 남기면 다음 사람이 덜 헤맨다.
2. `windows-smoke.ps1`의 비공유 경로 함정 재현(5절)이 항상 SKIP으로 빠졌다. `Join-Path`를
   인자 세 개로 부르는데 PowerShell 5.1은 이를 받지 못한다. 중첩 호출로 고치면 이 검사가
   실제로 돈다.
3. Windows에서 PowerShell `Compress-Archive`로 만든 zip은 경로 구분자가 역슬래시라
   컨테이너의 `unzip`이 거부한다. 이번엔 정슬래시로 다시 묶어 통과했다. 사용자가 같은 방식으로
   zip을 만들면 걸리므로, `unzip` 실패 안내에 탐색기 압축을 권하는 힌트를 넣으면 좋다.
4. 보안 스캔을 켠 소스 스캔을 백그라운드로 돌리면 Trivy 단계 끝에서 종종 중단됐다. 매
   `--rm` 컨테이너가 Trivy DB를 새로 받는 탓으로 보인다. 이미지 스캔은 완주했고 SPDX와 bom은
   그 이전에 이미 기록되므로 결과 검증에는 지장이 없었다.
