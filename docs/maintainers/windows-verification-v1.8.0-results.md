# Windows 검증 결과 — v1.8.0 (2026-07)

> 대상: v1.8.0 릴리즈(태그 `7bd7a3e`). 검증 원칙은 **릴리즈 산출물 기준** — 로컬 빌드가 아니라
> 발행된 이미지 `ghcr.io/sktelecom/bomlens:1.8.0`(digest `sha256:ac45e019…`, 1.03 GB)를 pull해서 검증했다.
> 절차는 [windows-verification.md](windows-verification.md)를 따른다.

## 검증 대상 vs 저장소 상태 (중요)

v1.8.0 태그(`7bd7a3e`)는 `sbom-tools → bomlens` 리네임(PR #391, `78d0f77`) **이전** 커밋이다. 현재 `main`(`02aa938`)은
리네임 이후. 따라서 발행 이미지/스크립트가 현재 문서와 어긋나는 지점이 있고, 아래 "리네임 잔여" 절에 정리했다.
스크립트·문서·수정은 현재 `main` 기준으로 진행했다.

## 환경

- 호스트: Windows 11 Enterprise 26100, Git Bash(MINGW64), **PowerShell 5.1(pwsh 없음)**.
  검증 시점에 호스트 Docker 데몬(Rancher Desktop) **미기동**(`npipe` 없음) → 호스트 네이티브 실스캔은 인계 항목.
- CLI 기능 검증: **WSL2 Ubuntu + docker.io(Server 29.1.3)**, root. 이 경로는 Rancher Desktop과 무관하게 독립 동작.
- 이미지 pull: 사내 프록시(`HTTP_PROXY=…:9090`) 환경. ghcr.io는 접근 가능하나 docker 크리덴셜 헬퍼
  `docker-credential-secretservice`가 `libsecret` 부재로 죽어 익명 pull이 막힘 → 빈 자격증명을 반환하는
  더미 헬퍼 shim을 PATH에 심어 우회(아래 "환경 함정" 참고).

## 검증 방식과 커버리지 경계

| 표면 | 검증 방법 | 이번에 커버 | 인계(호스트 Docker/사람 필요) |
|---|---|---|---|
| CLI `.bat` 계약 | 호스트 PS5.1 `test-bat-contract.ps1`(스텁 docker) | ✅ 자동 | — |
| CLI 기능(스캔/SPDX/ANALYZE) | WSL `scan-sbom.sh` + 릴리즈 이미지 | ✅ 자동 | — |
| CLI 호스트 네이티브(named-pipe/MSYS 경로변환) | `scan-sbom.bat` + 실 Docker | — | ✅ Rancher 기동 후 `windows-smoke.ps1` |
| Web UI 서버측 | WSL 컨테이너 + curl `/capabilities`·번들 문자열 | ✅ 자동 | — |
| Web UI 시각(SPDX 칩/다운로드/재스캔 토글) | 브라우저 | — | ✅ 사람 육안 |
| Desktop 설치 | `BomLens-Setup.exe` + SmartScreen | — | ✅ 사람 클릭 |
| 릴리즈 자산 목록 | `gh release view v1.8.0` | — | ✅ gh 인증 |

> **경계 주의**: WSL 경로는 릴리즈 이미지의 스캔/후처리(Linux 컨테이너 동작)를 검증한다. 컨테이너 내부 동작은
> OS와 무관하게 동일하므로 기능 회귀 검증으로 유효하다. 하지만 Windows 고유의 마운트/경로변환/브라우저
> 렌더링/설치 UX는 WSL로 대체되지 않으며, 위 표의 인계 항목으로 남는다.

## 결과 요약

| # | 항목 | 결과 | 비고 |
|---|---|---|---|
| 0a | `test-bat-contract.ps1`(호스트, No-Docker) | ✅ PASS | 4/4. BOM 덕에 PS5.1에서 직접 실행됨(PR #387) |
| 0b | 릴리즈 이미지 pull `bomlens:1.8.0` | ✅ PASS | digest `ac45e019…`, 크리덴셜 헬퍼 우회 후 |
| 1 | CLI 소스 스캔(`--generate-only`) | ✅ PASS | CycloneDX, **119 컴포넌트**, cdxgen 정상(syft 폴백 아님), NOTICE/security/risk 생성 |
| 2 | SPDX 출력(`--spdx`) | ✅ PASS | SPDX-2.3, `SPDXRef-DOCUMENT`, name=`WinTest-1.0`, **121 packages**(=119+2) |
| 2b | byte-stable(`--byte-stable --spdx` 2회) | ✅ PASS | 2회 sha256 완전 일치(`d6afefc3…`) |
| 3 | 이미지 스캔(`alpine:latest --spdx`) | ✅ PASS | **96 컴포넌트**, musl/busybox 존재, SPDX 생성 |
| 4 | ZIP 스캔(`--target app.zip --all`) | ✅ PASS* | 119 컴포넌트 + SPDX. *WSL에 `unzip` 설치 후. 아래 참고 |
| 5 | ANALYZE(SPDX→CDX 라운드트립) | ✅ PASS | CycloneDX 변환 + `_conformance.json/.md/.html` 생성 |
| 6 | Web UI 서버측 | ✅ PASS | 컨테이너 부팅·HTTP 200·`/capabilities` 정상·번들에 "SPDX export" 문자열 존재 |
| 6v | Web UI 시각 3항목 | ⏸ 인계 | SPDX 칩/다운로드/재스캔 토글 복원 → 사람 육안 |
| 7 | Desktop 설치 UX | ⏸ 인계 | `BomLens-Setup.exe` 다운로드→SmartScreen→설치→스캔 |

**결론**: 발행 이미지 `bomlens:1.8.0`의 CLI 기능(소스/이미지/ZIP 스캔, SPDX 출력·byte-stability, ANALYZE
라운드트립)과 웹 UI 서버측은 회귀 없이 동작한다. `.bat` 진입점 계약도 실제 Windows에서 통과. Windows 고유
호스트-통합 레이어(실 마운트, 브라우저 시각, 설치 UX)와 릴리즈 자산 목록은 인계 항목으로 남는다.

## STEP 4(ZIP)에 대한 주석 — 결함 아님

첫 실행은 실패했는데, 원인은 v1.8.0가 아니라 **WSL 최소 환경**이었다. `scan-sbom.sh`는 아카이브를
컨테이너 이전에 호스트에서 추출한다(`scripts/scan-sbom.sh:459-482`): `unzip`이 있으면 unzip, 없으면
`tar`로 폴백(Windows Git Bash의 **bsdtar**는 zip 처리 가능). 그런데 이 WSL Ubuntu에는 `unzip`도 `bsdtar`도
없어 GNU `tar`로 떨어졌고, GNU tar는 zip을 못 읽어 실패했다. `unzip` 설치 후 재실행하니 119 컴포넌트 +
SPDX로 정상 통과. Windows Git Bash 경로는 번들 bsdtar로 동작하며 2026-07 검증에서 이미 PASS.

## 환경 함정 (절차 개선 후보)

1. **docker 크리덴셜 헬퍼 크래시(WSL)**: `docker pull`이 공개 이미지 익명 pull에서도
   `docker-credential-secretservice`를 호출하는데 헤드리스 WSL엔 `libsecret`이 없어 죽는다. `DOCKER_CONFIG`나
   `--config`로 우회되지 않았다. `~/bin`에 빈 자격증명을 반환하는 동명 shim을 두고 PATH 선두에 놓으면 뚫린다.
2. **WSL VM이 호출 간 종료**되어 `/tmp`(tmpfs)가 초기화된다. docker 이미지·`$HOME`은 유지되나, 여러 단계를
   이어 하려면 한 세션에서 실행하거나 상태를 `$HOME`에 둬야 한다.
3. **프록시가 localhost까지 프록시**한다(`HTTP_PROXY` 설정). 웹 UI 헬스체크가 502를 반환 → `curl --noproxy "*"`
   필요. `windows-smoke.ps1`의 `Invoke-WebRequest`도 같은 함정 가능(호스트 프록시 설정 시).

## 이번에 적용한 확정 수정 (커밋 `4da8c4e`)

검증 중 확인된 명백한 리네임/버전 잔여를 수정:
- `tests/windows-smoke.ps1:24` — 기본 스캐너 이미지가 리네임 전 `ghcr.io/sktelecom/sbom-generator:latest`(별칭)를
  가리켰다 → 대표명 `bomlens:latest`로. (PR #387은 v1.8.0/리네임 이전이라 이 기본값을 놓쳤다.)
- `docs/reference/cli.md:97`, `cli.ko.md:97` — 버전 핀 예시 `bomlens:1.7.0` → `1.8.0`.
- `CHANGELOG.md` — 누락된 `[v1.7.0]`/`[v1.8.0]` 링크 정의 추가, `[Unreleased]` compare를 `v1.8.0`로.

`tests/check-docs-drift.sh` 통과 확인.

## 리네임 잔여 (리포트 — 별도 판단 필요)

대부분의 `sbom-generator`/`sbom-scanner`는 **의도된 레거시 별칭**이다(docker-publish가 3개 이름 동시 발행,
문서에 "별칭" 명시, CI 내부 빌드태그 `sbom-scanner:test/local`). 다만 별칭이 아닌 잔여가 있다:

- **`docker/web/server.py:47`** — `SBOM_FIRMWARE_IMAGE` 기본값이 `ghcr.io/sktelecom/sbom-scanner-firmware:latest`.
  실행 중 `/capabilities`에서 `firmwareImage: …/sbom-scanner-firmware`인데 `aibomImage: …/bomlens-aibom`로
  **firmware만 구명, aibom은 신규명** — 불일치. 별칭이라 동작은 하나 `bomlens-firmware`로 통일 권장.
  (`docs/maintainers/firmware-analysis.md:139`도 같은 구명 기본값.)
- **`electron/package.json:2`** — `"name": "sbom-generator-desktop"`. 앱 데이터 폴더(`%APPDATA%\sbom-generator-desktop`)
  경로를 결정하고 `desktop.yml`도 그 경로를 읽으므로, 변경 시 마이그레이션 필요 → 의도적 보류로 보임(README에 명시).
- **`THIRD_PARTY_LICENSES.md:12`, `docker/Dockerfile:3`** — 기본 이미지 표기가 아직 `sbom-scanner`(문서 정합성).

> 위 3건은 런타임/마이그레이션 영향이 있어 이번 커밋에 포함하지 않았다. 통일 여부는 메인테이너 판단.

## 문서 ↔ 실동작, 스크린샷 최신성

- 가이드 문서의 Windows 안내(`first-scan.md`, `no-cli.md`, `cli.md`, `ui.md`)는 실동작과 일치. SPDX 기능도
  릴리즈 이미지 UI 번들에 "SPDX export"/"SPDX 내보내기" 문자열로 존재 확인.
- **스크린샷**: 모두 v1.8.0 이전. `docs/images/web-ui-demo.gif`는 커밋 메시지상 **v1.5.0 UI** 기준(README 히어로,
  가장 낡음). 웹 스틸(`web-ui-*.png`, `app-results.png`)은 2026-07-11(v1.8.0 2일 전).
- **재생성 시도 결과(중요)**: `npm run capture:ui`로 14장을 재생성해봤으나, **커밋하지 않고 되돌렸다.**
  스크린샷 생성기 `capture.spec.ts`의 stub에는 **v1.8.0의 EOL(end-of-life) 컴포넌트 데이터가 없다**(EOL stub은
  기능 테스트 `shell.spec.ts:489`에만 존재). 따라서 재생성해도 새 기능이 스틸에 드러나지 않고, 바이트 차이는
  Windows chromium 폰트 렌더링 차이(플랫폼 노이즈)일 뿐 내용 변화가 아니다.
  - 권장: 가이드 스틸에 EOL을 보이려면 `capture.spec.ts` stub에 EOL 컴포넌트를 추가하고, 폰트 churn을 피하려면
    정규 플랫폼(기존 스틸을 캡처한 환경)에서 재생성.
  - `web-ui-demo.gif`(v1.5.0)는 실 UI 녹화가 필요해 별도 작업.

## 테스트 커버리지 갭 (자동 테스트가 못 잡는 부분)

1. **Windows 실 Docker 스캔이 CI에 전무**(스텁만). 마운트/경로변환/스캔완료는 수동
   [windows-verification.md](windows-verification.md) + `windows-smoke.ps1` 전용.
2. `docker -v C:/...` 실제 마운트 라운드트립이 CI에서 미검증(스텁 docker).
3. `windows-smoke.ps1`/`windows-verify.ps1`는 CI 미실행(실 daemon 필요). `test-bat-contract.ps1`만 자동.
4. 설치 UX: `desktop.yml`은 silent `/S` 설치만 → 마법사/SmartScreen(미서명)/바로가기/언인스톨 미검증.
5. Windows에서 desktop→Docker→scan 전체 여정 미검증(Electron 스모크는 `SBOM_SMOKE`로 Docker 미접촉).
6. 브라우저 렌더링은 chromium-on-linux만 — Windows 브라우저/드래그앤드롭/cp949 콘솔 인코딩 미검증.
7. `docs/start/no-cli.md`(Windows no-CLI 온보딩 핵심)가 `test-docs-walkthrough.sh` 실행 세트에 없음.

## 인계 항목 (호스트 Docker 기동 / gh 인증 / 사람 필요)

1. **Rancher Desktop 기동 후** 호스트에서:
   `powershell -ExecutionPolicy Bypass -File tests\windows-smoke.ps1` → named-pipe 마운트 + `capabilities.hostDir`
   드라이브 경로 확인. 이어 `scripts\scan-sbom.bat`로 소스/SPDX 실스캔(windows-verification.md 1~5단계).
2. **웹 UI 시각**: `scripts\sbom-ui.bat --ui` → 브라우저에서 SPDX 토글/칩/다운로드, "동일 설정 재스캔" 토글 복원.
3. **Desktop 설치**: releases의 `BomLens-Setup.exe` → SmartScreen "More info → Run anyway" → 설치 → 실행 →
   스캔 완료(`%USERPROFILE%\sbom-output`) → 언인스톨. `tests\windows-verify.ps1 -Capture … -Window`로 화면 캡처.
4. **릴리즈 자산 확인**: `gh auth login` 후 `gh release view v1.8.0 --json assets` — `BomLens-Setup.exe`/`.dmg`
   존재·크기(≥1MB) 및 자산명(BomLens- vs 리네임 전 SBOM-Generator-) 확인. `scripts/verify-release.sh v1.8.0`.
