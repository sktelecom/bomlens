# Windows 검증 결과 — v1.8.0 (2026-07)

> 대상: v1.8.0 릴리즈(태그 `7bd7a3e`). 검증 원칙은 **릴리즈 산출물 기준** — 로컬 빌드가 아니라
> 발행된 이미지 `ghcr.io/sktelecom/bomlens:1.8.0`(digest `sha256:ac45e019…`, 1.03 GB)와 발행된
> 설치 파일 `BomLens-Setup.exe`를 받아 검증했다. 절차는 [windows-verification.md](windows-verification.md)를 따른다.

## 검증 대상 vs 저장소 상태 (중요)

v1.8.0 태그(`7bd7a3e`)는 `sbom-tools → bomlens` 리네임(PR #391, `78d0f77`) **이전** 커밋이다. 현재 `main`(`02aa938`)은
리네임 이후. 발행 자산 이름은 이미 `BomLens-`로 일관됐으나(아래 확인), 일부 스크립트/런타임 기본값에 구명 잔여가 있어
"리네임 잔여" 절에 정리했다. 스크립트·문서·수정은 현재 `main` 기준으로 진행했다.

## 환경

- 호스트: Windows 11 Enterprise 26100, Git Bash(MINGW64), **PowerShell 5.1(pwsh 없음)**,
  **Rancher Desktop**(dockerd Server 29.1.3, `\\.\pipe\docker_engine`). 검증 위해 이번에 기동.
- CLI 기능 검증: **WSL2 Ubuntu + docker.io(Server 29.1.3)**, root. Rancher와 무관하게 독립 동작.
- 프록시 환경(`HTTP_PROXY=…:9090`). ghcr.io 접근은 가능하나 WSL에서 docker 크리덴셜 헬퍼
  `docker-credential-secretservice`가 `libsecret` 부재로 죽어 익명 pull이 막힘 → 더미 헬퍼 shim으로 우회(아래 "환경 함정").

## 결과 요약

| # | 항목 | 환경 | 결과 | 비고 |
|---|---|---|---|---|
| A0 | 릴리즈 자산 존재/이름/크기 | 공개 API | ✅ PASS | `BomLens-Setup.exe`(97.25MB)·`.dmg`(203MB)·`bomlens-cli-windows.zip`·`SHA256SUMS.txt`, draft=false |
| A1 | 설치 파일 무결성 | 호스트 | ✅ PASS | 다운로드본 SHA256 = SHA256SUMS 발행값(`6c8c1b27…`) 일치 |
| 0a | `test-bat-contract.ps1`(No-Docker) | 호스트 PS5.1 | ✅ PASS | 4/4. BOM 덕에 PS5.1 직접 실행(PR #387) |
| 0b | 릴리즈 이미지 pull `bomlens:1.8.0` | WSL | ✅ PASS | digest `ac45e019…`, 크리덴셜 헬퍼 우회 후 |
| 1 | CLI 소스 스캔(`--generate-only`) | WSL | ✅ PASS | CycloneDX, **119 컴포넌트**, cdxgen 정상(syft 폴백 아님), NOTICE/security/risk |
| 2 | SPDX 출력(`--spdx`) | WSL | ✅ PASS | SPDX-2.3, `SPDXRef-DOCUMENT`, name=`WinTest-1.0`, **121 packages**(=119+2) |
| 2b | byte-stable(`--byte-stable` 2회) | WSL | ✅ PASS | 2회 sha256 완전 일치(`d6afefc3…`) |
| 3 | 이미지 스캔(`alpine:latest --spdx`) | WSL | ✅ PASS | **96 컴포넌트**, musl/busybox, SPDX |
| 4 | ZIP 스캔(`--target app.zip --all`) | WSL | ✅ PASS* | 119 컴포넌트 + SPDX. *`unzip` 설치 후(아래 주석) |
| 5 | ANALYZE(SPDX→CDX 라운드트립) | WSL | ✅ PASS | CycloneDX 변환 + `_conformance.json/.md/.html` |
| H1 | **호스트 네이티브 `windows-smoke.ps1`** | 호스트+Rancher | ✅ PASS | 명명 파이프 마운트+파일 공유+NOTICE 생성, UI HTTP 200, **`capabilities.hostDir`=드라이브 경로(C:\…)** |
| H2 | `check-setup.bat` 환경 점검 | 호스트 | ✅ PASS | Docker 설치/엔진/이미지/포트 `[O]` 4개, 한글 출력 정상 |
| 6 | Web UI 서버측 | WSL | ✅ PASS | 부팅·HTTP 200·`/capabilities`·번들 "SPDX export" 문자열 |
| 7a | **Desktop 설치(silent /S)** | 호스트 | ✅ PASS | exit 0, `…\Programs\BomLens\BomLens.exe`(222MB), 시작메뉴 바로가기 생성 |
| 7b | **Desktop 실행 → Docker 핸드오프** | 호스트+Rancher | ✅ PASS | startup.log: checking→starting→**ready**, 앱이 UI 컨테이너 기동(`bomlens:latest …→8080`) |
| 7c | **Desktop 언인스톨(silent /S)** | 호스트 | ✅ PASS | exit 0, 프로그램 폴더·바로가기 제거(사용자 데이터 폴더는 NSIS 관례상 잔존) |
| 6v | Web UI 시각(SPDX 칩/다운로드/재스캔 토글 복원) | 브라우저 | ⏸ 사람 | 기능은 서버측+CLI로 확인; 순수 시각 확인만 잔여 |
| 7d | 대화형 설치 SmartScreen 경고 화면 | 브라우저 다운로드 | ⏸ 사람 | 미서명 빌드의 GUI 경고 — 본질적으로 육안 |

**결론**: v1.8.0는 실제 Windows(Rancher Desktop)에서 CLI(네이티브 `.bat` 경로 + 명명 파이프/파일 공유 마운트),
SPDX 출력·byte-stability·ANALYZE, 웹 UI 서버측, 그리고 **데스크톱 앱 설치→실행→Docker 스캔 핸드오프→언인스톨**까지
회귀 없이 동작한다. 발행 설치 파일은 무결성(SHA256)까지 일치. 남은 것은 **순수 시각 확인 2건**(웹 UI SPDX 칩/다운로드/토글
복원, 미서명 SmartScreen 경고)뿐이다.

## STEP 4(ZIP)에 대한 주석 — 결함 아님

첫 실행은 실패했는데, 원인은 v1.8.0가 아니라 **WSL 최소 환경**이었다. `scan-sbom.sh`는 아카이브를 컨테이너 이전에
호스트에서 추출한다(`scripts/scan-sbom.sh:459-482`): `unzip`이 있으면 unzip, 없으면 `tar`로 폴백(Windows Git Bash의
**bsdtar**는 zip 처리 가능). 이 WSL Ubuntu에는 `unzip`도 `bsdtar`도 없어 GNU `tar`로 떨어졌고 GNU tar는 zip을 못
읽어 실패했다. `unzip` 설치 후 재실행하니 119 컴포넌트 + SPDX로 정상 통과. Windows Git Bash 경로는 번들 bsdtar로
동작한다(2026-07 검증에서도 PASS).

## 환경 함정 (절차 개선 후보)

1. **docker 크리덴셜 헬퍼 크래시(WSL)**: `docker pull`이 공개 이미지 익명 pull에서도 `docker-credential-secretservice`를
   호출하는데 헤드리스 WSL엔 `libsecret`이 없어 죽는다. `DOCKER_CONFIG`/`--config`로 우회되지 않았다. `~/bin`에 빈
   자격증명을 반환하는 동명 shim을 두고 PATH 선두에 놓으면 뚫린다. (호스트 Windows는 Windows 자격증명 저장소를 써서 무관.)
2. **WSL VM이 호출 간 종료**되어 `/tmp`(tmpfs)가 초기화된다. docker 이미지·`$HOME`은 유지되므로 상태를 `$HOME`에 둘 것.
3. **프록시가 localhost까지 프록시**한다(`HTTP_PROXY`). 웹 UI 헬스체크가 502 → `curl --noproxy "*"` 필요.
   `windows-smoke.ps1`의 `Invoke-WebRequest`는 호스트에서 정상(호스트에 프록시 미설정).

## 이번에 적용한 확정 수정 (커밋 `4da8c4e`)

- `tests/windows-smoke.ps1:24` — 기본 스캐너 이미지가 리네임 전 `ghcr.io/sktelecom/sbom-generator:latest`(별칭)를
  가리켰다 → 대표명 `bomlens:latest`로. (PR #387은 v1.8.0/리네임 이전이라 이 기본값을 놓쳤다.)
- `docs/reference/cli.md:97`, `cli.ko.md:97` — 버전 핀 예시 `bomlens:1.7.0` → `1.8.0`.
- `CHANGELOG.md` — 누락된 `[v1.7.0]`/`[v1.8.0]` 링크 정의 추가, `[Unreleased]` compare를 `v1.8.0`로.

`tests/check-docs-drift.sh` 통과 확인.

## 리네임 잔여 (리포트 — 별도 판단 필요)

대부분의 `sbom-generator`/`sbom-scanner`는 **의도된 레거시 별칭**이다(docker-publish가 3개 이름 동시 발행, 문서에 "별칭"
명시, CI 내부 빌드태그 `sbom-scanner:test/local`). 다만 별칭이 아닌 잔여가 있다:

- **`docker/web/server.py:47`** — `SBOM_FIRMWARE_IMAGE` 기본값이 `…/sbom-scanner-firmware:latest`. 실행 중
  `/capabilities`에서 `firmwareImage: …/sbom-scanner-firmware`인데 `aibomImage: …/bomlens-aibom`로 **firmware만
  구명, aibom은 신규명** — 불일치. 별칭이라 동작은 하나 `bomlens-firmware`로 통일 권장.
  (`docs/maintainers/firmware-analysis.md:139`도 같은 구명 기본값.)
- **`electron/package.json:2` `"name": "sbom-generator-desktop"`** — 실측 확인: 데스크톱 앱의 데이터/로그 폴더가
  `%APPDATA%\sbom-generator-desktop\`(startup.log 여기)로 생성된다. 변경 시 마이그레이션 필요 → 의도적 보류로 보임.
- **`THIRD_PARTY_LICENSES.md:12`, `docker/Dockerfile:3`** — 기본 이미지 표기가 아직 `sbom-scanner`(문서 정합성).

> 위 3건은 런타임/마이그레이션 영향이 있어 이번 커밋에 포함하지 않았다. 통일 여부는 메인테이너 판단.

## 문서 ↔ 실동작, 스크린샷 최신성

- 가이드 문서의 Windows 안내(`first-scan.md`, `no-cli.md`, `cli.md`, `ui.md`)는 실동작과 일치. 설치 파일 이름/SmartScreen
  안내, 파일 공유 경로 주의, `check-setup.bat` 동작 모두 실측과 부합.
- **스크린샷**: 모두 v1.8.0 이전. `docs/images/web-ui-demo.gif`는 커밋 메시지상 **v1.5.0 UI** 기준(README 히어로, 가장
  낡음). 웹 스틸(`web-ui-*.png` 등)은 2026-07-11(v1.8.0 2일 전).
- **재생성 시도 결과(중요)**: `npm run capture:ui`로 14장을 재생성해봤으나 **커밋하지 않고 되돌렸다.** 스크린샷 생성기
  `capture.spec.ts`의 stub에는 **v1.8.0의 EOL(end-of-life) 컴포넌트 데이터가 없다**(EOL stub은 기능 테스트
  `shell.spec.ts:489`에만). 따라서 재생성해도 새 기능이 스틸에 드러나지 않고, 바이트 차이는 Windows chromium 폰트
  렌더링 차이(플랫폼 노이즈)일 뿐이다.
  - 권장: 가이드 스틸에 EOL을 보이려면 `capture.spec.ts` stub에 EOL 컴포넌트를 추가하고, 폰트 churn을 피하려면 정규
    플랫폼에서 재생성. `web-ui-demo.gif`(v1.5.0)는 실 UI 녹화가 필요해 별도 작업.

## 테스트 커버리지 갭 (자동 테스트가 못 잡는 부분)

> 이번 검증으로 1·2·5의 상당 부분을 수동/반자동으로 메웠으나, **CI 자동화에는 여전히 빠져 있다.**

1. **Windows 실 Docker 스캔이 CI에 전무**(스텁만). 마운트/경로변환/스캔완료는 수동 `windows-smoke.ps1` 전용
   — 이번에 실측 PASS했으나 CI화는 안 됨.
2. `docker -v C:/...` 실제 마운트 라운드트립이 CI에서 미검증(스텁 docker).
3. `windows-smoke.ps1`/`windows-verify.ps1`는 CI 미실행(실 daemon 필요). `test-bat-contract.ps1`만 자동.
4. 설치 UX: `desktop.yml`은 silent `/S`만 → 대화형 마법사/SmartScreen(미서명)은 미검증(이번에도 GUI는 육안 몫).
5. Windows desktop→Docker→scan 전체 여정 — 이번에 실측 PASS했으나 CI 스모크는 `SBOM_SMOKE`로 Docker 미접촉.
6. 브라우저 렌더링은 chromium-on-linux만 — Windows 브라우저/드래그앤드롭/cp949 콘솔 인코딩 미검증.
7. `docs/start/no-cli.md`(Windows no-CLI 온보딩 핵심)가 `test-docs-walkthrough.sh` 실행 세트에 없음.

## 남은 인계 항목 (순수 시각 — 사람 필요)

1. **웹 UI 시각**: `scripts\sbom-ui.bat --ui` → 브라우저에서 SPDX 토글/칩/다운로드, "동일 설정 재스캔" 시 토글 복원.
   (기능·산출물은 CLI SPDX + 서버측 번들 문자열 + `windows-smoke` UI 200으로 확인됨. 육안 확인만 잔여.)
2. **미서명 SmartScreen 경고**: 브라우저로 `BomLens-Setup.exe`를 받아 더블클릭 시 "More info → Run anyway" 화면.
   (설치/실행/언인스톨 메커니즘은 이번에 실측 PASS. MOTW가 붙는 브라우저 다운로드 경로의 GUI 경고만 잔여.)
