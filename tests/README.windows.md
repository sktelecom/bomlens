# Windows 검증 절차

릴리스된 BomLens를 **Windows 프로그램으로서** 검증하는 절차다. 리눅스 CI가 잡지
못하는 표면 — 실제 Docker Desktop/Rancher Desktop 엔진 경로, NSIS 인스톨러 전
여정, GUI 상호작용 — 을 실기기에서 확인하는 것이 목적이다.

`tests\windows-*.ps1`과 `tests\test-bat-contract.ps1`의 사용 설명서를 겸한다.

- **대상**: 릴리스 태그 하나 (예: `v1.10.0`)
- **소요**: 자동 구간 약 50분 + 수동 GUI 구간 약 15분 (Phase 1~3은 실측, 4~5는 추정)
- **결과물**: 저장소 밖에 검증 리포트 1건 (§6)

---

## 0. 스크립트 실행 환경

Windows에서 무엇이 네이티브로 돌고 무엇이 Git Bash를 타는지부터 구분해야 한다.

| 스크립트 | 종류 | 실행 방법 | Docker 엔진 |
| --- | --- | --- | --- |
| `tests\test-windows.sh` | bash | Git Bash: `bash tests/test-windows.sh` | 불필요 (스텁 docker) |
| `tests\test-bat-contract.ps1` | PowerShell | `powershell -ExecutionPolicy Bypass -File ...` | 불필요 (스텁 docker.exe를 csc.exe로 즉석 컴파일) |
| `tests\windows-smoke.ps1` | PowerShell | 동일 | **필요** (실 엔진 + 이미지 풀) |
| `tests\windows-installer-e2e.ps1` | PowerShell | 동일 | 부분 (부팅 스모크는 불필요, 전 여정은 필요) |
| `tests\windows-verify.ps1` | PowerShell | 오케스트레이터 (`-Smoke` / `-Installer` / `-Capture`) | 하위 스크립트에 따름 |
| `scripts\verify-release.sh` | bash | Git Bash, `gh` 로그인 필요 | 필요 |
| `electron\` 테스트 | Node/Playwright | `npm test`, `npm run test:smoke` | 불필요 |

모든 `.ps1`은 **Windows PowerShell 5.1 호환**으로 작성돼 있다. PowerShell 7(`pwsh`)이
없어도 `powershell`로 그대로 실행하면 된다.

---

## 1. 사전 준비

### 필요한 것

| 항목 | 요구 | 확인 명령 |
| --- | --- | --- |
| Node.js | 20 이상 | `node --version` |
| Git for Windows | `.bat` 런처가 Git Bash를 직접 탐색하므로 필수 | `git --version` |
| Docker CLI + **엔진 기동** | 필수 | `docker info` (성공해야 함) |
| csc.exe (.NET Framework) | `.bat` 계약 테스트의 스텁 컴파일용 | `Test-Path "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"` |
| `gh` CLI | 릴리스 자산 다운로드용 | `gh auth status` |
| `curl.exe` | Windows 11 기본 포함 (없으면 해당 단계 SKIP) | `Get-Command curl.exe` |

한 번에 점검:

```powershell
node --version; git --version; docker info; gh auth status
Test-Path "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
Get-Command curl.exe
```

### 필요 없는 것

- **관리자 권한** — NSIS가 `%LOCALAPPDATA%\Programs\BomLens`에 사용자 설치한다
- **syft / cdxgen / trivy 호스트 설치** — 전부 스캐너 이미지 안에 들어 있다
- **Python** — 검증 절차에 쓰이지 않는다

### 디스크·네트워크

스캐너 이미지 약 250MB, 언어별 이미지 0.6~1.7GB. `ghcr.io` 접근이 되어야 한다.
사내 프록시나 SSL 인스펙션 환경에서는 풀이 실패할 수 있다 — 그 경우 앱이 사유별
안내를 제대로 내는지도 겸사 확인 대상이다.

---

## 2. 검증 범위

### CI가 이미 잡는 것 (로컬은 회귀 확인 수준)

- `test-windows.sh` + `test-bat-contract.ps1` — `ci.yml`의 `contract` 잡, windows-latest, 매 PR
- Electron 단위 테스트 + Playwright 부팅 스모크 + NSIS 빌드 + 사일런트 설치 후 부팅 — `desktop.yml`, windows-latest, 야간 포함
- 릴리스 다운로드 URL·체크섬 — `release-assets-verify.yml`, 주 1회

### 실기기에서만 가능한 것 (여기에 시간을 쓴다)

1. **실 Docker 엔진 경로** — 명명 파이프 대 유닉스 소켓 마운트, 파일 공유 경로에서
   산출물이 호스트에 실제로 떨어지는지 (Phase 3)
2. **릴리스 exe 전 여정** — 설치 → 기동 → 이미지 풀 → UI 컨테이너 → ZIP 업로드 스캔
   → 산출물 → 종료 시 컨테이너 정리 → 언인스톨 (Phase 5)
3. **GUI 전용 단계** — SmartScreen 경고, 설치 마법사, 드래그드롭, ko/en 로캘 (Phase 6)
4. **웹 UI의 `capabilities.hostDir`** — Windows에서 드라이브 경로(`C:\...`)로 잡혀야
   sibling 스캔이 성립한다
5. **릴리스 자산 무결성** — 빌드가 **코드 서명되지 않으므로** 체크섬이 유일한 무결성
   수단이다 (Phase 4는 생략 불가)

---

## 3. 실행 순서

빠르고 가벼운 것부터 배치해 실패를 조기에 노출시킨다.

### Phase 0 — 준비 (5분)

1. Docker Desktop 또는 Rancher Desktop 실행, 트레이 아이콘이 안정될 때까지 대기
2. `docker info` 성공 확인
3. 저장소가 사설이면 `gh auth login`
4. 작업 트리 확인 — `git -C C:\projects\bomlens status`가 깨끗해야 한다. 테스트가
   `examples\`를 복사해 쓰므로 예제 폴더에 정체불명의 파일이 있으면 유래를 먼저 확인한다

### Phase 1 — 계약 테스트 (~5분, Docker 불필요)

```bash
# Git Bash
cd /c/projects/bomlens && bash tests/test-windows.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File C:\projects\bomlens\tests\test-bat-contract.ps1
```

전자는 `scan-sbom.sh`의 오케스트레이션(인자 파싱, 언어 감지, 모드 라우팅, zip/git
인제스천)을 스텁 docker로 검증한다. 후자는 진짜 `cmd.exe`로 `.bat` 3종
(`scan-sbom` / `sbom-ui` / `check-setup`)을 실행해 Git Bash 탐색, 인자 전달, 설정
파일(`bomlens.settings.txt`), ko/en 메시지 테이블 정합성까지 7개 섹션을 본다.

**통과 기준**: 둘 다 종료 코드 0, FAIL 0건.

실측 기준선(2026-08-04): `test-windows.sh`가 `PASS=63 FAIL=0 SKIP=1`,
`.bat` 계약 테스트는 7개 섹션 전 항목 통과. SKIP 1건은 zip 인제스천으로,
호스트에 `zip`/`unzip`이 없을 때 발생한다(tar.gz 경로가 같은 함수를 덮으므로
치명적이지 않다). 이 숫자보다 PASS가 줄었다면 회귀를 의심한다.

### Phase 2 — Electron 단위 + 부팅 스모크 (~5분, Docker 불필요)

```powershell
Set-Location C:\projects\bomlens\electron
npm install          # node_modules가 오래됐을 때만
npm test             # node --test test/*.test.mjs
npm run test:smoke   # Playwright가 Electron 바이너리를 직접 기동
```

> **주의**: BomLens 앱이 이미 켜져 있으면 단일 인스턴스 락 때문에 `test:smoke`가
> 실패한다. 먼저 앱을 종료할 것.

**통과 기준**: 두 명령 모두 종료 코드 0. 실패 흔적은 `electron\test-results\`에 남는다.

실측 기준선(2026-08-04): 단위 테스트 `71 pass / 0 fail`, Playwright
`9 passed / 3 skipped`. SKIP 3건의 정체를 알고 있어야 한다 —

| 스킵된 테스트 | 조건 | 성격 |
| --- | --- | --- |
| `capture.spec.ts` (ko/en) | `SBOM_CAPTURE=1` 일 때만 실행 | 정상. 캡처는 Phase 6에서 별도 수행 |
| `boot-recovery.spec.ts` | `process.platform !== "linux"` | **Windows에서 영구 스킵** — §5 갭 참고 |

### Phase 3 — 실 Docker 스모크 (~15분, 실측)

```powershell
powershell -ExecutionPolicy Bypass -File C:\projects\bomlens\tests\windows-verify.ps1 -Smoke
```

`windows-smoke.ps1`이 5단계를 돈다 — ① 엔진 점검 ② 스캐너 이미지 풀 ③ `examples\nodejs`를
`%USERPROFILE%` 아래로 복사해 `scan-sbom.bat --notice --generate-only` 실행 후
`SmokeApp_0.0.1_NOTICE.txt` / `.html` 생성 확인 ④ UI 컨테이너 기동 →
`http://localhost:8080` 200 + `capabilities.hostDir`가 `C:\` 형태인지 ⑤ 파일 공유 밖
경로(`C:\Windows\Temp`) 함정 재현.

기본값은 `:latest` 이미지다. 특정 릴리스를 고정 검증하려면:

```powershell
$env:SBOM_SCANNER_IMAGE = 'ghcr.io/sktelecom/bomlens:1.10.0'
```

포트 8080이 선점됐으면 `$env:UI_PORT`로 우회한다.

**통과 기준**: 종료 코드 0, `[FAIL]` 0건. `[SKIP]`은 사유를 리포트에 기록한다.

실측 기준선(2026-08-04, Rancher Desktop 29.5.3): exit 0, **5 PASS / 1 SKIP**,
소요 **약 15분**. 3단계(CLI 스캔 e2e) 하나가 14분 가까이 걸린다 — 언어별 이미지를
처음 받으면서 스캔까지 하기 때문이다. **10분 타임아웃으로 감싸면 중간에 잘리니
넉넉히 잡을 것.** 종료 후 `%USERPROFILE%`의 작업 폴더와 라벨 컨테이너가 모두
정리되는 것까지 확인했다.

SKIP 1건은 5단계(비공유 경로 함정)로, `%USERPROFILE%`가 파일 공유에 포함된 환경에서는
함정이 재현되지 않는다. 스크립트가 best-effort로 표시하는 정상 동작이지만, 뒤집어
말하면 **이 PC에서는 "공유 밖 경로에서 산출물이 안 나오는" 실패 모드가 검증되지 않았다**는
뜻이다. 해당 실패 모드를 실제로 봐야 한다면 Docker 설정에서 파일 공유 범위를 좁힌 뒤
다시 돌려야 한다.

### Phase 4 — 릴리스 자산 무결성 (~5분)

```powershell
$d = "$env:TEMP\bomlens-rel"; New-Item -ItemType Directory -Force $d | Out-Null
$base = 'https://github.com/sktelecom/bomlens/releases/download/v1.10.0'
foreach ($f in 'BomLens-Setup.exe','SHA256SUMS.txt','bomlens-cli-windows.zip') {
  Invoke-WebRequest "$base/$f" -OutFile "$d\$f" -UseBasicParsing
}
$expected = (Select-String -Path "$d\SHA256SUMS.txt" -Pattern 'BomLens-Setup\.exe').Line.Split(' ')[0]
$actual = (Get-FileHash "$d\BomLens-Setup.exe" -Algorithm SHA256).Hash.ToLower()
if ($actual -eq $expected) { 'CHECKSUM OK' } else { "MISMATCH: $actual vs $expected" }
```

위 URL이 404면(사설 저장소) `gh`로 대체한다:

```powershell
gh release download v1.10.0 --repo sktelecom/bomlens --pattern 'BomLens-Setup.exe' --dir $d
```

**통과 기준**: exe 20MB 이상, 체크섬 일치, `bomlens-cli-windows.zip` 안에
`scan-sbom.bat` / `scan-sbom.sh` / `sbom-ui.bat` / `check-setup.bat` 존재
(`Expand-Archive`로 확인).

실측 기준선(v1.10.0, 2026-08-04): 저장소가 **공개**라 `gh` 로그인 없이 공개 URL로
받힌다. `BomLens-Setup.exe` 101,983,789 bytes(약 97MB, 다운로드 19초), Windows 관련
2종 체크섬 모두 일치, zip은 10항목이고 필수 런처 4종이 `scripts/` 아래에 정상 포함
(엔트리 구분자도 역슬래시가 아닌 슬래시). exe의 `ProductVersion` / `FileVersion`이
모두 `1.10.0`.

`SHA256SUMS.txt`에는 6개 자산 해시가 모두 들어 있다. Windows 검증만 한다면 exe와
zip 두 줄만 대조하면 되고, 나머지(linux/dmg/tarball)는 SKIP으로 남겨도 된다.

**서명 상태 확인** — 문서가 전제하는 "미서명"이 실제로 그런지 매번 확인한다:

```powershell
Get-AuthenticodeSignature "$env:TEMP\bomlens-rel\BomLens-Setup.exe" | Select-Object Status
```

v1.10.0 기준 `NotSigned`가 정상이다. 이 값이 언젠가 `Valid`로 바뀐다면 서명이
도입된 것이므로, Phase 6의 SmartScreen 체크 항목과 아래 "체크섬이 유일한 무결성
수단" 전제를 모두 다시 써야 한다. 반대로 `HashMismatch` 등이 나오면 자산이
변조된 것이니 즉시 중단한다.

### Phase 5 — 인스톨러 전 여정 e2e (~20~30분, 핵심)

```powershell
powershell -ExecutionPolicy Bypass -File C:\projects\bomlens\tests\windows-verify.ps1 `
  -Installer -ExePath "$env:TEMP\bomlens-rel\BomLens-Setup.exe" -Version v1.10.0
```

7단계를 자동 검증한다:

1. 사일런트 설치 (`/S`)
2. `%LOCALAPPDATA%\Programs\BomLens\BomLens.exe` 존재
3. exe의 ProductVersion이 대상 버전과 일치
4. `SBOM_SMOKE` 부팅 — `%APPDATA%\sbom-generator-desktop\startup.log`가
   `Ready. Opening the UI.`에 도달
5. 실기동 → 이미지 풀 → `bomlens.desktop=1` 라벨의 UI 컨테이너 탐지 → 200 응답 →
   `hostDir` 검사 → ZIP 업로드 스캔 → `_bom.json` / `_bom.spdx.json` / `_NOTICE.*`가
   호스트에 도착, `bomFormat=CycloneDX` / `spdxVersion=SPDX-2.3` 확인
6. 앱 종료 시 컨테이너 정리
7. 언인스톨 (`/S`) 후 잔재 없음

첫 풀이 느리면 `-PullTimeoutMin 30`을 준다.

**통과 기준**: 종료 코드 0. SKIP으로 남은 GUI 항목은 Phase 6에서 수동 보완한다.

> **SPDX는 스캔 산출물이 아니다** — 결과 목록에 `_bom.spdx.json`이 없는 것이 정상이다.
> `docker/web/server.py`가 못박아 둔다: "No GENERATE_SPDX: SPDX is exported on demand
> after the scan"(2166행), "The UI does not decide SPDX before a scan (the pipeline
> always writes CycloneDX); the user asks for the conversion from the results
> screen"(2262행). 웹 UI에서 SPDX는 결과 화면에서 `GET /spdx-export?id=<rid>`로
> **사후 변환**하는 것이고, 스캔 전에 고르는 옵션이 아니다. CLI의 `--spdx`와는
> 경로가 다르다.
>
> 이 하네스는 한때 스캔 쿼리에 `spdx=true`를 붙이고(서버가 읽지 않는 파라미터)
> 결과에 SPDX가 있으리라 단언해, UI 경로에서 **구조적으로 통과할 수 없었다.**
> 5e81fbf(#437)에서 들어와 오래 남아 있었는데, 이 하네스가 CI에 없고 실물 Windows
> PC에서만 도는 탓에 드러날 기회가 없었다. 지금은 `/spdx-export`를 실제로 호출해
> 변환 결과를 검증한다.

실측 기준선(v1.10.0, 2026-08-04): **FAIL 0건**. 설치·버전 스탬프·부팅·이미지 풀·
UI 컨테이너·업로드 스캔·CycloneDX 산출·SPDX 사후 변환·언인스톨까지 전부 PASS.
`hostDir`는 드라이브 경로, `bomFormat=CycloneDX specVersion=1.6`,
변환된 문서는 `spdxVersion=SPDX-2.3`. 종료 후 설치 폴더·시작 메뉴 바로가기·
출력 폴더·라벨 컨테이너가 모두 정리됐다.

SKIP 2건은 정상이다 — SmartScreen 클릭(자동화 불가, Phase 6으로 이월)과
`taskkill` 그레이스풀 종료 미관측(컨테이너 정리는 다음 기동의 `cleanupOrphans`가
보장하며 단위 테스트가 이를 덮는다).

### Phase 6 — GUI 체크 (~15분)

**먼저 자동화되는 것부터 걷어낸다.** 화면 검증을 통째로 수작업으로 돌리기 쉬운데,
절반은 Playwright로 처리된다. 아래 두 가지를 먼저 돌리고 남는 것만 손으로 한다.

```bash
# (a) 시작 화면 ko/en 렌더링 — 실제 화면을 PNG로 남긴다.
#     주의: docs/images/desktop-startup*.png(추적 파일)를 덮어쓴다.
#     증빙만 필요하면 끝나고 git checkout -- docs/images/ 로 되돌릴 것.
cd electron && SBOM_CAPTURE=1 npx playwright test capture
```

(b) **앱 창이 컨테이너 UI를 실제로 부르는지** — Phase 5까지의 단언은 전부
`curl`/API 레벨이라, Electron 창이 `http://127.0.0.1:<port>`를 띄우는지는 아무도
보지 않는다. `_electron.launch()`로 앱을 띄우고 `win.url()`이 `127.0.0.1`로 바뀔
때까지 기다린 뒤 `win.screenshot()`을 찍으면 확인된다(첫 기동이라 Docker가 필요하고
2~4분 걸린다). v1.10.0에서 `http://127.0.0.1:64699/` 이동과 한국어 스캔 화면
렌더링을 확인했다.

> **브라우저 자동화로 localhost를 열려 하지 말 것** — 사내 PC의 Chrome은
> `localhost` / `127.0.0.1` / `[::1]` 어느 형태로도 로컬 UI에 붙지 못한다(오류 페이지).
> 같은 순간 `curl`은 200을 받고, PAC 파일 첫 규칙은 `localhost`를 `DIRECT`로 명시
> 허용하며 `InsecurePrivateNetworkRequestsAllowed=1`이다. 즉 프록시 설정 문제가
> 아니라 Chrome 경로의 별도 보안 계층이며, **Electron은 영향을 받지 않는다.**
> 제품 결함이 아니니 여기서 시간을 쓰지 말고 위 (b)로 검증할 것.

남는 수동 항목 — 네이티브 창이라 자동화가 원천적으로 불가능하다:

1. `BomLens-Setup.exe` 더블클릭 → SmartScreen "Windows가 PC를 보호했습니다" →
   **추가 정보 → 실행**이 동작하는지 (서명이 없으므로 이 경고는 정상이다)
2. 설치 마법사 완주 — `oneClick=false`라 설치 경로를 바꿀 수 있어야 하고, 시작 메뉴
   바로가기가 생겨야 한다
3. 앱에 실제 ZIP을 **드래그드롭** → 스캔 → NOTICE.html / txt 다운로드 버튼으로 내려받기
4. (위 (a)/(b)로 이미 덮인다 — 스크린샷에서 문구가 어색하거나 잘리지 않았는지만 눈으로 본다)
5. CLI 배포 경로 — `scripts\check-setup.bat` 더블클릭이 전 항목 `[O]`로 완주하는지,
   `scripts\sbom-ui.bat` 더블클릭이 브라우저로 localhost:8080을 여는지, 결과가
   `%USERPROFILE%\sbom-output\{Project}_{Version}\`에 떨어지는지
6. **Docker 상태 전이 복구** (§5 갭 6을 메우는 수동 확인) — 앱을 켠 상태에서 Docker
   엔진을 내리고 오류 화면과 안내 문구가 뜨는지, 엔진을 다시 올린 뒤 "다시 확인"으로
   READY까지 복귀하는지. 자동 테스트가 Windows에서 스킵되는 유일한 시나리오다

증빙 캡처:

```powershell
powershell -File tests\windows-verify.ps1 -Capture smartscreen -Window -OutDir <리포트폴더>
```

> **주의**: `-Capture`는 기본적으로 `docs\images\`에 파일을 쓴다. 문서 갱신 목적이
> 아니라 검증 증빙이 필요한 것뿐이라면 **반드시 `-OutDir`로 저장소 밖을 지정**한다.

### Phase 7 — 릴리스 게이트 재실행 (선택)

```bash
# Git Bash, gh 로그인 + Docker 엔진 필요
cd /c/projects/bomlens && GH_TOKEN=$(gh auth token) bash scripts/verify-release.sh v1.10.0
```

인스톨러 첨부 여부, 게시된 이미지 풀, 문서화된 첫 스캔 명령을 **게시본 기준으로**
재검증한다. 다만 이 스크립트는 리눅스 CI용으로 작성돼 Git Bash에서의 동작은
검증된 바 없다 — 실패하면 스크립트 문제인지 릴리스 문제인지 구분해 기록할 것.

---

## 4. 판정 기준

| Phase | PASS 조건 | 로그 위치 |
| --- | --- | --- |
| 1 | 두 스크립트 exit 0, FAIL 0 | 콘솔 (스텁 로그는 `%TEMP%` 임시 폴더, 자동 삭제) |
| 2 | `npm test` / `test:smoke` exit 0 | `electron\test-results\` |
| 3 | exit 0, `[FAIL]` 0 | 콘솔, 작업 폴더 `%USERPROFILE%\sbom-smoke-*` (자동 삭제) |
| 4 | 체크섬 일치, 크기 정상 | `%TEMP%\bomlens-rel` |
| 5 | exit 0, 버전 스탬프 일치 | 콘솔 + `%APPDATA%\sbom-generator-desktop\startup.log` |
| 6 | 체크리스트 전 항목 확인, 캡처 저장 | `-OutDir` 지정 폴더 |
| 7 | exit 0 | 콘솔 |

**전체 판정**: Phase 1~5 전부 exit 0 **그리고** Phase 6 체크리스트 완료 = 합격.
FAIL이 1건이라도 있으면 해당 Phase 로그 전문을 첨부해 이슈화한다.

**Phase 5 시작 전 정리** — `%APPDATA%\sbom-generator-desktop\startup.log`가 남아
있으면 지우거나 폴더째 옮긴다. Phase 2의 Playwright 실행도 같은 경로에
`Ready. Opening the UI.`를 쓰는데, Phase 5가 바로 그 문자열로 부팅 성공을
판정한다. 앱이 아예 뜨지 않아도 낡은 로그 때문에 통과로 읽힐 수 있다.

---

## 5. 알려진 갭

기존 하네스가 **커버하지 않는** 항목이다. 수동 확인 대상이자 신규 테스트 후보다.

1. **공백·한글이 포함된 프로젝트 경로** — 어떤 테스트도
   `C:\Users\...\내 프로젝트 (v2)\` 같은 경로를 쓰지 않는다. Phase 3 이후 한 번 수동
   실행을 권한다
2. **C: 외 드라이브** — `hostDir` 검사식은 `[A-Za-z]:`를 허용하지만 D: 실마운트는 미검증
3. **260자 초과 긴 경로**, OneDrive로 리디렉션된 `%USERPROFILE%`
4. **웹 UI 브라우저 자동화 없음** — Windows 표면의 UI 검증은 헬스체크·API 수준까지다.
   리눅스 CI의 `test-web-ui.sh`는 Windows에서 돌지 않으므로 화면 상호작용은 전부 수동
5. **자동 업데이트 안내 대화상자** — `electron\lib\update.mjs`에 단위 테스트만 있고
   실기기 확인이 없다. `SBOM_FORCE_UPDATE_CHECK=1`로 수동 확인 가능
6. **Docker 상태 전이 복구가 Windows에서 검증되지 않는다** — `boot-recovery.spec.ts`는
   "docker 없음 → 데몬 복귀 → READY" 복구 경로를 보지만, 가짜 docker CLI가 POSIX sh라
   `platform !== "linux"`에서 통째로 스킵된다. 하필 Docker Desktop/Rancher Desktop의
   기동·중단 전이는 Windows에서 가장 깨지기 쉬운 지점이라 **커버리지 공백이 실제 위험과
   겹친다**. 당분간은 Phase 6에서 수동으로 확인한다 — 앱을 켠 채 Docker 엔진을 내렸다가
   다시 올리고, 화면이 오류 상태에서 READY로 돌아오는지 본다
7. **HEAD가 태그보다 앞선 상태에서의 검증** — 로컬 스크립트(HEAD)와 릴리스 자산(태그)의
   조합을 본 것이므로 결과에 반드시 명기한다. 순수 태그 검증이 필요하면
   `git worktree`로 별도 폴더에 태그를 체크아웃해 반복한다

### 이미 우회돼 있는 것 (하네스가 회귀를 잡는다)

- Rancher Desktop의 명명 파이프 마운트 거부 → 앱이 `/var/run/docker.sock`을 쓰도록 우회
- 파일 공유 밖 경로에서 산출물 미생성 → 스모크 5단계가 함정을 재현
- PATH의 `bash`가 WSL 런처인 문제 → `.bat`이 Git Bash를 직접 탐색 (`SBOM_BASH`로 강제 가능)
- PowerShell 5.1의 stderr → 오류 승격, `Compress-Archive`의 역슬래시 엔트리

---

## 6. 산출물

검증 리포트는 **저장소 밖**에 둔다. 매 릴리스마다 쌓이는 일회성 기록이라 저장소
이력에 남길 성격이 아니다. 예: `%USERPROFILE%\Documents\bomlens-verify-v1.10.0.md`

리포트 구성:

- **헤더** — 날짜, OS 빌드, Docker 배포판/버전, Node 버전, 대상 태그와 로컬 커밋
- **Phase별 표** — 명령, 종료 코드, PASS/FAIL/SKIP 카운트, SKIP 사유
- **실패 항목** — 콘솔 로그 전문 + `startup.log` tail
- **화면 캡처** — smartscreen, app-running, app-results, bat-console
- **판정 한 줄** — "vX.Y.Z Windows 검증 — Phase 1~5 자동 N건 PASS / M건 SKIP / K건 FAIL,
  GUI 체크리스트 완료"

FAIL 1건당 GitHub 이슈 1건을 올린다. 재현 명령(위 Phase 명령 그대로), 기대/실제,
환경 표를 첨부한다:

```powershell
gh issue create --repo sktelecom/bomlens --title "..." --body-file <파일>
```
