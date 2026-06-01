# 고지문 · 보안 보고서 · 웹 UI 가이드

> sbom-tools는 SBOM 생성에 더해 오픈소스 고지문(NOTICE)과 보안 취약점 보고서를 한 번에 만들고, CLI에 익숙하지 않은 사용자를 위한 웹 UI를 제공합니다. 이 문서는 이 세 기능의 사용법을 다룹니다.

## Quickstart (5분)

처음이라면 이것만 따라 하면 됩니다. Docker 엔진이 실행 중인 상태에서 스캔할 프로젝트 폴더로 이동한 뒤 둘 중 하나를 실행하세요 (`SBOM`은 `scan-sbom.sh`의 실제 경로로 바꾸세요):

```bash
SBOM=/path/to/sbom-tools/scripts/scan-sbom.sh

# (A) CLI — SBOM + 고지문 + 보안보고서를 한 번에
cd /path/to/your-project
$SBOM --project MyApp --version 1.0.0 --all --generate-only

# (B) 브라우저 UI — CLI가 부담스럽다면
$SBOM --ui            # http://localhost:8080 자동 오픈 (포트 충돌 시 UI_PORT=9090 $SBOM --ui)
```

끝나면 같은 폴더에 생긴 `MyApp_1.0.0_NOTICE.html`(고지문)과 `MyApp_1.0.0_security.html`(보안)을 브라우저로 열어 결과를 바로 확인하세요. 더 자세한 옵션은 아래를 참고하세요.

## 목차
- [Quickstart (5분)](#quickstart-5분)
- [사전 준비](#사전-준비)
- [한 번에 모두 생성하기 (`--all`)](#한-번에-모두-생성하기---all)
- [오픈소스 고지문 (`--notice`)](#오픈소스-고지문---notice)
- [보안 취약점 보고서 (`--security`)](#보안-취약점-보고서---security)
- [정밀 라이선스 탐지 (`--deep-license`)](#정밀-라이선스-탐지---deep-license)
- [결정론적 출력 (`--byte-stable`)](#결정론적-출력---byte-stable)
- [웹 UI (`--ui`)](#웹-ui---ui)
- [산출물 파일 정리](#산출물-파일-정리)
- [트러블슈팅](#트러블슈팅)

---

## 사전 준비

- Docker 엔진 20.10 이상 (무료: WSL2 + docker-ce 또는 Rancher Desktop / Docker Desktop은 조직 사용 시 유료)
- 스캐너 이미지 pull:
  ```bash
  docker pull ghcr.io/sktelecom/sbom-generator:latest   # 이전 이름 sbom-scanner 도 같은 이미지
  ```
- 모든 예시는 스캔할 프로젝트 루트에서 실행합니다.

> 옵션 플래그는 `--generate-only`(로컬 저장)와 함께 쓰는 것을 권장합니다. trustedoss-portal(Dependency-Track 호환) 자동 업로드를 함께 쓰려면 생략하세요.

---

## 한 번에 모두 생성하기 (`--all`)

`--all`은 `--notice --security`의 단축형입니다. SBOM과 고지문, 보안보고서를 한 번의 스캔으로 만듭니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --all --generate-only
```

생성 파일:
```
MyApp_1.0.0_bom.json            # SBOM (CycloneDX 1.6)
MyApp_1.0.0_NOTICE.txt          # 고지문 (텍스트)
MyApp_1.0.0_NOTICE.html         # 고지문 (HTML)
MyApp_1.0.0_security.json       # 보안보고서 (Trivy 원본)
MyApp_1.0.0_security.md         # 보안보고서 (요약)
MyApp_1.0.0_security.html       # 보안보고서 (시각화)
MyApp_1.0.0_risk-report.md      # 오픈소스위험분석보고서 (요약)
MyApp_1.0.0_risk-report.html    # 오픈소스위험분석보고서 (시각화)
```

> 오픈소스위험분석보고서(`_risk-report`)는 모든 분석 모드에서 기본 생성됩니다(라이선스+취약점 집계, 대응 기한 포함). 생략하려면 `--no-report`를 쓰세요. 5가지 입력 형태별 처리는 [시나리오별 가이드](scenarios-guide.md)를 참고하세요.

---

## 오픈소스 고지문 (`--notice`)

SBOM의 `components[].licenses` 정보를 모아 라이선스별로 컴포넌트를 묶은 고지문을 생성합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --generate-only
```

- `_NOTICE.txt` — 배포물에 동봉하기 좋은 표준 텍스트.
- `_NOTICE.html` — 브라우저로 보기 좋은 형식. 모든 패키지 메타데이터는 HTML escape되어 안전합니다.
- 라이선스 정보가 없는 컴포넌트는 `NOASSERTION`으로 분류됩니다.

예시(텍스트):
```
License: Apache-2.0
Components (1):
  - requests@2.31
```

---

## 보안 취약점 보고서 (`--security`)

생성된 SBOM을 Trivy로 스캔해 알려진 취약점(CVE)을 보고합니다. (NVD + OSV + GHSA DB)

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --security --generate-only
```

- `_security.json` — Trivy 원본 JSON. CI나 기계 처리용.
- `_security.md` — severity별 집계 표와 CVE 목록. PR/이슈에 붙이기 좋습니다.
- `_security.html` — severity 배지와 표가 포함된 시각적 보고서.

보고서는 취약점이 있어도 스캔을 실패시키지 않습니다(report-only). 게이트가 필요하면 `_security.json`을 후처리하세요.

### 결과 해석 & 후속 조치

| Severity | 의미 | 권장 조치 |
|----------|------|----------|
| **Critical** | 즉시 악용 가능, 심각 | 최우선 패치 — `Fixed` 버전으로 즉시 업그레이드 |
| **High** | 위험도 높음 | 단기 내 패치 계획 수립 |
| **Medium / Low** | 영향 제한적 | 정기 점검 시 처리 |
| **Unknown** | 심각도 미평가 | 해당 CVE를 직접 확인 후 분류 |

- 보고서의 `Fixed` 열에 버전이 있으면, 그 버전 이상으로 의존성을 올리면 해결됩니다. 가장 빠른 1차 대응입니다.
- CI 게이트 예시. Critical이 1건이라도 있으면 빌드 실패:
  ```bash
  crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
  [ "$crit" -gt 0 ] && { echo "Critical 취약점 ${crit}건"; exit 1; }
  ```
- 오탐(실제 영향 없음) 판단, 예외 승인, 이력 관리 같은 triage는 sbom-tools 범위를 넘습니다. SBOM을 trustedoss-portal에 업로드해 처리하세요.

---

## 정밀 라이선스 탐지 (`--deep-license`)

기본 고지문은 의존성(3rd-party)의 라이선스를 다룹니다. `--deep-license`는 scancode-toolkit으로 프로젝트 자체 소스코드(1st-party)의 라이선스 헤더까지 탐지합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --deep-license --generate-only
```

> scancode는 무겁고 느립니다(대형 저장소는 수 분~수십 분). 기본 이미지에는 포함되지 않으며, 사용하려면 이미지를 다음과 같이 빌드해야 합니다:
> ```bash
> docker build --build-arg SBOM_DEEP_LICENSE=true -t sbom-scanner:deep ./docker
> SBOM_SCANNER_IMAGE=sbom-scanner:deep ./scripts/scan-sbom.sh ... --deep-license
> ```

추가 산출물: `MyApp_1.0.0_scancode.json`

---

## 결정론적 출력 (`--byte-stable`)

같은 입력이면 항상 동일한 바이트의 SBOM을 생성합니다. CI에서 의미 없는 diff(타임스탬프, 랜덤 ID, 정렬 차이)를 제거하고 재현성을 확보합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --byte-stable --generate-only
```

적용 내용: `metadata.timestamp`를 `1970-01-01T00:00:00Z`로 고정, 랜덤 `serialNumber` 제거, `components`를 purl 기준 정렬, 키 정렬.

---

## SBOM 서명 (`--sign`)

cosign으로 SBOM에 detached 서명을 만들어 공급망 신뢰를 확보합니다. 오프라인 키 기반 서명(`--tlog-upload=false`)이라 네트워크·OIDC가 필요 없습니다.

```bash
# 1) 키 생성 (최초 1회). 무비밀번호 키는 COSIGN_PASSWORD="" 로 생성
docker run --rm -v "$PWD":/keys -w /keys -e COSIGN_PASSWORD="" \
  --entrypoint cosign ghcr.io/sktelecom/sbom-scanner:latest generate-key-pair

# 2) 서명하며 스캔 (COSIGN_KEY=개인키 경로, COSIGN_PASSWORD=키 비밀번호)
COSIGN_KEY="$PWD/cosign.key" COSIGN_PASSWORD="" \
  ./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --sign --generate-only

# 3) 검증
docker run --rm -v "$PWD":/w -w /w --entrypoint cosign \
  ghcr.io/sktelecom/sbom-scanner:latest \
  verify-blob --key cosign.pub --signature MyApp_1.0.0_bom.json.sig \
  --insecure-ignore-tlog MyApp_1.0.0_bom.json
```

개인키는 컨테이너에 읽기 전용으로 마운트됩니다. 추가 산출물: `MyApp_1.0.0_bom.json.sig`

---

## 웹 UI (`--ui`)

CLI 없이 브라우저에서 스캔합니다. UI 서버는 스캐너 이미지에 내장되어 있어 추가 설치가 필요 없습니다.

![SBOM Generator 웹 UI](images/web-ui.png)

**macOS / Linux:**
```bash
cd ~/sbom-output      # 산출물 저장 폴더 (어디든 무방)
/path/to/sbom-tools/scripts/scan-sbom.sh --ui
# → http://localhost:8080 자동 열림
```

**Windows:** `scripts\sbom-ui.bat`를 더블클릭합니다.

> 실행 위치는 산출물 저장 폴더이며, 스캔 대상으로 "현재 폴더"를 고를 때만 그 폴더의 소스를 스캔합니다. GitHub URL이나 업로드, Docker 이미지를 쓸 거라면 실행 위치는 무관합니다.

화면 구성:
1. **스캔 설정** — 프로젝트 이름과 버전(필수, 인라인 검증), 스캔 대상 선택, 생성 옵션(고지문, 보안, 정밀 라이선스).
2. **스캔 대상** — 6가지 중 선택하고 형태에 맞게 입력하거나 업로드합니다:

   | 스캔 대상 | 입력 방법 | 백엔드 모드 |
   |-----------|-----------|-------------|
   | 현재 폴더 | UI 실행 폴더의 소스 스캔 | SOURCE |
   | GitHub URL | 저장소 URL 입력 | SOURCE(클론) |
   | ZIP 업로드 | `.zip`/tar 파일 업로드 | SOURCE(해제) |
   | SBOM 업로드 | 기존 SBOM(JSON) 업로드 | ANALYZE |
   | 펌웨어 업로드 | `.bin` 등 업로드 | FIRMWARE |
   | Docker 이미지 | 이미지명 입력 | IMAGE |

3. **스캔 실행** — 진행 중 실시간 로그가 스트리밍됩니다. 오류(클론 실패, 소켓 없음, 미지원 파일 등)는 로그에 명확히 표시됩니다.
4. **요약** — 완료되면 컴포넌트 수, 취약점 심각도 배지, 그리고 공급사 SBOM의 경우 적합성(적합/부적합) 카드가 표시됩니다.
5. **결과물** — SBOM, 고지문, 오픈소스위험분석보고서, 보안보고서, 적합성을 표에서 바로 열거나 내려받습니다. 위험분석보고서는 강조 표시됩니다.

우측 상단의 한국어 / EN 토글로 표시 언어를 바꿀 수 있습니다.

> SBOM 업로드(ANALYZE)를 선택하면 위험분석을 위해 고지문과 보안이 자동 활성화됩니다.
> 펌웨어 업로드 탭은 펌웨어 도구가 포함된 이미지에서 UI를 실행할 때만 활성화됩니다:
> `SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/sbom-scanner-firmware:latest ./scripts/scan-sbom.sh --ui`
>
> **참고:** UI의 소스 스캔(현재 폴더/ZIP/GitHub)은 컨테이너 내부에서 syft로 디렉터리를 분석합니다. 잠금 파일(`package-lock.json`, `go.sum` 등)이나 설치된 의존성이 있어야 구성요소가 잡힙니다. 매니페스트만 있다면 더 깊은 해석이 필요할 때 CLI 소스 모드(cdxgen)를 사용하세요.

**포트 변경 / 충돌 시:** 기본 포트(8080)가 다른 서비스에 점유돼 있으면 다른 포트를 지정하세요:
```bash
UI_PORT=9090 ./scripts/scan-sbom.sh --ui      # http://localhost:9090
```

> **참고:** UI가 쉬워도 Docker 엔진 설치와 실행이 전제입니다(무료: WSL2 + docker-ce 또는 Rancher Desktop). 런처는 Docker 미설치/미실행을 감지해 설치 링크를 안내합니다.

---

## 산출물 파일 정리

| 파일 | 생성 조건 | 설명 |
|------|----------|------|
| `{P}_{V}_bom.json` | 항상 | SBOM (CycloneDX 1.6) |
| `{P}_{V}_NOTICE.txt` / `.html` | `--notice` / `--all` / 위험분석보고서 기본 | 오픈소스 고지문 |
| `{P}_{V}_security.json` / `.md` / `.html` | `--security` / `--all` / 위험분석보고서 기본 | Trivy 보안보고서 |
| `{P}_{V}_risk-report.md` / `.html` | 기본(전 모드) — `--no-report`로 생략 | 오픈소스위험분석보고서 |
| `{P}_{V}_conformance.json` / `.md` / `.html` | `--analyze` | 포맷 적합성 보고서 |
| `{P}_{V}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{P}_{V}_bom.json.sig` | `--sign` | cosign 서명 |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

---

## 트러블슈팅

| 증상 | 원인 / 해결 |
|------|------------|
| `trivy not installed ... skipping` | 구버전 이미지. `docker pull`로 최신 이미지를 받으세요. |
| `--deep-license requested but scancode not in image` | `--build-arg SBOM_DEEP_LICENSE=true`로 이미지를 빌드하세요. |
| UI에서 `Docker is not running` | Docker 엔진(Rancher Desktop/Docker Desktop 등)을 시작한 뒤 다시 실행하세요. |
| 고지문에 `NOASSERTION`이 많음 | 의존성에 라이선스 메타데이터가 없는 경우입니다. `--deep-license`로 보완하거나 수동 확인하세요. |
| 포트 충돌(`--ui`) | `UI_PORT`로 다른 포트를 지정하세요. |

자세한 설계 배경은 [방향성 조사 보고서](direction-study.md)를 참고하세요.
