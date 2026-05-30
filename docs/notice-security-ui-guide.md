# 고지문 · 보안 보고서 · 웹 UI 가이드

> sbom-tools는 SBOM 생성에 더해 **오픈소스 고지문(NOTICE)**, **보안 취약점 보고서**를 한 번에 만들고, CLI에 익숙하지 않은 사용자를 위한 **웹 UI**를 제공합니다. 이 문서는 이 세 기능의 사용법을 다룹니다.

## 목차
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

- Docker 20.10 이상 (Docker Desktop 권장)
- 스캐너 이미지 pull:
  ```bash
  docker pull ghcr.io/sktelecom/sbom-scanner:latest
  ```
- 모든 예시는 **스캔할 프로젝트 루트**에서 실행합니다.

> 옵션 플래그는 `--generate-only`(로컬 저장)와 함께 쓰는 것을 권장합니다. Dependency-Track 업로드를 함께 쓰려면 생략하세요.

---

## 한 번에 모두 생성하기 (`--all`)

`--all`은 `--notice --security`의 단축형입니다. SBOM·고지문·보안보고서를 한 번의 스캔으로 만듭니다.

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
```

---

## 오픈소스 고지문 (`--notice`)

SBOM의 `components[].licenses` 정보를 모아 라이선스별로 컴포넌트를 묶은 고지문을 생성합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --generate-only
```

- **`_NOTICE.txt`** — 배포물에 동봉하기 좋은 표준 텍스트.
- **`_NOTICE.html`** — 브라우저로 보기 좋은 형식. 모든 패키지 메타데이터는 HTML escape되어 안전합니다.
- 라이선스 정보가 없는 컴포넌트는 `NOASSERTION`으로 분류됩니다.

예시(텍스트):
```
License: Apache-2.0
Components (1):
  - requests@2.31
```

---

## 보안 취약점 보고서 (`--security`)

생성된 SBOM을 **Trivy**로 스캔해 알려진 취약점(CVE)을 보고합니다. (NVD + OSV + GHSA DB)

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --security --generate-only
```

- **`_security.json`** — Trivy 원본 JSON. CI·기계 처리용.
- **`_security.md`** — severity별 집계 표 + CVE 목록. PR/이슈에 붙이기 좋습니다.
- **`_security.html`** — severity 배지·표가 포함된 시각적 보고서.

보고서는 취약점이 있어도 **스캔을 실패시키지 않습니다**(report-only). 게이트가 필요하면 `_security.json`을 후처리하세요.

---

## 정밀 라이선스 탐지 (`--deep-license`)

기본 고지문은 의존성(3rd-party)의 라이선스를 다룹니다. `--deep-license`는 **scancode-toolkit**으로 프로젝트 **자체 소스코드(1st-party)**의 라이선스 헤더까지 탐지합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --deep-license --generate-only
```

> ⚠️ scancode는 무겁고 느립니다(대형 저장소는 수 분~수십 분). 기본 이미지에는 포함되지 않으며, 사용하려면 이미지를 다음과 같이 빌드해야 합니다:
> ```bash
> docker build --build-arg SBOM_DEEP_LICENSE=true -t sbom-scanner:deep ./docker
> SBOM_SCANNER_IMAGE=sbom-scanner:deep ./scripts/scan-sbom.sh ... --deep-license
> ```

추가 산출물: `MyApp_1.0.0_scancode.json`

---

## 결정론적 출력 (`--byte-stable`)

동일한 입력에 대해 **항상 동일한 바이트**의 SBOM을 생성합니다. CI에서 의미 없는 diff(타임스탬프·랜덤 ID·정렬 차이)를 제거하고 재현성을 확보합니다.

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

개인키는 컨테이너에 **읽기 전용**으로 마운트됩니다. 추가 산출물: `MyApp_1.0.0_bom.json.sig`

---

## 웹 UI (`--ui`)

CLI 없이 브라우저에서 스캔합니다. UI 서버는 스캐너 이미지에 내장되어 있어 추가 설치가 필요 없습니다.

**macOS / Linux:**
```bash
cd /path/to/your/project
/path/to/sbom-tools/scripts/scan-sbom.sh --ui
# → http://localhost:8080 자동 열림
```

**Windows:** `scripts\sbom-ui.bat`를 **더블클릭**합니다.

화면에서:
1. 프로젝트 이름·버전 입력 (타겟을 비우면 현재 디렉토리 소스 스캔, Docker 이미지명을 넣으면 이미지 스캔)
2. 고지문·보안보고서 등 옵션 체크
3. **스캔 실행** → 로그 확인 → 생성된 결과물을 화면에서 열기/다운로드

포트 변경: `UI_PORT=9000 ./scripts/scan-sbom.sh --ui`

> **참고:** UI가 쉬워도 **Docker Desktop 설치·실행이 전제**입니다. 런처는 Docker 미설치/미실행을 감지해 안내합니다.

---

## 산출물 파일 정리

| 파일 | 생성 조건 | 설명 |
|------|----------|------|
| `{P}_{V}_bom.json` | 항상 | SBOM (CycloneDX 1.6) |
| `{P}_{V}_NOTICE.txt` / `.html` | `--notice` / `--all` | 오픈소스 고지문 |
| `{P}_{V}_security.json` / `.md` / `.html` | `--security` / `--all` | Trivy 보안보고서 |
| `{P}_{V}_scancode.json` | `--deep-license` | scancode 원본 결과 |
| `{P}_{V}_bom.json.sig` | `--sign` | cosign 서명 |

`{P}`=프로젝트 이름, `{V}`=버전 (특수문자는 `_`로 정규화).

---

## 트러블슈팅

| 증상 | 원인 / 해결 |
|------|------------|
| `trivy not installed ... skipping` | 구버전 이미지. `docker pull`로 최신 이미지를 받으세요. |
| `--deep-license requested but scancode not in image` | `--build-arg SBOM_DEEP_LICENSE=true`로 이미지를 빌드하세요. |
| UI에서 `Docker is not running` | Docker Desktop을 시작한 뒤 다시 실행하세요. |
| 고지문에 `NOASSERTION`이 많음 | 의존성에 라이선스 메타데이터가 없는 경우입니다. `--deep-license`로 보완하거나 수동 확인하세요. |
| 포트 충돌(`--ui`) | `UI_PORT`로 다른 포트를 지정하세요. |

자세한 설계 배경은 [방향성 조사 보고서](direction-study.md)를 참고하세요.
