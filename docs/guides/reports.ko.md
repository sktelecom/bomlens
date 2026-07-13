---
description: BomLens로 SBOM에서 오픈소스 고지문(NOTICE), 보안 취약점 보고서, 관련 산출물을 생성하는 방법을 다룹니다.
---

# 고지문·보안·위험 보고서 생성

BomLens는 SBOM 생성에 더해 오픈소스 고지문(NOTICE)과 보안 취약점 보고서를 한 번에 만듭니다. 이 문서는 그 산출물을 생성하는 방법을 다룹니다. 읽고 해석하는 방법은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

## Quickstart (5분)

처음이라면 이것만 따라 하면 됩니다. Docker 엔진이 실행 중인 상태에서 SBOM과 고지문, 보안보고서를 한 번에 만듭니다. 브라우저로도, CLI로도 됩니다.

### 브라우저 UI (명령어 불필요)

UI를 실행하고 프로젝트 이름과 버전을 입력한 뒤 스캔 대상을 골라 실행하면, 고지문과 보안보고서를 내려받을 수 있습니다.

```bash
./scripts/scan-sbom.sh --ui     # http://localhost:8080 (포트 충돌 시 UI_PORT=9090 ./scripts/scan-sbom.sh --ui)
#   Windows: scripts\sbom-ui.bat 더블클릭
```

### CLI

스캔할 프로젝트 폴더에서 실행합니다.

```bash
cd /path/to/your-project
/path/to/bomlens/scripts/scan-sbom.sh --project MyApp --version 1.0.0 --all --generate-only
```

Windows에서는 `scripts\scan-sbom.bat`(Git Bash)를 쓰거나 WSL2에서 그대로 실행합니다. 설치는 [시작하기](../start/first-scan.ko.md)를 참고하세요.

끝나면 같은 폴더에 생긴 `MyApp_1.0.0_NOTICE.html`과 `MyApp_1.0.0_security.html`을 브라우저로 열어 결과를 바로 확인하세요. 더 자세한 옵션은 아래를 참고하세요.

---

## 사전 준비

- Docker 엔진 20.10 이상. 무료로는 WSL2 + docker-ce나 Rancher Desktop을 쓰면 되고, Docker Desktop은 조직 사용 시 유료입니다.
- 스캐너 이미지 pull:
  ```bash
  docker pull ghcr.io/sktelecom/bomlens:latest   # 이전 이름 sbom-scanner 도 같은 이미지
  ```
- 모든 예시는 스캔할 프로젝트 루트에서 실행합니다.

> 옵션 플래그는 `--generate-only`(로컬 저장)와 함께 쓰는 것을 권장합니다. 외부 시스템(Dependency-Track 서버나 TRUSCA) 자동 업로드를 함께 쓰려면 생략하세요. 대상은 `UPLOAD_TARGET`으로 고릅니다.

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

> 오픈소스위험분석보고서(`_risk-report`)는 모든 분석 모드에서 기본 생성됩니다(라이선스+취약점 집계, 대응 기한 포함). 생략하려면 `--no-report`를 쓰세요. 6가지 입력 형태별 처리는 [시나리오별 가이드](by-input.ko.md)를 참고하세요.

산출물 종류 전체 목록은 [산출물 레퍼런스](../reference/artifacts.ko.md)를, 웹 UI로 만들려면 [웹 UI](../reference/ui.ko.md)를 참고하세요.

---

## 오픈소스 고지문 (`--notice`)

SBOM의 `components[].licenses` 정보를 모아 라이선스별로 컴포넌트를 묶은 고지문을 생성합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --generate-only
```

- `_NOTICE.txt` — 배포물에 동봉하기 좋은 표준 텍스트.
- `_NOTICE.html` — 브라우저로 보기 좋은 형식. 모든 패키지 메타데이터는 HTML escape되어 안전합니다.
- 라이선스 정보가 없는 컴포넌트는 `NOASSERTION`으로 분류됩니다.

라이선스 정규화와 전문 번들 동작은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

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

심각도·CVSS·EPSS·KEV 우선순위 신호와 후속 조치 해석은 [보고서 읽는 법](../concepts/reports-explained.ko.md)을 참고하세요.

---

## 정밀 라이선스 탐지 (`--deep-license`)

기본 고지문은 의존성(3rd-party)의 라이선스를 다룹니다. `--deep-license`는 scancode-toolkit으로 프로젝트 자체 소스코드(1st-party)의 라이선스 헤더까지 탐지합니다.

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --notice --deep-license --generate-only
```

웹 UI에서는 정밀 라이선스 탐지가 생성 옵션 중 하나로 제공됩니다. 어느 쪽이든 scancode에 의존하는데, scancode는 무겁고 느리며(대형 저장소는 수 분~수십 분) 기본 이미지에는 포함되지 않습니다. 쓰려면 scancode가 포함된 이미지로 실행해야 합니다.

> ```bash
> docker build --build-arg SBOM_DEEP_LICENSE=true -t bomlens:deep ./docker
> # CLI:    SBOM_SCANNER_IMAGE=bomlens:deep ./scripts/scan-sbom.sh ... --deep-license
> # 웹 UI:  SBOM_SCANNER_IMAGE=bomlens:deep ./scripts/scan-sbom.sh --ui
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

cosign으로 SBOM에 detached 서명을 만들어 공급망 신뢰를 확보합니다. 오프라인 키 기반 서명(`--tlog-upload=false`)이라 네트워크나 OIDC가 필요 없습니다.

```bash
# 1) 키 생성 (최초 1회). 무비밀번호 키는 COSIGN_PASSWORD="" 로 생성
docker run --rm -v "$PWD":/keys -w /keys -e COSIGN_PASSWORD="" \
  --entrypoint cosign ghcr.io/sktelecom/bomlens:latest generate-key-pair

# 2) 서명하며 스캔 (COSIGN_KEY=개인키 경로, COSIGN_PASSWORD=키 비밀번호)
COSIGN_KEY="$PWD/cosign.key" COSIGN_PASSWORD="" \
  ./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --sign --generate-only

# 3) 검증
docker run --rm -v "$PWD":/w -w /w --entrypoint cosign \
  ghcr.io/sktelecom/bomlens:latest \
  verify-blob --key cosign.pub --signature MyApp_1.0.0_bom.json.sig \
  --insecure-ignore-tlog MyApp_1.0.0_bom.json
```

개인키는 컨테이너에 읽기 전용으로 마운트됩니다. 추가 산출물: `MyApp_1.0.0_bom.json.sig`

---

## 트러블슈팅

| 증상 | 원인 / 해결 |
|------|------------|
| `trivy not installed ... skipping` | 구버전 이미지. `docker pull`로 최신 이미지를 받으세요. |
| `--deep-license requested but scancode not in image` | `--build-arg SBOM_DEEP_LICENSE=true`로 이미지를 빌드하세요. |
| UI에서 `Docker is not running` | Docker 엔진(Rancher Desktop/Docker Desktop 등)을 시작한 뒤 다시 실행하세요. |
| 고지문에 `NOASSERTION`이 많음 | 의존성에 라이선스 메타데이터가 없는 경우입니다. `--deep-license`로 보완하거나 수동 확인하세요. |
| 포트 충돌(`--ui`) | `UI_PORT`로 다른 포트를 지정하세요. |
