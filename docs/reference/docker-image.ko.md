---
description: BomLens 스캐너 Docker 이미지를 docker run으로 직접 호출하는 방법. 스크립트를 둘 수 없는 CI 러너, Kubernetes 잡 등의 환경을 위한 안내입니다.
---

# Docker 이미지 직접 사용

평소에는 [`scan-sbom.sh`](../reference/cli.ko.md) 스크립트 사용을 권장합니다. 스크립트가 언어 감지와 이미지 선택, 볼륨 마운트를 대신 처리하기 때문입니다. 이 문서는 스크립트를 둘 수 없는 환경(CI 러너, 쿠버네티스 잡 등)에서 이미지를 `docker run`으로 직접 호출하는 방법을 설명합니다.

## 이미지와 태그

| 이미지 | 용도 |
|--------|------|
| `ghcr.io/sktelecom/bomlens` | 스캔과 후처리 (대표 이름) |
| `ghcr.io/sktelecom/sbom-generator`, `ghcr.io/sktelecom/sbom-scanner` | 같은 이미지의 별칭 (이전 이름, 같은 다이제스트) |
| `ghcr.io/sktelecom/bomlens-firmware` | 펌웨어 분석용 (GPL 도구 포함, opt-in) (legacy alias: sbom-scanner-firmware) |

`latest`와 버전 태그를 제공하며, `linux/amd64`와 `linux/arm64`를 지원합니다. 이미지는 cosign으로 서명되어 발행됩니다.

```bash
docker pull ghcr.io/sktelecom/bomlens:latest
```

## 이미지에 들어 있는 것

언어 toolchain이 없는 경량 이미지(python 3.12 slim 기반)입니다. 소스 스캔의 전이 의존성 해석은 스크립트가 cdxgen 언어별 이미지를 따로 받아 처리합니다. 구조는 [아키텍처](../concepts/architecture.ko.md)를 참고하세요.

| 도구 | 버전 | 역할 |
|------|------|------|
| syft | v1.46.0 | 이미지, 바이너리, 디렉터리 스캔 |
| Trivy | v0.72.0 | 취약점 보고서 |
| cosign | v2.4.1 | SBOM 서명 |
| jq | — | SBOM 정규화와 고지문 생성 |
| ScanCode Toolkit | 32.5.0 | 정밀 라이선스 탐지 (opt-in 빌드에만 포함) |

도구 버전은 `docker/Dockerfile`의 `ARG`로 고정됩니다.

## 직접 실행

분석 모드는 환경 변수 `MODE`로 지정합니다. 모든 예시는 산출물을 현재 디렉터리에 남기고 업로드는 하지 않습니다(`UPLOAD_ENABLED=false`).

### Docker 이미지 분석

<!-- runnable -->
```bash
docker run --rm \
  -v "$(pwd)":/host-output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MODE=IMAGE \
  -e TARGET_IMAGE="nginx:alpine" \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Nginx" \
  -e PROJECT_VERSION="alpine" \
  ghcr.io/sktelecom/bomlens:latest
```

### 바이너리 파일 분석

```bash
docker run --rm \
  -v "$(pwd)":/target \
  -v "$(pwd)":/host-output \
  -e MODE=BINARY \
  -e TARGET_FILE=/target/firmware.bin \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Firmware" \
  -e PROJECT_VERSION="1.0" \
  ghcr.io/sktelecom/bomlens:latest
```

### 소스 디렉터리 분석

<!-- runnable -->
```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="MyApp" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

직접 실행의 `SOURCE` 모드는 컨테이너 안에서 syft가 패키지 매니페스트를 읽는 방식이라 직접 의존성만 잡힐 수 있습니다. 전이 의존성까지 필요하면 cdxgen 언어 이미지를 라우팅하는 `scan-sbom.sh`를 쓰세요.

### 고지문과 보고서까지 한 번에

직접 실행에서는 고지문과 보안 보고서가 기본으로 꺼져 있습니다. 다음 변수를 켜면 CLI의 `--all`과 같은 산출물이 나옵니다.

<!-- runnable -->
```bash
docker run --rm \
  -v "$(pwd)":/host-output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MODE=IMAGE \
  -e TARGET_IMAGE="nginx:alpine" \
  -e GENERATE_NOTICE=true \
  -e GENERATE_SECURITY=true \
  -e GENERATE_REPORT=true \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="Nginx" \
  -e PROJECT_VERSION="alpine" \
  ghcr.io/sktelecom/bomlens:latest
```

## 환경 변수

| 환경 변수 | 필수 | 기본값 | 설명 |
|-----------|------|--------|------|
| `MODE` | O | `POSTPROCESS` | 분석 모드: `SOURCE`, `IMAGE`, `BINARY`, `ROOTFS`, `FIRMWARE`, `ANALYZE` |
| `PROJECT_NAME` | O | — | 프로젝트 이름 |
| `PROJECT_VERSION` | O | — | 프로젝트 버전 |
| `TARGET_IMAGE` | 모드별 | — | `IMAGE` 모드의 이미지명 (docker.sock 마운트 필요) |
| `TARGET_FILE` | 모드별 | — | `BINARY`/`FIRMWARE` 모드의 파일 경로 (컨테이너 내부 경로) |
| `TARGET_DIR` | 모드별 | — | `ROOTFS` 모드의 디렉터리 경로 |
| `UPLOAD_ENABLED` | — | `true` | `false`면 업로드 없이 로컬 저장만 (CLI `--generate-only`와 동일) |
| `HOST_OUTPUT_DIR` | — | — | 산출물을 복사할 마운트 경로 |
| `GENERATE_NOTICE` | — | `false` | 오픈소스 고지문 생성 (CLI `--notice`) |
| `GENERATE_SECURITY` | — | `false` | Trivy 보안 보고서 생성 (CLI `--security`) |
| `GENERATE_REPORT` | — | `false` | 오픈소스위험분석보고서 생성 (CLI 기본값과 달리 직접 실행은 꺼짐) |
| `ENRICH_MAVEN_CPE` | — | `true` | maven 컴포넌트에 groupId로 유도한 NVD 매칭용 `cpe:2.3`을 부여해 CPE 기반 엔진이 NVD 전용 CVE를 찾게 함. 매핑 불가한 group은 CPE를 붙이지 않음 (AI SBOM은 건너뜀) |
| `SECURITY_NVD_VERIFY` | — | `false` | `--deep-cve` 사용 시: grype `nvd:cpe` 결과를 실시간 NVD 버전 범위로 검증해 범위 밖 오탐을 제거 (`NVD_API_KEY`·네트워크 필요, 수 분 추가). 기본 off — 결과는 유지하되 버전 미검증으로 표시 |
| `NVD_API_KEY` | `SECURITY_NVD_VERIFY`에 필요 | — | deep-cve 버전 필터가 쓰는 NVD API 키. 컨테이너에 이름으로만 전달(값은 인라인하지 않음) |
| `ENRICH_EOL` | — | `true` | 번들된 오프라인 스냅샷으로 upstream end-of-life가 지난 컴포넌트를 표시 (AI SBOM은 건너뜀) |
| `ENRICH_OS_CONTEXT` | — | `true` | 배포판(rpm) 패키지 PURL에서 `operating-system` 컴포넌트를 합성해 스캐너가 OS 취약점을 매칭하게 함. 인식 가능한 배포판 패키지가 없으면 아무 동작도 하지 않음 (AI SBOM은 건너뜀) |
| `STALENESS_ENRICH` | — | `false` | deps.dev 버전 최신성(최신 대비 몇 릴리스 뒤처졌는지) 추가. 네트워크 접근 필요 |
| `API_KEY`, `API_URL` | 업로드 시 | — | 업로드 자격과 서버 주소. DT는 `X-Api-Key`, TRUSCA는 Bearer 토큰으로 쓰입니다 |
| `UPLOAD_TARGET` | — | `dependency-track` | 업로드 대상. `dependency-track`(DT 호환) 또는 `trusca`(네이티브 ingest, DT 비호환) |
| `TRUSCA_PROJECT_ID` | `trusca`일 때 | — | 업로드할 TRUSCA 프로젝트 id(UUID). 사전에 존재해야 합니다(자동 생성 없음) |
| `TRUSCA_REF` | — | `main` | ingest ref 라벨 |
| `TRUSCA_RELEASE` | — | `PROJECT_VERSION` | ingest release 라벨 |
| `BOMLENS_MAVEN_FULL_GRAPH` | — | — | Maven 소스 스캔: `1`로 설정하면 compile/runtime 스코프로 거르지 않고 전체 해석 그래프를 유지 |
| `BOMLENS_NODE_FULL_GRAPH` | — | — | Node.js 소스 스캔: `1`로 설정하면 production 전용 집합 대신 dev와 production을 합친 전체 그래프를 유지 |
| `CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6` | 적합성 검사가 허용하는 CycloneDX spec 버전(공백 구분). 기본 범위를 덮어씀 |
| `AI_CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6 1.7` | AI SBOM(ML-BOM)이 허용하는 CycloneDX 버전. 1.7을 추가로 허용 |
| `SPDX_SPEC_VERSIONS` | — | `SPDX-2.2 SPDX-2.3` | 적합성 검사가 허용하는 SPDX spec 버전 |

> TRUSCA(구 TrustedOSS Portal)의 네이티브 ingest 엔드포인트(`POST /v1/projects/{id}/sbom-ingest`, Bearer 인증)는 Dependency-Track와 호환되지 않습니다. 일반 Dependency-Track 서버로 올릴 때는 `UPLOAD_TARGET=dependency-track`(기본값)을 그대로 두세요.

CLI 플래그와 환경 변수의 전체 대응은 [아키텍처의 플래그 매핑](../concepts/architecture.ko.md#플래그--단계-매핑)을 참고하세요.

## 이미지 빌드와 배포

이미지를 직접 빌드하거나 멀티 플랫폼으로 발행하는 절차는 기여자용 [docker/README](https://github.com/sktelecom/bomlens/blob/main/docker/README.md)에 있습니다.

---

> **관련 문서**: [시작하기](../start/first-scan.ko.md) | [CLI 레퍼런스](../reference/cli.ko.md) | [아키텍처](../concepts/architecture.ko.md)
