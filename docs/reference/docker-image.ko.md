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
| `ghcr.io/sktelecom/bomlens-deep-cve` | 심층 CVE 매칭용 grype 포함 (opt-in). CLI의 `--deep-cve`와 웹 UI의 심층 CVE 매칭 토글이 쓰며, 둘 다 지금 실행 중인 이미지가 이 이미지가 아니면 곁들임 컨테이너로 자동으로 내려받습니다 |
| `ghcr.io/sktelecom/bomlens-deep-license` | 프로젝트 자체 파일의 라이선스 탐지용 scancode 포함 (opt-in). 소스 스캔에서 CLI의 `--deep-license`가 쓰며, 자동으로 내려받습니다. LGPL 구성요소(linux/amd64의 7-Zip, intbitset, chardet)가 들어 있습니다. 7-Zip과 intbitset의 소스는 이미지 안 `/usr/share/bomlens/sources/`에 있고, chardet은 파이썬 소스 형태로 들어 있습니다 |
| `ghcr.io/sktelecom/bomlens-aibom` | AI 모델 ML-BOM 생성용 (opt-in, legacy alias: sbom-scanner-aibom). `--model`/`--model-file`과 웹 UI의 AI 모델 타일이 쓰며, 곁들임 컨테이너로 자동으로 내려받습니다 |

`latest`와 버전 태그를 제공합니다. 발행되는 모든 이미지(`ghcr.io/sktelecom/bomlens`, `bomlens-firmware`, `bomlens-deep-cve`, `bomlens-deep-license`, `bomlens-aibom` 및 별칭)가 `linux/amd64`와 `linux/arm64`를 모두 지원하므로, `arm64` 호스트(Apple Silicon 맥, Arm 서버)에서도 그대로 pull해 쓸 수 있습니다. 이미지는 cosign으로 서명되어 발행됩니다.

`arm64` 호스트에서는 `linux/amd64`를 강제하지 마세요(`--platform linux/amd64`나 `DOCKER_DEFAULT_PLATFORM=linux/amd64`). 그러면 이미지가 에뮬레이션으로 돌고, 펌웨어 이미지 안의 syft가 비정상 종료할 수 있습니다. 펌웨어 스캔은 실패한 syft 실행을 한 번 더 시도하고(시간 제한을 넘겼거나 메모리 부족으로 강제 종료된 실행은 다시 시도하지 않음), 에뮬레이션으로 돌고 있다는 사실을 로그에 남깁니다. 두 번째 시도도 실패하면 `bomlens-result.json`에 `generate`를 `degraded`로 기록합니다.

```bash
docker pull ghcr.io/sktelecom/bomlens:1.15.2   # 릴리스 태그. :latest는 main에서 빌드한 이미지
```

## 이미지에 들어 있는 것

언어 toolchain이 없는 경량 이미지(python 3.12 slim 기반)입니다. 소스 스캔의 전이 의존성 해석은 스크립트가 cdxgen 언어별 이미지를 따로 받아 처리합니다. 구조는 [아키텍처](../concepts/architecture.ko.md)를 참고하세요.

| 도구 | 버전 | 역할 |
|------|------|------|
| syft | v1.54.1 | 이미지, 바이너리, 디렉터리 스캔 |
| Trivy | v0.75.0 | 취약점 보고서 |
| cosign | v3.1.3 | SBOM 서명 |
| jq | — | SBOM 정규화와 고지문 생성 |
| ScanCode Toolkit | 32.5.0 | 정밀 라이선스 탐지 (opt-in 빌드에만 포함) |
| SCANOSS | 1.54.3 | C/C++ 소스에 복사해 넣은 오픈소스 식별(`--identify-vendored`) |
| docker CLI | 29.9.2 | 웹 UI가 소스 스캔에서 cdxgen 컨테이너를 sibling으로 띄울 때 사용 |
| cdxgen | 13.5.0 | 모델 계보 정보 보강(`bomlens-aibom` 이미지 전용) |

도구 버전은 `docker/Dockerfile`의 `ARG`로 고정됩니다.

모든 이미지에는 NVD CPE 인덱스(`cpe_match.sqlite`, 약 146 MB)도 들어 있으며, 이미지를 빌드할 때 NVD 데이터로 만듭니다. 펌웨어, 루트 파일시스템, 바이너리 스캔에서 `--security`를 켜면 패키지 PURL이 없는 컴포넌트의 CPE를 네트워크 없이 이 인덱스와 대조합니다([CVE 대조 방식](../guides/firmware.ko.md#cve-대조-방식) 참고). 인덱스를 만들 때 GitHub에서 NVD 데이터 피드를 복제합니다. GitHub에 접속할 수 없는 환경에서 이미지를 직접 빌드하면 빌드가 이 단계에서 멈추고 `--build-arg SBOM_CPE_INDEX=false`를 안내하며, 이 옵션으로 인덱스를 뺄 수 있습니다. 펌웨어 빌드는 이 옵션을 받지 않으므로 펌웨어 이미지에는 항상 인덱스가 들어갑니다.

## 이미지가 디스크를 얼마나 차지하나요?

스캐너 이미지 `ghcr.io/sktelecom/bomlens`는 압축을 풀면 디스크에서 약 1.4GB입니다. 소스 스캔은 여기에 프로젝트 언어용 이미지를 하나 더 받는데, 이쪽이 훨씬 큽니다. 아래 크기는 `docker/lib/image-sizes.json`에 기록된 cdxgen 태그로 측정한, 디스크에서 차지하는 크기입니다.

| 이미지 | 쓰이는 곳 | 디스크 크기 |
|--------|-----------|-------------|
| `bomlens` | 모든 스캔 | 약 1.4GB |
| `cdxgen-alpine-node24` | Node.js | 약 2.9GB |
| `cdxgen-debian-golang124` | Go | 약 3.8GB |
| `cdxgen-java17` | Java 17 toolchain을 쓰는 Java | 약 3.8GB |
| `cdxgen-debian-rust` | Rust | 약 4.0GB |
| `cdxgen-debian-ruby34` | Ruby | 약 4.2GB |
| `cdxgen-debian-php84` | PHP | 약 4.3GB |
| `cdxgen-python312` | Python | 약 4.9GB |
| `cdxgen-temurin-java21` | Java(기본) | 약 5.6GB |
| `bomlens-android-sdk<API>` | Android, 직접 빌드, API 레벨마다 하나 | 약 6.3GB |
| `cdxgen-debian-dotnet9` | .NET | 약 14.7GB |
| `cdxgen` | 여러 언어가 섞인 트리 | 약 16GB |

Swift 이미지와 선택형 이미지(`bomlens-firmware`, `bomlens-aibom`, `bomlens-deep-cve`)는 크기가 기록되어 있지 않아 표에 없습니다. AI 모델 스캔은 약 3.5GB를 받습니다([AI 모델 SBOM](../guides/ai-model.ko.md)).

`scan-sbom.sh`는 이미지를 받기 전에 크기를 출력하고, Docker 엔진의 여유 공간이 그 크기에 2GB를 더한 값보다 적으면 여유 공간, 내려받을 크기, 정리 방법을 알리며 멈춥니다. 웹 UI는 경고만 합니다. `BOMLENS_SKIP_DISK_CHECK=1`을 지정하면 이 점검을 건너뜁니다. 여유 공간을 읽지 못하면 경고만 하고 스캔을 계속합니다. macOS와 Windows에서는 엔진이 가상 머신 안에서 돌고 그 디스크가 호스트의 파일이라, 일부 엔진(Rancher Desktop, WSL 2의 Docker Desktop)은 가상 디스크의 최대 크기를 여유 공간으로 알려 줍니다. 그래서 엔진이 알려 준 값과 홈 폴더가 있는 호스트 디스크의 여유 공간 중 작은 값을 씁니다. `scripts/check-setup.sh`(Windows는 `check-setup.bat`)는 이 컴퓨터의 BomLens 이미지(`SBOM_SCANNER_IMAGE`로 지정한 스캐너 이미지 포함)와 크기, 합계, 엔진의 여유 공간을 보여 줍니다.

### 디스크 공간은 어떻게 비우나요?

BomLens가 받은 이미지만 이름으로 골라 지우면 다른 이미지는 그대로 남습니다.

```bash
docker image ls --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '^ghcr\.io/(cdxgen/|sktelecom/)|^bomlens-android-sdk' \
  | xargs docker image rm
```

`docker image prune -a`는 BomLens 이미지만이 아니라 컨테이너가 쓰지 않는 이미지를 모두 지웁니다. 지운 이미지는 스캔에 필요해지면 다시 받습니다. 스캔 결과는 건드리지 않습니다.

Docker 안에서 이미지를 지워도 엔진의 디스크 파일 크기는 줄지 않아 컴퓨터에 공간이 돌아오지 않을 때가 있습니다. 그럴 때는 디스크를 압축하세요.

- Docker Desktop과 Rancher Desktop: Settings > Resources에서 디스크 크기를 늘리거나 디스크를 압축합니다. Windows에서 엔진의 디스크는 `.vhdx` 파일이며(Rancher Desktop은 `%LOCALAPPDATA%\rancher-desktop\distro-data` 아래 `ext4.vhdx`), 앱을 닫고 관리자 권한으로 `Optimize-VHD`나 `diskpart`로 압축할 수 있습니다.
- Colima: `colima ssh -- sudo fstrim -av`.

## 직접 실행

분석 모드는 환경 변수 `MODE`로 지정합니다. 모든 예시는 산출물을 현재 디렉터리에 남기고 업로드는 하지 않습니다(`UPLOAD_ENABLED=false`). 예시의 `:latest`는 `main`에서 빌드한 이미지입니다. 쓰고 있는 릴리스의 이미지로 실행하려면 위의 `docker pull` 줄처럼 그 자리에 릴리스 태그를 넣습니다.

### Docker 이미지 분석

Windows Git Bash에서는 MSYS가 `/var/run/docker.sock`과 컨테이너 쪽 경로인
`/host-output`을 둘 다 Docker에 넘기기 전에 자기 마음대로 Windows 경로로
바꿔버려서 두 마운트가 조용히 깨집니다. 아래 `MSYS_NO_PATHCONV`와
`MSYS2_ARG_CONV_EXCL`은 그 변환을 끄고, `cygpath -m`으로 호스트 쪽 경로만
직접 변환합니다(`scripts/scan-sbom.sh`도 같은 이유로 같은 조합을 씁니다).
WSL2·macOS·Linux 셸은 경로를 바꾸지 않으므로 그냥 평범한 `docker run` 줄로
바로 넘어갑니다.

<!-- runnable -->
```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/host-output \
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
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/target \
  -v "$HOSTPATH":/host-output \
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
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/src \
  -v "$HOSTPATH":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="MyApp" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/bomlens:latest
```

직접 실행의 `SOURCE` 모드는 트리 전체를 덮는 lock 파일(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock`, `gradle.lockfile` 중 하나이고 루트 아래 다른 매니페스트가 없을 때)을 빌드도 Docker 소켓도 없이 그대로 읽고, 빠진 라이선스는 패키지 레지스트리에서 채웁니다. SBOM에는 이 방식이 `bomlens:detection`으로 남습니다. 사이드 컨테이너를 띄울 Docker가 없는 환경, 예를 들어 이 이미지를 작업 이미지로 쓰는 CI 작업에서 쓰는 형태입니다. 그 밖의 트리는 컨테이너 안에서 syft가 패키지 매니페스트를 읽는 방식이라 직접 의존성만 잡힐 수 있습니다. 전이 의존성까지 필요하면 cdxgen 언어 이미지를 라우팅하는 `scan-sbom.sh`를 쓰세요. syft의 매니페스트 판독기는 의존성을 하나라도 풀어내려면 락파일(Node는 `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, 다른 생태계도 마찬가지)이 있어야 합니다. 락파일이 없으면 직접 실행의 `SOURCE` 모드는 읽을 것이 없어, 빈 결과를 완료로 보고하는 대신 안내와 함께 실패합니다.

### 고지문과 보고서까지 한 번에

직접 실행에서는 고지문과 보안 보고서가 기본으로 꺼져 있습니다. 다음 변수를 켜면 CLI의 `--all`과 같은 산출물이 나옵니다.

<!-- runnable -->
```bash
HOSTPATH="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
  -v "$HOSTPATH":/host-output \
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
| `MODE` | X | `POSTPROCESS` | 분석 모드: `SOURCE`, `IMAGE`, `BINARY`, `ROOTFS`, `FIRMWARE`, `ANALYZE`, 또는 `PLAN`(소스 스캔의 실행 계획 작성, [엔진 계약](engine-contract.ko.md#실행-계획) 참조). 지정하지 않으면 출력 디렉터리에 이미 있는 SBOM을 후처리만 한다 — 실제로 무언가를 스캔하려면 명시적으로 지정해야 한다. |
| `PROJECT_NAME` | O | — | 프로젝트 이름 |
| `PROJECT_VERSION` | O | — | 프로젝트 버전 |
| `TARGET_IMAGE` | 모드별 | — | `IMAGE` 모드의 이미지. docker.sock을 마운트하면 Docker 데몬에서 읽고, 마운트하지 않으면 레지스트리에서 읽거나 형식 접두사가 붙은 아카이브(`docker-archive:`, `oci-archive:`, `oci-dir:`, 컨테이너에 마운트한 경로)에서 읽음 |
| `SYFT_REGISTRY_AUTH_USERNAME`, `SYFT_REGISTRY_AUTH_PASSWORD`, `SYFT_REGISTRY_AUTH_TOKEN`, `SYFT_REGISTRY_AUTH_AUTHORITY` | — | — | `IMAGE` 모드: 비공개 레지스트리의 자격 증명. docker 설정 파일을 마운트하고 `DOCKER_CONFIG`로 지정해도 됨. `SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY`와 `SYFT_REGISTRY_INSECURE_USE_HTTP`는 자체 서명 인증서나 HTTP 레지스트리에 접속할 때 씀. `SYFT_PLATFORM`은 여러 플랫폼 이미지에서 플랫폼을 고름 |
| `TARGET_FILE` | 모드별 | — | `BINARY`/`FIRMWARE` 모드의 파일 경로 (컨테이너 내부 경로) |
| `TARGET_DIR` | 모드별 | — | `ROOTFS` 모드의 디렉터리 경로 |
| `UPLOAD_ENABLED` | — | `true` | `false`면 업로드 없이 로컬 저장만 (CLI `--generate-only`와 동일) |
| `HOST_OUTPUT_DIR` | — | — | 산출물을 복사할 마운트 경로 |
| `BOMLENS_STAGE1_EXIT`, `BOMLENS_STAGE1_OOM`, `BOMLENS_STAGE1_LOG`, `BOMLENS_STAGE1_REASON` | — | — | 1단계를 직접 실행한 뒤의 `POSTPROCESS`: 그 종료 코드, 메모리 부족으로 종료됐으면 `true`, 출력 폴더에 둔 로그 파일 이름. 뒤의 두 값 대신 이미 분류한 사유(`oom`, `disk-space`, `tls-trust`, `registry-auth`, `network`, `cdxgen-crash`, `cdxgen-unavailable`)를 넘겨도 됨. 종료 코드 127은 `cdxgen-unavailable`로 읽으므로, 1단계를 실행하지 않는 `unsupported` 계획에서는 이 값을 넘김. 1단계가 SBOM을 남기지 않았으면 2단계가 syft 스캔으로 대신함([엔진 계약](engine-contract.ko.md#실행-계획) 참조) |
| `BOMLENS_EVENTS` | — | — | `file` 또는 `stderr`: 진행 이벤트를 한 줄에 JSON 객체 하나씩 출력 폴더의 `bomlens-events.jsonl` 또는 표준 오류에 씀([엔진 계약](engine-contract.ko.md#진행-이벤트) 참조) |
| `BOMLENS_IMAGE_REF`, `BOMLENS_IMAGE_DIGEST` | — | — | 호출자가 실행한 이미지 참조와 다이제스트. `bomlens-result.json`에 그대로 적습니다([엔진 계약](engine-contract.ko.md) 참고) |
| `GENERATE_NOTICE` | — | `false` | 오픈소스 고지문 생성 (CLI `--notice`) |
| `GENERATE_SECURITY` | — | `false` | Trivy 보안 보고서 생성 (CLI `--security`) |
| `DEEP_LICENSE` | — | `false` | scancode로 프로젝트 자체 파일의 라이선스 탐지 (CLI `--deep-license`, 이미지에 scancode 필요) |
| `DEEP_LICENSE_MAX_FILES` | — | `20000` | `DEEP_LICENSE`: 프로젝트 자체 파일이 이보다 많은 트리는 검사하지 않음 |
| `DEEP_LICENSE_TIMEOUT` | — | `600` | `DEEP_LICENSE`: scancode를 멈출 때까지의 초 |
| `BOMLENS_DEEP_LICENSE_ALL` | — | — | `DEEP_LICENSE`: `1`이면 의존성, 빌드, 도구 폴더까지 검사 (기본은 제외) |
| `DETECTION` | — | `auto` | `SOURCE` 모드 전용. `auto`는 트리를 덮는 lock 파일이 있으면 정적으로 읽고 그 외에는 예전처럼 빌드나 syft 경로를 쓴다. `static`은 항상 정적으로 읽고, `build`는 정적으로 읽지 않는다(CLI `--detection`). 정적 검출은 빠진 라이선스를 패키지 레지스트리에서 채우므로 `BYTE_STABLE=true`나 `FETCH_LICENSE=false`에서는 `auto`가 빌드한다 |
| `REACHABILITY` | — | `false` | 각 Go 보안 권고의 코드에 도달하는지 govulncheck로 판정 (CLI `--reachability`). `BINARY` 모드는 실행 파일을 읽고, `SOURCE`와 `POSTPROCESS`는 1단계가 남긴 govulncheck 출력을 읽는다(CLI가 이미지의 govulncheck를 1단계에 넘긴다) |
| `GENERATE_REPORT` | — | `false` | 오픈소스 위험 보고서 생성 (CLI 기본값과 달리 직접 실행은 꺼짐) |
| `ENRICH_MAVEN_CPE` | — | `true` | maven 컴포넌트에 groupId로 유도한 NVD 매칭용 `cpe:2.3`을 부여해 CPE 기반 엔진이 NVD 전용 CVE를 찾게 함. 매핑 불가한 group은 CPE를 붙이지 않음 (AI SBOM은 건너뜀) |
| `ENRICH_GITHUB_CPE` | — | `true` | 소수의 손검증된 `pkg:github/` 컴포넌트(패키지 매니저 생태계가 없는 대형 C/C++ 프로젝트에 흔한, 소스 저장소 좌표로만 식별되는 컴포넌트)에 NVD 매칭용 `cpe:2.3`을 부여해 CPE 기반 엔진이 NVD 전용 CVE를 찾게 함. 큐레이션 목록에 없으면 CPE를 붙이지 않음 (AI SBOM은 건너뜀) |
| `ENRICH_UPSTREAM_PURL` | — | `true` | 펌웨어, 루트 파일시스템, 바이너리 스캔과 Yocto 빌드의 기록에서 읽은 SBOM에서 purl이 없거나 `pkg:generic`, `pkg:opkg` purl인 컴포넌트에 upstream 소스 저장소 purl(`pkg:github/<owner>/<repo>@<tag>`, `pkg:sourceforge`, `pkg:gnu`)을 붙임. `docker/lib/upstream-purl-map.json`의 변환표에 있는 프로젝트와, 소스 내려받기 주소가 GitHub이나 GNU 릴리스를 밝히는 컴포넌트만 바꾸고, 나머지는 원래 식별자를 둠 |
| `ENRICH_INTERPRETER_CPE` | — | `true` | 소수의 손검증된 인터프리터 컴포넌트(예: conda나 NuGet 패키지로 배포된 Python)에 NVD 매칭용 `cpe:2.3`을 부여해 CPE 기반 엔진이 NVD 전용 CVE를 찾게 함. 큐레이션 목록에 없으면 CPE를 붙이지 않음 (AI SBOM은 건너뜀) |
| `SECURITY_NVD_VERIFY` | — | `false` | `--deep-cve` 사용 시: grype `nvd:cpe` 결과를 실시간 NVD 버전 범위로 검증해 범위 밖 오탐을 제거 (`NVD_API_KEY`·네트워크 필요, 수 분 추가). 기본 off — 결과는 유지하되 버전 미검증으로 표시 |
| `NVD_API_KEY` | `SECURITY_NVD_VERIFY`에 필요 | — | deep-cve 버전 필터가 쓰는 NVD API 키. 컨테이너에 이름으로만 전달(값은 인라인하지 않음) |
| `BOMLENS_OS_LICENSES` | — | `true` | `IMAGE`와 `ROOTFS` 모드: Debian 패키지의 라이선스를 Trivy로 읽음. syft가 해시로 남기는 copyright 파일에서 Trivy가 라이선스 이름, common-licenses 참조, 라이선스 본문을 읽음. 이미지를 한 번 더 읽으며, `false`로 끔(해시는 그대로 지움) |
| `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` | — | `7` | `/trivy-db`에 Trivy 데이터베이스를 마운트했을 때(갱신 없이 오프라인으로 읽음), 보안 단계를 열화로 기록하는 경과 일수 |
| `BOMLENS_GRYPE_DB_MAX_AGE_DAYS` | — | `7` | `--deep-cve` 사용 시 grype 데이터베이스를 대조 전에 `grype db update`로 갱신하는 기준 경과 일수. 이미지의 캐시에 쓸 수 없으면 임시 폴더에 받고, `TRIVY_OFFLINE_SCAN`이나 `TRIVY_SKIP_DB_UPDATE`가 `true`이면 갱신하지 않는다. 갱신하지 못한 데이터베이스도 그대로 읽고, `deep-cve` 단계를 경과 일수와 함께 `degraded`로 기록한다. 갱신한 데이터베이스는 컨테이너가 끝나면 사라지므로, 이미지의 데이터베이스가 오래된 동안에는 스캔할 때마다 다시 내려받는다. `/trivy-db`에 Trivy 데이터베이스를 마운트하면 오프라인 스캔이 되어 grype도 갱신하지 않는다 |
| `GRYPE_DB_UPDATE_URL` | — | grype 기본값 | `--deep-cve` 사용 시 `grype db update`가 grype 데이터베이스를 받는 주소. 미러를 쓸 때 지정한다 |
| `BOMLENS_GO_VULNDB` | — | `true` | `--security`를 켰을 때 Go 모듈을 이미지에 든 Go 취약점 데이터베이스 스냅숏과도 대조. `false`면 건너뜀 |
| `BOMLENS_GO_VULNDB_PATH` | — | 이미지에 든 스냅숏 | 스냅숏 대신 읽을 컨테이너 안의 Go 취약점 데이터베이스 내보내기 파일(https://vuln.go.dev/vulndb.zip 의 `vulndb.zip` 또는 그 압축을 푼 폴더). 내려받은 데이터베이스로 바꾸지 않으며, 오래됐으면 열화로만 기록 |
| `BOMLENS_GO_VULNDB_MAX_AGE_DAYS` | — | `7` | Go 취약점 데이터베이스를 오래된 것으로 보는 경과 일수. 내보내기 파일을 출처에서 받은 시각부터 셈(이미지 빌드와 내려받기 때 기록, 기록이 없으면 파일 수정 시각). `index/db.json`의 데이터베이스 자체 날짜는 그보다 늦을 때만 씀. vuln.go.dev는 이 날짜가 그대로여도 내보내기 파일을 매일 새로 냄. 이미지에 든 스냅숏이 오래됐으면 그 스캔에서는 임시 폴더에 내려받은 데이터베이스(약 3.6 MB, 제한 60초)를 대신 읽고, 스캔이 끝나면 지움. 오프라인 스캔이거나(`TRIVY_OFFLINE_SCAN` 또는 `TRIVY_SKIP_DB_UPDATE`가 `true`, `/trivy-db` 마운트일 때처럼) 내려받기에 실패하면 오래된 스냅숏을 읽고 `go-vulndb` 단계를 열화로 기록 |
| `BOMLENS_GO_VULNDB_URL` | — | `https://vuln.go.dev/vulndb.zip` | 그 내려받기의 주소. `vulndb.zip`의 미러를 지정(`http`, `https`, `file` URL). 읽기 전에 이미지 빌드 때와 같은 방법으로 검사 |
| `BOMLENS_EXTRA_CA_CERTS` | - | - | TLS를 검사하는 프록시를 쓸 때 신뢰할 CA 번들(PEM)의 컨테이너 안 경로. 이미지를 직접 실행할 때는 번들을 마운트하고(읽기 전용이면 충분) 이 변수에 그 경로를 지정. 엔트리포인트가 시스템 번들의 사본(`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `GIT_SSL_CAINFO`, `PIP_CERT`), `NODE_EXTRA_CA_CERTS`, `JAVA_TOOL_OPTIONS`로 지정한 JDK 트러스트 스토어 사본에 추가한다. 이 파일들은 `/tmp` 아래에만 쓰므로 `/tmp`만 쓸 수 있으면 루트 파일 시스템이 읽기 전용이어도 된다. 읽을 수 없거나 PEM 인증서가 없는 경로면 `[WARN]`을 출력하고 추가 CA 없이 계속 진행. CLI는 `SBOM_EXTRA_CA_CERTS`로 이 값을 대신 설정 |
| `ENRICH_EOL` | — | `true` | 번들된 오프라인 스냅샷으로 upstream end-of-life가 지난 컴포넌트를 표시 (AI SBOM은 건너뜀) |
| `ENRICH_MALICIOUS` | — | `true` | 번들된 오프라인 OSV 스냅샷으로 악성 패키지(오타 도용, 계정 탈취 배포본)를 표시. 취약점과 별개 신호이며, 대응도 업그레이드가 아니라 제거와 자격 증명 교체다 |
| `ENRICH_OS_CONTEXT` | — | `true` | 배포판 패키지 PURL(rpm·deb·apk)에서 `operating-system` 컴포넌트를 합성. Trivy가 이 컴포넌트를 보고 배포판 취약점 피드를 고르므로, 없으면 공급사 SBOM이나 rootfs 스캔의 OS 패키지는 OS CVE 매칭이 전혀 안 됨. 인식 가능한 배포판 패키지가 없으면 아무 동작도 하지 않음. Trivy가 피드를 제공하지 않는 배포판(예: OpenWRT)도 대상에서 제외 (AI SBOM은 건너뜀) |
| `ENRICH_DISTRO_SUPPLIER` | — | `true` | rpm·deb·apk 컴포넌트의 `supplier`를 배포판 프로젝트 이름으로 채움. `ENRICH_OS_CONTEXT`가 합성한 `operating-system` 컴포넌트에서 배포판을 읽는다. 확인된 공급자 이름이 없는 배포판, 배포판이 섞인 SBOM, 이미 supplier가 있는 컴포넌트는 그대로 둠 (AI SBOM은 건너뜀) |
| `STALENESS_ENRICH` | — | `false` | deps.dev 버전 최신성(최신 대비 몇 릴리스 뒤처졌는지) 추가. 네트워크 접근 필요 |
| `ENRICH_HF_SECURITY` | — | `true` | AIBOM 모드에서 HuggingFace의 파일별 보안 스캔 결과(ClamAV·picklescan)를 ML-BOM에 기록. 메타데이터만 읽고 파일은 내려받지 않음 |
| `API_KEY`, `API_URL` | 업로드 시 | — | 업로드 자격과 서버 주소. DT는 `X-Api-Key`, TRUSCA는 Bearer 토큰으로 쓰입니다 |
| `UPLOAD_TARGET` | — | `dependency-track` | 업로드 대상. `dependency-track`(DT 호환) 또는 `trusca`(네이티브 ingest, DT 비호환) |
| `TRUSCA_PROJECT_ID` | `trusca`일 때 | — | 업로드할 TRUSCA 프로젝트 id(UUID). 사전에 존재해야 합니다(자동 생성 없음) |
| `TRUSCA_REF` | — | `main` | ingest ref 라벨 |
| `TRUSCA_RELEASE` | — | `PROJECT_VERSION` | ingest release 라벨 |
| `BOMLENS_MAVEN_FULL_GRAPH` | — | — | Maven 소스 스캔: `1`로 설정하면 compile/runtime 스코프로 거르지 않고 전체 해석 그래프를 유지 |
| `BOMLENS_NODE_FULL_GRAPH` | - | - | Node.js 소스 스캔: `1`로 설정하면 production 전용 집합 대신 dev와 production을 합친 전체 그래프를 유지. `BOMLENS_INCLUDE_DEV_DEPENDENCIES` 중 Node.js 부분에 해당하며, 그 변수는 Node.js에서 같은 일을 하고 다른 생태계의 개발 의존성도 그대로 둠 |
| `BOMLENS_NODE_INSTALLED_LOCK` | - | 켜짐 | Node.js 소스 스캔: `false`(또는 `0`)로 두면 npm이나 pnpm이 설치할 때 써 둔 lock 파일(`node_modules/.package-lock.json`, `node_modules/.pnpm/lock.yaml`)을 읽지 않음. 그 밖에는 `package.json`이 있고 그 폴더와 상위 폴더에 커밋한 lock 파일이 없는 폴더를 이 lock으로 스캔하며, lock 파일은 스캔하는 동안만 두었다가 지움([Node.js](ecosystems.ko.md#nodejs)) |
| `BOMLENS_ANDROID_FULL_GRAPH` | - | - | Android 소스 스캔(Android SDK 이미지): `1`로 설정하면 release 런타임 클래스패스로 거르지 않고 빌드와 테스트 도구까지 포함한 전체 그래프를 유지 |
| `BOMLENS_GRADLE_FULL_GRAPH` | - | - | Java Gradle 소스 스캔: `1`로 설정하면 각 프로젝트의 런타임 클래스패스로 거르지 않고 테스트와 compileOnly 의존성까지 포함한 전체 그래프를 유지. 필터용 Gradle 실행은 루트만 해석하던 기존 준비 실행과 달리 모든 프로젝트를 해석하므로, 하위 프로젝트가 많은 빌드에서는 이 단계가 더 오래 걸림 |
| `BOMLENS_MAVEN_USER_REPOSITORY` | - | 켜짐 | Maven 소스 스캔: `false`(또는 `0`)로 두면 `/bomlens-settings/m2/repository`에 붙인 사용자의 Maven 로컬 저장소를 쓰지 않음. 그 밖에는 Maven이 이 폴더를 스캔 자체 저장소 다음에 읽되 쓰지 않고(`-Dmaven.repo.local.tail`, Maven 3.9 이상), cdxgen이 여기서 POM, 라이선스, jar 해시를 읽으며(`MAVEN_CACHE_DIR`), 내려받을 저장소가 응답하지 않을 때만 Maven을 오프라인(`-o`)으로 실행함([Java (Maven)](ecosystems.ko.md#java-maven)) |
| `BOMLENS_MAVEN_PROBE_TIMEOUT` | - | `5` | 사용자의 Maven 로컬 저장소를 붙인 Maven 소스 스캔: Maven이 내려받을 저장소(`settings.xml`의 첫 `<mirror>`, 없으면 Maven Central)의 응답을 기다리는 시간(초). 이 안에 응답하지 않으면 Maven을 오프라인(`-o`)으로 실행함 |
| `BOMLENS_GRADLE_USER_CACHE` | - | 켜짐 | Gradle 소스 스캔: `false`(또는 `0`)로 두면 `/bomlens-user-cache/gradle`과 `/bomlens-user-cache/gradle-wrapper`에 붙인 사용자의 Gradle 캐시와 래퍼 배포본을 쓰지 않음. 그 밖에는 캐시를 Gradle의 읽기 전용 의존성 캐시(`GRADLE_RO_DEP_CACHE`)로 쓰고, 빌드의 저장소가 하나도 응답하지 않을 때만 Gradle을 `--offline`으로 실행함([Java (Gradle)](ecosystems.ko.md#java-gradle)) |
| `BOMLENS_PYTHON_VENV` | - | 켜짐 | Python 소스 스캔: `false`(또는 `0`)로 두면 프로젝트에 설치된 가상 환경을 읽지 않음. 그 밖에는 소스에 `.venv/`, `venv/`, 또는 `pyvenv.cfg`가 든 다른 최상위 폴더 하나가 있고 pip이 쓸 패키지 저장소가 짧은 확인 요청에 응답하지 않거나 `pip install`이 실패하면, SBOM의 Python 부분을 그 환경의 `*.dist-info` 메타데이터에서 읽기 전용으로 가져오고 SBOM에 `bomlens:python-environment`를 기록함. 어느 쪽이든 환경 폴더는 cdxgen의 탐색, syft 폴백, 정적 읽기에서 빠짐([Python](ecosystems.ko.md#python)) |
| `BOMLENS_BUILD_TOOL` | - | `auto` | 최상위 폴더에 `pom.xml`과 `build.gradle`이 함께 있는 Java 소스 스캔. `maven` 또는 `gradle`이면 그 도구의 파일만 읽고, `auto`는 Gradle을 유지한다. CLI에서는 `--build-tool`로 지정한다 |
| `BOMLENS_PHP_FULL_GRAPH` | - | - | PHP(Composer) 소스 스캔: `1`로 설정하면 required 대상으로 거르지 않고 require와 require-dev를 합친 전체 그래프를 유지. `BOMLENS_INCLUDE_DEV_DEPENDENCIES` 중 PHP 부분에 해당 |
| `BOMLENS_KEEP_BUILD_OUTPUT` | — | — | 소스 스캔: `1`로 설정하면 의존성 해석 결과를 그대로 남김. 기본값에서는 해석 과정이 고쳐 쓴 파일(`go.mod`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `Package.resolved`)을 되돌리고 새로 생긴 빌드 디렉터리를 지워 스캔한 프로젝트를 원래 상태로 돌려줌 |
| `BOMLENS_PREP_TIMEOUT` | - | `900`(Gradle/Android 단계는 `1800`) | 의존성 해석 단계(Cargo, Go, Bundler, pip, npm, pnpm, PHP Composer, Swift, Gradle/Android) 하나가 실행될 수 있는 최대 시간(초). 넘으면 그 단계를 멈추고 스캔은 그 단계 없이 계속됨. 값을 주면 모든 단계의 두 기본값을 함께 덮어씀. 실패하거나 시간을 넘긴 단계는 자신의 출력과 함께 로그에 남고 SBOM에 `bomlens:pipeline-step-failed`로 기록되며, 스캔 자체는 끝까지 완료됨 |
| `BOMLENS_LICENSE_PROBE_TIMEOUT` | - | `6` | `FETCH_LICENSE`가 켜진 소스 스캔: cdxgen 실행 전에 발견한 생태계의 패키지 저장소마다 요청 한 번에 응답을 기다리는 시간(초). 응답하지 않는 저장소가 있으면 그 스캔의 라이선스 조회를 끄고 SBOM에 `bomlens:pipeline-step-failed` `license-fetch`로 기록함. 이때 라이선스는 lock 파일과 패키지 메타데이터에서 가져오며, 빠진 의존성은 없고 완전성 판정에도 반영하지 않음(CLI는 `[INFO]` 한 줄, 웹 UI는 안내 메모로 알림) |
| `BOMLENS_LICENSE_FETCH_TIMEOUT` | - | `1800` | `FETCH_LICENSE`가 켜진 소스 스캔: cdxgen 실행이 걸릴 수 있는 최대 시간(초). 넘으면 멈추고 라이선스 조회를 끈 채 다시 실행함(`license-fetch`로 기록). `0`이면 제한하지 않음 |
| `BOMLENS_CANCEL_GRACE` | — | `30` | 스캔을 취소했을 때(CLI Ctrl+C 또는 웹 UI의 취소 버튼) 깔끔하게 멈출 수 있도록 주는 유예 시간(초). 이 시간이 지나도 안 멈추면 강제로 정지시킴. CLI와 `--ui`에 적용되고, 데스크톱 앱은 항상 기본값을 쓴다 |
| `BOMLENS_REATTACH_GRACE` | - | `30` | 웹 UI: 어느 브라우저 탭에도 열려 있지 않은 스캔을 취소하기 전까지 계속 실행하는 시간(초, 0~600). 그동안 새로 고친 탭이나 다른 탭에서 다시 열 수 있음. 컨테이너 안의 웹 UI 서버가 읽음 |
| `BOMLENS_INCLUDE_NON_SHIPPED` | - | - | 소스 스캔: `1`로 설정하면 기본으로 제외하는 테스트, 예제, 벤치마크, 데모 폴더의 매니페스트, `.github/workflows`의 GitHub Actions 워크플로, `gradle/wrapper`의 Gradle 래퍼를 포함 |
| `BOMLENS_INCLUDE_DEV_DEPENDENCIES` | - | - | 소스 스캔: `1`로 설정하면 기본으로 빼는 개발 의존성을 모든 생태계에서 그대로 둠. 대상은 npm `devDependencies`와 그것만 필요로 하는 것(`BOMLENS_NODE_FULL_GRAPH=1`처럼 production 필터를 적용하지 않음), cdxgen이 개발 전용으로 표시한 컴포넌트(npm, pnpm, yarn, bun, uv와 Poetry 의존성 그룹, Cargo, sbt, Crystal, Gleam), 루트 `Gemfile`의 `development`, `test` 그룹에만 선언된 gem, Composer `require-dev`(`BOMLENS_PHP_FULL_GRAPH=1`과 같음), 설치된 Python 가상 환경에서 읽는 Poetry 의존성 그룹임. 개발 전용 표시 필터가 뺀 컴포넌트는 `bomlens:excluded-components`에 기록됨. Maven, Gradle, Android 범위 필터는 개발 의존성 말고도 빼는 것이 있어 각자의 스위치(`BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_GRADLE_FULL_GRAPH`, `BOMLENS_ANDROID_FULL_GRAPH`)를 따름 |
| `BOMLENS_NO_COPYRIGHT` | - | - | 소스 스캔: `1`로 설정하면 설치된 패키지의 라이선스 파일에서 npm, Python, Go, Rust 컴포넌트의 `copyright`를 채우는 단계를 건너뜀 |
| `BOMLENS_NO_CARGO_LICENSE` | - | - | 소스 스캔: `1`로 설정하면 `cargo metadata`로 Rust 컴포넌트의 라이선스를 채우는 단계를 건너뜀(명령줄의 `FETCH_LICENSE=false`도 건너뜀) |
| `BOMLENS_NO_AI_USAGE` | - | - | 소스 스캔: `1`로 설정하면 코드가 쓰는 AI(모델, AI 서비스, MCP 서버, 에이전트 지침 파일)를 기록하는 단계를 건너뜀([소스 스캔의 AI 사용 기록](artifacts.ko.md#소스-스캔의-ai-사용-기록) 참고) |
| `BOMLENS_AI_USAGE_TIMEOUT` | - | `300` | 소스 스캔: AI 사용 분석 두 가지가 각각 실행될 수 있는 시간(초). 넘으면 멈추고 그 결과는 넣지 않음 |
| `CYCLONEDX_SPEC_VERSION` | — | `1.6` | 생성하는 SBOM의 CycloneDX 버전. `1.6` 또는 `1.7`(CLI의 `--spec-version`). AI 모델과 데이터셋 SBOM은 항상 1.7. 다른 값이면 실행을 멈춤 |
| `CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6 1.7` | 적합성 검사가 허용하는 CycloneDX spec 버전(공백 구분). 기본 범위를 덮어씀 |
| `AI_CYCLONEDX_SPEC_VERSIONS` | — | `1.3 1.4 1.5 1.6 1.7` | AI SBOM(ML-BOM)이 허용하는 CycloneDX 버전. AIBOM 도구가 내보내는 1.7을 항상 포함 |
| `SPDX_SPEC_VERSIONS` | — | `SPDX-2.2 SPDX-2.3` | 적합성 검사가 허용하는 SPDX spec 버전 |
| `PURL_MIN_PCT` | — | `90` | 적합성 검사: PURL을 가진 컴포넌트 비율의 최소 기준(필수 검사). CLI든 웹 UI든 `--deep-cve` 스캔에도 적용됨 |
| `LICENSE_MIN_PCT` | — | `80` | 적합성 검사: 라이선스를 가진 컴포넌트 비율의 최소 기준(권장, 경고만 표시). CLI든 웹 UI든 `--deep-cve` 스캔에도 적용됨 |
| `HASH_MIN_PCT` | — | `50` | 적합성 검사: 해시를 가진 컴포넌트 비율의 최소 기준(권장, 경고만 표시). CLI든 웹 UI든 `--deep-cve` 스캔에도 적용됨 |
| `FIELD_MIN_PCT` | — | `80` | 적합성 검사: 규제 대응용 컴포넌트별 필드의 참고 기준 커버리지. CLI든 웹 UI든 `--deep-cve` 스캔에도 적용됨 |
| `PURL_TYPES_FILE` | — | `docker/lib/purl-types.json` | 적합성 검사: 어떤 purl 타입이 있고 그중 어떤 타입이 네임스페이스를 요구하는지 담은 purl-spec 데이터 |
| `OS_DISTROS_FILE` | — | `docker/lib/os-distros.json` | 적합성 검사: rpm, deb, apk 네임스페이스에 올 수 있는 배포판 식별자 목록 |
| `NS_ADVISORY_TYPES` | — | `golang huggingface` | 적합성 검사: 네임스페이스가 없어도 실패로 보지 않고 권고 항목으로만 보고할 타입(공백 구분) |
| `LICENSE_REGISTRY` | — | `false` | 스크립트의 `--license-registry`. 빠진 라이선스를 조회하고, 하나뿐인 강한 카피레프트나 비상업 라이선스를 패키지 레지스트리(deps.dev)와 대조한다. 네트워크를 사용 |
| `LICENSE_REGISTRY_VERIFY` | — | GPL, AGPL, SSPL-1.0, BUSL-1.1, CC-BY-NC 식별자 | 하나뿐일 때 레지스트리와 대조할 SPDX 식별자(공백 또는 쉼표 구분) |
| `LICENSE_REGISTRY_BUDGET` | — | `240` | 조회 전체에 허용하는 시간(초). 시간 안에 조회하지 못한 컴포넌트는 그대로 두고 단계를 degraded로 기록한다 |
| `LICENSE_REGISTRY_API` | — | `https://api.deps.dev/v3` | deps.dev v3 버전 조회에 같은 형식으로 답하는 서버의 기본 URL. 레지스트리에 자체 미러나 프록시로만 닿는 네트워크용. 응답이 없으면 컴포넌트는 그대로 두고 단계를 degraded(`unavailable`)로 기록한다 |
| `COCOAPODS_CDN_URL` | - | `https://cdn.cocoapods.org` | `FETCH_LICENSE`가 켜진 소스 스캔. pod 라이선스를 읽어 오는 CocoaPods trunk CDN, 또는 같은 `Specs/` 구조를 가진 미러의 기본 URL. 응답이 없으면 pod는 라이선스 없이 남고 로그에 그 사실을 적는다 |
| `COCOAPODS_LICENSE_BUDGET` | - | `120` | CocoaPods podspec 조회에 쓰는 전체 시간(초). 시간 안에 조회하지 못한 pod는 라이선스 없이 남는다 |
| `PURL_RESOLVE` | — | `false` | `--analyze` 전용(스크립트의 `--resolve-purl`). 각 식별자를 패키지 저장소(deps.dev)에 조회해 적합성 검사 보고서에 권고 항목으로 덧붙인다. 네트워크를 사용 |
| `MODEL_RESOLVE` | - | `false` | 소스 스캔 전용(스크립트의 `--resolve-models`). 코드가 참조하는 Hugging Face 모델을 허브에서 읽음. 네트워크를 쓰며, `HF_ENDPOINT`로 미러를 지정하고 `HF_TOKEN`으로 비공개 모델을 읽음 |
| `MODEL_RESOLVE_MAX` | - | `20` | 스캔 한 번에 조회하는 모델 수. 나머지는 `not-attempted`로 표시 |
| `MODEL_RESOLVE_BUDGET` | - | `240` | 스캔 한 번의 전체 조회에 허용하는 시간(초). 기반 모델 조회를 포함하며, 닿지 못한 모델은 `not-attempted`로 표시 |
| `PURL_RESOLVE_IGNORE` | — | — | 조회에서 제외할 네임스페이스 접두사(공백 또는 쉼표 구분). 사내 저장소에만 올리는 네임스페이스에 쓴다. 잘못된 식별자와 구분할 수 없기 때문이다 |
| `PURL_RESOLVE_BUDGET` | — | `240` | 조회 전체에 허용하는 시간(초). 시간 안에 조회하지 못한 식별자는 없음이 아니라 확인 불가로 보고한다 |
| `ANALYZE_CPE_INDEX` | — | `false` | `--analyze` 전용(스크립트의 `--analyze-cpe-index`). `bomlens:purlSource=upstream-map` 속성이 붙은 컴포넌트를 번들 CPE 색인에 대조한다. |

> TRUSCA(구 TrustedOSS Portal)의 네이티브 ingest 엔드포인트(`POST /v1/projects/{id}/sbom-ingest`, Bearer 인증)는 Dependency-Track와 호환되지 않습니다. 일반 Dependency-Track 서버로 올릴 때는 `UPLOAD_TARGET=dependency-track`(기본값)을 그대로 두세요.

CLI 플래그와 환경 변수의 전체 대응은 [아키텍처의 플래그 매핑](../concepts/architecture.ko.md#플래그--단계-매핑)을 참고하세요.

## 이미지 빌드와 배포

이미지를 직접 빌드하거나 멀티 플랫폼으로 발행하는 절차는 기여자용 [docker/README](https://github.com/sktelecom/bomlens/blob/main/docker/README.md)에 있습니다.

---

> **관련 문서**: [첫 스캔](../start/first-scan.ko.md) | [CLI 레퍼런스](../reference/cli.ko.md) | [아키텍처](../concepts/architecture.ko.md)
