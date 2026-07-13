# Docker 이미지 가이드 (빌드와 배포)

BomLens Docker 이미지를 직접 빌드하고 배포하려는 기여자를 위한 가이드입니다.

이미지를 사용만 한다면 이 문서가 아니라 사이트의 [Docker 이미지 직접 사용](https://sktelecom.github.io/bomlens/docker-image/) 가이드를 보세요. `docker run` 예시와 환경 변수 설명이 거기에 있습니다.

## 이미지 정보

- 대표 이름: `ghcr.io/sktelecom/bomlens` (별칭 `sbom-generator`, `sbom-scanner` — 같은 다이제스트)
- 펌웨어 분석용: `ghcr.io/sktelecom/bomlens-firmware` (opt-in) (legacy alias: sbom-scanner-firmware)
- 플랫폼: `linux/amd64`, `linux/arm64`
- 베이스: `python:3.12-slim`. 언어 toolchain 없는 경량 후처리 이미지이며, 포함 도구와 버전은 `Dockerfile`의 `ARG`로 고정됩니다 (syft, Trivy, cosign, scancode 등).

## 직접 빌드하기

### 사전 요구사항

- Docker 20.10 이상
- 디스크 공간 5GB 이상

### 로컬 빌드

```bash
# 저장소 클론
git clone https://github.com/sktelecom/bomlens.git
cd bomlens/docker

# 빌드
docker build -t sbom-scanner:local .

# 빌드 시간: 약 10-15분 (네트워크 속도에 따라 다름)
```

### 빌드 확인

이미지에 실제로 들어 있는 도구로 확인합니다. cdxgen은 이 이미지에 없습니다. 소스 스캔의 cdxgen은 `scan-sbom.sh`가 필요할 때 언어별 공식 이미지를 따로 받아 실행합니다.

```bash
# 이미지 확인
docker images | grep sbom-scanner

# 테스트 실행
docker run --rm --entrypoint syft sbom-scanner:local version
docker run --rm --entrypoint trivy sbom-scanner:local --version
```

### 빌드 옵션

#### opt-in 도구 선택

기능별 도구는 `--build-arg`로 켭니다. 기본 빌드는 경량을 유지하기 위해 대부분 꺼져 있습니다.

| 빌드 인자 | 기본값 | 켜면 포함되는 것 |
|-----------|--------|------------------|
| `SBOM_FIRMWARE` | `false` | 펌웨어 분석 도구(unblob, cve-bin-tool, ubi_reader)와 CPE→CVE 인덱스 번들. `bomlens-firmware` 이미지가 이 옵션으로 빌드됩니다. NVD 데이터는 빌드 시 `fkie-cad/nvd-json-data-feeds`를 clone해 로컬에서 인덱스로 증류하므로 NVD API 키나 시크릿이 필요 없습니다 |
| `SBOM_AIBOM` | `false` | AI 모델 SBOM 생성 도구(OWASP aibom-generator + cdxgen) |
| `SBOM_DEEP_LICENSE` | `false` | scancode-toolkit 기반 딥 라이선스 스캔 |
| `SBOM_SCANOSS` | `true` | vendored OSS 식별 클라이언트(scanoss.py). 실행은 런타임 `--identify-vendored`로 다시 gate됩니다 |
| `SBOM_PDF` | `false` | 고지문 PDF 렌더러(weasyprint) |

```bash
# 예: 펌웨어 분석 이미지 빌드 (NVD 키·시크릿 불필요)
docker build --build-arg SBOM_FIRMWARE=true \
  -t sbom-scanner-firmware:local .
```

#### 캐시 없이 빌드

```bash
docker build --no-cache -t sbom-scanner:local .
```

#### 특정 플랫폼용 빌드

```bash
# AMD64 (Intel/AMD)
docker build --platform linux/amd64 -t sbom-scanner:amd64 .

# ARM64 (Apple Silicon)
docker build --platform linux/arm64 -t sbom-scanner:arm64 .
```

## 멀티 플랫폼 빌드

정식 배포는 사람이 수동으로 하지 않습니다. `main` push와 릴리스 태그에서 `.github/workflows/docker-publish.yml`이 멀티 플랫폼 빌드와 3개 이름(bomlens, sbom-generator, sbom-scanner) 배포를 수행합니다. 아래 절차는 워크플로를 우회해야 하는 예외 상황(예: 레지스트리 장애 복구, 사전 검증)용입니다.

### buildx 설정

```bash
# buildx 빌더 생성
docker buildx create --name multiplatform-builder --use

# 빌더 부팅
docker buildx inspect --bootstrap

# 지원 플랫폼 확인
docker buildx inspect
```

### 멀티 플랫폼 빌드 실행

```bash
# AMD64 + ARM64 동시 빌드
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/bomlens:latest \
  --push \
  .
```

참고: `--load`는 단일 플랫폼만 가능합니다. 멀티 플랫폼은 `--push`를 사용합니다.

## GitHub Container Registry 배포 (예외 상황용)

### 1. Personal Access Token 생성

1. GitHub에서 Settings, Developer settings, Personal access tokens 순으로 들어가 Tokens (classic)을 엽니다.
2. "Generate new token (classic)" 클릭
3. 권한 선택:
   - `write:packages` - 패키지 업로드
   - `read:packages` - 패키지 다운로드
4. 토큰 생성 및 저장

### 2. GitHub Container Registry 로그인

```bash
# 환경변수 설정
export GITHUB_TOKEN="ghp_your_personal_access_token"
export GITHUB_USERNAME="your_github_username"

# 로그인
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin
```

### 3. 이미지 빌드 및 푸시

```bash
# 멀티 플랫폼 빌드 + 푸시
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/bomlens:latest \
  --push \
  .
```

### 4. 푸시 확인

```bash
# 이미지 메타데이터 확인 (amd64/arm64 매니페스트가 모두 보여야 함)
docker buildx imagetools inspect ghcr.io/sktelecom/bomlens:latest
```

### 5. 패키지 공개 설정

기본적으로 패키지는 Private입니다. Public으로 변경:

1. https://github.com/orgs/sktelecom/packages 접속
2. `bomlens` 패키지 선택 (별칭 `sbom-generator`, `sbom-scanner`도 같은 방식)
3. "Package settings"에서 "Change visibility"를 눌러 "Public"을 고릅니다
4. 패키지명 입력하여 확인

## 이미지 상세 정보

### Dockerfile 구조

2-스테이지 빌드입니다. 언어 toolchain은 넣지 않습니다. 소스 코드의 SBOM 생성은 `scan-sbom.sh`가 cdxgen 언어별 공식 이미지를 그때그때 받아 위임하고, 이 이미지는 후처리와 스캔을 담당합니다.

- 스테이지 1 (`node:26-alpine`): 웹 UI(React SPA)를 빌드합니다. node는 이 스테이지에만 있고 결과물 `dist/`만 런타임으로 복사됩니다.
- 스테이지 2 (`python:3.12-slim`): 실행 이미지입니다. syft(이미지/바이너리/RootFS 스캔), Trivy(보안 보고서), cosign(서명), docker CLI(웹 UI 소스 스캔이 cdxgen 형제 컨테이너를 띄울 때 사용), 그리고 entrypoint와 후처리 스크립트가 들어갑니다.

도구 버전은 `Dockerfile`의 `ARG`로 고정되며 Renovate가 업스트림 릴리스를 추적해 갱신 PR을 엽니다.

| 도구 | ARG | 고정 버전 |
|------|-----|----------|
| syft | `SYFT_VERSION` | v1.46.0 |
| Trivy | `TRIVY_VERSION` | v0.72.0 |
| cosign | `COSIGN_VERSION` | v2.4.1 |
| docker CLI | `DOCKER_CLI_VERSION` | 27.5.1 |
| scanoss.py | `SCANOSS_VERSION` | 1.25.2 |
| scancode-toolkit (opt-in) | `SCANCODE_VERSION` | 32.5.0 |
| cdxgen (aibom opt-in) | `CDXGEN_VERSION` | 12.7.0 |

### 이미지 크기

기본 빌드는 약 1GB입니다(로컬 실측 981MB). 레이어별 크기는 직접 확인하는 편이 정확합니다.

```bash
docker history sbom-scanner:local
```

펌웨어 이미지(`SBOM_FIRMWARE=true`)는 번들된 CVE DB(약 0.5~1.5GB)만큼 커집니다.

### 지원 아키텍처

| 아키텍처 | 플랫폼 | 사용 환경 |
|---------|--------|----------|
| `linux/amd64` | x86_64 | Intel/AMD 서버, WSL2 |
| `linux/arm64` | aarch64 | Apple Silicon (M1/M2/M3), ARM 서버 |

Docker가 자동으로 현재 플랫폼에 맞는 이미지를 다운로드합니다.

## 테스트

### 통합 테스트

```bash
# 테스트 스크립트 실행 (SBOM_SCANNER_IMAGE로 방금 빌드한 이미지 지정)
cd /path/to/bomlens
SBOM_SCANNER_IMAGE=sbom-scanner:local ./tests/test-scan.sh
```

테스트 시나리오:
- Node.js 프로젝트
- Python 프로젝트
- Java Maven 프로젝트
- Ruby 프로젝트
- PHP 프로젝트
- Rust 프로젝트
- Docker 이미지
- 바이너리 파일
- RootFS 디렉토리

### 수동 테스트

```bash
# 간단한 Node.js 프로젝트 생성
mkdir test-project
cd test-project
echo '{"name":"test","version":"1.0.0","dependencies":{"express":"4.18.0"}}' > package.json
npm install --package-lock-only

# SBOM 생성 테스트 (방금 빌드한 이미지)
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME=TestProject \
  -e PROJECT_VERSION=1.0.0 \
  sbom-scanner:local

# 결과 확인 (docker run 직접 실행은 출력 폴더에 바로 저장됩니다)
ls -la TestProject_1.0.0_bom.json
cat TestProject_1.0.0_bom.json | jq '.components | length'
```

## 문제 해결

### 빌드 실패

#### 오류: "manifest unknown"

원인: GitHub Container Registry에 이미지가 없음

해결:
```bash
# 로그인 확인
docker login ghcr.io

# 이미지 경로 확인
echo ghcr.io/sktelecom/bomlens:latest
```

#### 오류: "no space left on device"

원인: 디스크 공간 부족

해결:
```bash
# 사용하지 않는 이미지 정리
docker system prune -a

# 디스크 공간 확인
df -h
```

### 실행 오류

#### 오류: "Cannot connect to the Docker daemon"

원인: Docker 소켓이 마운트되지 않음 (IMAGE 모드)

해결:
```bash
# Linux/macOS
-v /var/run/docker.sock:/var/run/docker.sock

# Windows (Docker Desktop)
-v //./pipe/docker_engine://./pipe/docker_engine
```

#### 오류: "Permission denied" (파일 쓰기)

원인: 컨테이너 내부 사용자 권한 문제

해결:
```bash
# 현재 사용자 권한으로 실행
docker run --rm --user $(id -u):$(id -g) ...
```

## 고급 사용법

### 프록시 환경에서 빌드

```bash
# 프록시 설정
docker build \
  --build-arg HTTP_PROXY=http://proxy.company.com:8080 \
  --build-arg HTTPS_PROXY=http://proxy.company.com:8080 \
  -t sbom-scanner:local .
```

### 사용자 정의 entrypoint

```bash
# Bash 셸로 진입
docker run --rm -it \
  -v "$(pwd)":/src \
  --entrypoint /bin/bash \
  sbom-scanner:local

# 컨테이너 내부에서 수동 실행 (이미지에 든 syft 사용)
root@container:/src# syft dir:/src -o cyclonedx-json > bom.json
```

## 참고 자료

- **Dockerfile**: [docker/Dockerfile](Dockerfile)
- **Entrypoint 스크립트**: [docker/entrypoint.sh](entrypoint.sh)
- **Docker 공식 문서**: https://docs.docker.com/
- **Docker Buildx**: https://docs.docker.com/buildx/working-with-buildx/

## 문의

- **이메일**: opensource@sktelecom.com
- **이슈**: [GitHub Issues](https://github.com/sktelecom/bomlens/issues)
