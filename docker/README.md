# Docker 이미지 가이드 (빌드와 배포)

BomLens Docker 이미지를 직접 빌드하고 배포하려는 기여자를 위한 가이드입니다.

이미지를 사용만 한다면 이 문서가 아니라 사이트의 [Docker 이미지 직접 사용](https://sktelecom.github.io/sbom-tools/docker-image/) 가이드를 보세요. `docker run` 예시와 환경 변수 설명이 거기에 있습니다.

## 이미지 정보

- 대표 이름: `ghcr.io/sktelecom/bomlens` (별칭 `sbom-generator`, `sbom-scanner` — 같은 다이제스트)
- 펌웨어 분석용: `ghcr.io/sktelecom/sbom-scanner-firmware` (opt-in)
- 플랫폼: `linux/amd64`, `linux/arm64`
- 베이스: `python:3.12-slim`. 언어 toolchain 없는 경량 후처리 이미지이며, 포함 도구와 버전은 `Dockerfile`의 `ARG`로 고정됩니다 (syft, Trivy, cosign, scancode 등).

## 직접 빌드하기

### 사전 요구사항

- Docker 20.10 이상
- 디스크 공간 5GB 이상

### 로컬 빌드

```bash
# 저장소 클론
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools/docker

# 빌드
docker build -t sbom-scanner:local .

# 빌드 시간: 약 10-15분 (네트워크 속도에 따라 다름)
```

### 빌드 확인

```bash
# 이미지 확인
docker images | grep sbom-scanner

# 테스트 실행
docker run --rm sbom-scanner:local cdxgen --version
```

출력 예시:
```
10.2.0
```

### 빌드 옵션

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

### buildx 설정

```bash
# buildx 빌더 생성
docker buildx create --name multiplatform-builder --use

# 빌더 부팅
docker buildx inspect --bootstrap

# 지원 플랫폼 확인
docker buildx inspect
```

출력 예시:
```
Name:   multiplatform-builder
Driver: docker-container

Platforms: linux/amd64, linux/arm64, linux/arm/v7
```

### 멀티 플랫폼 빌드 실행

```bash
# AMD64 + ARM64 동시 빌드
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/sbom-scanner:v1 \
  -t ghcr.io/sktelecom/sbom-scanner:latest \
  --load \
  .
```

참고: `--load`는 단일 플랫폼만 가능. 멀티 플랫폼은 `--push` 사용.

### GitHub Container Registry에 푸시

```bash
# 멀티 플랫폼 빌드 + 푸시
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/sktelecom/sbom-scanner:v1 \
  -t ghcr.io/sktelecom/sbom-scanner:latest \
  --push \
  .
```

빌드 시간: 약 15-20분 (플랫폼 2개)

## GitHub Container Registry 배포

### 1. Personal Access Token 생성

1. GitHub에서 Settings, Developer settings, Personal access tokens 순으로 들어가 Tokens (classic)을 엽니다.
2. "Generate new token (classic)" 클릭
3. 권한 선택:
   - `write:packages` - 패키지 업로드
   - `read:packages` - 패키지 다운로드
   - `delete:packages` - 패키지 삭제 (선택)
4. 토큰 생성 및 저장

### 2. GitHub Container Registry 로그인

```bash
# 환경변수 설정
export GITHUB_TOKEN="ghp_your_personal_access_token"
export GITHUB_USERNAME="your_github_username"

# 로그인
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin
```

성공 메시지:
```
Login Succeeded
```

### 3. 이미지 빌드 및 푸시

```bash
# 조직명 설정
ORG_NAME="sktelecom"
IMAGE_NAME="sbom-scanner"
VERSION="v1"

# 멀티 플랫폼 빌드 + 푸시
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/${ORG_NAME}/${IMAGE_NAME}:${VERSION} \
  -t ghcr.io/${ORG_NAME}/${IMAGE_NAME}:latest \
  --push \
  .
```

### 4. 푸시 확인

```bash
# 이미지 메타데이터 확인
docker buildx imagetools inspect ghcr.io/${ORG_NAME}/${IMAGE_NAME}:${VERSION}
```

출력 예시:
```
Name:      ghcr.io/sktelecom/sbom-scanner:v1
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:abc123def456...

Manifests:
  Name:      ghcr.io/sktelecom/sbom-scanner:v1@sha256:111...
  MediaType: application/vnd.oci.image.manifest.v1+json
  Platform:  linux/amd64

  Name:      ghcr.io/sktelecom/sbom-scanner:v1@sha256:222...
  MediaType: application/vnd.oci.image.manifest.v1+json
  Platform:  linux/arm64
```

### 5. 패키지 공개 설정

기본적으로 패키지는 Private입니다. Public으로 변경:

1. https://github.com/orgs/sktelecom/packages 접속
2. `bomlens` 패키지 선택 (별칭 `sbom-generator`, `sbom-scanner`도 같은 방식)
3. "Package settings"에서 "Change visibility"를 눌러 "Public"을 고릅니다
4. 패키지명 입력하여 확인

## 이미지 상세 정보

### Dockerfile 구조

```dockerfile
FROM node:20-bookworm

# 기본 도구 설치
RUN apt-get update && apt-get install -y \
    curl bash jq git maven gradle python3 ...

# Java 다중 버전 설치 (8, 11, 17, 21)
RUN apt-get install -y temurin-21-jdk temurin-17-jdk ...

# Python 2.x 지원 (레거시)
RUN apt-get install -y python2 python2-dev ...

# Ruby, PHP, Rust 설치
RUN apt-get install -y ruby bundler php composer ...
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y

# SBOM 도구 설치
RUN npm install -g @cyclonedx/cdxgen
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Entrypoint 설정
COPY entrypoint.sh /usr/local/bin/run-scan
ENTRYPOINT ["/usr/local/bin/run-scan"]
```

### 레이어 크기 분석

| 레이어 | 크기 | 설명 |
|--------|------|------|
| 베이스 이미지 (node:20-bookworm) | ~900MB | Node.js + Debian |
| Java JDK (4개 버전) | ~800MB | Temurin 8, 11, 17, 21 |
| Python 2/3 | ~200MB | Python 런타임 및 pip |
| Ruby + PHP | ~150MB | 런타임 및 패키지 매니저 |
| Rust | ~200MB | Rust 툴체인 |
| SBOM 도구 | ~150MB | cdxgen, syft |
| 기타 도구 | ~100MB | Maven, Gradle, Git 등 |

총 크기: 약 2.5GB (압축 전: ~4GB)

### 지원 아키텍처

| 아키텍처 | 플랫폼 | 사용 환경 |
|---------|--------|----------|
| `linux/amd64` | x86_64 | Intel/AMD 서버, WSL2 |
| `linux/arm64` | aarch64 | Apple Silicon (M1/M2/M3), ARM 서버 |

Docker가 자동으로 현재 플랫폼에 맞는 이미지를 다운로드합니다.

## 테스트

### 통합 테스트

```bash
# 테스트 스크립트 실행
cd /path/to/sbom-tools
./tests/test-scan.sh
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

# SBOM 생성 테스트
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME=TestProject \
  -e PROJECT_VERSION=1.0.0 \
  ghcr.io/sktelecom/sbom-scanner:v1

# 결과 확인
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
echo ghcr.io/sktelecom/sbom-scanner:v1
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

### 캐시 디렉토리 마운트

빌드 성능 향상을 위해 Maven/Gradle 캐시를 마운트:

```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$HOME/.m2":/root/.m2 \
  -v "$HOME/.gradle":/root/.gradle \
  ...
```

### 사용자 정의 entrypoint

```bash
# Bash 셸로 진입
docker run --rm -it \
  -v "$(pwd)":/src \
  --entrypoint /bin/bash \
  ghcr.io/sktelecom/sbom-scanner:v1

# 컨테이너 내부에서 수동 실행
root@container:/src# cdxgen -o bom.json .
```

## 참고 자료

- **Dockerfile**: [docker/Dockerfile](Dockerfile)
- **Entrypoint 스크립트**: [docker/entrypoint.sh](entrypoint.sh)
- **Docker 공식 문서**: https://docs.docker.com/
- **Docker Buildx**: https://docs.docker.com/buildx/working-with-buildx/

## 문의

- **이메일**: opensource@sktelecom.com
- **이슈**: [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)
