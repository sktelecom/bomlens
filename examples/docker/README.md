# Docker 이미지 예제

멀티 스테이지 빌드를 사용한 Node.js 애플리케이션 Docker 이미지입니다. Docker 이미지의 SBOM 생성 테스트를 위한 예제로 사용됩니다.

## Docker 이미지 정보

- 베이스 이미지: node:18-alpine
- 빌드 방식: 멀티 스테이지 빌드
- 애플리케이션: Express.js REST API
- 크기: 약 150MB (압축 후)

## 사전 요구사항

- Docker 20.10 이상

## Docker 이미지 빌드

### 기본 빌드

```bash
# 프로젝트 디렉토리로 이동
cd examples/docker

# Node.js 소스 파일 준비 (../nodejs에서 복사)
cp ../nodejs/package*.json ./
cp ../nodejs/index.js ./

# 이미지 빌드
docker build -t sbom-example:latest .
```

### 태그 지정 빌드

```bash
docker build -t sbom-example:1.0.0 -t sbom-example:latest .
```

## SBOM 생성

### 방법 1: SBOM Generator 스크립트 사용 (권장)

```bash
# 이미지 빌드 후
docker images | grep sbom-example

# SBOM 생성
../../scripts/scan-sbom.sh \
  --target "sbom-example:latest" \
  --project "DockerImageExample" \
  --version "1.0.0" \
  --generate-only
```

결과로 `DockerImageExample_1.0.0_sbom-example_latest_bom.json` 파일이 생성됩니다.

### 방법 2: Docker 직접 사용

```bash
docker run --rm \
  -v "$(pwd)":/host-output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MODE=IMAGE \
  -e TARGET_IMAGE="sbom-example:latest" \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="DockerImageExample" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/sbom-scanner:v1
```

### 방법 3: Syft 직접 사용

```bash
# Syft 설치
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# SBOM 생성
syft sbom-example:latest -o cyclonedx-json > bom.json
```

### 방법 4: Trivy 사용

> 보안 경고 (2026-03-24): `aquasecurity/trivy-action` GitHub Action에 공급망 공격(악성 코드 삽입)이 보고되었습니다.
> Trivy CLI 자체의 안전성도 공식적으로 재확인될 때까지, 아래 명령어 실행 전 반드시 [공식 릴리스 페이지](https://github.com/aquasecurity/trivy/releases)에서 최신 보안 공지를 확인하세요.

```bash
# Trivy 설치
brew install trivy  # macOS
# 또는
sudo apt-get install trivy  # Ubuntu

# SBOM 생성
trivy image --format cyclonedx sbom-example:latest > bom.json
```

## Docker 이미지 실행

### 기본 실행

```bash
docker run -p 3000:3000 sbom-example:latest
```

접속 주소는 http://localhost:3000 입니다.

### 백그라운드 실행

```bash
docker run -d \
  --name sbom-example \
  -p 3000:3000 \
  sbom-example:latest

# 로그 확인
docker logs -f sbom-example

# 중지
docker stop sbom-example

# 삭제
docker rm sbom-example
```

### 환경변수 전달

```bash
docker run -p 3000:3000 \
  -e PORT=3000 \
  -e NODE_ENV=production \
  sbom-example:latest
```

### Docker Compose 사용

`docker-compose.yml` 생성:

```yaml
version: '3.8'

services:
  app:
    build: .
    image: sbom-example:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
```

실행:

```bash
docker-compose up -d
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh *_bom.json

# 컴포넌트 개수 확인
cat *_bom.json | jq '.components | length'

# OS 패키지 확인
cat *_bom.json | jq -r '.components[] | select(.type == "operating-system") | "\(.name)@\(.version)"'

# npm 패키지 확인
cat *_bom.json | jq -r '.components[] | select(.purl | contains("npm")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 100-150개입니다.
- Alpine Linux 시스템 패키지: 20-30개
- Node.js 런타임: 10-20개
- npm 의존성: 70-100개

## 예상 SBOM 내용

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

### OS 레이어
- Alpine Linux: musl, busybox, apk-tools 등
- 시스템 라이브러리: libssl, libcrypto, zlib 등

### Node.js 런타임
- Node.js: v18.x.x
- npm: v9.x.x

### 애플리케이션 의존성
- Express 스택: express, body-parser, serve-static
- 보안: helmet, cors
- 유틸리티: lodash, moment
- 로깅: morgan, winston

## Docker 이미지 분석

### 이미지 레이어 확인

```bash
docker history sbom-example:latest
```

### 이미지 크기 확인

```bash
docker images sbom-example:latest
```

### 취약점 스캔

> 보안 경고 (2026-03-24): Trivy 관련 공급망 공격이 보고되었습니다. 실행 전 공식 보안 공지를 확인하세요.

```bash
# Trivy로 취약점 스캔
trivy image sbom-example:latest

# Grype로 취약점 스캔
grype sbom-example:latest
```

## 원격 레지스트리 이미지

### Docker Hub 공개 이미지

```bash
# Nginx Alpine 이미지 SBOM 생성
../../scripts/scan-sbom.sh \
  --target "nginx:alpine" \
  --project "NginxAlpine" \
  --version "alpine" \
  --generate-only
```

### GitHub Container Registry

```bash
# ghcr.io 이미지 SBOM 생성
../../scripts/scan-sbom.sh \
  --target "ghcr.io/owner/image:tag" \
  --project "CustomImage" \
  --version "1.0" \
  --generate-only
```

### 프라이빗 레지스트리

```bash
# 1. Docker 로그인
docker login registry.company.com

# 2. SBOM 생성
../../scripts/scan-sbom.sh \
  --target "registry.company.com/myapp:latest" \
  --project "MyPrivateApp" \
  --version "latest" \
  --generate-only
```

## 이미지 tar 파일

### 이미지 저장

```bash
# Docker 이미지를 tar로 저장
docker save sbom-example:latest -o sbom-example.tar

# 파일 확인
ls -lh sbom-example.tar
```

### tar 파일 SBOM 생성

```bash
# tar 파일 분석
../../scripts/scan-sbom.sh \
  --target sbom-example.tar \
  --project "DockerTarExample" \
  --version "1.0" \
  --generate-only
```

## 최적화 팁

### 멀티 스테이지 빌드

Dockerfile은 이미 멀티 스테이지를 사용하고 있습니다:

- Stage 1 (builder): 의존성 설치 및 빌드
- Stage 2 (production): 최종 실행 이미지 (필요한 파일만 포함)

이렇게 하면 이미지 크기가 줄고, 빌드 도구가 최종 이미지에 포함되지 않아 보안에도 도움이 됩니다.

### Alpine Linux 사용

Alpine Linux는 매우 작은 크기의 베이스 이미지입니다:

- 크기: 약 5MB
- 패키지 매니저: apk
- 보안: 정기적인 보안 업데이트

### .dockerignore 사용

`.dockerignore` 파일 생성:

```
node_modules
npm-debug.log
.git
.env
*.md
Dockerfile
.dockerignore
```

## 문제 해결

### 이미지 빌드 실패

```bash
# 캐시 없이 빌드
docker build --no-cache -t sbom-example:latest .

# 빌드 로그 상세 출력
docker build --progress=plain -t sbom-example:latest .
```

### Docker 소켓 접근 오류

```bash
# Docker 소켓 권한 확인
ls -la /var/run/docker.sock

# 현재 사용자 docker 그룹 추가
sudo usermod -aG docker $USER
# 로그아웃 후 다시 로그인
```

### SBOM 생성 실패

```bash
# 이미지 존재 확인
docker images | grep sbom-example

# 이미지 pull (원격 이미지인 경우)
docker pull sbom-example:latest

# Syft 직접 실행하여 디버그
syft sbom-example:latest -vv
```

## 보안 고려사항

### 비-루트 사용자

Dockerfile은 이미 비-루트 사용자(`nodejs`)를 사용합니다.

```dockerfile
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs
```

### 헬스 체크

헬스 체크가 포함되어 있어 컨테이너 상태를 모니터링할 수 있습니다.

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "..."
```

### 취약점 스캔

정기적으로 이미지를 스캔하여 취약점을 확인하세요.

> 보안 경고 (2026-03-24): Trivy 관련 공급망 공격이 보고되었습니다. 실행 전 공식 보안 공지를 확인하세요.

```bash
trivy image --severity HIGH,CRITICAL sbom-example:latest
```

## 다음 단계

- [사용 가이드](../../docs/usage-guide.md) - Docker 이미지 분석 상세
- [시작하기](../../docs/getting-started.md) - 첫 SBOM 생성
- [Docker README](../../docker/README.md) - Scanner 이미지 가이드

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 보안 스캔, 모니터링, 로그 수집, 비밀 관리 등을 추가해야 합니다.
