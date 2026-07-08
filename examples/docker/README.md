# Docker 이미지 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

멀티 스테이지 빌드를 사용한 Node.js 애플리케이션 Docker 이미지입니다. Docker 이미지의 SBOM 생성 테스트를 위한 예제로 사용됩니다. 베이스 이미지는 node:18-alpine입니다.

## Docker 이미지 빌드

먼저 스캔할 이미지를 빌드합니다.

```bash
# 프로젝트 디렉토리로 이동
cd examples/docker

# Node.js 소스 파일 준비 (../nodejs에서 복사)
cp ../nodejs/package*.json ./
cp ../nodejs/index.js ./

# 이미지 빌드
docker build -t sbom-example:latest .
```

## SBOM 생성

### 방법 1: BomLens 스크립트 사용 (권장)

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/start/first-scan.ko.md) 참고.

```bash
../../scripts/scan-sbom.sh \
  --target "sbom-example:latest" \
  --project "DockerImageExample" \
  --version "1.0.0" \
  --generate-only
```

결과는 `DockerImageExample_1.0.0/` 폴더에 저장됩니다(`DockerImageExample_1.0.0_bom.json` 등).

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
  ghcr.io/sktelecom/bomlens:latest
```

이 방법은 스크립트와 달리 출력 폴더에 바로(하위 폴더 없이) 저장됩니다.

### 방법 3: Syft 직접 사용

```bash
# Syft 설치
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# SBOM 생성
syft sbom-example:latest -o cyclonedx-json > bom.json
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json

# 컴포넌트 개수 확인
cat DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json | jq '.components | length'

# OS 패키지 확인
cat DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json | jq -r '.components[] | select(.type == "operating-system") | "\(.name)@\(.version)"'

# npm 패키지 확인
cat DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json | jq -r '.components[] | select(.purl | contains("npm")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 100-150개입니다.
- Alpine Linux 시스템 패키지: 20-30개
- Node.js 런타임: 10-20개
- npm 의존성: 70-100개

## 원격 레지스트리 이미지와 tar 파일

레지스트리에 있는 이미지는 `--target`에 이미지 이름을 그대로 지정합니다. 프라이빗 레지스트리는 `docker login` 후 같은 방식으로 스캔합니다.

```bash
../../scripts/scan-sbom.sh \
  --target "nginx:alpine" \
  --project "NginxAlpine" \
  --version "alpine" \
  --generate-only
```

`docker save`로 저장한 이미지 tar 파일도 `--target sbom-example.tar`처럼 파일 경로를 지정해 스캔할 수 있습니다.

## 문제 해결

SBOM 생성이 실패하면 이미지 존재 여부와 Docker 소켓 권한을 먼저 확인하세요.

```bash
# 이미지 존재 확인
docker images | grep sbom-example

# Docker 소켓 권한 확인
ls -la /var/run/docker.sock

# 현재 사용자 docker 그룹 추가 (로그아웃 후 다시 로그인)
sudo usermod -aG docker $USER
```

## 다음 단계

- [사용 가이드](../../docs/reference/cli.ko.md) - Docker 이미지 분석 상세
- [시작하기](../../docs/start/first-scan.ko.md) - 첫 SBOM 생성
- [Docker README](../../docker/README.md) - Scanner 이미지 가이드
