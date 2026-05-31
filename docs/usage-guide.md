# 사용 가이드

> **관련 문서**: [시작하기](getting-started.md) | [예제 가이드](examples-guide.md) | [아키텍처](architecture.md)

SBOM Tools의 전체 옵션, 분석 모드, CI/CD 통합 방법 및 트러블슈팅을 설명합니다.

## 목차

- [옵션 레퍼런스](#옵션-레퍼런스)
- [분석 모드](#분석-모드)
- [고급 사용법](#고급-사용법)
- [CI/CD 통합](#cicd-통합)
- [출력 형식](#출력-형식)
- [트러블슈팅](#트러블슈팅)

## 옵션 레퍼런스

```bash
./scripts/scan-sbom.sh [옵션]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--project <이름>` | — | **(필수)** 프로젝트 이름 |
| `--version <버전>` | — | **(필수)** 프로젝트 버전 |
| `--target <경로 또는 이미지>` | 현재 디렉토리 | 분석 대상 (디렉토리 · Docker 이미지 · 바이너리 파일) |
| `--output <경로>` | 현재 디렉토리 | SBOM 파일 출력 경로 |
| `--generate-only` | false | SBOM 생성만 수행 (취약점 스캔 제외) |
| `--image <이미지명>` | `ghcr.io/sktelecom/sbom-scanner:latest` | 사용할 스캐너 Docker 이미지 |
| `--verbose` | false | 상세 로그 출력 |
| `--help` | — | 도움말 출력 |

## 분석 모드

분석 대상의 유형에 따라 내부적으로 적합한 도구(cdxgen 또는 syft)가 자동으로 선택됩니다. 자세한 선택 로직은 [아키텍처](architecture.md#분석-도구-선택-로직)를 참고하세요.

### 소스 코드 분석 (cdxgen)

패키지 매니저 파일(`pom.xml`, `package.json`, `go.mod` 등)을 파싱하여 의존성 목록을 추출합니다.

```bash
# 현재 디렉토리 분석
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only

# 특정 디렉토리 지정
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --target "/path/to/project" \
  --generate-only
```

**감지 지원 파일**: `pom.xml`, `build.gradle`, `build.gradle.kts`, `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `composer.json`, `Gemfile`, `*.csproj` 등

> **팁**: 잠금 파일(lockfile)이 있어야 정확한 버전 정보가 포함됩니다. `npm install`, `go mod tidy` 등을 먼저 실행하세요.

### Docker 이미지 분석 (syft)

설치된 OS 패키지 및 애플리케이션 패키지를 분석합니다.

```bash
# 원격 이미지
./scripts/scan-sbom.sh \
  --project "NginxApp" --version "1.25.0" \
  --target "nginx:1.25.0" \
  --generate-only

# 로컬에 빌드된 이미지
./scripts/scan-sbom.sh \
  --project "MyService" --version "1.0.0" \
  --target "myservice:local" \
  --generate-only
```

### 바이너리 / RootFS 분석 (syft)

```bash
# 바이너리 파일
./scripts/scan-sbom.sh \
  --project "MyFirmware" --version "3.0.0" \
  --target "./release/firmware.bin" \
  --generate-only

# 압축 해제된 RootFS 디렉토리
./scripts/scan-sbom.sh \
  --project "EmbeddedOS" --version "1.0.0" \
  --target "./rootfs/" \
  --generate-only
```

## 고급 사용법

### 출력 경로 지정

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --output "/var/reports/sbom/" \
  --generate-only
```

### 특정 버전의 스캐너 이미지 사용

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --image "ghcr.io/sktelecom/sbom-scanner:1.2.0" \
  --generate-only
```

### 상세 로그 출력

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --verbose --generate-only
```

## CI/CD 통합

### GitHub Actions

```yaml
name: Generate SBOM

on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Pull SBOM Scanner
        run: docker pull ghcr.io/sktelecom/sbom-scanner:latest

      - name: Generate SBOM
        run: |
          ./scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --generate-only

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: "*_bom.json"
```

### GitLab CI

```yaml
generate-sbom:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker pull ghcr.io/sktelecom/sbom-scanner:latest
    - ./scripts/scan-sbom.sh
        --project "$CI_PROJECT_NAME"
        --version "$CI_COMMIT_SHA"
        --generate-only
  artifacts:
    paths:
      - "*_bom.json"
```

## 출력 형식

생성된 SBOM은 **CycloneDX 1.6** JSON 형식입니다.

**파일명**: `{ProjectName}_{Version}_bom.json` (예: `MyApp_1.0.0_bom.json`)

### SBOM 구조 요약

```
bomFormat          "CycloneDX"
specVersion        "1.6"
metadata
  ├── timestamp    생성 시각 (ISO 8601)
  └── component    프로젝트 정보 (name, version, type)
components[]
  ├── type         "library" | "framework" | "application"
  ├── name         컴포넌트 이름
  ├── version      버전
  ├── purl         Package URL (고유 식별자)
  └── licenses[]   라이선스 정보 (SPDX ID)
```

언어별 PURL 형식은 [예제 가이드 > 결과 비교](examples-guide.md#결과-비교)를 참고하세요.

## 트러블슈팅

### Docker 권한 오류

```
Got permission denied while trying to connect to the Docker daemon
```

현재 사용자를 `docker` 그룹에 추가합니다.

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### 디스크 공간 부족

```
no space left on device
```

Docker 캐시를 정리합니다.

```bash
docker system prune -f
```

### 언어 미감지 (컴포넌트가 0개)

소스 코드 분석 시 의존성이 감지되지 않는 경우, 아래 잠금 파일이 있는지 확인하세요.

| 언어 | 필요한 파일 |
|------|-----------|
| Java (Maven) | `pom.xml` |
| Java (Gradle) | `build.gradle` 또는 `build.gradle.kts` |
| Node.js | `package.json` + `package-lock.json` 또는 `yarn.lock` |
| Python | `requirements.txt` 또는 `pyproject.toml` + `poetry.lock` |
| Go | `go.mod` + `go.sum` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj` + `packages.lock.json` |

새로운 언어 지원 추가 방법은 [패키지 매니저 추가 가이드](contributing/package-manager-guide.md)를 참고하세요.

### 그 밖의 문제

1. `--verbose` 또는 `DEBUG_MODE=true ./tests/test-scan.sh` 로 상세 로그를 확인합니다.
2. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/sbom-scanner:latest`
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)에 환경 정보와 로그를 첨부해 리포트해 주세요.
