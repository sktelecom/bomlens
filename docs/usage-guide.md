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
| `--target <대상>` | 현재 디렉토리 | 분석 대상 (디렉토리 · Docker 이미지 · 바이너리 파일 · `.zip`/`.tar.gz` 아카이브) |
| `--git <url>` | — | git/GitHub URL을 얕은 클론(shallow) 후 소스로 분석 (비공개 저장소: `GIT_TOKEN` 환경변수) |
| `--branch <ref>` | 기본 브랜치 | `--git` 대상의 브랜치·태그·커밋 |
| `--firmware` | false | `--target` 파일을 펌웨어 모드로 강제 (opt-in 펌웨어 이미지) |
| `--analyze <sbom>` | — | 공급사 SBOM 검증·분석 (별칭 `--sbom`). CycloneDX/SPDX. `--target`와 배타 |
| `--generate-only` | false | 업로드 없이 로컬에만 저장 |
| `--notice` | (기본 on) | 오픈소스 고지문(NOTICE, txt+html) 생성 |
| `--security` | (기본 on) | Trivy 보안 보고서(json+md+html) 생성 |
| `--all` | — | `--notice --security` |
| `--no-report` | false | 오픈소스위험분석보고서(risk-report) 생략 (아래 참고) |
| `--deep-license` | false | scancode 정밀 라이선스 탐지 (opt-in 이미지) |
| `--byte-stable` | false | 결정론적(재현 가능) SBOM 출력 |
| `--sign` | false | cosign 서명 (`COSIGN_KEY` 필요) |
| `--ui` | — | 로컬 웹 UI 실행 |
| `--help` | — | 도움말 출력 |

> **환경변수**: `SBOM_SCANNER_IMAGE`(스캐너 이미지 재정의), `SBOM_FIRMWARE_IMAGE`(펌웨어 이미지), `GIT_TOKEN`(비공개 git 클론), `COSIGN_KEY`(서명 키). 출력 플래그 상세는 [고지문·보안·UI 가이드](notice-security-ui-guide.md)를, 공급사 SBOM 분석은 [공급사 SBOM 분석](supplier-sbom-analysis.md)을 참고하세요.

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

> **C/C++**: 패키지 매니저(Conan `conanfile.txt` / vcpkg `vcpkg.json`)가 있으면 의존성이 해석됩니다. 매니저 없는 순수 CMake/Make 소스는 SBOM이 희소하게 나오므로, 1st-party 라이선스는 `--deep-license`로 보강하고 빌드 산출물 디렉터리는 `--target <dir>`(syft)로 분석하는 것을 권장합니다.

### GitHub URL 수집 (`--git`)

저장소 URL을 직접 전달하면 얕은 클론(shallow clone) 후 소스 코드 모드로 분석합니다. 수동 `git clone`이 필요 없습니다.

```bash
# 공개 저장소
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/repo" \
  --all --generate-only

# 특정 브랜치/태그
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/repo" --branch "v1.2.3" --all --generate-only

# 비공개 저장소 (토큰은 환경변수로만 주입, 로그에 남지 않음)
GIT_TOKEN="ghp_xxx" ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" \
  --git "https://github.com/org/private-repo" --all --generate-only
```

URL은 허용된 형식(`https://`, `git@`, `ssh://git@`, `file://`)만 받으며, 셸 메타문자·`..`·공백이 포함되면 거부됩니다(경로 탐색·옵션 인젝션 방지).

### 소스 아카이브 수집 (ZIP / tar)

`--target`에 `.zip`/`.tar.gz` 등 아카이브를 전달하면 임시 디렉터리로 자동 해제 후 소스 모드로 분석합니다(zip-slip 방지 검사 포함). GitHub zip처럼 최상위 폴더가 하나면 자동으로 그 안으로 진입합니다.

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --target "./app-src.zip" \
  --all --generate-only
```

지원 형식: `.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar`. (Windows Git Bash에 `unzip`이 없으면 `tar`로 처리됩니다.)

### 오픈소스위험분석보고서 (모든 모드)

`_risk-report.{md,html}`(오픈소스위험분석보고서)는 **모든 분석 모드**(소스·아카이브·GitHub·이미지·바이너리·RootFS·펌웨어·SBOM 분석)에서 **기본 생성**됩니다. 라이선스(고지문)와 취약점(보안) 데이터를 집계하므로 고지문·보안 스캔이 자동으로 함께 켜집니다.

- 생략하려면 `--no-report`를 사용합니다(고지문/보안도 강제로 켜지지 않음).
- 공급사 SBOM(`--analyze`) 모드에서는 포맷 적합성(conformance) 검증 결과가 보고서 1절에 추가됩니다. 자체 생성 SBOM에는 해당 절이 생략되고 제목이 "오픈소스위험분석보고서"로 표기됩니다.
- 취약점 대응 기한은 SKT 검증 프로세스를 따릅니다: **Critical 7일 이내, High 30일 이내**.

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

### 산출물 위치

산출물은 명령을 실행한 현재 디렉터리(`$(pwd)`)에 저장됩니다(`{Project}_{Version}_*`). `--git`/아카이브 수집 시에도 클론·해제는 임시 디렉터리에서 이뤄지고 **산출물만 현재 디렉터리에 남습니다**(임시 디렉터리는 종료 시 자동 정리).

### 특정 버전의 스캐너 이미지 사용

스캐너 이미지는 `SBOM_SCANNER_IMAGE` 환경변수로 재정의합니다.

```bash
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/sbom-scanner:1.2.0" \
  ./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --generate-only
```

### 결정론적(재현 가능) 출력

CI에서 동일 입력에 대해 바이트 단위로 동일한 SBOM이 필요하면 `--byte-stable`을 사용합니다(타임스탬프 고정, 랜덤 serial 제거).

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --byte-stable --generate-only
```

### 3종 산출물 한 번에 (고지문 · SBOM · 위험분석보고서)

```bash
./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.0.0" \
  --all --generate-only
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

### 산출물 목록

| 산출물 | 파일 | 생성 조건 |
|--------|------|-----------|
| SBOM | `{P}_{V}_bom.json` | 항상 |
| 오픈소스 고지문 | `{P}_{V}_NOTICE.{txt,html}` | `--notice`/`--all` 또는 위험분석보고서 기본 생성 시 |
| 보안 보고서 | `{P}_{V}_security.{json,md,html}` | `--security`/`--all` 또는 위험분석보고서 기본 생성 시 |
| **오픈소스위험분석보고서** | `{P}_{V}_risk-report.{md,html}` | 기본(전 모드) — `--no-report`로 생략 |
| 포맷 적합성 보고서 | `{P}_{V}_conformance.{json,md,html}` | `--analyze` (공급사 SBOM 분석) |
| 정밀 라이선스 | `{P}_{V}_scancode.json` | `--deep-license` |
| SBOM 서명 | `{P}_{V}_bom.json.sig` | `--sign` |

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

1. `VERBOSE=true ./tests/test-scan.sh` 로 상세 로그를 확인합니다.
2. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/sbom-scanner:latest`
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)에 환경 정보와 로그를 첨부해 리포트해 주세요.
