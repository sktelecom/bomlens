# 사용 가이드

> **관련 문서**: [시작하기](getting-started.md) | [시나리오 가이드](scenarios-guide.md) | [예제 가이드](examples-guide.md)

BomLens의 전체 옵션, 분석 모드, CI/CD 통합 방법 및 트러블슈팅을 설명합니다.

## 옵션 레퍼런스

```bash
./scripts/scan-sbom.sh [옵션]
```

> **Windows 사용자**: 위 명령은 macOS/Linux 기준입니다. `./scripts/scan-sbom.sh`를 `scripts\scan-sbom.bat`로 바꿔 실행하거나(Git Bash 필요), WSL2에서 그대로 실행하세요. 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭하면 됩니다. 설치는 [시작하기](getting-started.md#설치)를 참고하세요.

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
| `--security` | (기본 on) | Trivy 보안 보고서(json+md+html) 생성. CVSS·EPSS·CISA KEV 우선순위 신호 포함 |
| `--all` | — | `--notice --security` |
| `--no-report` | false | 오픈소스위험분석보고서(risk-report) 생략 (아래 참고) |
| `--deep-license` | false | scancode 정밀 라이선스 탐지 (opt-in 이미지) |
| `--byte-stable` | false | 결정론적(재현 가능) SBOM 출력 |
| `--sign` | false | cosign 서명 (`COSIGN_KEY` 필요) |
| `--ui` | — | 로컬 웹 UI 실행 |
| `--help` | — | 도움말 출력 |

> **환경변수**: `SBOM_SCANNER_IMAGE`(스캐너 이미지 재정의), `SBOM_FIRMWARE_IMAGE`(펌웨어 이미지), `GIT_TOKEN`(비공개 git 클론), `COSIGN_KEY`(서명 키), `FETCH_LICENSE`(기본 true, 소스 스캔 시 의존성 라이선스 자동 조회. `false`면 조회를 생략해 속도를 높임), `SECURITY_ENRICH`(기본 true, 보안 보고서에 EPSS와 CISA KEV 신호 보강. 폐쇄망에서는 `false`로 두면 외부 조회를 생략). 출력 플래그 상세는 [고지문·보안 보고서 가이드](notice-and-security.md)를, 공급사 SBOM 검증은 [공급사 SBOM 검증](supplier-sbom-validation.md)을 참고하세요.

## 분석 모드

분석 대상의 유형에 따라 내부적으로 적합한 도구(cdxgen 또는 syft)가 자동으로 선택됩니다. 선택 로직의 자세한 내부 동작은 기여자용 [아키텍처](https://github.com/sktelecom/sbom-tools/blob/main/docs/internal/architecture.md#분석-도구-선택-로직) 문서에 있습니다.

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

URL은 허용된 형식(`https://`, `git@`, `ssh://git@`, `file://`)만 받으며, 셸 메타문자, `..`, 공백이 포함되면 거부됩니다(경로 탐색과 옵션 인젝션 방지).

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

`_risk-report.{md,html}`(오픈소스위험분석보고서)는 소스, 아카이브, GitHub, 이미지, 바이너리, RootFS, 펌웨어, SBOM 분석 등 모든 분석 모드에서 기본으로 생성됩니다. 라이선스(고지문)와 취약점(보안) 데이터를 집계하므로 고지문과 보안 스캔이 자동으로 함께 켜집니다.

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
SBOM_SCANNER_IMAGE="ghcr.io/sktelecom/bomlens:1.2.0" \
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

SBOM은 의존성의 특정 시점 스냅샷이므로, 의존성이 바뀔 때마다 다시 생성해야 항상 코드와 일치합니다. CI에 통합하면 매 빌드와 릴리스마다 SBOM이 자동 갱신되고, 릴리스 아티팩트에 첨부되며, 취약점 정책 게이트의 기준이 됩니다.

> **중요**: 스캐너는 취약점을 발견해도 보고만 하고 항상 성공으로 종료합니다(report-only). Critical 취약점에서 빌드를 실패시키려면 생성된 `*_security.json`을 검사하는 step을 직접 추가해야 합니다(아래 게이트 예시 참고).

부하를 줄이려면 트리거에 따라 깊이를 나눕니다. PR에서는 SBOM만 빠르게 생성하고(`--generate-only --no-report`), `main`과 릴리스에서는 보안 보고서까지 전체 생성한 뒤(`--all --generate-only`) 게이트를 적용합니다.

### GitHub Actions

`ubuntu-latest` 러너에는 `jq`가 기본 설치되어 있습니다.

```yaml
name: SBOM

on:
  pull_request:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  # PR: SBOM만 가볍게 생성 (보고서 생략)
  sbom-pr:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
      - name: Generate SBOM (lightweight)
        run: |
          ./scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --generate-only --no-report
      - uses: actions/upload-artifact@v4
        with:
          name: sbom-pr
          path: "*_bom.json"

  # main/release: 전체 생성 + 취약점 게이트
  sbom-full:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
      - name: Generate SBOM + reports
        run: |
          ./scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --all --generate-only

      # 스캐너는 report-only라 항상 성공한다. Critical이 있으면 여기서 빌드를 실패시킨다.
      - name: Fail on Critical vulnerabilities
        run: |
          CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
          echo "Critical vulnerabilities: $CRIT"
          if [ "$CRIT" -gt 0 ]; then
            echo "::error::$CRIT critical vulnerability(ies) found"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        if: always()   # 게이트 실패 시에도 보고서는 보존
        with:
          name: sbom
          path: |
            *_bom.json
            *_security.*
            *_risk-report.*
```

### GitLab CI

`docker:latest` 이미지에는 `jq`가 없으므로 게이트 전에 설치합니다.

```yaml
generate-sbom:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache jq
  script:
    - docker pull ghcr.io/sktelecom/bomlens:latest
    - ./scripts/scan-sbom.sh
        --project "$CI_PROJECT_NAME"
        --version "$CI_COMMIT_SHA"
        --all --generate-only
    # report-only 스캐너를 빌드 게이트로 사용: Critical이 있으면 실패
    - |
      CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
      [ "$CRIT" -eq 0 ] || { echo "$CRIT critical vulnerability(ies) found"; exit 1; }
  artifacts:
    when: always
    paths:
      - "*_bom.json"
      - "*_security.*"
```

## 출력 형식

생성된 SBOM은 CycloneDX 1.6 JSON 형식입니다.

파일명은 `{ProjectName}_{Version}_bom.json`입니다(예: `MyApp_1.0.0_bom.json`).

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

### Windows: 산출물이 생기지 않음

스캔이 끝났는데 산출물 파일이 PC에 보이지 않으면, 실행 폴더가 Docker 파일 공유에 포함된 경로인지 확인하세요. 홈 디렉터리(`C:\Users\...`) 아래는 Rancher Desktop과 Docker Desktop 모두 기본 공유되므로 안전합니다. 공유되지 않은 위치에서 실행하면 컨테이너가 결과를 호스트에 쓰지 못합니다.

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

새로운 언어 지원 추가 방법은 [패키지 매니저 추가 가이드](https://github.com/sktelecom/sbom-tools/blob/main/docs/contributing/package-manager-guide.md)를 참고하세요.

### 그 밖의 문제

1. `VERBOSE=true ./tests/test-scan.sh` 로 상세 로그를 확인합니다.
2. Docker 이미지를 최신 버전으로 업데이트합니다: `docker pull ghcr.io/sktelecom/bomlens:latest`
3. 해결되지 않으면 [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues)에 환경 정보와 로그를 첨부해 리포트해 주세요.
