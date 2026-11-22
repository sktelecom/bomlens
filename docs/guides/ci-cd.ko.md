---
description: 스캐너를 CI에 통합해 빌드마다 SBOM을 갱신하고, 정책 게이트(취약점 심각도, 악성 패키지, 라이선스 충돌, 빈 결과, 라이선스 포함률)로 파이프라인을 실패시킵니다.
---

# CI/CD 연동

SBOM은 의존성의 특정 시점 스냅샷이므로, 의존성이 바뀔 때마다 다시 생성해야 항상 코드와 일치합니다. CI에 통합하면 매 빌드와 릴리스마다 SBOM이 자동 갱신되고, 릴리스 아티팩트에 첨부되며, 취약점 정책 게이트의 기준이 됩니다.

> **중요**: 스캔은 게이트를 요청하지 않으면 취약점을 보고하고 성공으로 종료합니다. `--fail-on`을 주면 지정한 조건에 걸렸을 때(종료 4), 또는 스캔 결과만으로 조건을 판정할 수 없을 때(종료 5) 스캔 자체가 0이 아닌 코드로 종료합니다. 조건은 특정 심각도 이상의 취약점, 알려진 악성 패키지, 라이선스 충돌, 소프트웨어를 하나도 식별하지 못한 스캔(`empty-result`), 부분 또는 신뢰 불가인 결과(`incomplete-result`, 이 조건이 없으면 lock 파일이 없거나 손상된 스캔도 종료 코드 0입니다), 지정한 비율에 못 미치는 라이선스 포함률(`license-coverage=<0-100>`)입니다. `--fail-on-conformance`는 같은 방식으로 적합성 검사 보고서를 판정합니다(종료 2). [종료 코드](../reference/cli.ko.md#종료-코드)를 참고하세요. 보고서 파일을 따로 검사하는 step은 필요 없습니다.

부하를 줄이려면 트리거에 따라 깊이를 나눕니다. PR에서는 SBOM만 빠르게 생성하고(`--generate-only --no-report`), `main`과 릴리스에서는 보안 보고서까지 전체 생성한 뒤(`--all --generate-only`) 게이트를 적용합니다.

아래 예시는 `BOMLENS_VERSION`에 적은 릴리스의 명령줄 압축 파일을 받으므로, 실행할 때마다 같은 스크립트와 그 릴리스의 스캐너 이미지를 씁니다. 이미지는 첫 스캔이 받습니다. 새 [릴리스](https://github.com/sktelecom/bomlens/releases)로 옮길 때 이 값을 올립니다.

## GitHub Actions

```yaml
name: SBOM

on:
  pull_request:
  push:
    branches: [main]
  release:
    types: [published]

env:
  BOMLENS_VERSION: v1.15.2   # 사용할 BomLens 릴리스. 새 릴리스를 쓰려면 이 값을 올린다

jobs:
  # PR: SBOM만 가볍게 생성 (보고서 생략)
  sbom-pr:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install BomLens
        run: |
          mkdir -p /tmp/bomlens
          curl -fsSL "https://github.com/sktelecom/bomlens/releases/download/$BOMLENS_VERSION/bomlens-cli.tar.gz" | tar -xz -C /tmp/bomlens
      - name: Generate SBOM (lightweight)
        run: |
          /tmp/bomlens/scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --generate-only --no-report
      - uses: actions/upload-artifact@v4
        with:
          name: sbom-pr
          path: "*/*_bom.json"

  # main/release: 전체 생성 + 취약점 게이트
  sbom-full:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install BomLens
        run: |
          mkdir -p /tmp/bomlens
          curl -fsSL "https://github.com/sktelecom/bomlens/releases/download/$BOMLENS_VERSION/bomlens-cli.tar.gz" | tar -xz -C /tmp/bomlens
      - name: Generate SBOM + reports
        run: |
          /tmp/bomlens/scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --all --generate-only --fail-on-conformance \
            --fail-on vulnerability=critical --fail-on malicious-package

      # 위 스캔이 이 step을 이미 실패시킨다. 적합성 검사 보고서가 "fail"이면 종료 2,
      # Critical 취약점이나 악성 패키지가 있으면 종료 4, 둘 중 하나를 판정할 수
      # 없으면 종료 5다. 라이선스 충돌도 막으려면
      # `--license <SPDX id> --fail-on license-conflict`를 더한다. 산출물은
      # {project}_{version}/ 하위 폴더에 생기므로(CLI 레퍼런스 참고) 아래에서 */ 글롭을 쓴다.

      - uses: actions/upload-artifact@v4
        if: always()   # 게이트 실패 시에도 보고서는 보존
        with:
          name: sbom
          path: |
            */*_bom.json
            */*_security.*
            */*_risk-report.*
```

## GitLab CI

스캔 자체가 게이트하므로 job에 `jq`가 필요 없습니다.

```yaml
stages: [security]

# GitLab.com의 Linux 인스턴스 러너처럼 특권 서비스를 허용하는 Docker 실행기를 가정한다.
generate-sbom:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    BOMLENS_VERSION: v1.15.2   # 사용할 BomLens 릴리스. 새 릴리스를 쓰려면 이 값을 올린다
  before_script:
    - apk add --no-cache bash curl
    - mkdir -p /tmp/bomlens
    - curl -fsSL "https://github.com/sktelecom/bomlens/releases/download/$BOMLENS_VERSION/bomlens-cli.tar.gz" | tar -xz -C /tmp/bomlens
  script:
    - /tmp/bomlens/scripts/scan-sbom.sh
        --project "$CI_PROJECT_NAME"
        --version "$CI_COMMIT_SHA"
        --all --generate-only --fail-on-conformance
        --fail-on vulnerability=critical --fail-on malicious-package
    # 스캔이 이 job을 이미 실패시킨다. 적합성 검사 보고서가 "fail"이면 종료 2,
    # Critical 취약점이나 악성 패키지가 있으면 종료 4, 둘 중 하나를 판정할 수
    # 없으면 종료 5다. 산출물은 {project}_{version}/ 하위 폴더에 생기므로(CLI
    # 레퍼런스 참고) 아래에서 */ 글롭을 쓴다.
  artifacts:
    when: always
    paths:
      - "*/*_bom.json"
      - "*/*_security.*"
```

## CI에서 선언 구성요소 사용

직접 만든 실행 파일, 라이브러리, 펌웨어와, 스캔이 찾지 못하는 벤더 바이너리나 복사한 소스는 저장소에 둔 선언 파일에 적습니다([자체 구성요소 선언](declared-components.ko.md) 참고). 스캔은 이 파일이 가리키는 빌드 산출물을 읽으므로, 작업은 먼저 빌드한 뒤 스캔합니다. 아래 릴리스 작업은 결과를 BSI TR-03183-2 기준으로 검사하고 버전을 태그에서 가져옵니다.

```yaml
name: Release SBOM

on:
  push:
    tags: ['v*']

env:
  BOMLENS_VERSION: v1.15.2   # 사용할 BomLens 릴리스. 새 릴리스를 쓰려면 이 값을 올린다

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make   # sbom-declared.cdx.json이 가리키는 파일(예: out/bin/media-daemon)을 만든다
      - name: Install BomLens
        run: |
          mkdir -p /tmp/bomlens
          curl -fsSL "https://github.com/sktelecom/bomlens/releases/download/$BOMLENS_VERSION/bomlens-cli.tar.gz" | tar -xz -C /tmp/bomlens
      - name: Generate SBOM
        run: |
          /tmp/bomlens/scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${GITHUB_REF_NAME#v}" \
            --components sbom-declared.cdx.json \
            --conformance-profile bsi-tr-03183-2 --fail-on-conformance \
            --supplier "Example Corp <https://example.com>" \
            --sbom-author "Example Corp <sbom@example.com>" \
            --license Apache-2.0 \
            --generate-only

      # 선언 파일이 거부되면(가리킨 빌드 산출물이 없거나, 구성요소에
      # bomlens:origin이 없는 경우 등) 이 step은 종료 1로 실패한다. 이때 SBOM은
      # _bom.json이 아니라 {project}_{version}_bom.refused.json으로 남으므로
      # 뒤 단계가 불완전한 SBOM을 가져가지 않는다. BSI 항목이 실패하면
      # 종료 2로 끝난다(--fail-on-conformance).

      - uses: actions/upload-artifact@v4
        if: always()   # 적합성 보고서와 거부된 SBOM도 보존
        with:
          name: sbom
          path: |
            */*_bom.json
            */*_conformance.*
            */*_bom.refused.json
```

`${GITHUB_REF_NAME#v}`는 태그 `v2.1.0`을 `2.1.0`으로 바꾸며, 자체 `version`이 없는 `first-party` 구성요소가 이 값을 씁니다. `--components`로 파일을 명시했지만, 옵션이 없어도 저장소 루트의 `sbom-declared.cdx.json`은 읽습니다. `--license`에는 SPDX 식별자를 줍니다.

## 러너에는 무엇이 있어야 하나요?

CI 러너는 이미지도 인증 정보도 없는 상태로 시작하므로, 개발자 컴퓨터에는 이미 있는 몇 가지를 따로 준비해야 합니다.

- 디스크 공간. 새 러너에서 처음 스캔하면 스캐너 이미지(디스크에서 약 1.4GB)와 언어별 이미지(3~16GB, [크기](../reference/docker-image.ko.md#이미지가-디스크를-얼마나-차지하나요))를 받습니다. 엔진의 여유 공간이 그 크기에 2GB를 더한 값보다 적으면 스크립트는 받기 전에 멈추며, 종료 코드는 1이고 로그에 수치가 남습니다. `BOMLENS_SKIP_DISK_CHECK=1`로 점검을 끄기보다 러너의 공간을 비우거나 이미지를 캐시하세요. 이 변수는 러너 유형에서 여유 공간을 정확히 읽지 못할 때만 지정합니다.
- 사내 저장소. Maven과 Gradle은 노트북에서와 같은 파일, 곧 러너 홈 폴더에서 인증 정보를 읽습니다. 스캔 전 단계에서 CI 시크릿으로 `~/.m2/settings.xml`(또는 `~/.gradle/gradle.properties`)을 만들어 두면 BomLens가 이를 읽기 전용으로 스캔에 넘깁니다. [자세한 내용과 확인할 점](java-maven.ko.md#사내-저장소도-되나요)을 보세요.
- HTTPS를 다시 서명하는 프록시. `SBOM_EXTRA_CA_CERTS`에 사내 CA의 PEM 파일을 지정합니다. `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`는 같은 이름으로 전달됩니다.
- `pom.xml`과 `build.gradle`이 함께 있는 폴더. `--build-tool maven`을 주거나 `BOMLENS_BUILD_TOOL=maven`을 지정하지 않으면 Gradle로 읽습니다. 실행마다 같은 결과를 얻으려면 CI에서 도구를 고정하세요.
- `--target` 오타. 없는 경로(`.`, `/`, `~`, 드라이브 문자로 시작하는 것)는 이미지 이름으로 해석되지 않고 종료 코드 1로 끝나므로, 폴더를 잘못 적은 파이프라인은 실패합니다.
- 오래 걸리는 빌드. 몇 분 걸리는 단계는 1분마다 `Still running` 줄을 출력하므로, CI 로그가 조용해도 멈춘 것은 아닙니다. 출력이 없는 시간이 길면 작업을 끊는 러너에서도 이 줄이 도움이 됩니다.

## 러너에 Docker가 없을 때

`scan-sbom.sh`는 컨테이너를 띄우므로 Docker 엔진이 필요합니다. 엔진이 없는 러너(쿠버네티스 러너, `docker:dind`를 쓰지 않는 GitLab 작업)에서는 위 예시를 쓸 수 없습니다. 이때는 스캐너 이미지를 작업 이미지로 그대로 씁니다. lock 파일이 트리 전체를 덮으면(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock`, `gradle.lockfile` 중 하나이고 루트 아래 다른 매니페스트가 없을 때) 이미지 안의 소스 스캔은 Docker 소켓 없이 lock 파일을 그대로 읽고, 빠진 라이선스는 패키지 레지스트리에서 채웁니다. 그런 lock 파일이 없는 트리는 syft가 매니페스트를 읽어 직접 의존성만 나오므로(의존성을 선언했는데 lock 파일이 없는 Node 프로젝트는 안내와 함께 거부됩니다) lock 파일을 커밋하거나 Docker가 있는 러너를 쓰세요.

```yaml
stages: [security]

generate-sbom:
  stage: security
  image:
    name: ghcr.io/sktelecom/bomlens:1.15.2   # 앞의 v를 뺀 릴리스 태그. 새 릴리스를 쓰려면 이 값을 올린다
    entrypoint: [""]
  variables:
    MODE: SOURCE
    SOURCE_ROOT: $CI_PROJECT_DIR
    PROJECT_NAME: $CI_PROJECT_NAME
    PROJECT_VERSION: $CI_COMMIT_SHA
    GENERATE_NOTICE: "true"
    GENERATE_SECURITY: "true"
    UPLOAD_ENABLED: "false"
    HOST_OUTPUT_DIR: $CI_PROJECT_DIR/sbom-out
    FAIL_ON: "vulnerability=critical,malicious-package"
  script:
    - mkdir -p sbom-out && cd sbom-out
    - /usr/local/bin/run-scan
    # 직접 실행에서 게이트 판정은 종료 코드가 아니라 파일로 남습니다. 조건에 걸렸거나
    # ("met") 판정할 수 없으면("unjudged") 작업을 실패시킵니다.
    - '! grep -qE "^(met|unjudged)" *_gate.result'
  artifacts:
    when: always
    paths:
      - sbom-out/
```

변수는 [직접 `docker run`](../reference/docker-image.ko.md)과 같습니다. 스캔은 `SOURCE_ROOT`에서 프로젝트를 읽고 실행한 폴더에 결과를 씁니다.

---

> **관련 문서**: [CLI 레퍼런스](../reference/cli.ko.md) | [고지문·보안·위험 보고서 생성](reports.ko.md) | [보고서 읽는 법](../concepts/reports-explained.ko.md)
