---
description: 스캐너를 CI에 통합해 빌드마다 SBOM을 갱신하고, 정책 게이트(취약점 심각도, 악성 패키지, 라이선스 충돌, 빈 결과, 라이선스 포함률)로 파이프라인을 실패시킵니다.
---

# CI/CD 연동

SBOM은 의존성의 특정 시점 스냅샷이므로, 의존성이 바뀔 때마다 다시 생성해야 항상 코드와 일치합니다. CI에 통합하면 매 빌드와 릴리스마다 SBOM이 자동 갱신되고, 릴리스 아티팩트에 첨부되며, 취약점 정책 게이트의 기준이 됩니다.

> **중요**: 스캔은 게이트를 요청하지 않으면 취약점을 보고하고 성공으로 종료합니다. `--fail-on`을 주면 지정한 조건에 걸렸을 때(종료 4), 또는 스캔 결과만으로 조건을 판정할 수 없을 때(종료 5) 스캔 자체가 0이 아닌 코드로 종료합니다. 조건은 특정 심각도 이상의 취약점, 알려진 악성 패키지, 라이선스 충돌, 소프트웨어를 하나도 식별하지 못한 스캔(`empty-result`), 지정한 비율에 못 미치는 라이선스 포함률(`license-coverage=<0-100>`)입니다. `--fail-on-conformance`는 같은 방식으로 적합성 보고서를 판정합니다(종료 2). [종료 코드](../reference/cli.ko.md#종료-코드)를 참고하세요. 보고서 파일을 따로 검사하는 step은 필요 없습니다.

부하를 줄이려면 트리거에 따라 깊이를 나눕니다. PR에서는 SBOM만 빠르게 생성하고(`--generate-only --no-report`), `main`과 릴리스에서는 보안 보고서까지 전체 생성한 뒤(`--all --generate-only`) 게이트를 적용합니다.

## GitHub Actions

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
      - run: git clone --depth 1 https://github.com/sktelecom/bomlens.git /tmp/bomlens
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
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
      - run: git clone --depth 1 https://github.com/sktelecom/bomlens.git /tmp/bomlens
      - run: docker pull ghcr.io/sktelecom/bomlens:latest
      - name: Generate SBOM + reports
        run: |
          /tmp/bomlens/scripts/scan-sbom.sh \
            --project "${{ github.event.repository.name }}" \
            --version "${{ github.sha }}" \
            --all --generate-only --fail-on-conformance \
            --fail-on vulnerability=critical --fail-on malicious-package

      # 위 스캔이 이 step을 이미 실패시킨다. 적합성 보고서가 "fail"이면 종료 2,
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
generate-sbom:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache git
    - git clone --depth 1 https://github.com/sktelecom/bomlens.git /tmp/bomlens
  script:
    - docker pull ghcr.io/sktelecom/bomlens:latest
    - /tmp/bomlens/scripts/scan-sbom.sh
        --project "$CI_PROJECT_NAME"
        --version "$CI_COMMIT_SHA"
        --all --generate-only --fail-on-conformance
        --fail-on vulnerability=critical --fail-on malicious-package
    # 스캔이 이 job을 이미 실패시킨다. 적합성 보고서가 "fail"이면 종료 2,
    # Critical 취약점이나 악성 패키지가 있으면 종료 4, 둘 중 하나를 판정할 수
    # 없으면 종료 5다. 산출물은 {project}_{version}/ 하위 폴더에 생기므로(CLI
    # 레퍼런스 참고) 아래에서 */ 글롭을 쓴다.
  artifacts:
    when: always
    paths:
      - "*/*_bom.json"
      - "*/*_security.*"
```

---

> **관련 문서**: [CLI 레퍼런스](../reference/cli.ko.md) | [고지문·보안·위험 보고서 생성](reports.ko.md) | [보고서 읽는 법](../concepts/reports-explained.ko.md)
