---
description: 스캐너를 CI에 통합해 빌드마다 SBOM을 갱신하고 Critical 취약점 게이트로 파이프라인을 실패시킵니다.
---

# CI/CD 연동

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
