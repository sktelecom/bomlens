---
description: Integrate the scanner into CI so the SBOM refreshes on every build and a Critical-vulnerability gate can fail the pipeline.
---

# Use in CI/CD

An SBOM is a point-in-time snapshot of dependencies, so it must be regenerated whenever dependencies change to stay in sync with the code. In CI it refreshes on every build and release, attaches to release artifacts, and becomes the basis for a vulnerability policy gate.

> **Important**: the scanner is report-only — it reports vulnerabilities but always exits successfully. To fail a build on Critical findings, add a step that inspects the generated `*_security.json` (gate example below).

To reduce load, split depth by trigger: on PRs generate the SBOM quickly (`--generate-only --no-report`); on `main` and releases generate everything (`--all --generate-only`) and apply the gate.

### GitHub Actions

The `ubuntu-latest` runner ships with `jq`.

```yaml
name: SBOM

on:
  pull_request:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  # PR: lightweight SBOM only (no report)
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

  # main/release: full generation + vulnerability gate
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

      # The scanner is report-only and always succeeds. Fail the build here if Critical exists.
      - name: Fail on Critical vulnerabilities
        run: |
          CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
          echo "Critical vulnerabilities: $CRIT"
          if [ "$CRIT" -gt 0 ]; then
            echo "::error::$CRIT critical vulnerability(ies) found"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        if: always()   # keep reports even when the gate fails
        with:
          name: sbom
          path: |
            *_bom.json
            *_security.*
            *_risk-report.*
```

### GitLab CI

The `docker:latest` image has no `jq`, so install it before the gate.

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
    # Use the report-only scanner as a build gate: fail if Critical exists
    - |
      CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' *_security.json)
      [ "$CRIT" -eq 0 ] || { echo "$CRIT critical vulnerability(ies) found"; exit 1; }
  artifacts:
    when: always
    paths:
      - "*_bom.json"
      - "*_security.*"
```
