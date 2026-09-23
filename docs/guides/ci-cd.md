---
description: Integrate the scanner into CI so the SBOM refreshes on every build and a policy gate (vulnerability severity, malicious packages, license conflicts, empty results, license coverage) can fail the pipeline.
---

# Use in CI/CD

An SBOM is a point-in-time snapshot of dependencies, so it must be regenerated whenever dependencies change to stay in sync with the code. In CI it refreshes on every build and release, attaches to release artifacts, and becomes the basis for a vulnerability policy gate.

> **Important**: a scan reports vulnerabilities and exits successfully unless you ask it to gate. `--fail-on` makes the scan itself exit non-zero when a condition you name is met (exit 4), or cannot be judged from what the scan produced (exit 5): a finding at a severity or worse, a known malicious package, a license conflict, a scan that found no software (`empty-result`), or license coverage below a percentage you set (`license-coverage=<0-100>`). `--fail-on-conformance` does the same for the conformance report (exit 2). See [Exit codes](../reference/cli.md#exit-codes). No separate step that inspects the report files is needed.

To reduce load, split depth by trigger: on PRs generate the SBOM quickly (`--generate-only --no-report`); on `main` and releases generate everything (`--all --generate-only`) and apply the gate.

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
  # PR: lightweight SBOM only (no report)
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

  # main/release: full generation + vulnerability gate
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

      # The scan above already failed this step if the conformance report says
      # "fail" (exit 2), if a Critical finding or a malicious package was found
      # (exit 4), or if either could not be judged (exit 5). Add
      # `--license <SPDX id> --fail-on license-conflict` to gate on license
      # conflicts too. Outputs land in a {project}_{version}/ subfolder (see the
      # CLI reference), hence the */ glob below.

      - uses: actions/upload-artifact@v4
        if: always()   # keep reports even when the gate fails
        with:
          name: sbom
          path: |
            */*_bom.json
            */*_security.*
            */*_risk-report.*
```

## GitLab CI

The scan itself gates, so the job needs no `jq`.

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
    # The scan already fails this job: exit 2 if the conformance report says
    # "fail", 4 if a Critical finding or a malicious package was found, 5 if
    # either could not be judged. Outputs land in a {project}_{version}/
    # subfolder (see the CLI reference), hence the */ globs below.
  artifacts:
    when: always
    paths:
      - "*/*_bom.json"
      - "*/*_security.*"
```

---

> **Related**: [CLI reference](../reference/cli.md) | [Generate notice, security & risk reports](reports.md) | [What the reports mean](../concepts/reports-explained.md)
