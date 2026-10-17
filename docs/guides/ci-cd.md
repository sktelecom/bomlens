---
description: Integrate the scanner into CI so the SBOM refreshes on every build and a policy gate (vulnerability severity, malicious packages, license conflicts, empty results, license coverage) can fail the pipeline.
---

# Use in CI/CD

An SBOM is a point-in-time snapshot of dependencies, so it must be regenerated whenever dependencies change to stay in sync with the code. In CI it refreshes on every build and release, attaches to release artifacts, and becomes the basis for a vulnerability policy gate.

> **Important**: a scan reports vulnerabilities and exits successfully unless you ask it to gate. `--fail-on` makes the scan itself exit non-zero when a condition you name is met (exit 4), or cannot be judged from what the scan produced (exit 5): a finding at a severity or worse, a known malicious package, a license conflict, a scan that found no software (`empty-result`), or license coverage below a percentage you set (`license-coverage=<0-100>`). `--fail-on-conformance` does the same for the conformance check report (exit 2). See [Exit codes](../reference/cli.md#exit-codes). No separate step that inspects the report files is needed.

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

      # The scan above already failed this step if the conformance check report says
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
    # The scan already fails this job: exit 2 if the conformance check report says
    # "fail", 4 if a Critical finding or a malicious package was found, 5 if
    # either could not be judged. Outputs land in a {project}_{version}/
    # subfolder (see the CLI reference), hence the */ globs below.
  artifacts:
    when: always
    paths:
      - "*/*_bom.json"
      - "*/*_security.*"
```

## When the runner has no Docker

`scan-sbom.sh` starts containers, so it needs a Docker engine: a runner without one (a Kubernetes runner, a GitLab job without `docker:dind`) cannot use the examples above. Run the scanner image itself as the job image instead. A source scan inside it needs no Docker socket when a lock file covers the whole tree (a `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock` or `gradle.lockfile`, with no other manifest below the root): it reads the lock file as it is and fills the licenses it lacks from the package registry. A tree without such a lock file is read by syft from its manifests, which gives direct dependencies only (a Node project with none is refused with guidance), so commit a lock file or use a runner that has Docker.

```yaml
generate-sbom:
  stage: security
  image:
    name: ghcr.io/sktelecom/bomlens:latest
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
    # In a direct run the gate's verdict is a file, not an exit code: fail the job
    # when a condition was met (status "met") or could not be judged ("unjudged").
    - '! grep -qE "^(met|unjudged)" *_gate.result'
  artifacts:
    when: always
    paths:
      - sbom-out/
```

The variables are the ones of the [direct `docker run`](../reference/docker-image.md); the scan reads the project from `SOURCE_ROOT` and writes into the folder it runs in.

---

> **Related**: [CLI reference](../reference/cli.md) | [Generate notice, security & risk reports](reports.md) | [What the reports mean](../concepts/reports-explained.md)
