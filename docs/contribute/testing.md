---
description: The BomLens test structure — how to run the suites, write new tests, and debug failures.
---

# Testing guide

This guide explains the test structure of BomLens, how to run and write tests, and how to debug failures.

## Test structure

```
tests/
├── test-scan.sh          # Integration test entry point (runs all tests)
├── helpers/
│   ├── assert.sh         # Assertion helper functions
│   └── setup.sh          # Test environment setup/teardown
└── cases/
    ├── test-java.sh      # Java test cases
    ├── test-nodejs.sh    # Node.js test cases
    ├── test-python.sh    # Python test cases
    ├── test-go.sh        # Go test cases
    └── test-docker.sh    # Docker image analysis tests
```

## Running tests

### Run all tests

```bash
./tests/test-scan.sh
```

Example output on success:

```
[PASS] Java Maven source code analysis
[PASS] Java Gradle source code analysis
[PASS] Node.js npm source code analysis
[PASS] Python pip source code analysis
[PASS] Go modules source code analysis
[PASS] Docker image analysis (nginx:alpine)
─────────────────────────────────
6 of 6 tests passed (0 failed)
```

### Test a specific language only

```bash
./tests/cases/test-java.sh
./tests/cases/test-nodejs.sh
```

## Execution modes

| Environment variable | Value | Output |
|-----------|-----|----------|
| (none) | — | Prints only the test result summary |
| `VERBOSE` | `true` | Prints key progress logs for each step |
| `DEBUG_MODE` | `true` | Includes Docker execution logs and full cdxgen/syft output |
| `LOG_FILE` | file path | Saves logs to a file |

```bash
# Verbose mode
VERBOSE=true ./tests/test-scan.sh

# Debug mode (for troubleshooting)
DEBUG_MODE=true ./tests/test-scan.sh

# Save logs to a file
LOG_FILE="./test-results.log" ./tests/test-scan.sh
```

Example output in verbose mode:

```
[INFO] Starting Java Maven test
[INFO] Preparing Docker image...
[INFO] Generating SBOM...
[PASS] Java Maven source code analysis
  - Detected components: 47
  - PURL format: pkg:maven/...
  - License information: included
```

## Writing tests

When adding support for a new language, write a test case in the following format.

```bash
# tests/cases/test-kotlin.sh

#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/../helpers/assert.sh"
source "$(dirname "$0")/../helpers/setup.sh"

TEST_NAME="Kotlin Gradle source code analysis"
EXAMPLE_DIR="examples/kotlin"

setup_test "$TEST_NAME"

# Generate SBOM
run_scan \
  --project "KotlinExample" \
  --version "1.0.0" \
  --target "$EXAMPLE_DIR" \
  --generate-only

# Assertions
assert_file_exists "KotlinExample_1.0.0_bom.json"
assert_json_field ".bomFormat" "CycloneDX"
assert_json_field ".specVersion" "1.6"
assert_components_count_gte 1
assert_purl_prefix "pkg:maven/"  # Kotlin uses the Gradle/Maven ecosystem

teardown_test
```

Then register the new test in `tests/test-scan.sh`.

```bash
# Add inside tests/test-scan.sh
source "$(dirname "$0")/cases/test-kotlin.sh"
```

For the full procedure, see the [package manager guide](package-managers.md).

## Assertion function reference

| Function | Description |
|------|------|
| `assert_file_exists <file>` | Checks that a file exists |
| `assert_json_field <field> <expected>` | Checks a JSON field value |
| `assert_components_count_gte <count>` | Checks that the component count is at least N |
| `assert_purl_prefix <prefix>` | Checks the PURL prefix format |
| `assert_license_exists` | Checks that at least one license entry exists |
| `assert_no_empty_versions` | Checks that no version field is empty |

### Test writing principles

**Independence**: Each test must not depend on other tests. Results must stay the same regardless of test order.

**Cleanup**: Always delete generated files in `teardown_test` so they do not affect the next test.

**Clear names**: `TEST_NAME` should clearly express what the test verifies.

**Minimal assertions**: Assert only what is needed and avoid excessive checks.

## Logging and debugging

### Inspecting the generated SBOM directly

```bash
# Count components
jq '.components | length' NodeExample_1.0.0_bom.json

# List all PURLs
jq '[.components[].purl]' NodeExample_1.0.0_bom.json

# List licenses
jq '[.components[].licenses[]?.license.id] | unique' NodeExample_1.0.0_bom.json
```

### Debugging a specific test

```bash
DEBUG_MODE=true ./tests/cases/test-nodejs.sh
```

## CI integration

### GitHub Actions

```yaml
- name: Run integration tests
  run: |
    VERBOSE=true ./tests/test-scan.sh

- name: Upload test logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: test-logs
    path: "*.log"
```

### What to do when tests fail

1. Rerun with `DEBUG_MODE=true` and review the detailed logs.
2. Run `scan-sbom.sh` directly in the example directory of the failing language.
3. Update the Docker image to the latest version: `docker pull ghcr.io/sktelecom/bomlens:latest`
4. If the problem persists, report it on [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues) with your environment details and logs.

---

> **Related**: [Contributing](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.en.md) | [Architecture](../concepts/architecture.md) | [Adding a package manager](package-managers.md)
