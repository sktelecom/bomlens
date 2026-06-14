# Adding a package manager

> **한국어**: [패키지 매니저 추가 가이드](package-manager-guide.md)

This guide walks through adding support for a new programming language or package manager, step by step.

## Before you start

Check the following before adding a new language or package manager.

- **cdxgen support**: Check the [cdxgen supported project types](https://github.com/CycloneDX/cdxgen#supported-project-types). If an official cdxgen language image exists, adding it to the routing table is enough.
- **syft support**: If you need binary or image analysis, check the [syft supported ecosystems](https://github.com/anchore/syft#supported-ecosystems).
- **Need for a custom analyzer**: Consider a custom analysis script only when neither tool supports the ecosystem.

Source scanning is a two-stage design that routes to per-language official cdxgen images rather than using a single image. See [Architecture](../architecture.en.md) for the full picture.

## Steps

### 1. Add language detection and image routing

`docker/lib/source-detect.sh` is the shared detection logic used by both the CLI and the web UI. Modify two functions.

- `detect_lang()` — add a rule that detects the language from the project's manifest files (for example, Kotlin checks for `build.gradle.kts` — Kotlin is already covered by the `java` branch).
- `img_for_lang()` — add the official cdxgen image that corresponds to the detected language.

```bash
# img_for_lang() example — add a new language entry
newlang) echo "ghcr.io/cyclonedx/cdxgen-debian-newlang:$CDXGEN_TAG" ;;
```

### 2. Update build-prep.sh if dependency preparation is needed

If cdxgen cannot resolve transitive dependencies in the ecosystem without a lock file, add preparation logic to `docker/lib/build-prep.sh`, which creates lock files right before cdxgen runs. Rust (`cargo generate-lockfile`) and Go (`go mod download`) are existing precedents. Write the preparation as best-effort so it never fails the scan.

### 3. Add an example project

Add an example project under the `examples/` directory.

```
examples/kotlin/
├── README.md              # Example description
├── build.gradle.kts       # Build file
├── gradle.lockfile        # Lock file (required!)
└── src/main/kotlin/
    └── Main.kt
```

> **Why the lock file matters**: cdxgen extracts exact version information from lock files. Without one, dependency detection is incomplete.

### 4. Add a test

Create a `tests/cases/test-{언어}.sh` file. See the [testing guide](testing-guide.en.md#writing-tests) for details on how to write it.

```bash
#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/../helpers/assert.sh"
source "$(dirname "$0")/../helpers/setup.sh"

TEST_NAME="Kotlin Gradle 소스 코드 분석"
EXAMPLE_DIR="examples/kotlin"

setup_test "$TEST_NAME"

run_scan \
  --project "KotlinExample" \
  --version "1.0.0" \
  --target "$EXAMPLE_DIR" \
  --generate-only

assert_file_exists "KotlinExample_1.0.0_bom.json"
assert_json_field ".bomFormat" "CycloneDX"
assert_json_field ".specVersion" "1.6"
assert_components_count_gte 1
assert_purl_prefix "pkg:maven/"

teardown_test
```

Then register the new test in `tests/test-scan.sh`.

```bash
source "$(dirname "$0")/cases/test-kotlin.sh"
```

### 5. Update the documentation

After adding a new language, update the following documents.

- `README.md` — add it to the supported language list
- [Examples guide](../examples-guide.en.md) — add a section for the new language (follow the format of the existing language examples)
- [Usage guide](../usage-guide.en.md) — add a row to the "language not detected" table in the troubleshooting section:

```markdown
| Kotlin | `build.gradle.kts` + `gradle.lockfile` |
```

### 6. Submit a PR

Submit a PR following the [contributing guide](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.md). Include the following in the PR description.

- The name of the language or package manager you added
- Test run results (screenshot or log)
- A sample of the generated SBOM output

## Example: adding Kotlin support

Kotlin uses the Gradle build system and runs on the JVM, so it reuses the `java` branch of `detect_lang()` (which detects `*.gradle.kts`) and the `cdxgen-temurin-java21` image as is.

### How to generate a Gradle lock file

```bash
cd examples/kotlin

# Add dependency locking to build.gradle.kts
cat >> build.gradle.kts << 'EOF'
dependencyLocking {
    lockAllConfigurations()
}
EOF

# Generate the lock file
./gradlew dependencies --write-locks
```

### Expected SBOM output (partial components)

```json
{
  "components": [
    {
      "type": "library",
      "name": "kotlin-stdlib",
      "version": "1.9.21",
      "purl": "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.21"
    }
  ]
}
```

Kotlin shares the Maven ecosystem, so its PURL uses the `pkg:maven/` prefix.

## Checklist

Confirm every item before submitting a PR that adds a new language.

- [ ] Detection rules and image routing are added to `docker/lib/source-detect.sh`.
- [ ] If transitive dependency preparation is needed, it is reflected in `docker/lib/build-prep.sh`.
- [ ] An example project exists under `examples/{언어}/`.
- [ ] The example project includes a lock file.
- [ ] A `tests/cases/test-{언어}.sh` test is written.
- [ ] The test is registered in `tests/test-scan.sh`.
- [ ] The full `./tests/test-scan.sh` run passes.
- [ ] The supported language list in `README.md` is updated.
- [ ] An example section is added to the examples guide.
- [ ] The troubleshooting table in the usage guide is updated.

---

> **Related**: [Contributing](https://github.com/sktelecom/sbom-tools/blob/main/CONTRIBUTING.en.md) | [Architecture](../architecture.en.md) | [Testing guide](testing-guide.en.md)
