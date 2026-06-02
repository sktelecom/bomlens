# Java Gradle Example

This example demonstrates SBOM generation for Java projects using Gradle.

## Project Structure

- `build.gradle`: Gradle build configuration with dependencies
- `src/main/java/`: Java source code
- Uses popular libraries: Guava, Jackson, SLF4J, Logback

## Dependencies

- **Guava** (32.1.3-jre): Google core libraries
- **Jackson Databind** (2.16.0): JSON processing
- **SLF4J** (2.0.9): Logging facade
- **Logback** (1.4.14): Logging implementation
- **JUnit Jupiter** (5.10.1): Testing framework (test scope)

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.


```bash
cd examples/java-gradle
../../scripts/scan-sbom.sh --project "JavaGradle" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `JavaGradle_1.0.0_bom.json` containing:
- ~40-50 total components (including transitive dependencies)
- Guava and its dependencies
- Jackson core, annotations, databind
- SLF4J and Logback
- License information for each component

### Sample Components

- com.google.guava:guava v32.1.3-jre
- com.fasterxml.jackson.core:jackson-databind v2.16.0
- org.slf4j:slf4j-api v2.0.9
- ch.qos.logback:logback-classic v1.4.14

## Build and Run (Optional)

```bash
# Build project
./gradlew build

# Run application
./gradlew run
```

## Validate Results

```bash
# Count components
jq '.components | length' JavaGradle_1.0.0_bom.json

# View Guava entry
jq '.components[] | select(.name == "guava")' JavaGradle_1.0.0_bom.json

# List all dependencies
jq -r '.components[].name' JavaGradle_1.0.0_bom.json | sort
```

## Common Issues

### Gradle Wrapper Not Found

If `./gradlew` doesn't exist, the Docker image will use the system Gradle.

**Solution:** This is normal for SBOM generation. The Docker image includes Gradle.

### Dependencies Not Downloaded

If SBOM is empty:

**Solution:** The entrypoint.sh automatically runs `gradle dependencies` before scanning.

## Next Steps

- Modify `build.gradle` to add more dependencies
- Test with different Gradle versions
- Compare SBOM output with Maven equivalent
