# Java Maven Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Spring Boot REST API built with Maven.

## Project Structure

- `pom.xml`: Maven dependencies (Java 17, Spring Boot 3.2.0)
- `src/main/java/`: Java source code

## Dependencies

- **Spring Boot Starter Web** (3.2.0): REST API framework
- **Spring Boot Starter Data JPA** (3.2.0): JPA/Hibernate data access
- **H2 Database** (2.2.224): in-memory database (runtime scope)
- **Lombok** (1.18.30): boilerplate reduction (provided scope)
- **Apache Commons Lang3** (3.14.0): general utilities
- **Jackson Databind** (2.16.0): JSON processing
- **Spring Boot Starter Test** (3.2.0): testing framework (test scope)

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat`; see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/java-maven
../../scripts/scan-sbom.sh --project "JavaMavenExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `JavaMavenExample_1.0.0/` folder. The main SBOM, `JavaMavenExample_1.0.0/JavaMavenExample_1.0.0_bom.json`, lists roughly 50-80 components (including transitive dependencies):
<!-- expected-components: 50-80 -->

- Spring Boot: spring-boot-starter-web, spring-core, spring-context, and related modules
- Database: h2, hibernate-core, spring-data-jpa
- Logging: logback-classic, slf4j-api
- Utilities: commons-lang3, jackson-databind
- Servlet container: tomcat-embed-core

### Sample Components

- org.springframework.boot:spring-boot-starter-web
- com.h2database:h2
- org.apache.commons:commons-lang3
- com.fasterxml.jackson.core:jackson-databind

## Build and Run (Optional)

Requires Java 17+ and Maven 3.6+ (the scan itself only needs Docker).

```bash
mvn spring-boot:run
# or build a jar and run it directly
mvn clean package
java -jar target/sbom-example-app-1.0.0.jar
# Visit http://localhost:8080
```

## Validate Results

```bash
# Count components
jq '.components | length' JavaMavenExample_1.0.0/JavaMavenExample_1.0.0_bom.json

# List Spring-related dependencies
jq -r '.components[] | select(.name | contains("spring")) | "\(.name)@\(.version)"' JavaMavenExample_1.0.0/JavaMavenExample_1.0.0_bom.json
```

## Common Issues

### Maven build fails

```bash
./mvnw clean package
# or force a dependency refresh
mvn clean install -U
```

### SBOM is empty

```bash
ls -la pom.xml
mvn dependency:tree
```

**Solution:** confirm `pom.xml` is where the scan expects it, and that the dependency tree resolves.

### Java version error

The project targets Java 17.

```bash
java -version
export JAVA_HOME=/path/to/jdk-17
```

### Generating an SBOM with the Maven plugin instead

Add the CycloneDX Maven plugin to `pom.xml`:

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-maven-plugin</artifactId>
            <version>2.7.9</version>
            <executions>
                <execution>
                    <phase>package</phase>
                    <goals>
                        <goal>makeAggregateBom</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

Then `mvn clean package` writes the SBOM to `target/bom.json`.

## Next Steps

- Add more Maven dependencies to `pom.xml` and re-scan
- Compare this SBOM with the Gradle example's output for equivalent libraries
- Point `pom.xml` at a private/internal repository and confirm the scan still resolves it
