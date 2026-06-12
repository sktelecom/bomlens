# Java Maven 프로젝트 예제

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/getting-started.en.md) and the [usage guide](../../docs/usage-guide.en.md).

Spring Boot 기반 간단한 REST API 애플리케이션입니다. SBOM 생성 테스트를 위한 예제로 사용됩니다.

## 프로젝트 정보

- 언어: Java 17
- 빌드 도구: Maven 3.x
- 프레임워크: Spring Boot 3.2.0
- 주요 의존성:
  - Spring Boot Starter Web
  - Spring Boot Starter Data JPA
  - H2 Database
  - Lombok
  - Apache Commons Lang3
  - Jackson

## 사전 요구사항

- Java 17 이상
- Maven 3.6 이상 (또는 Docker)

## SBOM 생성

### 방법 1: BomLens 스크립트 사용 (권장)

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.

```bash
# 프로젝트 디렉토리로 이동
cd examples/java-maven

# SBOM 생성
../../scripts/scan-sbom.sh \
  --project "JavaMavenExample" \
  --version "1.0.0" \
  --generate-only
```

결과로 `JavaMavenExample_1.0.0_bom.json` 파일이 생성됩니다.

### 방법 2: Docker 직접 사용

```bash
docker run --rm \
  -v "$(pwd)":/src \
  -v "$(pwd)":/host-output \
  -e MODE=SOURCE \
  -e UPLOAD_ENABLED=false \
  -e HOST_OUTPUT_DIR=/host-output \
  -e PROJECT_NAME="JavaMavenExample" \
  -e PROJECT_VERSION="1.0.0" \
  ghcr.io/sktelecom/sbom-scanner:v1
```

### 방법 3: Maven 플러그인 사용

pom.xml에 CycloneDX 플러그인 추가:

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

실행:

```bash
mvn clean package
# 결과: target/bom.json
```

## 애플리케이션 실행

### 로컬에서 실행

```bash
# Maven으로 실행
mvn spring-boot:run

# 또는 JAR 빌드 후 실행
mvn clean package
java -jar target/sbom-example-app-1.0.0.jar
```

접속 주소는 http://localhost:8080 입니다.

### Docker로 실행

```bash
# Dockerfile 생성 (간단한 예시)
cat > Dockerfile <<EOF
FROM eclipse-temurin:17-jre-alpine
COPY target/sbom-example-app-1.0.0.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
EOF

# 빌드 및 실행
mvn clean package
docker build -t java-example:latest .
docker run -p 8080:8080 java-example:latest
```

## 생성된 SBOM 확인

```bash
# SBOM 파일 확인
ls -lh JavaMavenExample_1.0.0_bom.json

# 컴포넌트 개수 확인 (jq 필요)
cat JavaMavenExample_1.0.0_bom.json | jq '.components | length'

# 주요 의존성 확인
cat JavaMavenExample_1.0.0_bom.json | jq -r '.components[] | select(.name | contains("spring")) | "\(.name)@\(.version)"'
```

예상 컴포넌트 수는 약 50-80개입니다(전이적 의존성 포함).

## 예상 SBOM 내용

생성된 SBOM에는 다음과 같은 정보가 포함됩니다:

- Spring Boot 관련: spring-boot-starter-web, spring-core, spring-context 등
- 데이터베이스: h2, hibernate-core, spring-data-jpa 등
- 로깅: logback-classic, slf4j-api 등
- 유틸리티: commons-lang3, jackson-databind 등
- 서블릿: tomcat-embed-core 등

## 문제 해결

### Maven 빌드 실패

```bash
# Maven wrapper 사용
./mvnw clean package

# 의존성 강제 업데이트
mvn clean install -U
```

### SBOM이 비어있음

```bash
# pom.xml 위치 확인
ls -la pom.xml

# Maven 의존성 확인
mvn dependency:tree
```

### Java 버전 오류

```bash
# Java 버전 확인
java -version

# Java 17 이상 필요
# JAVA_HOME 환경변수 설정
export JAVA_HOME=/path/to/jdk-17
```

## 다음 단계

- [사용 가이드](../../docs/usage-guide.md) - 상세한 사용법
- [시작하기](../../docs/getting-started.md) - 첫 SBOM 생성
- [Docker 가이드](../../docker/README.md) - Docker 이미지 사용법

## 참고

이 예제는 SBOM 생성 테스트 목적으로 만들어졌습니다. 실제 프로덕션 환경에서는 보안 설정, 에러 처리, 테스트 등을 추가해야 합니다.
