---
description: Java, Python, Node.js 등 언어별 예제 프로젝트로 BomLens의 SBOM 생성을 직접 실습하고, 감지에 필요한 파일과 언어별 결과를 비교합니다.
---

# 지원 생태계

`examples/` 디렉터리의 언어별 예제 프로젝트로 직접 실습해 보는 가이드입니다. 각 예제를 실행하면 SBOM 출력 결과를 바로 확인할 수 있습니다.

BomLens가 생태계마다 빌드 도구를 어떻게 실행하고 결과를 배포되는 구성으로 어떻게 좁히는지는 [의존성을 해석하는 방식](../concepts/dependency-resolution.ko.md)에 설명돼 있습니다.

## 예제 디렉터리 구조

```
examples/
├── java-maven/      # Java + Maven
├── java-gradle/     # Java + Gradle
├── nodejs/          # Node.js + npm
├── python/          # Python + pip / Poetry
├── go/              # Go modules
├── ruby/            # Ruby + Bundler
├── php/             # PHP + Composer
├── rust/            # Rust + Cargo
├── dotnet/          # .NET + NuGet
├── swift/           # Swift + SPM (Swift Package Manager)
├── modelica/        # Modelica (.mo) uses() 선언
└── docker/          # Docker 이미지 분석
```

## 공통 실행 방법

모든 소스 코드 예제는 저장소 루트에서 같은 방식으로 실행합니다. `--target`에 예제 폴더를 지정하고 프로젝트 이름을 정하면, 결과는 `{Project}_{Version}/` 하위 폴더에 저장됩니다. Node.js 예제로 보면 다음과 같습니다.

<!-- runnable -->
```bash
# 1. SBOM 생성 (저장소 루트에서)
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only

# 2. 결과 확인
jq '.components | length' NodeExample_1.0.0/NodeExample_1.0.0_bom.json
```

소스 스캔은 기본으로 테스트, 테스트 데이터, 예제, 벤치마크, 데모 폴더(`test`, `tests`, `spec`, `fixtures`, `testdata`, `__tests__`, `e2e`, `example`, `examples`, `sample`, `samples`, `bench`, `benches`, `benchmark`, `benchmarks`, `demo`, `demos`, `playground`) 아래의 매니페스트, `.github/workflows`의 GitHub Actions 워크플로, `gradle/wrapper`의 Gradle 래퍼(`gradle-wrapper.jar`)를 제외합니다. 모두 제품과 함께 배포되지 않기 때문입니다. SBOM에는 적용한 패턴이 `bomlens:excluded-paths` 속성에, 제외한 파일이 `bomlens:excluded-manifests` 속성에 기록됩니다. 포함하려면 `BOMLENS_INCLUDE_NON_SHIPPED=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

설치된 Python 가상 환경은 소스 스캔이 프로젝트로 읽는 대상에서 항상 빠집니다. `pyvenv.cfg`가 든 최상위 폴더(`.venv/`, `venv/` 또는 다른 이름)는 모두 cdxgen의 탐색, syft 폴백, lock 파일 정적 읽기에서 제외되며, `BOMLENS_INCLUDE_NON_SHIPPED=1`이나 `BOMLENS_PYTHON_VENV=false`를 설정해도 같습니다. 그 안에 설치된 패키지는 프로젝트 자체의 매니페스트가 아니고, 네트워크가 없으면 cdxgen이 패키지마다 패키지 저장소의 응답을 기다리게 되기 때문입니다. 이 폴더의 패턴(`.venv/**`)은 `bomlens:excluded-paths`에 기록되고, 그 안의 파일은 `bomlens:excluded-manifests`에 나열하지 않습니다. 패키지 저장소를 쓸 수 없을 때 BomLens가 이 환경을 직접 읽는 동작은 그대로입니다([Python](#python) 참고). 트리 더 깊은 곳에 있는 가상 환경이나, 이름에 영문자, 숫자, `.`, `_`, `-` 외의 문자(예: 공백이나 글롭 문자)가 든 가상 환경은 제외되지 않습니다.

소스 스캔은 cdxgen이 개발 전용으로 표시한 컴포넌트도 뺍니다. 대상은 npm, pnpm, yarn, bun의 개발 패키지, uv와 Poetry에서 `main`이 아닌 의존성 그룹, Cargo의 dev-dependencies, sbt, Crystal, Gleam의 개발 의존성입니다. Ruby는 BomLens가 `Gemfile`의 그룹을 직접 읽습니다([Ruby](#ruby) 참고). cdxgen이 한 컴포넌트에 같은 표시를 여러 번 붙였으면 모든 값이 개발용일 때만 개발 전용으로 봅니다. 표시된 컴포넌트와 표시된 컴포넌트만 필요로 하는 의존성은 의존성 그래프의 다른 어떤 컴포넌트도 닿지 않을 때만 빠집니다. 표시가 없는 컴포넌트는 루트에서 닿지 않더라도 자신이 의존하는 컴포넌트를 남기고, 워크스페이스 멤버도 자신의 의존성을 남깁니다. 그래서 Cargo 워크스페이스 멤버 크레이트의 dev-dependencies와 uv 워크스페이스 멤버의 의존성 그룹은 남습니다. npm 개발 패키지는 예외입니다. cdxgen 13.5.0은 이 표시를 워크스페이스 전체를 기준으로 붙이므로, 표시가 붙은 패키지는 어느 멤버의 운영 의존성에서도 닿지 않는 패키지이고 멤버가 적어 두었더라도 빠집니다. 뺀 컴포넌트는 SBOM의 `bomlens:excluded-components` 속성에 기록됩니다. 그대로 두려면 `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)). 생태계별로 달라지는 점은 아래 언어별 절에 적었습니다.

npm, Python(pip), Go, Rust(Cargo) 패키지는 소스 스캔이 설치된 패키지에 들어 있는 라이선스 파일(`LICENSE`, `LICENCE`, `COPYING`, `NOTICE`, `COPYRIGHT`)에서 저작권 문구를 읽어 컴포넌트의 `copyright`를 채웁니다. 고지문에 저작권 표기 줄이 나오게 하려는 것입니다. `Copyright` 바로 뒤에 `(c)`, 저작권 기호, 연도, `by` 중 하나가 오거나 `(c)`나 저작권 기호 뒤에 연도가 오면서 권리자 이름이 있는 줄만 사용합니다. `Copyright Acme, Inc.`처럼 연도가 없는 표기는 가져오지 않습니다. 읽는 곳은 패키지 자신의 폴더뿐이고(pip은 `.dist-info` 폴더, Go는 `go list`가 알려 주는 폴더로 모듈 캐시, `replace`한 모듈은 대체본 폴더, 또는 `vendor/`이며, Rust는 `cargo metadata`가 알려 주는 폴더로 cargo registry, git 체크아웃, 경로 의존성입니다), 파일은 최대 6개, 파일마다 앞 64KiB와 400줄까지, 컴포넌트당 문구는 최대 5개이며 `; `로 이어 붙입니다. 채우지 않은 서식(`<year>`, `[fullname]`)이나 라이선스 문서 자체의 문구(예: GNU 라이선스에 든 Free Software Foundation의 줄)는 제외하고, 패키지 밖을 가리키는 링크 파일도 읽지 않습니다. 이미 저작권 값이 있는 컴포넌트는 바꾸지 않고, 그런 줄이 없는 패키지는 비워 둡니다. 채운 값에는 `bomlens:copyrightSource` 속성이 붙습니다. `BOMLENS_NO_COPYRIGHT=1`로 끌 수 있습니다. Java(Maven)는 지원하지 않습니다. Maven은 소스 폴더가 아니라 jar 파일을 내려받으므로 의존성의 라이선스 파일이 디스크에 없습니다. `replace`한 Go 모듈에는 실제로 빌드되는 코드의 문구가 들어가므로 컴포넌트가 가리키는 버전과 다를 수 있습니다. 스캔 대상 자신의 Go 모듈과 Rust 워크스페이스 크레이트는 채우지 않습니다. Rust 단계는 이미 디스크에 있는 크레이트 소스만 읽고 네트워크로 내려받지 않으므로, `FETCH_LICENSE=false`나 `--byte-stable`에서는 내려받지 않은 크레이트가 비어 있습니다. 폴더가 디스크에 없는 Go와 Rust 컴포넌트(예: 내려받기 실패)도 비어 있습니다. 한 생태계의 폴더를 하나도 조회하지 못하면 SBOM의 `bomlens:copyrightUnread` 메타데이터 속성(`golang`, `cargo`)에 기록하므로, 저작권이 없는 것과 단계가 실행되지 않은 것을 구분할 수 있습니다.

아래 언어별 절에 그대로 붙여넣을 수 있는 명령을 정리했습니다.

---

## Java (Maven)

```bash
./scripts/scan-sbom.sh --project "JavaMavenExample" --version "1.0.0" --target examples/java-maven --generate-only
```

감지 파일: `pom.xml`

```xml
<!-- 예제 pom.xml -->
<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>3.2.0</version>
  </dependency>
</dependencies>
```

> 주의: cdxgen은 전체 빌드 그래프를 해석하므로, BomLens는 SBOM을 배포 대상 집합인 compile·runtime 스코프로 걸러 test·provided 도구(JUnit, Lombok 등)를 덜어냅니다. 결과가 전체 빌드가 아니라 실제 배포되는 구성을 반영하도록 하려는 것입니다. 전체 해석 그래프를 그대로 두려면 `BOMLENS_MAVEN_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).
> `<optional>true</optional>`로 선언한 runtime 의존성도 cdxgen이 test 스코프와 같은 태그를 붙이므로 함께 빠집니다.
> 멀티 모듈 리액터에는 배포되는 모듈과 함께, 데모처럼 한 번도 배포되지 않는 모듈이 섞여 있을 수 있습니다(`maven-deploy-plugin`의 `skip`이 어떤 방식으로 설정됐든 결국 `true`로 풀리는 모듈). 그런 모듈 자신의 컴포넌트는 빠집니다. 그 모듈만 필요로 하는 의존성도 함께 빠지지만, 같은 리액터의 배포되는 모듈이 어떤 스코프로도 그 의존성을 선언하지 않을 때만 그렇습니다(배포되는 모듈의 `provided`나 `test` 선언 하나만 있어도, `compile`·`runtime`이 아니어도, 남습니다). SBOM의 의존성 그래프가 각 연결이 어떤 스코프인지 따로 기록하지 않기 때문입니다. `BOMLENS_MAVEN_FULL_GRAPH=1`로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 모듈과 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-modules`, `bomlens:excluded-components`로 기록됩니다.

> 주의: cdxgen은 Maven 컴포넌트의 라이선스를 그 컴포넌트 자신의 `pom.xml`에서만 읽으므로, `<licenses>`를 선언하지 않고 부모 POM의 Maven 상속에 기대는 컴포넌트는 라이선스가 빈 채로 넘어옵니다. BomLens는 이제 그 부모 체인을 직접 따라가(리액터 자신의 모듈부터, 리액터 밖 부모는 로컬 저장소에서) 처음으로 라이선스를 선언한 조상의 값을 채우고, 어느 조상도 선언하지 않았거나 이미 라이선스가 있는 컴포넌트는 그대로 둡니다. 채운 컴포넌트에는 `bomlens:licenseSource` 속성이 `parent POM` 값으로 기록됩니다.

> 주의: 의존성과 라이선스를 해석하려면 컨테이너가 Maven Central(또는 사내 미러)에 접속할 수 있어야 합니다. 접속하지 못하면 `pom.xml`에 적힌 의존성만 담기고 전이 의존성과 라이선스는 비며, 스캔은 경고 없이 끝납니다. 그중 test, provided, system 스코프와 `<optional>true</optional>` 의존성은 전체 해석 때와 마찬가지로 빠지며, `BOMLENS_MAVEN_FULL_GRAPH=1`을 설정하면 남습니다. 컴포넌트 수가 예상보다 훨씬 적으면 네트워크 접속부터 확인하세요.

> 참고: 이 컴퓨터에서 빌드한 프로젝트는 사용자의 Maven 로컬 저장소에서 해석합니다. CLI, `--ui`, 데스크톱 앱은 `~/.m2/settings.xml`의 `<localRepository>`(XML 주석 밖의 값이며, `${user.home}`은 홈 폴더로 바꿉니다)를, 없으면 `~/.m2/repository`를 `/bomlens-settings/m2/repository`에 읽기 전용으로 붙입니다. 폴더가 없거나, `<localRepository>` 값이 다른 속성을 쓰거나 상대 경로이거나, 경로에 `"`, `$`, 백틱, 백슬래시가 들어 있으면 붙이지 않습니다. `pom.xml`이 있는 트리에서 스캔은 이 폴더를 Maven에 `-Dmaven.repo.local.tail`로 넘깁니다. 그래서 Maven은 BomLens 자체 저장소 다음에 이 폴더를 읽고, 여기에는 아무것도 내려받지 않습니다. cdxgen에는 `MAVEN_CACHE_DIR`로 넘겨 POM, 라이선스, jar 해시도 여기서 찾게 하며, 부모 POM 라이선스 단계와 jar 개수 확인도 이 폴더를 봅니다. 이 속성은 Maven 3.9 이상이 읽고, 그보다 낮은 Maven은 무시합니다. 붙인 폴더가 비어 있으면 대개 Docker 엔진이 그 폴더를 공유하지 않는 것이며, 스캔은 읽지 않는다는 사실을 로그에 남깁니다. 스캔은 해석하기 전에 Maven이 내려받을 저장소(`settings.xml`의 첫 `<mirror>` URL, 없으면 Maven Central)에 5초 제한으로 한 번 접속해 봅니다. 이때 `settings.xml`에서 켜져 있는 `<proxy>`나 프록시 변수를 거치고, 컨테이너의 CA 신뢰 설정을 씁니다. 접속할 수 없을 때(이름을 찾지 못함, 연결 거부, 도달 불가, 시간 초과)만 Maven을 오프라인(`-o`)으로 실행하고, 그 호스트를 적은 로그 한 줄을 남깁니다. HTTP 응답은 오류 상태 코드라도, 그리고 인증서 오류도 접속된 것으로 봅니다. `settings.xml`에 `<offline>true</offline>`가 있거나 `-o`를 이미 주었으면 접속해 보지 않습니다. SBOM에는 `bomlens:maven-user-repository`(`read-only`)와 `bomlens:maven-offline`(`probe`, `settings`, `false`)을 기록합니다. 3.9보다 낮은 Maven 래퍼(`mvnw`)는 사용자 저장소를 읽지 않으며, 오프라인에서는 자기 Maven 배포본도 내려받지 못합니다. `~/.m2/wrapper`가 아니라 `~/.m2/repository`만 붙이기 때문입니다. 그래서 오프라인에서 `.mvn/wrapper/maven-wrapper.properties`가 3.9보다 낮은 Maven을 가리키면 `mvnw` 대신 이미지의 `mvn`을 실행하고 cdxgen도 이를 쓰게 하며(`MVN_CMD`와 `CDXGEN_JVM_TOOL_PINNED=true`), 그 이유를 로그에 남깁니다. 트리에 Gradle 빌드도 있으면 cdxgen은 래퍼를 그대로 쓰고(`mvnw`를 건너뛰게 하면 Gradle 래퍼도 건너뛰기 때문입니다) `maven-dependency-tree`를 실패로 기록합니다. 오프라인에서 cdxgen의 `dependency:tree`는 사용자의 Maven 로컬 저장소나 BomLens의 Maven 캐시에 `maven-dependency-plugin`과 Maven의 플러그인 접두어 정보(접두어 `dependency`를 적은 `org/apache/maven/plugins/maven-metadata-*.xml`)가 함께 있어야 합니다. `mvn package`로만 채운 저장소에는 플러그인이 없고, 3.9보다 낮은 Maven이 채운 저장소에는 접두어 정보가 없습니다. 이때는 어느 쪽이 없는지 로그에 남기고(이 컴퓨터의 프로젝트에서 Maven 3.9 이상으로 `mvn dependency:tree`를 한 번 실행하세요), jar 내려받기를 건너뛰며 `maven-dependency-tree`를 실패로 기록합니다. 오프라인에서 Maven이 해석한 jar가 두 저장소 어디에도 없을 때도 의존성 트리가 함께 빠지므로 같은 방식으로 기록합니다. 접속해 보는 미러는 첫 `<mirror>` 하나뿐입니다. `BOMLENS_MAVEN_USER_REPOSITORY=false`로 두면 이 폴더를 붙이지 않습니다([CLI 레퍼런스](cli.ko.md)).

> 주의: Maven 3.10 이상은 같은 의존성을 두 번 선언한 `pom.xml`을 거부합니다(`'dependencies.dependency.(groupId:artifactId:type:classifier)' must be unique`, `dependencyManagement`도 마찬가지). Maven 3.9는 경고만 했고, cdxgen 이미지에는 Maven 3.10이 들어 있습니다. Maven 래퍼(`mvnw`와 `.mvn/wrapper/`)가 있는 프로젝트는 항상 그 래퍼로 읽으므로, 래퍼가 3.10보다 낮은 Maven을 지정하면 POM을 받아들입니다. 그래도 cdxgen을 실행하기 전에 이 오류가 보이면 BomLens는 Apache Maven 3.9.16으로 다시 시도합니다. 이 Maven은 이미지에 든 Maven으로 내려받으므로 `settings.xml`의 미러, 프록시, 오프라인 설정이 그대로 적용됩니다. 그 방법이 실패하고 Maven이 오프라인이 아니면 Maven Central에서 직접 내려받습니다. 내려받은 압축 파일은 BomLens에 들어 있는 SHA-512 체크섬과 일치할 때만 씁니다. 그다음 cdxgen이 이 Maven으로 의존성 트리를 만듭니다. 다만 프로젝트의 `mvnw`가 Maven 3.10 이상을 쓰고 같은 트리에 Gradle 빌드도 있으면 예외입니다. 이때 Maven 3.9.16을 쓰게 하려면 cdxgen이 Gradle 래퍼까지 건너뛰어야 하므로, BomLens는 래퍼를 그대로 두고 경고를 출력한 뒤 이 단계를 실패로 기록합니다. 어떤 Maven도 POM을 읽지 못하면 결과에는 `pom.xml`에 적힌 의존성만 담기고(test, provided, system 스코프와 optional 의존성은 빠집니다), 실패한 단계 `maven-dependency-tree`가 기록되며 `generate`는 `degraded`가 됩니다. 반복된 `<dependency>` 항목을 지우면 Maven 버전과 관계없이 해결됩니다.

---

> 참고: 최상위 폴더에 `pom.xml`과 `build.gradle`(또는 `build.gradle.kts`)이 함께 있으면 예전처럼 Gradle 프로젝트로 읽습니다. `pom.xml`만 읽으려면 `--build-tool maven`을 쓰고(Gradle 파일은 스캔에서 제외하며 Gradle 단계도 실행하지 않습니다), Gradle 파일만 읽으려면 `--build-tool gradle`을 씁니다. 스캔 로그에 읽는 도구가 출력되고, SBOM에는 `bomlens:build-tool-choice`로 도구가, `bomlens:build-tool-choice-why`로 이유가 남습니다. 같은 프로젝트라도 두 도구가 해석하는 의존성 집합은 다를 수 있으니 고르기 전에 개수를 비교해 보세요. 빌드 도구가 하나뿐인 폴더나 `pom.xml`이 하위 폴더에만 있는 경우에는 영향이 없습니다.

> 참고: 사내 저장소나 미러는 본인의 Maven 설정으로 동작합니다. `~/.m2/settings.xml`과 `~/.m2/settings-security.xml`이 있으면 읽기 전용으로 스캔에 넘기고(컨테이너 안의 `/bomlens-settings/m2`), Gradle 파일인 `~/.gradle/gradle.properties`, `init.gradle`, `init.gradle.kts`, `init.d/`도 같습니다. CLI와 `--ui`, 데스크톱 앱은 이렇게 하지만 더블클릭하는 `sbom-ui.bat`은 하지 않습니다. 미러 주소는 컨테이너 안에서 접속할 수 있어야 합니다. HTTPS를 다시 서명하는 프록시라면 `SBOM_EXTRA_CA_CERTS`가 필요합니다. [Maven으로 빌드하는 자바 프로젝트는 어떻게 스캔하나요?](../guides/java-maven.ko.md)를 보세요.

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

감지 파일: `build.gradle` 또는 `build.gradle.kts`

> 주의: Maven과 마찬가지로 해석하려면 컨테이너가 Maven Central(또는 사내 미러)에 접속할 수 있어야 합니다. 접속하지 못하면 직접 의존성만 담기고 라이선스가 빌 수 있습니다. 컴포넌트 수가 예상보다 훨씬 적으면 네트워크 접속부터 확인하세요. Gradle은 의존성을 해석하지 못해도 정상 종료하므로(보고서에는 그 항목이 `FAILED`로 표시됩니다), 스캔이 그런 항목을 직접 셉니다. 로그에 `Gradle could not resolve N dependency entries`를 남기고 `gradle-dependencies` 단계를 실패로 기록하므로(`bomlens:pipeline-step-failed`) 결과 완전성은 부분이 됩니다.

> 참고: 이 컴퓨터에서 빌드한 프로젝트는 사용자의 Gradle 캐시에서 해석합니다. CLI, `--ui`, 데스크톱 앱은 `modules-2`가 든 폴더(`GRADLE_USER_HOME` 아래 `caches`, 없으면 `~/.gradle/caches`)를 읽기 전용으로 붙이고, 스캔은 이 폴더를 Gradle의 읽기 전용 의존성 캐시(`GRADLE_RO_DEP_CACHE`)로 넘깁니다. cdxgen도 여기서 jar와 해시를 읽습니다. 스캔은 첫 Gradle 실행 전에 빌드가 쓰는 저장소(빌드, 설정, init 스크립트의 `url`이나 `maven("...")`, 그리고 `mavenCentral()`, `google()`, 플러그인 포털)에 5초 제한으로 한 번씩 접속해 봅니다. 하나라도 응답하면 Gradle은 평소대로 실행합니다. 하나도 응답하지 않으면 Gradle을 `--offline`으로 실행해 캐시에서만 해석합니다. 어느 쪽이었는지는 SBOM에 기록합니다(`bomlens:gradle-user-cache`, `online` 또는 `offline`). Gradle은 자기 버전이 쓰는 캐시 구조의 메타데이터(`modules-2/metadata-2.NNN`)만 읽으므로, 캐시를 채운 Gradle과 같은 Gradle로 스캔할 때 캐시가 온전히 쓰입니다. 프로젝트의 래퍼가 그런 경우입니다. 오프라인에서 래퍼의 배포본이 BomLens의 Gradle 캐시에 없으면 역시 읽기 전용으로 붙인 사용자의 `wrapper/dists`에서 복사합니다. 거기에도 없으면 이미지의 Gradle(8.14.5)을 대신 실행하고 `[WARN]` 줄로 알립니다. 네트워크 없이 `examples/java-gradle`을 측정한 결과, Gradle 9.8.2가 채운 캐시를 Gradle 8.14.5로 읽었을 때와 프로젝트의 8.9 래퍼가 채운 캐시를 같은 래퍼로 읽었을 때 모두 온라인과 같은 컴포넌트 13개가 나왔습니다. Gradle 9.8.2가 채운 캐시를 8.9 래퍼로 읽으면 직접 의존성 4개만 나오고 단계가 실패로 기록되었습니다. `BOMLENS_GRADLE_USER_CACHE=false`로 두면 두 폴더 모두 붙이지 않습니다([CLI 레퍼런스](cli.ko.md)).

> 주의: SBOM에는 각 프로젝트의 `runtimeClasspath`가 해석한 의존성이 담깁니다. 그래서 컴파일 클래스패스에만 있는 의존성(`compileOnly`, `annotationProcessor`, 라이브러리가 컴파일 전용으로 선언한 Guava의 `j2objc-annotations` 같은 어노테이션)과 테스트 클래스패스에만 있는 의존성(JUnit, Mockito)은 빠집니다. 빌드가 코드를 쓰려고 다른 빌드를 포함하거나(`includeBuild`, `pluginManagement`로만 포함한 빌드는 해당하지 않음), 런타임 클래스패스를 해석하지 못했거나, Gradle 실행이 실패하면 전체 그래프를 그대로 두며, `BOMLENS_GRADLE_FULL_GRAPH=1`로 전체 그래프를 유지할 수 있습니다([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)). 한계는 [배포되는 구성만 남기기](../concepts/dependency-resolution.ko.md#배포되는-구성만-남기기)에 있습니다.

> 주의: cdxgen에는 스캔의 Gradle 캐시(`GRADLE_CACHE_DIR`, CLI는 스캔 사이에 이 캐시를 유지함)를 알려 줍니다. jar가 이미 그 캐시에 있는 구성요소는 MD5, SHA-1, SHA-256, SHA-512 해시가 붙고, Maven Central에 닿지 않을 때도 그 캐시의 POM에서 라이선스를 읽습니다. 파일이 캐시에 없는 구성요소는 둘 다 없으므로 해시와 라이선스는 Maven처럼 캐시 내용에 따라 달라집니다. 해시 계산은 부하가 있는 컴퓨터에서 jar 하나에 약 0.16초였습니다(jar 369개, 354MB에 60초).

cdxgen Java 이미지에는 JDK가 하나씩만 있고, Gradle 빌드에서는 두 가지가 필요한 JDK를 정합니다. 툴체인은 지정한 버전의 JDK를 정확히 요구합니다. Gradle 래퍼(`gradlew`와 `gradle/wrapper/gradle-wrapper.properties`)는 그 Gradle 버전이 지원하는 JDK에서만 실행됩니다. 예를 들어 6.9.4 래퍼는 Java 21에서 "Unsupported class file major version 65"로 실패합니다. 스캔은 두 가지를 모두 읽습니다.

- 툴체인은 `JavaLanguageVersion.of(N)`(`languageVersion = ...` 또는 `languageVersion.set(...)` 형태)과 Kotlin `jvmToolchain(N)`에서 읽습니다. 스캔한 폴더와 그 아래 다섯 단계까지의 `*.gradle`과 `*.gradle.kts` 파일(`buildSrc`와 컨벤션 플러그인 포함)에서 찾고, 가장 높은 버전을 씁니다. 인자는 같은 파일에 정의한 변수여도 되고, `.toInteger()`, `.toInt()`, `.toString()`, `as int`로 변환한 형태도 읽습니다. 변수의 값은 그 정의가 읽는 Gradle 속성(`hasProperty`, `getProperty`, `findProperty`, `property`, `providers.gradleProperty("p")`, `properties["p"]`, Kotlin `val p: String by project`)을 가장 가까운 `gradle.properties`에서 찾은 값입니다. 그 값이 없으면 정의가 주는 기본값(`?:`나 삼항 연산자의 `:` 뒤, 또는 `getOrElse("N")` 안의 숫자)을 쓰고, 그것도 없으면 변수에 대입한 숫자를 씁니다. 일반 파일인 `gradle.properties`만 읽으며, 블록 밖의 정의를 블록 안의 정의보다 먼저 봅니다.
- 래퍼의 Gradle 버전은 `distributionUrl` 끝의 파일 이름에서 읽습니다. Gradle 배포 파일 이름 형식(`gradle-X.Y[.Z]-bin.zip` 또는 `-all.zip`)이어야 하고, 마일스톤과 릴리스 후보, 스냅숏은 해당 정식 버전으로 봅니다. 래퍼는 옆에 `gradlew`가 있을 때만 셈하고, 없으면 이미지에 든 Gradle 8.14.5가 실행됩니다. 어느 래퍼를 셈할지는 스캔한 폴더에 따라 다릅니다.
    - `gradlew`가 있으면 그 폴더의 래퍼만 셈합니다. 버전을 읽지 못하면(예: 이름을 바꾼 배포 파일) `[INFO]` 줄로 알리고 툴체인만으로 고릅니다.
    - Gradle 설정 파일이나 빌드 파일이 있고 `gradlew`가 없으면 래퍼를 셈하지 않습니다. 그 폴더에서 이미지의 Gradle이 한 번 실행됩니다.
    - 둘 다 없으면 아래 다섯 단계까지에서 설정 파일이나 빌드 파일 옆에 `gradlew`가 있는 빌드의 래퍼를 모두 셈합니다. `buildSrc`, `build-logic`, 점으로 시작하는 폴더, 다른 빌드가 `includeBuild(...)`로 지정한 빌드는 건너뜁니다. 이미지는 이 래퍼를 모두 실행할 수 있어야 하며, 그런 이미지가 없으면 가장 낮은 버전에 맞춰 고르고 `[WARN]` 줄로 알립니다.

주석과 위에 적은 배포하지 않는 폴더는 건너뜁니다(`BOMLENS_INCLUDE_NON_SHIPPED=1`이면 그 폴더도 읽습니다). 이미지별 JDK와 그 JDK에서 실행되는 Gradle 버전은 다음과 같습니다([Gradle 호환성 표](https://docs.gradle.org/current/userguide/compatibility.html) 기준).

| 이미지 | JDK | 실행되는 래퍼 버전 |
|---|---|---|
| `cdxgen-temurin-java8` | 8 | 9.0 미만 |
| `cdxgen-java11` | 11 | 5.0~8.14.x |
| `cdxgen-java17` | 17 | 7.3 이상 |
| `cdxgen-temurin-java21` | 21 | 8.5 이상 |
| `cdxgen-temurin-java24` | 24 | 8.14 이상 |
| `cdxgen-temurin-java25` | 25 | 9.1.0 이상 |

래퍼가 툴체인의 JDK에서 실행되면 툴체인의 이미지를 고릅니다. 그렇지 않으면 래퍼가 Java 21에서 실행될 때는 `cdxgen-temurin-java21`을, 실행되지 않을 때는 래퍼가 실행되는 가장 새 이미지를 고릅니다(7.3~8.4 래퍼는 Java 17, 5.0~7.2는 11, 5.0 미만은 8). 툴체인과 래퍼가 모두 없으면 `cdxgen-temurin-java21`을 씁니다. Java 21이 아닌 이미지를 고르면 그 이유를 `[INFO]` 줄로 알립니다.

빌드가 요구하는 것을 맞출 수 없으면 `[WARN]`으로 알립니다. 이미지가 없는 툴체인(22, 23, 26 등)이나 래퍼가 실행되지 않는 툴체인(8.14 래퍼에 Java 25 툴체인)이 그런 경우입니다. 이때 Gradle은 툴체인의 JDK를 찾지 못하므로, 빌드에 툴체인 자동 내려받기(auto-provisioning)를 설정하지 않았다면 의존성 해석이 실패할 수 있습니다. 여러 언어가 섞인 트리는 툴체인과 관계없이 올인원 이미지에서 실행하며, 툴체인이 21이 아니면 같은 방식으로 경고합니다. 버전 카탈로그나 다른 파일의 변수, 더 복잡한 식에서 가져온 버전은 읽지 못합니다. 그래서 툴체인에 맞는 JDK가 없어 Gradle이 실패하면, 그 JDK가 있고 래퍼도 실행되는 이미지가 있을 때 그 이미지에서 의존성 단계를 한 번 더 실행합니다(`[INFO] Gradle asked for Java N; rerunning in <image>`). 로컬에 없는 이미지는 진행 상황을 보여 주며 받고, `SBOM_PULL=always`이면 먼저 새로 받습니다. 다시 실행한 결과에 SBOM이 없으면 처음 결과를 그대로 씁니다. `CDXGEN_JAVA_IMAGE`를 지정했거나, 그 이미지가 로컬에 없고 받을 수도 없으면(`SBOM_PULL=never`이면 받지 않습니다) 다시 실행하지 않습니다. 실행 계획(`MODE=PLAN`)도 다시 실행하지 않습니다. 그래도 빌드가 JDK를 얻지 못하면 `CDXGEN_JAVA_IMAGE`로 그 JDK가 있는 이미지를 지정합니다([CLI 레퍼런스](cli.ko.md)). Maven은 이런 선택이 필요 없습니다. `maven.compiler.release`와 toolchains 플러그인은 컴파일할 때 적용되고, 의존성 해석은 이것 없이 실행됩니다.

---

## Android

Gradle 루트(`settings.gradle[.kts]` 또는 `build.gradle[.kts]`가 루트에 있음)가 있고, Android Gradle 플러그인의 흔적이 함께 있을 때 감지합니다. 버전 카탈로그(`gradle/libs.versions.toml`)의 플러그인 id, 빌드 스크립트(루트 또는 `app/`)의 플러그인 id나 카탈로그 별칭, Kotlin DSL `namespace` 선언, 또는 몇 단계 아래의 `AndroidManifest.xml` 중 하나면 됩니다. Gradle 루트 없이 매니페스트만 있으면 인정하지 않는데, 이 덕분에 .NET MAUI 앱의 `Platforms/Android/AndroidManifest.xml`을 Android 프로젝트로 잘못 읽지 않습니다.

Android는 BomLens가 배포하지 않는 SDK 플랫폼 이미지가 필요합니다. 담긴 Android SDK 자체가 오픈소스가 아니고 구글 약관이 재배포를 허용하지 않아서, 이 이미지는 쓰는 쪽에서 직접 빌드해야 합니다. 찾은 `compileSdk`/`compileSdkVersion` 중 가장 높은 값으로 API 레벨을 정하고(못 찾으면 34), 루트와 `app/`의 빌드 파일, `build-logic/`과 `buildSrc/` 아래 소스(공통 플러그인이 여기서 값을 정하는 경우가 많습니다), 버전 카탈로그(`android-compileSdk` 같은 키)를 모두 읽습니다. `bomlens-android-sdk<API>:latest`를 찾습니다. 이미지가 없으면 스캔을 시작하기 전에 멈추고 빌드 명령을 그대로 출력합니다.

```bash
docker build --build-arg ANDROID_API=<API> -t bomlens-android-sdk<API> docker/android
```

빌드한다는 것은 구글 SDK 약관에 직접 동의한다는 뜻입니다. 다른 곳에서 빌드한 이미지를 쓰려면 `ANDROID_IMAGE_PREFIX`를 설정하세요. 이미지는 디스크에서 약 6.3GB를 차지하며 API 레벨마다 하나씩 필요합니다([크기](docker-image.ko.md#이미지가-디스크를-얼마나-차지하나요)). 단계별 안내는 [Gradle로 빌드하는 안드로이드 앱은 어떻게 스캔하나요?](../guides/android-gradle.ko.md)에 있습니다.

SDK 이미지는 Java 21에서 실행되므로 Gradle 8.5보다 오래된 래퍼는 이 이미지에서 실행되지 않습니다. 스캔을 시작하기 전에 이를 안내하고 SBOM에 실패 단계 `gradle-wrapper-jdk`를 남깁니다. `gradle/wrapper/gradle-wrapper.properties`의 `distributionUrl`을 8.5 이상으로 올리거나, `--build-arg BASE_JDK_IMAGE=<cdxgen Java 이미지>`로 더 낮은 JDK 기반 이미지를 직접 빌드한 뒤(`docker/android/Dockerfile` 참고) 그 이미지의 `ANDROID_IMAGE_PREFIX`로 스캔하세요. `gradle.properties`에서 Isolated Projects를 켠 빌드는 구성 캐시를 끄면 Gradle이 실행을 거부하므로, 구성 캐시를 켠 채로 읽습니다.

Gradle 빌드를 아예 실행할 수 없을 때(Docker 없음, 빌드 실패)는 대체 경로가 버전 카탈로그(`gradle/*.versions.toml`)에 선언된 라이브러리를 읽어 `bomlens:source=version-catalog` 표시와 함께 추가합니다. 빌드가 실제로 쓰는 의존성이 아니라 선언 목록이므로 결과는 계속 부분 등급입니다.

> 참고: v1.9.0까지 배포됐던 `ghcr.io/sktelecom/bomlens-android-sdk<API>` 이미지는 그 릴리스 라인 스캔에는 여전히 쓸 수 있지만, 더는 새로 올라가지 않습니다. 지금 스캔하려면 직접 빌드한 이미지가 필요합니다.

---

## Node.js

```bash
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only
```

감지 파일: `package.json` + `package-lock.json` (또는 `yarn.lock`, `pnpm-lock.yaml`)

> 주의: 잠금 파일은 실제로 설치된 버전을 정확히 고정합니다. 잠금 파일이 없어도 `package.json`에서 의존성을 찾아내지만, 잠금 파일을 커밋해 두면 결과가 재현 가능해집니다.

> 참고: lock 파일을 커밋하지 않았더라도 이 컴퓨터에서 설치한 프로젝트는 npm이나 pnpm이 설치할 때 써 둔 lock 파일을 읽으므로, 레지스트리 없이 전체 의존성 그래프를 해석합니다. `package.json`이 있고 그 폴더와 상위 폴더에 lock 파일(`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`)이 없는 폴더마다, BomLens는 `node_modules/.package-lock.json`(npm 7 이상)이나 `node_modules/.pnpm/lock.yaml`(pnpm)을 그 폴더의 lock 파일로 씁니다. npm의 lock은 lockfile 버전 2나 3이어야 하고 `package.json`의 `dependencies`에 있는 패키지를 모두 담고 있어야 합니다. BomLens는 `package.json`에서 루트 항목을 더해 이번 스캔용 `package-lock.json`을 쓰고, production 집합도 npm을 실행하지 않고 이 파일에서 읽습니다. pnpm의 lock은 importer에 선언된 의존성이 모두 있는지 확인한 뒤 `pnpm-lock.yaml`로 복사합니다. 둘 다 있으면 나중에 쓴 쪽을 씁니다. 이렇게 쓴 파일은 스캔이 끝나면 지우며, `BOMLENS_KEEP_BUILD_OUTPUT=1`이어도 지웁니다. 읽지 않는 lock은 로그에 이유와 함께 남습니다. 선언된 의존성이 빠진 lock(설치 후에 `package.json`이 바뀐 경우이므로, 다시 설치하거나 lock 파일을 커밋하세요), npm 워크스페이스 루트의 lock, importer가 둘 이상인 pnpm lock이 여기에 해당합니다. 읽지 않은 워크스페이스 lock은 `bomlens:pipeline-step-failed`에 실패한 단계 `npm-installed-lock` 또는 `pnpm-installed-lock`으로도 기록되므로, 결과는 부분 결과(사유 `resolution-failed`)가 되고 의존성 그래프는 `incomplete`가 됩니다. lock 파일을 커밋한 뒤 다시 스캔하세요. 이 lock에는 그 컴퓨터에 설치된 것만 기록되므로, 커밋한 lock과 달리 다른 플랫폼용 선택 패키지(예: esbuild나 rollup의 플랫폼별 빌드)는 들어 있지 않습니다. yarn과 bun이 `node_modules`에 남긴 설치 정보는 읽지 않습니다. lock 파일이 하나도 없으면 스캔은 먼저 프로젝트 밖에서 npm에 설정된 레지스트리(환경 변수, 사용자 npm 설정, 전역 npm 설정으로 정해지며 `npm config get registry`가 알려 주는 값입니다. 해석은 임시 폴더에서 실행하므로 프로젝트의 `.npmrc`는 적용되지 않습니다)에 짧은 제한 시간을 두고 응답을 요청합니다. 응답이 없으면 production 집합을 해석하지 않고, 의존 관계를 알 수 없다고 로그에 남기며, `npm-production-set`을 `bomlens:pipeline-step-failed`에 기록합니다(`bomlens:prep-step-applied`에는 기록하지 않습니다). 설치할 때 쓴 lock 파일이 있다고 트리를 정적으로 읽지는 않습니다. `--detection auto`는 여전히 빌드하고, 빌드가 네트워크 없이 이 파일을 읽습니다. SBOM에는 읽은 lock마다 `bomlens:node-lock-source`가, 단계로는 `npm-installed-lock` 또는 `pnpm-installed-lock`이 기록됩니다([SBOM 산출물](artifacts.ko.md#sbom-구조)). `BOMLENS_NODE_INSTALLED_LOCK=false`(또는 `0`)로 끌 수 있습니다.

> 주의: SBOM은 production 의존성 집합으로 걸러지므로 devDependencies는 덜어내고 실제 배포되는 구성을 반영합니다. dev와 production을 합친 전체 그래프를 그대로 두려면 `BOMLENS_NODE_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

> 주의: npm 워크스페이스 멤버가 `package-lock.json`에 등록돼 있으면, 그 멤버의 디렉터리가 제외 대상 트리 아래에 있어도 위의 파일 단위 제외로는 빠지지 않습니다. cdxgen이 `package-lock.json`을 직접 읽기 때문입니다. 이런 멤버 자신의 컴포넌트는 빠지고, 그 멤버만 필요로 하는 의존성도 함께 빠집니다. 다만 유지되는 멤버가 그 의존성을 필요로 하면 남습니다. `BOMLENS_INCLUDE_NON_SHIPPED=1`(위 파일 단위 제외와 같은 스위치)로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 멤버와 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-members`, `bomlens:excluded-components`로 기록됩니다. yarn 워크스페이스 멤버는 아직 같은 방식으로 잡히지 않습니다.

> 주의: production 필터와 별도로, cdxgen이 개발 패키지(npm, pnpm, yarn, bun)로 표시한 컴포넌트는 운영 의존성 경로에서 닿지 않으면 빠지고, 그 컴포넌트만 필요로 하는 의존성도 함께 빠집니다. production 필터가 읽지 않는 pnpm 워크스페이스도 여기에 해당합니다. 운영 의존성도 쓰는 패키지는 남습니다. `BOMLENS_NODE_FULL_GRAPH=1`이나 `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1`이면 이 컴포넌트들도 그대로 둡니다.

> 참고: lock 파일이 하나도 없을 때(`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`) npm이 내려받지 못하는 의존성 하나(비공개 `git+https` 주소, 저장소에 없는 패키지, 존재하지 않는 버전) 때문에 결과가 비는 일은 없습니다. BomLens가 그 의존성을 뺀 채로 최대 다섯 번 다시 해석하고, 뺀 의존성마다 실패한 단계 `npm-excluded:이름`으로 기록하므로 결과는 `partial`로 표시되고 이름이 나옵니다. 완전한 결과가 필요하면 그 의존성에 접근할 수 있게 하거나 `package-lock.json`을 커밋하세요.

---

## Python

```bash
./scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --target examples/python --generate-only
```

감지 파일: `requirements.txt` 또는 `pyproject.toml` + `poetry.lock`

> 주의: `poetry.lock`이 없는 Poetry 프로젝트는 `[tool.poetry.dependencies]`의 정확한 고정 버전(`requests = "2.31.0"`)으로 스캔합니다. `^2.0` 같은 범위와 경로·git 항목은 빠집니다. 고정 버전은 프로젝트에 연결되고 그 하위 의존성까지 나옵니다. 빠진 항목이 있거나 네트워크가 없어 하위 의존성을 풀지 못하면 SBOM은 의존 그래프를 불완전(incomplete)으로 표시합니다. 버전을 `==`로 고정하거나 `poetry.lock` 같은 잠금 파일을 커밋하세요. 그렇지 않으면 SBOM에는 실제로 쓰는 버전이 아니라 스캔 시점에 받을 수 있는 버전이 담깁니다. 번들 예제는 버전을 고정해 두었고 모든 컴포넌트에 라이선스가 있습니다.

> 주의: uv(`uv.lock`)나 Poetry 프로젝트에서 cdxgen이 `main`이 아닌 의존성 그룹(예: `dev`, `test`)에만 넣은 컴포넌트는 운영 의존성 경로에서 닿지 않으면 빠지고, 그 컴포넌트만 필요로 하는 의존성도 함께 빠집니다. 운영 의존성도 쓰는 패키지는 남습니다. 프로젝트 안의 어느 `pyproject.toml`이든 `[project]`의 `dependencies`나 `optional-dependencies`, 또는 `[tool.poetry.dependencies]`에 적은 패키지도 의존성 그룹에 함께 있더라도 남습니다. BomLens는 이 파일을 자체의 간단한 읽기 방식으로 읽습니다. 스캔 루트에 `pyproject.toml`이 없거나, 읽지 못하는 형식(예: `dynamic = ["dependencies"]`)을 쓴 파일이 있으면 Python 패키지를 하나도 빼지 않고 빌드 로그에 그렇게 남깁니다. `vendor`와 소스 스캔이 기본으로 제외하는 폴더(위 참고) 밖에 `requirements*.txt`, `setup.py`, `setup.cfg`, `Pipfile`이 있어도 같습니다. 이 파일들이 읽기 방식이 보지 못하는 운영 의존성을 선언할 수 있기 때문입니다. 이 검색은 폴더 8단계 깊이까지 내려가며 `vendor`, `node_modules`, `.git`, 가상 환경(`.venv`, `venv`)은 건너뜁니다. 이들과 기본 제외 폴더 밖에 더 깊은 폴더가 있어도 Python 패키지를 하나도 빼지 않습니다.

> 참고: `uv.lock`은 읽습니다(cdxgen 13.5.0이 그 패키지를 나열합니다). 런타임 의존성이 없는 프로젝트라서 `uv.lock`에 `dev`나 `tests` 같은 의존성 그룹의 패키지만 있으면 컴포넌트가 하나도 남지 않습니다. 이때 스캔은 결과를 해석 실패로도, 완전으로도 보고하지 않고 `only-excluded-dependencies` 사유의 부분 결과로 보고합니다. 제품에 런타임 의존성이 실제로 없다면 이 결과가 맞습니다. 제외된 패키지는 SBOM 속성 `bomlens:excluded-components`에 있고, `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1`로 목록에 넣을 수 있습니다.

> 참고: 이 컴퓨터에서 가상 환경에 설치까지 마친 프로젝트는 스캔이 패키지 저장소를 쓰지 못해도 해석됩니다. 스캔 대상 폴더에 `.venv/`, `venv/`, 또는 `pyvenv.cfg`가 든 다른 최상위 폴더 하나가 있고 그 `site-packages`에 `*.dist-info` 폴더가 있으면, 스캔은 먼저 pip이 쓸 패키지 저장소에 짧은 제한 시간을 두고 응답을 요청합니다. 저장소는 `requirements.txt`의 `-i`나 `--index-url`, 없으면 `PIP_INDEX_URL`이나 스캔 컨테이너 안 pip 설정 파일의 `index-url`, 그것도 없으면 `https://pypi.org/simple/`입니다. 저장소가 응답하지 않거나(사유 `index-unreachable`) `pip install`이 실패하면(사유 `pip-install-failed`) SBOM의 Python 부분은 설치된 패키지의 메타데이터에서 의존성 그래프, 라이선스와 함께 가져오고, cdxgen의 Python 단계는 빼고 실행합니다. 환경은 읽기만 하며, 그 안의 어떤 것도 실행하지 않고 그 폴더에 아무것도 쓰지 않습니다. 저장소에 접속되는 스캔은 달라지지 않습니다. 스캔 루트에 완전한 lock 파일(`poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`)도 있으면 환경은 읽지 않고 lock 파일을 읽으며, 빌드 로그에 그렇게 남깁니다.
>
> 목록은 선언된 의존성에서 시작합니다. 요구 사항 파일(소스 스캔이 제외하는 폴더 밖의 `requirements*.txt`이며 `requirements-dev.txt`도 포함), `pyproject.toml`의 `[project].dependencies`와 Poetry 기본 의존성, `setup.cfg`의 `install_requires`가 대상입니다. Poetry나 uv의 의존성 그룹은 `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1`일 때만 포함합니다. 여기서부터 각 패키지의 `Requires-Dist`를 따라가므로, 어디에도 선언되지 않은 채 옆에 설치된 도구(예: pytest)는 빠집니다. 환경 마커(`; python_version < "3.11"`)는 그 환경의 Python 버전(`pyvenv.cfg`)과 플랫폼(설치된 wheel의 태그)으로 판정하고, 판정하지 못한 마커가 붙은 요구 사항은 남기되 미확정으로 셉니다. 라이선스는 각 패키지의 `License-Expression`, 없으면 `License` 필드, 그것도 없으면 라이선스 분류자(classifier)에서 가져옵니다.
>
> SBOM에는 폴더가 `bomlens:python-environment`(스캔 루트 기준 상대 경로)에, 사유가 `bomlens:python-environment-reason`에, 단계 `python-environment`가 `bomlens:prep-step-applied`에 기록됩니다. 확정하지 못한 것이 있으면(판정하지 못한 마커, 선언했지만 설치되지 않은 패키지, 선언한 고정 버전과 다른 설치 버전, 한 패키지의 설치 버전이 둘 이상인 경우, 시스템 `site-packages`도 함께 쓰는 환경) `bomlens:python-environment-unsure`에 그 내용을 적고, 결과는 `installed-environment-unsure` 사유의 부분 결과가 됩니다. 이때 SBOM에 제품이 쓰지 않는 의존성이 들어 있거나 빠진 의존성이 있을 수 있습니다. 배포하는 플랫폼에서 의존성을 다시 설치하거나 스캔이 패키지 저장소에 접속할 수 있게 한 뒤 다시 스캔하면 이 사유가 없어집니다. 끄려면 `BOMLENS_PYTHON_VENV=false`(또는 `0`)를 설정하세요.
>
> conda `environment.yml`이 있는 프로젝트는 이 방식으로 읽지 않고 환경 파일을 읽습니다([Conda](#conda) 참고). 의존성을 `setup.py`에만 선언한 프로젝트는 시작점이 될 선언이 없어 환경을 쓰지 않습니다. 환경 옆의 lock 파일(`poetry.lock`, `uv.lock`, `pdm.lock`)과는 대조하지 않습니다. 환경을 읽으면 Python 부분은 환경에서만 가져옵니다.

---

## Go

```bash
./scripts/scan-sbom.sh --project "GoExample" --version "1.0.0" --target examples/go --generate-only
```

감지 파일: `go.mod` + `go.sum`

> 주의: `go.sum`이 있어야 정확한 버전 해시가 들어갑니다. `go mod tidy`를 먼저 실행한 뒤 시도하세요.

---

## Ruby

```bash
./scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --target examples/ruby --generate-only
```

감지 파일: `Gemfile.lock`

> 주의: `Gemfile.lock`이 커밋되어 있지 않으면 BomLens가 스캔 전에 `bundle lock`을 실행합니다. SBOM이 배포 구성과 일치하도록 잠금 파일을 커밋하세요.

> 주의: cdxgen은 Bundler 그룹을 표시하지 않으므로 BomLens가 스캔 루트의 `Gemfile`을 직접 읽습니다. `development`와 `test` 그룹에만 선언된 gem(`group ... do` 블록 안이나 `group:`, `groups:` 옵션으로 선언)은 빠지고, 그런 gem만 필요로 하는 의존성도 함께 빠집니다. 운영 gem도 필요로 하면 남습니다. `Gemfile`은 보수적으로 읽습니다. 조건문, `gemspec`, `eval_gemfile`, 여러 줄에 걸친 선언처럼 읽지 못하는 줄이 있거나, `Gemfile.lock`에 `Gemfile`에 없는 gem이 있으면 gem을 하나도 빼지 않고 로그에 `Gemfile groups not read`를 남깁니다. 스캔 루트 아래에 다른 `Gemfile`이나 `Gemfile.lock`이 있거나 프로젝트 어디든 `.gemspec` 파일이 있어도 같습니다. 같은 gem을 운영용으로 선언했을 수 있기 때문입니다. 이 검색은 폴더 8단계 깊이까지 내려가며 `vendor`(설치된 gem이 있는 `vendor/bundle` 포함), `node_modules`, `.git`, `.venv`, `venv`는 건너뜁니다. 이들 밖에 더 깊은 폴더가 있어도 gem을 하나도 빼지 않습니다.

> 참고: `optional: true`로 표시한 그룹(`group :avo, optional: true do`)에만 선언된 gem은 Bundler가 요청할 때만 설치하는 그룹이므로 `scope`를 `optional`로 달아 SBOM에 남깁니다. `development`와 `test` 그룹에만 있는 gem은 이전처럼 뺍니다.

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

감지 파일: `composer.lock`

> 주의: `composer.lock`이 커밋돼 있지 않으면 BomLens가 스캔 전에 직접 해석합니다(`composer update --no-dev`, `require-dev`와 `config.lock`을 뺀 `composer.json` 사본으로, 플랫폼 요구사항은 무시합니다). Ruby의 `Gemfile.lock`을 처리하는 방식과 같습니다. 스캔이 끝나면 원래 `composer.json`을 되돌려 놓습니다. PHP 버전을 강제하지 않으므로, 프로젝트가 선언한 것보다 새로운 PHP를 요구하는 의존성 버전이 선택될 수 있습니다. cdxgen은 이미 각 composer 컴포넌트에 해석된 스코프를 붙여서 줍니다(`require`는 required, `require-dev`는 optional). BomLens는 Maven과 같은 방식으로 이 정보를 이용해 SBOM을 required 대상으로 걸러냅니다. require와 require-dev를 합친 전체 그래프를 그대로 두려면 `BOMLENS_PHP_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

> 참고: `vendor/` 안의 `package-lock.json`(예: 프레임워크의 오류 화면용 파일)은 스캔에서 제외하므로, 그 안의 npm 패키지가 프로젝트의 의존성으로 나타나지 않습니다.

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

감지 파일: `Cargo.lock`

> 주의: cdxgen은 라이선스 정보가 없는 `Cargo.lock`만 읽으므로, BomLens는 각 크레이트 자신의 매니페스트를 읽는 `cargo metadata`로 라이선스를 채웁니다(스캔 대상 자신의 워크스페이스 크레이트 포함). 이를 위해 컨테이너가 크레이트 저장소(crates.io 또는 사내 미러)에 닿아야 합니다. 닿지 않으면 SBOM에 라이선스가 기록되는 Cargo 패키지가 거의 없고 스캔으로 만든 고지문이 거의 빕니다. 이때 스캔은 `cargo-license-metadata` 단계를 SBOM에 실패로 기록하며 결과 화면과 적합성 검사 보고서가 이를 보여 주고, 로그에는 `could not read crate licenses`가 남습니다. 라이선스를 파일로만 선언한 크레이트(`license-file`)는 채우지 못합니다. `MIT OR Apache-2.0` 같은 택일 표기는 고정된 순서로 적어, 크레이트가 어떻게 쓰든 같은 조합이 고지문에서 한 항목이 되게 하고, SPDX 표현식이 아닌 값은 라이선스 이름 그대로 둡니다. 번들 예제는 라이브러리 147개 중 146개에 라이선스가 있습니다. `BOMLENS_NO_CARGO_LICENSE=1`로 끌 수 있고, 명령줄에서는 `FETCH_LICENSE=false`도 같은 효과가 있습니다. `--deep-license`는 도움이 되지 않습니다. 이 옵션은 의존성이 아니라 스캔 대상 자신의 소스 파일을 훑고 별도 보고서를 씁니다.

> 주의: Cargo 워크스페이스 멤버가 `Cargo.lock`에 등록돼 있으면, 그 멤버의 디렉터리가 제외 대상 트리 아래에 있어도 위의 파일 단위 제외로는 빠지지 않습니다. cdxgen이 `Cargo.lock`을 직접 읽기 때문입니다. 이런 멤버 자신의 컴포넌트는 빠지고, 그 멤버만 필요로 하는 의존성도 함께 빠집니다. 다만 유지되는 멤버가 그 의존성을 어떤 식으로든 필요로 하면 남습니다. `BOMLENS_INCLUDE_NON_SHIPPED=1`(위 파일 단위 제외와 같은 스위치)로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 멤버와 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-members`, `bomlens:excluded-components`로 기록됩니다.

> 주의: cdxgen이 dev-dependencies(`[dev-dependencies]`)로만 표시한 크레이트는 운영 의존성 경로에서 닿지 않으면 빠지고, 그 크레이트만 필요로 하는 의존성도 함께 빠집니다. 운영 의존성도 쓰는 크레이트와 `[dependencies]`, `[dev-dependencies]`에 함께 적은 크레이트는 남습니다. `Cargo.lock`이 커밋돼 있지 않아도 BomLens가 먼저 해석해 만들므로 cdxgen은 이 표시를 붙입니다. 워크스페이스에서는 멤버 크레이트의 dev-dependencies가 남습니다. 멤버가 의존하는 컴포넌트는 표시와 관계없이 남기 때문이며, 빠질 수 있는 것은 루트 패키지의 dev-dependencies뿐입니다.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

감지 파일: 루트나 그 아래 세 단계 폴더까지의 `*.csproj`, `*.fsproj`, `*.sln`, `*.slnx`. `packages.lock.json`은 있으면 읽습니다

> 주의: 감지에는 프로젝트 또는 솔루션 파일이 필요합니다. `packages.lock.json`은 필수는 아니지만, 커밋해 두면(`dotnet restore --use-lock-file`) 해석된 버전이 고정되어 SBOM을 재현할 수 있습니다.

> 참고: `packages.config`나 `Reference` 항목에서 읽은 .NET Framework 기본 어셈블리(`System`, `System.Core`, `System.Data` 등)는 버전이 없으면 뺍니다. 프레임워크에 포함된 것이고 NuGet 패키지가 아니기 때문입니다. 버전이 있는 `System.*` 패키지는 남습니다.

---

## Swift / iOS

```bash
./scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --target examples/swift --generate-only
```

감지 파일: Swift Package Manager는 `Package.swift` (+ `Package.resolved`), CocoaPods는 `Podfile.lock`.

단계별 안내는 [SwiftPM이나 CocoaPods를 쓰는 iOS 앱은 어떻게 스캔하나요?](../guides/ios-swift.ko.md)에 있습니다.

의존성은 커밋된 잠금 파일에서 읽으므로 스캔에 함께 포함하세요.

- Swift Package Manager: `Package.resolved` (없으면 `swift package resolve`를 먼저 실행).
- CocoaPods: `Podfile.lock` (`pod install`로 생성). BomLens가 이 파일을 직접 파싱하므로 스캔 장비에 macOS나 CocoaPods 설치가 필요 없습니다.

> 주의: UIKit 등 Xcode가 관리하는 플랫폼 의존성은 macOS가 필요하며 Linux 스캐너에서는 해석되지 않습니다.

> 참고: 최상위에 매니페스트가 없어도 세 단계 아래까지 Xcode 프로젝트(`*.xcodeproj`), `Package.swift`, `Podfile`, `Package.resolved`가 있으면(예: `App/App.xcodeproj`) Swift로 스캔합니다. 다른 언어의 루트 매니페스트가 있는 트리는 그 언어를 유지합니다. Swift 의존성 해석 단계와 `cdxgen` 실행은 `BOMLENS_PREP_TIMEOUT`초(기본 900초)가 지나면 멈추고, 저장소 내려받기가 로그인 입력을 요구하지 않도록 설정되어 있어서, 끝나지 않는 의존성 내려받기가 스캔을 붙잡지 않고 해당 단계만 끝납니다.

> 주의: 번들 예제는 컴포넌트 6개 중 5개에 PURL(83%), 2개에 라이선스(33%)가 있습니다. 둘 다 적합성 검사의 기본 기준에 못 미칩니다. PURL 검사는 실패하고 라이선스 검사는 경고를 냅니다. 해석된 패키지 두 개(`swift-argument-parser`, `swift-log`)에는 PURL과 라이선스가 있습니다. 나머지는 패키지 자신과, 코드가 가져다 쓰는 플랫폼 모듈(`Foundation`, `XCTest`, `dispatch`)이며 이 모듈에는 선언할 라이선스가 없습니다. import 검사가 추가하는, 버전 없는 중복 항목은 BomLens가 제거해 패키지가 한 번만 집계됩니다.

---

## Modelica

```bash
./scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --target examples/modelica --generate-only
```

감지 파일: `*.mo`

cdxgen에는 Modelica 카탈로거가 없어 일반적인 패키지 관리자 방식으로는 의존성을 읽지 못합니다. 대신 `.mo` 패키지 자신이 선언하는 `annotation(uses(...))` 블록을 직접 파싱해서, 그 안에 이름과 버전이 함께 적힌 라이브러리를 컴포넌트로 편입합니다. `uses()` 선언에는 이름과 버전만 있으므로 라이선스는 프로젝트가 아니라 BomLens가 가진 알려진 라이브러리 표(`docker/lib/modelica-library-map.json`)에서 가져옵니다. 표에는 각 라이브러리의 업스트림 저장소 라이선스 파일에서 확인한 값을 적어 둡니다(Modelica Standard Library 3.2.3 이상은 `BSD-3-Clause`, Buildings 13.0.0 이상은 `BSD-3-Clause-LBNL`). 번들 예제의 두 라이브러리는 이 방식으로 모두 라이선스를 얻으며(2개 중 2개), 출처는 속성 `bomlens:licenseSource` 값 `modelica-library-map`으로 남습니다. 표에 없는 라이브러리나 기록된 것보다 낮은 버전에는 라이선스가 없습니다.

```modelica
annotation(uses(Modelica(version="4.0.0"), Buildings(version="13.0.0")));
```

> 주의: `uses()`에 직접 선언된 라이브러리만 식별됩니다. Modelica 생태계에는 잠금 파일이 없어 전이 의존성은 해석하지 않으며, 파일 안에 정의된 모델 자체의 구조(컴포넌트, 파라미터, 연결)는 오픈소스 의존성이 아니므로 다루지 않습니다.

---

## Conda

```bash
./scripts/scan-sbom.sh --project "CondaExample" --version "1.0.0" --target . --generate-only
```

감지 파일: 스캔 대상 폴더 최상위의 `environment.yml` 또는 `environment.yaml`

cdxgen에는 Conda 카탈로거가 없어 BomLens가 환경 파일의 `dependencies:` 목록을 직접 읽습니다. CLI, 웹 UI, 데스크톱 앱, 실행 계획 어느 쪽으로 스캔해도 같습니다. conda 항목은 `pkg:conda/...` 컴포넌트가 되고, `pip:` 항목 아래에 적힌 패키지는 `pkg:pypi/...` 컴포넌트가 됩니다.

```yaml
dependencies:
  - python=3.11
  - numpy=1.26.4
  - pip:
    - requests==2.31.0
```

환경 파일을 정상적으로 읽으면 그 스캔에서는 cdxgen의 Python 단계를 끕니다. 끄지 않으면 트리 안 다른 위치의 `setup.py`나 `requirements.txt`가 환경 파일을 대신해 결과의 근거가 됩니다.

> 주의: 위 예시처럼 두 단계 구조만 인식합니다. `dependencies:`는 왼쪽 끝에 두고, 항목은 공백 2칸, `pip:` 아래 항목은 공백 4칸으로 들여써야 합니다. 들여쓰기 폭이 다르거나 한 줄 목록 형식이거나 탭이 들어간 파일은 일부만 읽지 않고 파일 전체를 건너뛰며, 이 경우 cdxgen의 Python 단계가 이전처럼 실행됩니다. 버전이 없거나 `>=1.0` 같은 범위만 적힌 항목은 특정 버전을 가리키지 않으므로 버전과 PURL 없이 기록하고 `bomlens:versionUnpinned` 속성을 붙입니다. `pip:` 아래의 editable 설치와 VCS 설치는 제외합니다.

---

## Docker 이미지 분석

Docker 이미지 분석은 프로젝트 루트에서 실행합니다.

```bash
# 공개 이미지 분석
./scripts/scan-sbom.sh \
  --project "NginxSBOM" \
  --version "1.25" \
  --target "nginx:1.25-alpine" \
  --generate-only

# Ubuntu 기반 이미지
./scripts/scan-sbom.sh \
  --project "UbuntuSBOM" \
  --version "22.04" \
  --target "ubuntu:22.04" \
  --generate-only
```

> 주의: 이 경우 `--target`에는 이미지 이름이나 이미지 tar를 지정합니다. 의존성 목록 파일이 없는 `examples/docker` 폴더를 지정하면 컴포넌트를 찾지 못합니다.

---

## 감지에 필요한 파일

소스 코드 분석 시 의존성이 감지되지 않는 경우, 아래 잠금 파일이 있는지 확인하세요.

| 언어 | 필요한 파일 |
|------|-----------|
| Java (Maven) | `pom.xml` |
| Java (Gradle) | `build.gradle` 또는 `build.gradle.kts` |
| Node.js | `package.json` + `package-lock.json` 또는 `yarn.lock` |
| Python | `requirements.txt` 또는 `pyproject.toml` + `poetry.lock` |
| Go | `go.mod` + `go.sum` |
| Conda | `environment.yml` 또는 `environment.yaml` (최상위 폴더) |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.sln`, `*.slnx`(루트 또는 세 단계 아래 폴더까지), `packages.lock.json`은 선택 |
| Swift | `Package.swift` (+ `Package.resolved`) 또는 `Podfile.lock` |
| Modelica | `annotation(uses(...))` 블록이 있는 `.mo` 파일 |
| Android | Gradle 루트(`settings.gradle[.kts]` 또는 `build.gradle[.kts]`)와 Android Gradle 플러그인 사용 흔적, [Android](#android) 참고 |
| Docker 이미지 | 파일 없음: 이미지 이름이나 이미지 tar를 `--target`으로 지정 |

## 번들 예제 결과

번들 예제를 2026-09-21에 BomLens 1.12.0과 그 이후의 소스 스캔 변경으로 스캔했습니다. 표는 소프트웨어 컴포넌트만 셉니다. 저작권 열은 `copyright`가 채워진 컴포넌트의 비율입니다(위 설명 참고). Ruby, PHP, .NET, Swift, Modelica는 지원하지 않습니다. 적합성 검사의 기본 기준은 PURL 90%, 라이선스 80%입니다.

| 예제 | 컴포넌트 | PURL | 라이선스 | 저작권 |
|------|--------:|-----:|--------:|----------:|
| Node.js | 120 | 100% | 100% | 95% |
| Python | 39 | 100% | 100% | 82% |
| Go | 19 | 100% | 100% | 94% |
| Ruby | 9 | 100% | 100% | 0% |
| PHP | 16 | 100% | 100% | 0% |
| .NET | 70 | 100% | 98% | 0% |
| Rust | 157 | 100% | 99% | 83% |
| Swift | 6 | 83% | 33% | 0% |
| Modelica | 2 | 100% | 100% | 0% |

Java (Maven), Java (Gradle), Docker는 표에 없습니다. Java 스캔은 측정에 쓴 네트워크에서 Maven Central이 아티팩트를 내려주지 않아 측정하지 못했습니다(위 주의 참고). Docker 예제는 이미지를 스캔하는 예제라서 폴더로 스캔하면 아무것도 찾지 못합니다. 이 수치는 작은 예제 프로젝트의 결과이며 실제 프로젝트의 예측값이 아닙니다. 실제 프로젝트의 채움률은 그 프로젝트의 의존성에 따라 달라집니다.

## 결과 비교

언어별로 생성되는 SBOM의 PURL(Package URL) 형식이 다릅니다.

| 언어 | PURL 형식 예시 |
|------|--------------:|
| Java | `pkg:maven/org.springframework.boot/spring-boot@3.2.0` |
| Node.js | `pkg:npm/express@4.18.2` |
| Python | `pkg:pypi/requests@2.31.0` |
| Go | `pkg:golang/github.com/gin-gonic/gin@v1.9.1` |
| Rust | `pkg:cargo/serde@1.0.193` |
| Ruby | `pkg:gem/rails@7.1.2` |
| PHP | `pkg:composer/laravel/laravel@10.3.3` |
| .NET | `pkg:nuget/Newtonsoft.Json@13.0.3` |
| Swift | `pkg:swift/github.com/apple/swift-log@1.5.0` |
| Docker (OS 패키지) | `pkg:deb/debian/curl@7.88.1` |

## 문제 해결

예제를 실행하다 문제가 생기면 [CLI 레퍼런스의 트러블슈팅](cli.ko.md#트러블슈팅)을 참고하세요.

---

> **관련 문서**: [첫 스캔](../start/first-scan.ko.md) | [CLI 레퍼런스](cli.ko.md)
