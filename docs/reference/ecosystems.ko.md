---
description: Java, Python, Node.js 등 언어별 예제 프로젝트로 BomLens의 SBOM 생성을 직접 실습하고, 감지에 필요한 파일과 언어별 결과를 비교합니다.
---

# 지원 생태계

`examples/` 디렉터리의 언어별 예제 프로젝트로 직접 실습해 보는 가이드입니다. 각 예제를 실행하면 SBOM 출력 결과를 바로 확인할 수 있습니다.

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

소스 스캔은 기본으로 테스트, 테스트 데이터, 예제, 벤치마크, 데모 폴더(`test`, `tests`, `spec`, `fixtures`, `testdata`, `__tests__`, `e2e`, `example`, `examples`, `benches`, `benchmarks`, `playground`, `samples`) 아래의 매니페스트와 `.github/workflows`의 GitHub Actions 워크플로를 제외합니다. 모두 제품과 함께 배포되지 않기 때문입니다. SBOM에는 적용한 패턴이 `bomlens:excluded-paths` 속성에, 제외한 매니페스트 파일이 `bomlens:excluded-manifests` 속성에 기록됩니다. 포함하려면 `BOMLENS_INCLUDE_NON_SHIPPED=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

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

> 주의: 의존성과 라이선스를 해석하려면 컨테이너가 Maven Central(또는 사내 미러)에 접속할 수 있어야 합니다. 접속하지 못하면 `pom.xml`에 적힌 의존성만 담기고 전이 의존성과 라이선스는 비며, 스캔은 경고 없이 끝납니다. 컴포넌트 수가 예상보다 훨씬 적으면 네트워크 접속부터 확인하세요.

---

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

감지 파일: `build.gradle` 또는 `build.gradle.kts`

> 주의: Maven과 마찬가지로 해석하려면 컨테이너가 Maven Central(또는 사내 미러)에 접속할 수 있어야 합니다. 접속하지 못하면 직접 의존성만 담기고 라이선스가 빌 수 있습니다. 컴포넌트 수가 예상보다 훨씬 적으면 네트워크 접속부터 확인하세요.

---

## Android

Gradle 루트(`settings.gradle[.kts]` 또는 `build.gradle[.kts]`가 루트에 있음)가 있고, Android Gradle 플러그인의 흔적이 함께 있을 때 감지합니다. 버전 카탈로그(`gradle/libs.versions.toml`)의 플러그인 id, 빌드 스크립트(루트 또는 `app/`)의 플러그인 id나 카탈로그 별칭, Kotlin DSL `namespace` 선언, 또는 몇 단계 아래의 `AndroidManifest.xml` 중 하나면 됩니다. Gradle 루트 없이 매니페스트만 있으면 인정하지 않는데, 이 덕분에 .NET MAUI 앱의 `Platforms/Android/AndroidManifest.xml`을 Android 프로젝트로 잘못 읽지 않습니다.

Android는 BomLens가 배포하지 않는 SDK 플랫폼 이미지가 필요합니다. 담긴 Android SDK 자체가 오픈소스가 아니고 구글 약관이 재배포를 허용하지 않아서, 이 이미지는 쓰는 쪽에서 직접 빌드해야 합니다. 프로젝트의 `compileSdk`/`compileSdkVersion`으로 API 레벨을 정하고(못 찾으면 34), `bomlens-android-sdk<API>:latest`를 찾습니다. 이미지가 없으면 이미지 없음으로 실패하는 대신 빌드 명령을 그대로 출력합니다.

```bash
docker build --build-arg ANDROID_API=<API> -t bomlens-android-sdk<API> docker/android
```

빌드한다는 것은 구글 SDK 약관에 직접 동의한다는 뜻입니다. 다른 곳에서 빌드한 이미지를 쓰려면 `ANDROID_IMAGE_PREFIX`를 설정하세요.

> 참고: v1.9.0까지 배포됐던 `ghcr.io/sktelecom/bomlens-android-sdk<API>` 이미지는 그 릴리스 라인 스캔에는 여전히 쓸 수 있지만, 더는 새로 올라가지 않습니다. 지금 스캔하려면 직접 빌드한 이미지가 필요합니다.

---

## Node.js

```bash
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only
```

감지 파일: `package.json` + `package-lock.json` (또는 `yarn.lock`, `pnpm-lock.yaml`)

> 주의: 잠금 파일은 실제로 설치된 버전을 정확히 고정합니다. 잠금 파일이 없어도 `package.json`에서 의존성을 찾아내지만, 잠금 파일을 커밋해 두면 결과가 재현 가능해집니다.

> 주의: SBOM은 production 의존성 집합으로 걸러지므로 devDependencies는 덜어내고 실제 배포되는 구성을 반영합니다. dev와 production을 합친 전체 그래프를 그대로 두려면 `BOMLENS_NODE_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

> 주의: npm 워크스페이스 멤버가 `package-lock.json`에 등록돼 있으면, 그 멤버의 디렉터리가 제외 대상 트리 아래에 있어도 위의 파일 단위 제외로는 빠지지 않습니다. cdxgen이 `package-lock.json`을 직접 읽기 때문입니다. 이런 멤버 자신의 컴포넌트는 빠지고, 그 멤버만 필요로 하는 의존성도 함께 빠집니다. 다만 유지되는 멤버가 그 의존성을 필요로 하면 남습니다. `BOMLENS_INCLUDE_NON_SHIPPED=1`(위 파일 단위 제외와 같은 스위치)로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 멤버와 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-members`, `bomlens:excluded-components`로 기록됩니다. yarn 워크스페이스 멤버는 아직 같은 방식으로 잡히지 않습니다.

---

## Python

```bash
./scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --target examples/python --generate-only
```

감지 파일: `requirements.txt` 또는 `pyproject.toml` + `poetry.lock`

> 주의: 버전을 `==`로 고정하거나 `poetry.lock` 같은 잠금 파일을 커밋하세요. 그렇지 않으면 SBOM에는 실제로 쓰는 버전이 아니라 스캔 시점에 받을 수 있는 버전이 담깁니다. 번들 예제는 버전을 고정해 두었고 모든 컴포넌트에 라이선스가 있습니다.

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

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

감지 파일: `composer.lock`

> 주의: `composer.lock`이 커밋돼 있지 않으면 BomLens가 스캔 전에 직접 해석합니다(`composer update --no-dev`, `require-dev`와 `config.lock`을 뺀 `composer.json` 사본으로, 플랫폼 요구사항은 무시합니다). Ruby의 `Gemfile.lock`을 처리하는 방식과 같습니다. 스캔이 끝나면 원래 `composer.json`을 되돌려 놓습니다. PHP 버전을 강제하지 않으므로, 프로젝트가 선언한 것보다 새로운 PHP를 요구하는 의존성 버전이 선택될 수 있습니다. cdxgen은 이미 각 composer 컴포넌트에 해석된 스코프를 붙여서 줍니다(`require`는 required, `require-dev`는 optional). BomLens는 Maven과 같은 방식으로 이 정보를 이용해 SBOM을 required 대상으로 걸러냅니다. require와 require-dev를 합친 전체 그래프를 그대로 두려면 `BOMLENS_PHP_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

감지 파일: `Cargo.lock`

> 주의: cdxgen은 라이선스 정보가 없는 `Cargo.lock`만 읽으므로, BomLens는 각 크레이트 자신의 매니페스트를 읽는 `cargo metadata`로 라이선스를 채웁니다(스캔 대상 자신의 워크스페이스 크레이트 포함). 이를 위해 컨테이너가 크레이트 저장소(crates.io 또는 사내 미러)에 닿아야 합니다. 닿지 않으면 SBOM에 라이선스가 기록되는 Cargo 패키지가 거의 없고 스캔으로 만든 고지문이 거의 빕니다. 이때 스캔은 `cargo-license-metadata` 단계를 SBOM에 실패로 기록하며 결과 화면과 적합성 보고서가 이를 보여 주고, 로그에는 `could not read crate licenses`가 남습니다. 라이선스를 파일로만 선언한 크레이트(`license-file`)는 채우지 못합니다. `MIT OR Apache-2.0` 같은 택일 표기는 고정된 순서로 적어, 크레이트가 어떻게 쓰든 같은 조합이 고지문에서 한 항목이 되게 하고, SPDX 표현식이 아닌 값은 라이선스 이름 그대로 둡니다. 번들 예제는 라이브러리 147개 중 146개에 라이선스가 있습니다. `BOMLENS_NO_CARGO_LICENSE=1`로 끌 수 있고, 명령줄에서는 `FETCH_LICENSE=false`도 같은 효과가 있습니다. `--deep-license`는 도움이 되지 않습니다. 이 옵션은 의존성이 아니라 스캔 대상 자신의 소스 파일을 훑고 별도 보고서를 씁니다.

> 주의: Cargo 워크스페이스 멤버가 `Cargo.lock`에 등록돼 있으면, 그 멤버의 디렉터리가 제외 대상 트리 아래에 있어도 위의 파일 단위 제외로는 빠지지 않습니다. cdxgen이 `Cargo.lock`을 직접 읽기 때문입니다. 이런 멤버 자신의 컴포넌트는 빠지고, 그 멤버만 필요로 하는 의존성도 함께 빠집니다. 다만 유지되는 멤버가 그 의존성을 어떤 식으로든 필요로 하면 남습니다. `BOMLENS_INCLUDE_NON_SHIPPED=1`(위 파일 단위 제외와 같은 스위치)로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 멤버와 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-members`, `bomlens:excluded-components`로 기록됩니다.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

감지 파일: 루트나 그 아래 세 단계 폴더까지의 `*.csproj`, `*.fsproj`, `*.sln`, `*.slnx`. `packages.lock.json`은 있으면 읽습니다

> 주의: 감지에는 프로젝트 또는 솔루션 파일이 필요합니다. `packages.lock.json`은 필수는 아니지만, 커밋해 두면(`dotnet restore --use-lock-file`) 해석된 버전이 고정되어 SBOM을 재현할 수 있습니다.

---

## Swift / iOS

```bash
./scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --target examples/swift --generate-only
```

감지 파일: Swift Package Manager는 `Package.swift` (+ `Package.resolved`), CocoaPods는 `Podfile.lock`.

의존성은 커밋된 잠금 파일에서 읽으므로 스캔에 함께 포함하세요.

- Swift Package Manager: `Package.resolved` (없으면 `swift package resolve`를 먼저 실행).
- CocoaPods: `Podfile.lock` (`pod install`로 생성). BomLens가 이 파일을 직접 파싱하므로 스캔 장비에 macOS나 CocoaPods 설치가 필요 없습니다.

> 주의: UIKit 등 Xcode가 관리하는 플랫폼 의존성은 macOS가 필요하며 Linux 스캐너에서는 해석되지 않습니다.

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

cdxgen에는 Conda 카탈로거가 없어 BomLens가 환경 파일의 `dependencies:` 목록을 직접 읽습니다. conda 항목은 `pkg:conda/...` 컴포넌트가 되고, `pip:` 항목 아래에 적힌 패키지는 `pkg:pypi/...` 컴포넌트가 됩니다.

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
