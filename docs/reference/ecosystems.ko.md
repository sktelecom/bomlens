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

---

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

감지 파일: `build.gradle` 또는 `build.gradle.kts`

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

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

감지 파일: `composer.lock`

> 주의: cdxgen은 이미 각 composer 컴포넌트에 해석된 스코프를 붙여서 줍니다(`require`는 required, `require-dev`는 optional). BomLens는 Maven과 같은 방식으로 이 정보를 이용해 SBOM을 required 대상으로 걸러냅니다. require와 require-dev를 합친 전체 그래프를 그대로 두려면 `BOMLENS_PHP_FULL_GRAPH=1`을 설정하세요([Docker 이미지 환경 변수](docker-image.ko.md#환경-변수)).

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

감지 파일: `Cargo.lock`

> 주의: Cargo 워크스페이스 멤버가 `Cargo.lock`에 등록돼 있으면, 그 멤버의 디렉터리가 제외 대상 트리 아래에 있어도 위의 파일 단위 제외로는 빠지지 않습니다. cdxgen이 `Cargo.lock`을 직접 읽기 때문입니다. 이런 멤버 자신의 컴포넌트는 빠지고, 그 멤버만 필요로 하는 의존성도 함께 빠집니다. 다만 유지되는 멤버가 그 의존성을 어떤 식으로든 필요로 하면 남습니다. `BOMLENS_INCLUDE_NON_SHIPPED=1`(위 파일 단위 제외와 같은 스위치)로 이렇게 빠지는 것을 모두 그대로 둘 수 있습니다. 제외한 멤버와 그 때문에 빠진 컴포넌트는 SBOM에 각각 `bomlens:excluded-members`, `bomlens:excluded-components`로 기록됩니다.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

감지 파일: 루트나 그 아래 세 단계 폴더까지의 `*.csproj`, `*.fsproj`, `*.sln`, `*.slnx`와 `packages.lock.json`

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

---

## Modelica

```bash
./scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --target examples/modelica --generate-only
```

감지 파일: `*.mo`

cdxgen에는 Modelica 카탈로거가 없어 일반적인 패키지 관리자 방식으로는 의존성을 읽지 못합니다. 대신 `.mo` 패키지 자신이 선언하는 `annotation(uses(...))` 블록을 직접 파싱해서, 그 안에 이름과 버전이 함께 적힌 라이브러리를 컴포넌트로 편입합니다.

```modelica
annotation(uses(Modelica(version="4.0.0"), Buildings(version="13.0.0")));
```

> 주의: `uses()`에 직접 선언된 라이브러리만 식별됩니다. Modelica 생태계에는 잠금 파일이 없어 전이 의존성은 해석하지 않으며, 파일 안에 정의된 모델 자체의 구조(컴포넌트, 파라미터, 연결)는 오픈소스 의존성이 아니므로 다루지 않습니다.

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
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.sln`, `*.slnx`(루트 또는 세 단계 아래 폴더까지) + `packages.lock.json` |

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
