---
description: Java, Python, Node.js 등 언어별 예제 프로젝트로 BomLens의 SBOM 생성을 직접 실습하고 언어별 결과를 비교합니다.
---

# 예제 가이드

> **관련 문서**: [시작하기](getting-started.md) | [사용 가이드](usage-guide.md)

`examples/` 디렉토리의 언어별 예제 프로젝트로 직접 실습해 보는 가이드입니다. 각 예제를 실행하면 SBOM 출력 결과를 바로 확인할 수 있습니다.

## 예제 디렉토리 구조

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
└── docker/          # Docker 이미지 분석
```

## 공통 실행 방법

모든 소스 코드 예제는 동일한 방식으로 실행합니다.

```bash
# 1. 예제 디렉토리로 이동
cd examples/{언어}

# 2. SBOM 생성
../../scripts/scan-sbom.sh \
  --project "{언어}Example" \
  --version "1.0.0" \
  --generate-only

# 3. 결과 확인
python3 -m json.tool *_bom.json | head -60
# jq 사용 시
jq '.components | length' *_bom.json
```

---

## Java (Maven)

```bash
cd examples/java-maven
../../scripts/scan-sbom.sh --project "JavaMavenExample" --version "1.0.0" --generate-only
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

---

## Java (Gradle)

```bash
cd examples/java-gradle
../../scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --generate-only
```

감지 파일: `build.gradle` 또는 `build.gradle.kts`

---

## Node.js

```bash
cd examples/nodejs
../../scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --generate-only
```

감지 파일: `package.json` + `package-lock.json` (또는 `yarn.lock`, `pnpm-lock.yaml`)

> 주의: 잠금 파일이 없으면 의존성이 불완전하게 잡힙니다. `npm install`을 먼저 실행한 뒤 시도하세요.

---

## Python

```bash
cd examples/python
../../scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --generate-only
```

감지 파일: `requirements.txt` 또는 `pyproject.toml` + `poetry.lock`

---

## Go

```bash
cd examples/go
../../scripts/scan-sbom.sh --project "GoExample" --version "1.0.0" --generate-only
```

감지 파일: `go.mod` + `go.sum`

> 주의: `go.sum`이 있어야 정확한 버전 해시가 들어갑니다. `go mod tidy`를 먼저 실행한 뒤 시도하세요.

---

## Ruby

```bash
cd examples/ruby
../../scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --generate-only
```

감지 파일: `Gemfile.lock`

---

## PHP

```bash
cd examples/php
../../scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --generate-only
```

감지 파일: `composer.lock`

---

## Rust

```bash
cd examples/rust
../../scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --generate-only
```

감지 파일: `Cargo.lock`

---

## .NET

```bash
cd examples/dotnet
../../scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --generate-only
```

감지 파일: `*.csproj` + `packages.lock.json`

---

## Swift

```bash
cd examples/swift
../../scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --generate-only
```

감지 파일: `Package.swift` (+ `Package.resolved`)

> 주의: `Package.resolved`가 있어야 의존성이 정확히 잡힙니다. `swift package resolve`를 먼저 실행한 뒤 시도하세요.

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

예제를 실행하다 문제가 생기면 [사용 가이드의 트러블슈팅](usage-guide.md#트러블슈팅)을 참고하세요.
