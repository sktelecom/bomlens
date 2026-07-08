---
description: Try BomLens hands-on with per-language example projects (Java, Python, Node.js, and more), see the file needed for detection, and compare the SBOM output across languages.
---

# Supported ecosystems

A hands-on guide using the per-language example projects under `examples/`. Run each example to see the SBOM output right away.

## Example directory structure

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
└── docker/          # Docker image analysis
```

## Common run steps

Every source-code example runs the same way from the repository root: point `--target` at the example folder and pick a project name. The results are saved in a `{Project}_{Version}/` subfolder. For the Node.js example:

<!-- runnable -->
```bash
# 1. Generate the SBOM (from the repository root)
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only

# 2. Check the result
jq '.components | length' NodeExample_1.0.0/NodeExample_1.0.0_bom.json
```

The sections below give the ready-to-paste command for each language.

---

## Java (Maven)

```bash
./scripts/scan-sbom.sh --project "JavaMavenExample" --version "1.0.0" --target examples/java-maven --generate-only
```

Detected file: `pom.xml`

```xml
<!-- example pom.xml -->
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
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

Detected file: `build.gradle` or `build.gradle.kts`

---

## Node.js

```bash
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only
```

Detected file: `package.json` + `package-lock.json` (or `yarn.lock`, `pnpm-lock.yaml`)

> Note: a lock file pins the exact installed versions. Dependencies are still captured from `package.json` without one, but committing a lock file makes the result reproducible.

---

## Python

```bash
./scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --target examples/python --generate-only
```

Detected file: `requirements.txt`, or `pyproject.toml` + `poetry.lock`

---

## Go

```bash
./scripts/scan-sbom.sh --project "GoExample" --version "1.0.0" --target examples/go --generate-only
```

Detected file: `go.mod` + `go.sum`

> Note: `go.sum` is required for accurate version hashes. Run `go mod tidy` first, then try again.

---

## Ruby

```bash
./scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --target examples/ruby --generate-only
```

Detected file: `Gemfile.lock`

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

Detected file: `composer.lock`

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

Detected file: `Cargo.lock`

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

Detected file: `*.csproj` + `packages.lock.json`

---

## Swift / iOS

```bash
./scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --target examples/swift --generate-only
```

Detected files: `Package.swift` (+ `Package.resolved`) for Swift Package Manager, or `Podfile.lock` for CocoaPods.

Dependencies are read from the committed lockfiles, so include them in the scan:

- Swift Package Manager: `Package.resolved` (run `swift package resolve` first if it is missing).
- CocoaPods: `Podfile.lock` (produced by `pod install`). BomLens parses it directly, so the scanning machine needs neither macOS nor a CocoaPods install.

> Note: UIKit and other Xcode-driven platform dependencies require macOS and are not resolved in the Linux scanner.

---

## Docker image analysis

Run Docker image analysis from the project root.

```bash
# Analyze a public image
./scripts/scan-sbom.sh \
  --project "NginxSBOM" \
  --version "1.25" \
  --target "nginx:1.25-alpine" \
  --generate-only

# Ubuntu-based image
./scripts/scan-sbom.sh \
  --project "UbuntuSBOM" \
  --version "22.04" \
  --target "ubuntu:22.04" \
  --generate-only
```

---

## Files required for detection

If source analysis finds no dependencies, check for the lock file below.

| Language | Required file |
|----------|---------------|
| Java (Maven) | `pom.xml` |
| Java (Gradle) | `build.gradle` or `build.gradle.kts` |
| Node.js | `package.json` + `package-lock.json` or `yarn.lock` |
| Python | `requirements.txt` or `pyproject.toml` + `poetry.lock` |
| Go | `go.mod` + `go.sum` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj` + `packages.lock.json` |

## Comparing results

The PURL (Package URL) format in the generated SBOM differs by language.

| Language | PURL example |
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
| Docker (OS packages) | `pkg:deb/debian/curl@7.88.1` |

## Troubleshooting

If you run into trouble running an example, see [the troubleshooting section of the CLI reference](cli.md#troubleshooting).

---

> **Related**: [First scan](../start/first-scan.md) | [CLI reference](cli.md)
