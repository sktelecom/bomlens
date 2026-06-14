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

Every source-code example runs the same way.

```bash
# 1. Move into the example directory
cd examples/{language}

# 2. Generate the SBOM
../../scripts/scan-sbom.sh \
  --project "{language}Example" \
  --version "1.0.0" \
  --generate-only

# 3. Check the result
python3 -m json.tool *_bom.json | head -60
# with jq
jq '.components | length' *_bom.json
```

---

## Java (Maven)

```bash
cd examples/java-maven
../../scripts/scan-sbom.sh --project "JavaMavenExample" --version "1.0.0" --generate-only
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
cd examples/java-gradle
../../scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --generate-only
```

Detected file: `build.gradle` or `build.gradle.kts`

---

## Node.js

```bash
cd examples/nodejs
../../scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --generate-only
```

Detected file: `package.json` + `package-lock.json` (or `yarn.lock`, `pnpm-lock.yaml`)

> Note: without a lock file, dependencies are captured incompletely. Run `npm install` first, then try again.

---

## Python

```bash
cd examples/python
../../scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --generate-only
```

Detected file: `requirements.txt`, or `pyproject.toml` + `poetry.lock`

---

## Go

```bash
cd examples/go
../../scripts/scan-sbom.sh --project "GoExample" --version "1.0.0" --generate-only
```

Detected file: `go.mod` + `go.sum`

> Note: `go.sum` is required for accurate version hashes. Run `go mod tidy` first, then try again.

---

## Ruby

```bash
cd examples/ruby
../../scripts/scan-sbom.sh --project "RubyExample" --version "1.0.0" --generate-only
```

Detected file: `Gemfile.lock`

---

## PHP

```bash
cd examples/php
../../scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --generate-only
```

Detected file: `composer.lock`

---

## Rust

```bash
cd examples/rust
../../scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --generate-only
```

Detected file: `Cargo.lock`

---

## .NET

```bash
cd examples/dotnet
../../scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --generate-only
```

Detected file: `*.csproj` + `packages.lock.json`

---

## Swift

```bash
cd examples/swift
../../scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --generate-only
```

Detected file: `Package.swift` (+ `Package.resolved`)

> Note: `Package.resolved` is required for dependencies to be captured accurately. Run `swift package resolve` first, then try again.

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
