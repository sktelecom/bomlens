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
├── modelica/        # Modelica (.mo) uses() declarations
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

By default a source scan leaves out the manifests under test, fixture, example, benchmark and demo folders (`test`, `tests`, `spec`, `fixtures`, `testdata`, `__tests__`, `e2e`, `example`, `examples`, `benches`, `benchmarks`, `playground`, `samples`) and the GitHub Actions workflows in `.github/workflows`, because none of them ship with the product. The SBOM records the patterns in the `bomlens:excluded-paths` property and the manifest files it left out in `bomlens:excluded-manifests`. To include them, set `BOMLENS_INCLUDE_NON_SHIPPED=1` ([Docker image environment variables](docker-image.md#environment-variables)).

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

> Note: cdxgen resolves the whole build graph, so BomLens filters the SBOM to the deployable set — compile and runtime scope — and drops the test and provided toolchain (JUnit, Lombok, and the like) so the result reflects what ships rather than the full build. To keep the complete resolved graph instead, set `BOMLENS_MAVEN_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).
> A runtime dependency declared with `<optional>true</optional>` is dropped as well, because cdxgen gives it the same tag as a test-scope one.
> A multi-module reactor can carry modules that never get deployed alongside the ones that do: a demo, or a module the project itself excludes from `mvn deploy` (`maven-deploy-plugin`'s `skip` resolving to `true`, however it is set). Such a module's own component is left out. A dependency only that module needs is left out too, but only when no deployed module in the same reactor declares it at any scope (a deployed module's own `provided` or `test` declaration of it, not just a `compile`/`runtime` one, is enough to keep it, since the SBOM's dependency graph does not record which scope each edge represents). `BOMLENS_MAVEN_FULL_GRAPH=1` keeps everything this leaves out. The excluded modules and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-modules` and `bomlens:excluded-components`.

> Note: cdxgen reads a Maven component's license from its own `pom.xml` only, so one that declares no `<licenses>` and relies on Maven's own inheritance from a parent POM comes through with none. BomLens now walks that parent chain itself (the reactor's own modules, then the local repository for a parent outside it) and fills the license from the first ancestor that declares one, leaving the component untouched if none do or if it already carries a license. The filled component is recorded with a `bomlens:licenseSource` property set to `parent POM`.

---

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

Detected file: `build.gradle` or `build.gradle.kts`

---

## Android

Detected when the project has a Gradle root (`settings.gradle[.kts]` or `build.gradle[.kts]` at the root) and shows a sign of the Android Gradle plugin: the plugin id in the version catalog (`gradle/libs.versions.toml`), the plugin id or a catalog alias in a build script (root or `app/`), a Kotlin DSL `namespace` declaration, or an `AndroidManifest.xml` a few levels down. A manifest with no Gradle root does not count on its own, which also keeps a .NET MAUI app's `Platforms/Android/AndroidManifest.xml` from being misread as an Android project.

Android needs an SDK platform image BomLens does not publish: the Android SDK it contains is not open source, and Google's terms do not allow redistributing it, so the image is built locally instead. The project's `compileSdk`/`compileSdkVersion` picks the API level (34 if none is found); the scan then looks for `bomlens-android-sdk<API>:latest`, and if it is missing, prints the build command instead of failing on a missing image:

```bash
docker build --build-arg ANDROID_API=<API> -t bomlens-android-sdk<API> docker/android
```

Building it means accepting Google's SDK terms yourself. Set `ANDROID_IMAGE_PREFIX` to use an image built elsewhere.

> Note: images published under `ghcr.io/sktelecom/bomlens-android-sdk<API>` up to v1.9.0 still work for scans on that release line, but nothing new is pushed to them; a current scan needs a locally built image.

---

## Node.js

```bash
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only
```

Detected file: `package.json` + `package-lock.json` (or `yarn.lock`, `pnpm-lock.yaml`)

> Note: a lock file pins the exact installed versions. Dependencies are still captured from `package.json` without one, but committing a lock file makes the result reproducible.

> Note: the SBOM is filtered to the production dependency set, so devDependencies are dropped and the result reflects what ships. To keep the full dev-plus-production graph instead, set `BOMLENS_NODE_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).

> Note: an npm workspace member registered in `package-lock.json` survives the file-level exclusion above even when its own directory sits under an excluded tree, because cdxgen reads `package-lock.json` directly. Such a member's own component is left out too, along with a dependency only that member needs, unless a kept member reaches it as well. `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch as the file-level exclusion above) keeps everything this leaves out. The excluded members and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-members` and `bomlens:excluded-components`. A yarn workspace member is not caught the same way yet.

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

> Note: cdxgen already tags each composer component with its resolved scope (`require` becomes required, `require-dev` becomes optional), so BomLens filters the SBOM to the required set, the same way it does for Maven. To keep the full require-plus-require-dev graph instead, set `BOMLENS_PHP_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

Detected file: `Cargo.lock`

> Note: a Cargo workspace member registered in `Cargo.lock` survives the file-level exclusion above even when its own directory sits under an excluded tree, because cdxgen reads `Cargo.lock` directly. Such a member's own component is left out too, along with a dependency only that member needs, unless a kept member reaches it as well (any way at all). `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch as the file-level exclusion above) keeps everything this leaves out. The excluded members and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-members` and `bomlens:excluded-components`.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

Detected files: `*.csproj`, `*.fsproj`, `*.sln` or `*.slnx`, at the root or in folders up to three levels below it, plus `packages.lock.json`

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

## Modelica

```bash
./scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --target examples/modelica --generate-only
```

Detected files: `*.mo`

cdxgen has no Modelica cataloger, so the usual package-manager approach reads no dependencies. Instead, BomLens parses the `annotation(uses(...))` block a `.mo` package declares directly, picking up each library named there together with its version.

```modelica
annotation(uses(Modelica(version="4.0.0"), Buildings(version="13.0.0")));
```

> Note: only the libraries declared directly in `uses()` are identified. Modelica has no lockfile, so transitive dependencies are not resolved, and the model's own internal structure (its components, parameters, connections) is not open-source dependency data, so it is left out.

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
| .NET | `*.csproj`, `*.fsproj`, `*.sln` or `*.slnx` (root or up to three folders down) + `packages.lock.json` |

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
