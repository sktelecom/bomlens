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

For npm, Python (pip), Go and Rust (Cargo) packages, a source scan also fills each component's `copyright` from the license files the installed package ships (`LICENSE`, `LICENCE`, `COPYING`, `NOTICE`, `COPYRIGHT`), so the NOTICE can print an attribution line. Only a line that begins with `Copyright` followed directly by `(c)`, the copyright sign, a year or `by` (or with `(c)` or the sign followed by a year), and that names a holder, is used. A notice with no year, such as `Copyright Acme, Inc.`, is not taken. Lines come from the package's own folder only (its `.dist-info` folder for Python; for Go the folder `go list` reports, which is the module cache, the replacement's folder for a `replace`d module, or `vendor/`; for Rust the folder `cargo metadata` reports, which is the cargo registry, a git checkout or a path dependency), at most 6 files, the first 64 KiB and 400 lines of each, and at most 5 statements per component, joined with `; `. Lines that are an unfilled template (`<year>`, `[fullname]`) or the text of a license itself (for example the Free Software Foundation's own line in a GNU license) are skipped, and so are files that link outside the package. A component that already has a copyright is not changed, a package with no such line stays empty, and each value set carries the property `bomlens:copyrightSource`. Set `BOMLENS_NO_COPYRIGHT=1` to turn this off. Java (Maven) is not covered: Maven downloads jar files rather than source folders, so the license files of a dependency are not on disk to read. A `replace`d Go module carries the statement of the code that is actually built, which can be a different version from the one the component names. The scanned project's own Go module and Rust workspace crates are not filled. The Rust step reads the crate sources that are already on disk and never goes to the network for them, so with `FETCH_LICENSE=false` or `--byte-stable` a crate that was not downloaded stays empty. A Go or Rust component whose folder is not on disk, for example because the download failed, stays empty. When no folder of an ecosystem could be listed at all, the SBOM records it in the `bomlens:copyrightUnread` metadata property (`golang`, `cargo`), so that a missing copyright can be told from a step that did not run.

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

> Note: dependency and license resolution need the container to reach Maven Central, or your mirror. When it cannot, the result holds only the dependencies written in `pom.xml`, with no transitive dependencies and no licenses, and the scan finishes without a warning. If the component count is far below what you expect, check network access first.

---

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

Detected file: `build.gradle` or `build.gradle.kts`

> Note: as with Maven, resolution needs the container to reach Maven Central, or your mirror. When it cannot, the result can hold only the direct dependencies, with no licenses. If the component count is far below what you expect, check network access first.

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

> Note: pin versions with `==` or commit a lock file such as `poetry.lock`. Without them the SBOM lists the versions available at scan time, not the ones you run. The bundled example pins its versions, and every component carries a license.

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

> Note: with no `Gemfile.lock` committed, BomLens runs `bundle lock` before scanning. Commit the lock file so the SBOM matches what you deploy.

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

Detected file: `composer.lock`

> Note: with no `composer.lock` committed, BomLens resolves one itself (`composer update --no-dev`, on a copy of `composer.json` without `require-dev` and `config.lock`, with platform requirements ignored) before scanning, the same as it does for Ruby's `Gemfile.lock`. Your `composer.json` is put back afterwards. A dependency version that needs a newer PHP than the project declares can be picked, because the PHP version is not enforced. cdxgen already tags each composer component with its resolved scope (`require` becomes required, `require-dev` becomes optional), so BomLens filters the SBOM to the required set, the same way it does for Maven. To keep the full require-plus-require-dev graph instead, set `BOMLENS_PHP_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

Detected file: `Cargo.lock`

> Note: cdxgen reads only `Cargo.lock`, which carries no licenses, so BomLens fills them from `cargo metadata`, which reads each crate's own manifest (your own workspace crates included). The container needs a route to the crate registry (crates.io or your mirror) for this. Without one, the SBOM records a license for almost no Cargo packages and the notice file built from the scan is nearly empty. The scan then records the step `cargo-license-metadata` as failed on the SBOM, which the result screen and the conformance report show, and the log says `could not read crate licenses`. A crate that declares its license only as a file (`license-file`) stays without one. Alternatives such as `MIT OR Apache-2.0` are written in a fixed order, so the same pair is one entry in the notice however a crate spells it, and a value that is not an SPDX expression is kept as a plain license name. The bundled example lists 147 libraries and 146 of them carry a license. `BOMLENS_NO_CARGO_LICENSE=1` turns this off, and so does `FETCH_LICENSE=false` on the command line. `--deep-license` does not help here: it scans your own source files, not the dependencies, and writes a separate report.

> Note: a Cargo workspace member registered in `Cargo.lock` survives the file-level exclusion above even when its own directory sits under an excluded tree, because cdxgen reads `Cargo.lock` directly. Such a member's own component is left out too, along with a dependency only that member needs, unless a kept member reaches it as well (any way at all). `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch as the file-level exclusion above) keeps everything this leaves out. The excluded members and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-members` and `bomlens:excluded-components`.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

Detected files: `*.csproj`, `*.fsproj`, `*.sln` or `*.slnx`, at the root or in folders up to three levels below it. `packages.lock.json` is read when present

> Note: detection needs a project or solution file. `packages.lock.json` is not required, but committing one (`dotnet restore --use-lock-file`) pins the resolved versions so the SBOM is reproducible.

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

> Note: the bundled example lists 6 components, of which 5 carry a PURL (83%) and 2 a license (33%). Both are below the default thresholds of the conformance checks: the PURL check fails and the license check warns. The two resolved packages (`swift-argument-parser`, `swift-log`) have a PURL and a license. The rest are the package itself and the platform modules it imports (`Foundation`, `XCTest`, `dispatch`), which have no license to declare. BomLens drops the versionless duplicates of a resolved package that the import scan adds, so a package is counted once.

---

## Modelica

```bash
./scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --target examples/modelica --generate-only
```

Detected files: `*.mo`

cdxgen has no Modelica cataloger, so the usual package-manager approach reads no dependencies. Instead, BomLens parses the `annotation(uses(...))` block a `.mo` package declares directly, picking up each library named there together with its version. A `uses()` declaration carries only a name and a version, so a license comes from BomLens's own table of known libraries (`docker/lib/modelica-library-map.json`), not from your project. The table records the license read from each library's upstream license file (Modelica Standard Library 3.2.3 and later: `BSD-3-Clause`; Buildings 13.0.0 and later: `BSD-3-Clause-LBNL`). Both libraries in the bundled example get a license this way (2 of 2), recorded with the property `bomlens:licenseSource` = `modelica-library-map`. A library outside the table, or a version older than the recorded one, has no license.

```modelica
annotation(uses(Modelica(version="4.0.0"), Buildings(version="13.0.0")));
```

> Note: only the libraries declared directly in `uses()` are identified. Modelica has no lockfile, so transitive dependencies are not resolved, and the model's own internal structure (its components, parameters, connections) is not open-source dependency data, so it is left out.

---

## Conda

```bash
./scripts/scan-sbom.sh --project "CondaExample" --version "1.0.0" --target . --generate-only
```

Detected files: `environment.yml` or `environment.yaml` at the root of the scanned folder.

cdxgen has no Conda cataloger, so BomLens reads the `dependencies:` list of the environment file itself. Each conda entry becomes a `pkg:conda/...` component, and each entry under a `pip:` item becomes a `pkg:pypi/...` component.

```yaml
dependencies:
  - python=3.11
  - numpy=1.26.4
  - pip:
    - requests==2.31.0
```

When the file is read successfully, BomLens turns off cdxgen's Python step for that scan. Otherwise a `setup.py` or `requirements.txt` elsewhere in the tree would replace the environment file as the source of truth.

> Note: only the two-level layout shown above is recognized, with `dependencies:` at the left edge, entries indented by two spaces and `pip:` items by four. A file that uses another layout (a different indent width, a flow-style list, a tab) is not partly read. It is skipped as a whole and cdxgen's Python step runs as before. An entry with no version or only a range such as `>=1.0` does not name a version, so it is recorded without a version or PURL and carries the property `bomlens:versionUnpinned`. Editable and VCS installs under `pip:` are left out.

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

> Note: `--target` takes an image name or an image tar here. Pointing it at the `examples/docker` folder, which holds no dependency manifest, finds no components.

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
| Conda | `environment.yml` or `environment.yaml` (root folder) |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.sln` or `*.slnx` (root or up to three folders down); `packages.lock.json` is optional |
| Swift | `Package.swift` (+ `Package.resolved`) or `Podfile.lock` |
| Modelica | a `.mo` file with an `annotation(uses(...))` block |
| Android | a Gradle root (`settings.gradle[.kts]` or `build.gradle[.kts]`) plus a sign of the Android Gradle plugin, see [Android](#android) |
| Docker image | no file: pass an image name or an image tar as `--target` |

## Results on the bundled examples

The bundled examples were scanned on 2026-09-21 with BomLens 1.12.0 and the source-scan changes made after it. The table counts software components only. The Copyright column is the share of components whose `copyright` is filled (see above); Ruby, PHP, .NET, Swift and Modelica are not covered. The default conformance thresholds are 90% for PURL and 80% for license.

| Example | Components | PURL | License | Copyright |
|---------|-----------:|-----:|--------:|----------:|
| Node.js | 120 | 100% | 100% | 95% |
| Python | 39 | 100% | 100% | 82% |
| Go | 19 | 100% | 100% | 94% |
| Ruby | 9 | 100% | 100% | 0% |
| PHP | 16 | 100% | 100% | 0% |
| .NET | 70 | 100% | 98% | 0% |
| Rust | 157 | 100% | 99% | 83% |
| Swift | 6 | 83% | 33% | 0% |
| Modelica | 2 | 100% | 100% | 0% |

Java (Maven), Java (Gradle) and Docker are not in the table. The Java scans could not be measured on the network used, where Maven Central did not serve artifacts (see the notes above). The Docker example is an image-scan example and finds nothing when scanned as a folder. These are results on small example projects, not a forecast for yours: a real project's coverage depends on its own dependencies.

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
