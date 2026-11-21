---
description: Try BomLens hands-on with per-language example projects (Java, Python, Node.js, and more), see the file needed for detection, and compare the SBOM output across languages.
---

# Supported ecosystems

A hands-on guide using the per-language example projects under `examples/`. Run each example to see the SBOM output right away.

How BomLens runs each ecosystem's build tool, and how it narrows the result to what ships, is explained in [How dependencies are resolved](../concepts/dependency-resolution.md).

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

By default a source scan leaves out the manifests under test, fixture, example, benchmark and demo folders (`test`, `tests`, `spec`, `fixtures`, `testdata`, `__tests__`, `e2e`, `example`, `examples`, `sample`, `samples`, `bench`, `benches`, `benchmark`, `benchmarks`, `demo`, `demos`, `playground`), the GitHub Actions workflows in `.github/workflows` and the Gradle wrapper in `gradle/wrapper` (its `gradle-wrapper.jar`), because none of them ship with the product. The SBOM records the patterns in the `bomlens:excluded-paths` property and the files it left out in `bomlens:excluded-manifests`. To include them, set `BOMLENS_INCLUDE_NON_SHIPPED=1` ([Docker image environment variables](docker-image.md#environment-variables)).

An installed Python virtual environment is always left out of what a source scan reads as the project: every top-level folder that holds a `pyvenv.cfg` (`.venv/`, `venv/` or another name) stays out of cdxgen's search, the syft fallback and the static read of a lock file, also with `BOMLENS_INCLUDE_NON_SHIPPED=1` and with `BOMLENS_PYTHON_VENV=false`. The packages installed there are not the project's own manifests, and with no network cdxgen would wait on the package index for each of them. Its pattern (`.venv/**`) is recorded in `bomlens:excluded-paths`, and its files are not listed in `bomlens:excluded-manifests`. BomLens can still read the environment itself when the package index cannot be used (see [Python](#python)). A virtual environment deeper in the tree, or one whose name holds a character other than letters, digits, `.`, `_` and `-` (a space or a glob character, for example), is not left out.

A source scan also drops the development-only components that cdxgen marks: npm, pnpm, yarn and bun development packages, uv and Poetry dependency groups other than `main`, Cargo dev-dependencies, and sbt, Crystal and Gleam development dependencies. For Ruby, BomLens reads the `Gemfile` groups itself (see [Ruby](#ruby)). When cdxgen gives a component the same marker more than once, the component counts as development-only only if every value is a development one. A marked component, and a dependency that only marked components reach, is dropped only when nothing else in the dependency graph reaches it: every unmarked component keeps what it depends on, including a component the root does not reach, and a workspace member keeps its own dependencies, so the dev-dependencies of a Cargo workspace member crate and the dependency groups of a uv workspace member stay. npm development packages are the exception: cdxgen 13.5.0 sets that marker over the whole workspace, so a package that carries it is one no member's production dependencies reach, and it is dropped even when a member lists it. The SBOM records the dropped components in the `bomlens:excluded-components` property. To keep them, set `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1` ([Docker image environment variables](docker-image.md#environment-variables)). The language sections below say what this means for each ecosystem.

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

> Note: dependency and license resolution need the container to reach Maven Central, or your mirror. When it cannot, the result holds only the dependencies written in `pom.xml`, with no transitive dependencies and no licenses, and the scan finishes without a warning. The test, provided, system and `<optional>true</optional>` ones among them are left out, as in a full resolution; `BOMLENS_MAVEN_FULL_GRAPH=1` keeps them. If the component count is far below what you expect, check network access first.

> Note: a project you built on this machine resolves from your own Maven local repository. The CLI, `--ui` and the desktop app mount it read-only at `/bomlens-settings/m2/repository`: the `<localRepository>` in `~/.m2/settings.xml` (outside XML comments, with `${user.home}` replaced by your home folder), else `~/.m2/repository`. It is not mounted when the folder does not exist, when the `<localRepository>` value uses another property or is a relative path, or when the path holds `"`, `$`, a backtick or a backslash. For a tree with a `pom.xml`, the scan gives it to Maven as `-Dmaven.repo.local.tail`, so Maven reads it after BomLens's own repository and downloads nothing into it, and to cdxgen as `MAVEN_CACHE_DIR`, so POMs, licenses and jar hashes are found there too; the parent POM license step and the jar count look there as well. Maven 3.9 and later read this property, and an older Maven ignores it. An empty mount usually means the Docker engine does not share that folder, and the scan logs that it does not read it. Before resolving, the scan asks the repository Maven would download from (the first `<mirror>` URL in `settings.xml`, else Maven Central) once, with a 5-second limit, through an active `<proxy>` in `settings.xml` or the proxy variables and with the container's CA trust. Only when it cannot be reached (the name does not resolve, the connection is refused or unreachable, or no answer comes in time) does Maven run offline (`-o`), with one log line that names the host. Any HTTP answer, an error status included, and a certificate error count as reachable. `<offline>true</offline>` in `settings.xml` or a `-o` already given skips the question. The SBOM records `bomlens:maven-user-repository` (`read-only`) and `bomlens:maven-offline` (`probe`, `settings` or `false`). A Maven wrapper (`mvnw`) older than 3.9 does not read the user repository, and offline it cannot download its own Maven distribution, since only `~/.m2/repository` is mounted, not `~/.m2/wrapper`. So offline, when `.mvn/wrapper/maven-wrapper.properties` names a Maven older than 3.9, the image's `mvn` runs in place of `mvnw`, for cdxgen too (`MVN_CMD` with `CDXGEN_JVM_TOOL_PINNED=true`), and the log says why. When the tree also has a Gradle build, cdxgen keeps the wrappers (telling it to skip `mvnw` would also skip the Gradle wrappers), and `maven-dependency-tree` is recorded as failed. Offline, cdxgen's `dependency:tree` needs `maven-dependency-plugin` in your Maven local repository or BomLens's Maven cache, together with Maven's plugin prefix data (an `org/apache/maven/plugins/maven-metadata-*.xml` that names the prefix `dependency`). A repository filled only by `mvn package` lacks the plugin, and one filled by a Maven older than 3.9 lacks the prefix data; then the log says which (run `mvn dependency:tree` once in the project on this machine, with Maven 3.9 or later), the jar fetch is skipped and `maven-dependency-tree` is recorded as failed. It is recorded the same way when none of the jars Maven resolved offline is in either repository, since the dependency tree is then missing too. Only the first `<mirror>` is asked. `BOMLENS_MAVEN_USER_REPOSITORY=false` leaves the folder out ([CLI reference](cli.md)).

> Note: Maven 3.10 and later refuse a `pom.xml` that declares the same dependency twice (`'dependencies.dependency.(groupId:artifactId:type:classifier)' must be unique`, or the same for `dependencyManagement`), where Maven 3.9 only warns, and the cdxgen images ship Maven 3.10. A project with a Maven wrapper (`mvnw` and `.mvn/wrapper/`) is always read with that wrapper, so a wrapper that names a Maven before 3.10 accepts the POM. When BomLens still sees this error before cdxgen runs, it retries with Apache Maven 3.9.16. That Maven is fetched through the image's Maven, so the mirror, proxy and offline settings of your `settings.xml` apply, or from Maven Central when that fails and Maven is not offline. The archive is used only when it matches the SHA-512 checksum built into BomLens. cdxgen then builds the dependency tree with it. A project whose own `mvnw` runs Maven 3.10 or later is an exception when the tree also holds a Gradle build: cdxgen would then have to skip the Gradle wrappers as well to use Maven 3.9.16, so BomLens leaves the wrappers alone, prints a warning and records the step as failed. When no Maven reads the POM, the result holds only the dependencies written in `pom.xml` (without the test, provided, system and optional ones), the failed step `maven-dependency-tree` is recorded, and `generate` reads `degraded`. Removing the repeated `<dependency>` entries fixes this for every Maven version.

---

> Note: a folder that holds both `pom.xml` and `build.gradle` (or `build.gradle.kts`) at its root is read as a Gradle project by default, as before. Use `--build-tool maven` to read only `pom.xml` (the Gradle files are left out of the scan and no Gradle step runs), or `--build-tool gradle` to read only the Gradle files. The scan prints which tool it reads, and the SBOM records it in `bomlens:build-tool-choice` with the reason in `bomlens:build-tool-choice-why`. The two tools can resolve different dependency sets for the same project, so compare the counts before choosing. A folder with one build tool, or a `pom.xml` only in a subfolder, is not affected.

> Note: a private repository or mirror works through your own Maven settings. `~/.m2/settings.xml` and `~/.m2/settings-security.xml` are passed into the scan read-only when they exist (at `/bomlens-settings/m2` inside the container), and the same goes for the Gradle files `~/.gradle/gradle.properties`, `init.gradle`, `init.gradle.kts` and `init.d/`. The CLI, `--ui` and the desktop app do this; the double-click `sbom-ui.bat` does not. A mirror address has to be reachable from inside a container. A proxy that re-signs HTTPS needs `SBOM_EXTRA_CA_CERTS`. See [How do I scan a Java project that builds with Maven?](../guides/java-maven.md).

## Java (Gradle)

```bash
./scripts/scan-sbom.sh --project "JavaGradleExample" --version "1.0.0" --target examples/java-gradle --generate-only
```

Detected file: `build.gradle` or `build.gradle.kts`

> Note: as with Maven, resolution needs the container to reach Maven Central, or your mirror. When it cannot, the result can hold only the direct dependencies, with no licenses. If the component count is far below what you expect, check network access first. Gradle still exits successfully when it cannot resolve a dependency (its report marks the entry `FAILED`), so the scan counts those entries itself: it logs `Gradle could not resolve N dependency entries` and records the `gradle-dependencies` step as failed (`bomlens:pipeline-step-failed`), which makes the result completeness partial.

> Note: a project you built on this machine resolves from your own Gradle cache. The CLI, `--ui` and the desktop app mount the folder that holds `modules-2` (`caches` under `GRADLE_USER_HOME`, else `~/.gradle/caches`) read-only, and the scan gives it to Gradle as its read-only dependency cache (`GRADLE_RO_DEP_CACHE`); cdxgen reads jars and their hashes from it too. Before the first Gradle run the scan asks each repository the build names (a `url` or `maven("...")` in the build, settings and init scripts, and `mavenCentral()`, `google()` and the plugin portal), with a 5-second limit. When one answers, Gradle runs as it always does. When none does, Gradle runs `--offline` and resolves only from the caches. The SBOM records which (`bomlens:gradle-user-cache`, `online` or `offline`). Gradle reads the metadata of the cache layout its own version writes (`modules-2/metadata-2.NNN`), so the cache helps fully when the scan runs the same Gradle that filled it, as the project's own wrapper does. Offline, a wrapper whose distribution is not in BomLens's Gradle cache is copied from your `wrapper/dists`, which is mounted read-only as well; with no copy there, the image's Gradle (8.14.5) runs instead and says so in a `[WARN]` line. Measured on `examples/java-gradle` with no network: 13 components, the same as online, both from a cache that Gradle 9.8.2 filled and Gradle 8.14.5 read and from a cache that the project's 8.9 wrapper filled and read. A cache from Gradle 9.8.2 read by an 8.9 wrapper gave the 4 direct dependencies and a failed step. `BOMLENS_GRADLE_USER_CACHE=false` leaves both folders out ([CLI reference](cli.md)).

> Note: the SBOM lists what the `runtimeClasspath` of each project resolves, so a dependency only on the compile classpath (`compileOnly`, `annotationProcessor`, or a library's compile-only annotations such as Guava's `j2objc-annotations`) or only on a test classpath (JUnit, Mockito) is left out. The full graph stays when the build includes other builds for their code (`includeBuild`; a build included only through `pluginManagement` does not count), when a runtime classpath cannot be resolved, or when the Gradle run fails; `BOMLENS_GRADLE_FULL_GRAPH=1` keeps it ([Docker image environment variables](docker-image.md#environment-variables)). The limits are in [Keeping only what ships](../concepts/dependency-resolution.md#keeping-only-what-ships).

> Note: cdxgen is pointed at the Gradle cache of the scan (`GRADLE_CACHE_DIR`), which the CLI keeps between scans. A component whose jar is already in it gets MD5, SHA-1, SHA-256 and SHA-512 hashes, and its license is read from the POMs there when Maven Central cannot be reached. A component whose files are not in the cache has neither, so hashes and licenses vary with the cache's content, as they do for Maven. Hashing took about 0.16 s per jar on a loaded machine (60 s for 369 jars, 354 MB).

Each cdxgen Java image has one JDK, and two things in a Gradle build decide which one it needs. A toolchain asks for that exact JDK version. A Gradle wrapper (`gradlew` with `gradle/wrapper/gradle-wrapper.properties`) runs only on the JDKs its Gradle version supports; a 6.9.4 wrapper, for example, fails on Java 21 with "Unsupported class file major version 65". The scan reads both:

- the toolchain from `JavaLanguageVersion.of(N)` (as `languageVersion = ...` or `languageVersion.set(...)`) or Kotlin `jvmToolchain(N)`, in the `*.gradle` and `*.gradle.kts` files of the scanned folder and up to five folders below it, `buildSrc` and convention plugins included. The highest version counts. The argument can also be a variable defined in the same file, optionally converted with `.toInteger()`, `.toInt()`, `.toString()` or `as int`. Its value is the Gradle property it reads (`hasProperty`, `getProperty`, `findProperty`, `property`, `providers.gradleProperty("p")`, `properties["p"]`, or Kotlin `val p: String by project`) from the nearest `gradle.properties`, else the default it gives (after `?:` or the ternary's `:`, or in `getOrElse("N")`), else the number it is set to. Only regular `gradle.properties` files are read, and a definition outside any block counts before one inside a block.
- the wrapper's Gradle version from the file name at the end of `distributionUrl`, in Gradle's own form `gradle-X.Y[.Z]-bin.zip` or `-all.zip` (a milestone, release candidate or snapshot counts as its release). A wrapper counts only where `gradlew` sits beside it; without one the image's own Gradle 8.14.5 runs. Which wrappers count depends on the scanned folder:
    - with `gradlew`, its own wrapper alone. When its version cannot be read (a custom file name, for example), the scan says so in an `[INFO]` line and chooses by the toolchain alone.
    - with a Gradle settings or build file and no `gradlew`, none: the image's Gradle runs there, once.
    - with neither, the wrapper of every build below it that has `gradlew` beside a settings or build file, up to five folders down. `buildSrc`, `build-logic`, dot folders and the builds another build names in `includeBuild(...)` are skipped. The image must run every one of them; when no image does, the scan picks for the lowest version and says so in a `[WARN]` line.

Comments and the non-shipped folders listed above are skipped (`BOMLENS_INCLUDE_NON_SHIPPED=1` reads those folders too). The images and the Gradle versions that run on their JDK, from [Gradle's compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html):

| Image | JDK | Wrapper versions that run on it |
|---|---|---|
| `cdxgen-temurin-java8` | 8 | below 9.0 |
| `cdxgen-java11` | 11 | 5.0 to 8.14.x |
| `cdxgen-java17` | 17 | 7.3 and later |
| `cdxgen-temurin-java21` | 21 | 8.5 and later |
| `cdxgen-temurin-java24` | 24 | 8.14 and later |
| `cdxgen-temurin-java25` | 25 | 9.1.0 and later |

The scan takes the toolchain's image when the wrapper runs on it. Otherwise it takes `cdxgen-temurin-java21` when the wrapper runs on Java 21, and the newest image the wrapper runs on when it does not (Java 17 for a 7.3 to 8.4 wrapper, 11 for 5.0 to 7.2, 8 below 5.0). With no toolchain and no wrapper it stays on `cdxgen-temurin-java21`. A choice other than Java 21 prints an `[INFO]` line that says why.

A `[WARN]` says when the build cannot get what it asks for: a toolchain no image has (22, 23, 26 and so on), or one the wrapper cannot run on (a Java 25 toolchain with an 8.14 wrapper). Gradle then cannot find the toolchain's JDK, and dependency resolution can fail unless the build configures toolchain auto-provisioning. A mixed-language tree runs in the all-in-one image whatever the toolchain, and warns the same way for a toolchain other than 21. A version from a version catalog, from a variable of another file or from a longer expression is not read. When Gradle then fails because no JDK matches the toolchain, and an image has that JDK and runs the wrapper, the dependency step runs once more in that image (`[INFO] Gradle asked for Java N; rerunning in <image>`). An image that is not here is pulled with its progress shown, and `SBOM_PULL=always` pulls it first. If that run leaves no SBOM, the first result is kept. There is no rerun when `CDXGEN_JAVA_IMAGE` is set, or when the image is not here and cannot be pulled (`SBOM_PULL=never` does not pull). The execution plan (`MODE=PLAN`) does not rerun. When the build still cannot get its JDK, set `CDXGEN_JAVA_IMAGE` to an image that has the JDK ([CLI reference](cli.md)). Maven needs no such choice: `maven.compiler.release` and the toolchains plugin apply when the build compiles, and dependency resolution runs without them.

---

## Android

Detected when the project has a Gradle root (`settings.gradle[.kts]` or `build.gradle[.kts]` at the root) and shows a sign of the Android Gradle plugin: the plugin id in the version catalog (`gradle/libs.versions.toml`), the plugin id or a catalog alias in a build script (root or `app/`), a Kotlin DSL `namespace` declaration, or an `AndroidManifest.xml` a few levels down. A manifest with no Gradle root does not count on its own, which also keeps a .NET MAUI app's `Platforms/Android/AndroidManifest.xml` from being misread as an Android project.

Android needs an SDK platform image BomLens does not publish: the Android SDK it contains is not open source, and Google's terms do not allow redistributing it, so the image is built locally instead. The highest `compileSdk`/`compileSdkVersion` found picks the API level (34 if none is found). It is read from the root and `app/` build files, from the sources under `build-logic/` and `buildSrc/` (a convention plugin often sets it there), and from the version catalog (a key such as `android-compileSdk`); the scan then looks for `bomlens-android-sdk<API>:latest`, and if it is missing, the scan stops before it starts and prints the build command:

```bash
docker build --build-arg ANDROID_API=<API> -t bomlens-android-sdk<API> docker/android
```

Building it means accepting Google's SDK terms yourself. Set `ANDROID_IMAGE_PREFIX` to use an image built elsewhere. The image takes about 6.3 GB on disk, one per API level ([sizes](docker-image.md#how-much-disk-do-the-images-take)). A step-by-step page is [How do I scan an Android app that builds with Gradle?](../guides/android-gradle.md).

The SDK image runs Java 21, so a Gradle wrapper older than 8.5 cannot run in it. The scan says so before it starts and records the failed step `gradle-wrapper-jdk` on the SBOM. Raise `distributionUrl` in `gradle/wrapper/gradle-wrapper.properties` to 8.5 or later, or build the image on an older JDK with `--build-arg BASE_JDK_IMAGE=<cdxgen Java image>` (see `docker/android/Dockerfile`) and scan with that image's `ANDROID_IMAGE_PREFIX`. A build that turns Isolated Projects on in `gradle.properties` is read with the configuration cache on, since Gradle refuses to run it with the cache off.

Where the Gradle build cannot run at all (no Docker, or the build failed), the fallback reads the libraries a version catalog (`gradle/*.versions.toml`) declares and adds them with `bomlens:source=version-catalog`. They are declarations, not what the build uses, so the result stays graded partial.

> Note: images published under `ghcr.io/sktelecom/bomlens-android-sdk<API>` up to v1.9.0 still work for scans on that release line, but nothing new is pushed to them; a current scan needs a locally built image.

---

## Node.js

```bash
./scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --target examples/nodejs --generate-only
```

Detected file: `package.json` + `package-lock.json` (or `yarn.lock`, `pnpm-lock.yaml`)

> Note: a lock file pins the exact installed versions. Dependencies are still captured from `package.json` without one, but committing a lock file makes the result reproducible.

> Note: a project installed on this machine with no lock file committed is read from the lock file npm or pnpm wrote at install, so the full dependency graph resolves without the registry. For each folder with a `package.json` and no lock file of its own or in a folder above it (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`), BomLens uses `node_modules/.package-lock.json` (npm 7 or later) or `node_modules/.pnpm/lock.yaml` (pnpm) as that folder's lock file. The npm lock must be lockfile version 2 or 3 and name every package in the `dependencies` of `package.json`; BomLens adds the root entry from `package.json` and writes a `package-lock.json` for this scan, and reads the production set from it without running npm. The pnpm lock is copied as `pnpm-lock.yaml` after BomLens checks that its importer lists the declared dependencies. When both exist, the one written last is used. The written file is removed when the scan ends, also with `BOMLENS_KEEP_BUILD_OUTPUT=1`. The log names each lock that is not read: one that lacks a declared dependency (`package.json` changed after the install; run the install again or commit the lock file), the lock of an npm workspace root, and a pnpm lock with more than one importer. A workspace lock that is not read is also recorded as the failed step `npm-installed-lock` or `pnpm-installed-lock` in `bomlens:pipeline-step-failed`, so the result is partial (reason `resolution-failed`) and the dependency graph is `incomplete`: commit the lock file and scan again. Such a lock records only what was installed on that machine, so the optional packages for other platforms (the per-platform builds of esbuild or rollup, for example) are not in it, unlike a committed lock. What yarn and bun leave in `node_modules` is not read. With no lock file at all, the scan first asks the npm registry npm is configured with (`npm config get registry`), with a short time limit; when it does not answer, the production set is not resolved, the log says that dependency relations are not available, and `npm-production-set` is recorded in `bomlens:pipeline-step-failed` (not in `bomlens:prep-step-applied`). A lock file written at install does not make the tree static: `--detection auto` still builds, and the build reads it with no network. The SBOM records each lock read as `bomlens:node-lock-source` and the step `npm-installed-lock` or `pnpm-installed-lock` ([SBOM artifacts](artifacts.md#sbom-structure)). `BOMLENS_NODE_INSTALLED_LOCK=false` (or `0`) turns it off.

> Note: the SBOM is filtered to the production dependency set, so devDependencies are dropped and the result reflects what ships. To keep the full dev-plus-production graph instead, set `BOMLENS_NODE_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).

> Note: an npm workspace member registered in `package-lock.json` survives the file-level exclusion above even when its own directory sits under an excluded tree, because cdxgen reads `package-lock.json` directly. Such a member's own component is left out too, along with a dependency only that member needs, unless a kept member reaches it as well. `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch as the file-level exclusion above) keeps everything this leaves out. The excluded members and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-members` and `bomlens:excluded-components`. A yarn workspace member is not caught the same way yet.

> Note: on top of the production filter, a component cdxgen marks as a development package (npm, pnpm, yarn or bun) is dropped when no production dependency path reaches it, together with what only it reaches. This also covers a pnpm workspace, which the production filter does not read. A package a production dependency also uses stays. `BOMLENS_NODE_FULL_GRAPH=1` or `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1` keeps these too.

> Note: with no lock file at all (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` or `bun.lock`), one dependency npm cannot fetch (a private `git+https` URL, a package missing from the registry, a version that does not exist) no longer empties the result. BomLens resolves again without that dependency, up to five times, and records each one left out as a failed step `npm-excluded:NAME`, so the result reads `partial` and names it. Fix access to that dependency, or commit a `package-lock.json`, for a complete result.

---

## Python

```bash
./scripts/scan-sbom.sh --project "PythonExample" --version "1.0.0" --target examples/python --generate-only
```

Detected file: `requirements.txt`, or `pyproject.toml` + `poetry.lock`

> Note: a Poetry project without `poetry.lock` is scanned from the exact pins in `[tool.poetry.dependencies]` (`requests = "2.31.0"`); ranges such as `^2.0` and path or git entries are left out. The pins are linked from the project and come with their own dependencies; when some entries were left out, or the dependencies could not be resolved (no network), the SBOM declares its dependency graph incomplete. Pin versions with `==` or commit a lock file such as `poetry.lock`. Without them the SBOM lists the versions available at scan time, not the ones you run. The bundled example pins its versions, and every component carries a license.

> Note: with uv (`uv.lock`) or Poetry, a component cdxgen places only in dependency groups other than `main`, such as `dev` or `test`, is dropped when no production dependency path reaches it, together with what only it reaches. A package the production dependencies also use stays, and so does a package that any `pyproject.toml` in the project names in its `[project]` `dependencies` or `optional-dependencies` or in `[tool.poetry.dependencies]`, even when a dependency group lists it too. BomLens reads these files with a small reader of its own: when the scan root has no `pyproject.toml`, or a file uses a form the reader does not follow (for example `dynamic = ["dependencies"]`), no Python package is dropped and the build log says so. The same happens when a `requirements*.txt`, `setup.py`, `setup.cfg` or `Pipfile` is in the project outside `vendor` and the folders a source scan leaves out by default (see above), since it may declare production dependencies the reader does not see. The search goes 8 folders deep and skips `vendor`, `node_modules`, `.git` and virtual environments (`.venv`, `venv`); a deeper folder outside those and the non-shipped folders also means no Python package is dropped.

> Note: `uv.lock` is read (cdxgen 13.5.0 lists its packages). A project that has no runtime dependencies, with `uv.lock` listing only packages from dependency groups such as `dev` or `tests`, therefore ends with no component. The scan then reports the result as partial with the reason `only-excluded-dependencies`, not as resolved and not as complete: the result is correct when the product has no runtime dependencies. The packages that were left out are in the SBOM property `bomlens:excluded-components`, and `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1` lists them.

> Note: a project whose virtual environment you installed on this machine resolves even when the scan cannot use the package index. When the scanned folder has `.venv/`, `venv/` or one other top-level folder with a `pyvenv.cfg`, and its `site-packages` holds `*.dist-info` folders, the scan first asks the package index pip would use for an answer, with a short time limit: an `-i` or `--index-url` in `requirements.txt`, else `PIP_INDEX_URL` or `index-url` in a pip configuration file inside the scan container, else `https://pypi.org/simple/`. When the index does not answer (reason `index-unreachable`), or `pip install` fails (reason `pip-install-failed`), the Python part of the SBOM comes from the metadata of the installed packages, with their dependency graph and licenses, and cdxgen's Python step is left out. The environment is only read: nothing in it is run and nothing is written there. A scan that reaches the index is unchanged. When the scan root also has a complete lock file (`poetry.lock`, `uv.lock`, `pdm.lock` or `Pipfile.lock`), the lock file is read and the environment is not, and the build log says so.
>
> The packages listed start from the declared dependencies: the requirements files (`requirements*.txt`, `requirements-dev.txt` included, outside the folders a source scan leaves out), `[project].dependencies` and the Poetry main dependencies in `pyproject.toml`, and `install_requires` in `setup.cfg`. Poetry, uv and other dependency groups count only with `BOMLENS_INCLUDE_DEV_DEPENDENCIES=1`. From there the scan follows each package's `Requires-Dist`, so a tool installed beside them that nothing declares, such as pytest, is left out. Environment markers (`; python_version < "3.11"`) are evaluated for the environment's Python version (from `pyvenv.cfg`) and platform (from the tags of the installed wheels); a requirement whose marker cannot be decided is kept and counted as unsure. Licenses come from each package's `License-Expression`, else its `License` field, else its license classifiers.
>
> The SBOM records the folder in `bomlens:python-environment` (relative to the scan root), the reason in `bomlens:python-environment-reason` and the step `python-environment` in `bomlens:prep-step-applied`. When something could not be settled (a marker that could not be decided, a declared package that is not installed, an installed version that differs from a declared pin, two installed versions of one package, or an environment that also uses the system `site-packages`), `bomlens:python-environment-unsure` says what, and the result is partial with the reason `installed-environment-unsure`: the SBOM may list a dependency the product does not use, or miss one. Install the dependencies again on the platform you ship, or let the scan reach the package index, and scan again to remove the reason. Set `BOMLENS_PYTHON_VENV=false` (or `0`) to turn this off.
>
> A project with a conda `environment.yml` is not read this way: the environment file is read instead (see [Conda](#conda)). A project that declares its dependencies only in `setup.py` gives the scan nothing to start from, so its environment is not used. A lock file (`poetry.lock`, `uv.lock`, `pdm.lock`) next to the environment is not compared with it: when the environment is read, the Python part comes from the environment alone.

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

> Note: cdxgen does not mark Bundler groups, so BomLens reads the `Gemfile` at the scan root itself. A gem declared only in the `development` and `test` groups (in a `group ... do` block or with a `group:` or `groups:` option) is dropped, along with what only those gems need, unless a production gem also needs it. The `Gemfile` is read conservatively: a condition, `gemspec`, `eval_gemfile`, a declaration over several lines or any other line the reader does not recognise, or a `Gemfile.lock` that names a gem the `Gemfile` does not, leaves every gem in place, and the log says `Gemfile groups not read`. So does another `Gemfile` or `Gemfile.lock` below the scan root, or a `.gemspec` file anywhere in the project, since it may declare the same gems for production. That search goes 8 folders deep and skips `vendor` (with the installed gems in `vendor/bundle`), `node_modules`, `.git`, `.venv` and `venv`; a deeper folder outside those also leaves every gem in place.

> Note: a gem declared only in a group marked `optional: true` (`group :avo, optional: true do`) stays in the SBOM with `scope` `optional`, because Bundler installs such a group only when asked. Gems only in the `development` and `test` groups are dropped as before.

---

## PHP

```bash
./scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --target examples/php --generate-only
```

Detected file: `composer.lock`

> Note: with no `composer.lock` committed, BomLens resolves one itself (`composer update --no-dev`, on a copy of `composer.json` without `require-dev` and `config.lock`, with platform requirements ignored) before scanning, the same as it does for Ruby's `Gemfile.lock`. Your `composer.json` is put back afterwards. A dependency version that needs a newer PHP than the project declares can be picked, because the PHP version is not enforced. cdxgen already tags each composer component with its resolved scope (`require` becomes required, `require-dev` becomes optional), so BomLens filters the SBOM to the required set, the same way it does for Maven. To keep the full require-plus-require-dev graph instead, set `BOMLENS_PHP_FULL_GRAPH=1` ([Docker image environment variables](docker-image.md#environment-variables)).

> Note: a `package-lock.json` inside `vendor/` (for example a framework's error page) is left out of the scan, so its npm packages do not appear as dependencies of the project.

---

## Rust

```bash
./scripts/scan-sbom.sh --project "RustExample" --version "1.0.0" --target examples/rust --generate-only
```

Detected file: `Cargo.lock`

> Note: cdxgen reads only `Cargo.lock`, which carries no licenses, so BomLens fills them from `cargo metadata`, which reads each crate's own manifest (your own workspace crates included). The container needs a route to the crate registry (crates.io or your mirror) for this. Without one, the SBOM records a license for almost no Cargo packages and the notice file built from the scan is nearly empty. The scan then records the step `cargo-license-metadata` as failed on the SBOM, which the result screen and the conformance check report show, and the log says `could not read crate licenses`. A crate that declares its license only as a file (`license-file`) stays without one. Alternatives such as `MIT OR Apache-2.0` are written in a fixed order, so the same pair is one entry in the notice however a crate spells it, and a value that is not an SPDX expression is kept as a plain license name. The bundled example lists 147 libraries and 146 of them carry a license. `BOMLENS_NO_CARGO_LICENSE=1` turns this off, and so does `FETCH_LICENSE=false` on the command line. `--deep-license` does not help here: it scans your own source files, not the dependencies, and writes a separate report.

> Note: a Cargo workspace member registered in `Cargo.lock` survives the file-level exclusion above even when its own directory sits under an excluded tree, because cdxgen reads `Cargo.lock` directly. Such a member's own component is left out too, along with a dependency only that member needs, unless a kept member reaches it as well (any way at all). `BOMLENS_INCLUDE_NON_SHIPPED=1` (the same switch as the file-level exclusion above) keeps everything this leaves out. The excluded members and the components dropped because of them are recorded on the SBOM as `bomlens:excluded-members` and `bomlens:excluded-components`.

> Note: a crate cdxgen marks only as a dev-dependency (`[dev-dependencies]`) is dropped when no production dependency path reaches it, together with what only it reaches. A crate the production dependencies also use stays, and so does one listed in both `[dependencies]` and `[dev-dependencies]`. cdxgen sets this marker with or without a committed `Cargo.lock`, since BomLens resolves one when it is missing. In a workspace, the dev-dependencies of a member crate stay, because what a member depends on is kept whatever its marker; only the dev-dependencies of the root package can be dropped.

---

## .NET

```bash
./scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --target examples/dotnet --generate-only
```

Detected files: `*.csproj`, `*.fsproj`, `*.sln` or `*.slnx`, at the root or in folders up to three levels below it. `packages.lock.json` is read when present

> Note: detection needs a project or solution file. `packages.lock.json` is not required, but committing one (`dotnet restore --use-lock-file`) pins the resolved versions so the SBOM is reproducible.

> Note: .NET Framework base assemblies read from `packages.config` or a `Reference` entry (`System`, `System.Core`, `System.Data` and similar) are dropped when they carry no version, since they ship with the framework and are not NuGet packages. A `System.*` package with a version stays.

---

## Swift / iOS

```bash
./scripts/scan-sbom.sh --project "SwiftExample" --version "1.0.0" --target examples/swift --generate-only
```

Detected files: `Package.swift` (+ `Package.resolved`) for Swift Package Manager, or `Podfile.lock` for CocoaPods.

A step-by-step page is [How do I scan an iOS app that uses SwiftPM or CocoaPods?](../guides/ios-swift.md).

Dependencies are read from the committed lockfiles, so include them in the scan:

- Swift Package Manager: `Package.resolved` (run `swift package resolve` first if it is missing).
- CocoaPods: `Podfile.lock` (produced by `pod install`). BomLens parses it directly, so the scanning machine needs neither macOS nor a CocoaPods install.

> Note: UIKit and other Xcode-driven platform dependencies require macOS and are not resolved in the Linux scanner.

> Note: a folder with no manifest at its top level but an Xcode project (`*.xcodeproj`), `Package.swift`, `Podfile` or `Package.resolved` up to three folders down, for example `App/App.xcodeproj`, is scanned as Swift. A tree that has a root manifest of another language keeps that language. The Swift resolver steps and the `cdxgen` run stop after `BOMLENS_PREP_TIMEOUT` seconds (900 by default) and git is told not to ask for a login, so a dependency clone that cannot finish ends the step instead of holding the scan.

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

cdxgen has no Conda cataloger, so BomLens reads the `dependencies:` list of the environment file itself, in a scan from the CLI, the web UI, the desktop app or an execution plan. Each conda entry becomes a `pkg:conda/...` component, and each entry under a `pip:` item becomes a `pkg:pypi/...` component.

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
