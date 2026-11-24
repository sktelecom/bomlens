---
description: Scan an Android app that builds with Gradle. What to prepare (Docker memory, the Android SDK image), what the first scan downloads, and how to read the result.
---

# How do I scan an Android app that builds with Gradle?

An Android project needs one thing a plain Java project does not: an Android SDK image that BomLens builds on your computer once. Google's SDK terms do not allow BomLens to publish it, so you accept the terms and the image is built locally. After that, scans run like any other source scan.

## What to prepare

- A Docker engine with about 4 GB of memory. A Gradle build runs inside the scan, and with less memory the build can be killed and the result falls back to direct dependencies only. The [requirements](../start/first-scan.md#requirements) say how to raise it.
- The project folder with its Gradle root (`settings.gradle[.kts]` or `build.gradle[.kts]`). If the project has a Gradle wrapper, `gradle/wrapper/gradle-wrapper.properties` must name Gradle 8.5 or later, because the SDK image runs Java 21.
- Disk space. The SDK image takes about 6.3 GB, and each `compileSdk` level is a separate image, so two apps on different levels take about 12.6 GB. The scanner image adds about 1.4 GB. [Disk use and cleanup](../reference/docker-image.md#how-much-disk-do-the-images-take) lists every image.

## How do I scan it?

In the desktop app or the web UI, add the project folder and run the scan. When the SDK image is missing, a dialog explains why and links Google's terms. In the desktop app and the Windows launcher `sbom-ui.bat`, the dialog builds the image once if you accept. The web UI started with `scan-sbom.sh --ui` or with `docker run` cannot build it, so the dialog shows the `docker build` command to run yourself: it builds from the `docker/android` folder of your clone when there is one, and otherwise reads the recipe from GitHub at your release's tag, or at `main` when your copy does not report a release. Once the image is there, start the scan again from the New scan form.

On the command line, a scan with no SDK image stops before it starts and prints the `docker build` command, with the API level filled in. Run that command once, which means you accept [Google's SDK terms](https://developer.android.com/studio/terms), then scan again:

```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target ./my-android-app --generate-only
```

The build recipe is `docker/android/Dockerfile`, which the CLI download and a clone of the repository both contain.

## What if my network inspects HTTPS?

Building the SDK image downloads the Android command-line tools and platform from `dl.google.com`. A proxy that inspects HTTPS re-signs that traffic with a company CA, and the build does not trust it. `SBOM_EXTRA_CA_CERTS` does not help here: it applies to the scan containers, not to `docker build`. The build then stops with `curl: (60) SSL certificate problem`, or with `[build] ERROR: sdk-install: Android platform ... was not installed` and a `PKIX path building failed` line from `sdkmanager`. The dialog of the desktop app and `sbom-ui.bat` runs the same recipe, so it fails the same way. Build the image by hand with the CA in it:

1. Copy the recipe folder and put your company CA, as a PEM file named `company-ca.pem`, next to the Dockerfile:

   ```bash
   cp -R docker/android my-android-sdk && cp /path/to/company-ca.pem my-android-sdk/
   ```

2. In `my-android-sdk/Dockerfile`, add these lines after the first `RUN` (the one that checks for `unzip` and `curl`) and before the `RUN mkdir -p "$ANDROID_HOME/cmdline-tools"` line. The base image is Red Hat Enterprise Linux 9, so the system store is updated with `update-ca-trust` and the Java store with `keytool`:

   ```dockerfile
   COPY company-ca.pem /tmp/company-ca.pem
   RUN cp /tmp/company-ca.pem /etc/pki/ca-trust/source/anchors/company-ca.pem \
       && update-ca-trust extract \
       && keytool -importcert -noprompt -trustcacerts -alias company-ca -file /tmp/company-ca.pem -cacerts -storepass changeit
   ```

3. Run the `docker build` command the scan printed, with `my-android-sdk` as the folder instead of `docker/android`. Running it means you accept [Google's SDK terms](https://developer.android.com/studio/terms).

The scan itself still needs the CA for the Gradle build, which downloads dependencies: set `SBOM_EXTRA_CA_CERTS` as described in [How do I trust my company CA?](company-network.md#how-do-i-trust-my-company-ca).

## Does my private repository work?

Dependencies from a company repository need the credentials your own Gradle build uses. BomLens passes `~/.gradle/gradle.properties`, `~/.gradle/init.gradle`, `~/.gradle/init.gradle.kts` and the `~/.gradle/init.d` folder into the scan, read-only, when they exist. Put the repository address and credentials there, as you would for a local build. [How do I scan a Maven project](java-maven.md#does-my-private-repository-work) lists where each tool reads its settings from and what to check when a dependency stays unresolved.

## What does the result contain?

The SBOM lists what the release runtime classpath resolves, so libraries used only for tests are not in it. When the Gradle build cannot run at all, BomLens falls back to the libraries the version catalog declares. Those are declarations, not what the build uses, so the result is graded partial. The completeness grade is in `{Project}_{Version}_completeness.json` and on the Overview screen, and a partial grade names its reasons.

## What if the Gradle build fails?

When Gradle stops before it reads the release runtime classpath, the app's dependencies are not known. The SBOM then leaves out what the build's other configurations resolve, because those are build and test tooling (the Unified Test Platform, `ddmlib`, AndroidX test libraries), not what the app ships. The result is graded unreliable, and the reason quotes the error Gradle reported. The scan log shows Gradle's `What went wrong` text first, before its last lines.

A common cause is a project without `android.useAndroidX=true`. Android Studio writes that line into `gradle.properties` for a new project, so a copy of the project without that file fails with `contains AndroidX dependencies, but the android.useAndroidX property is not enabled`. Add the line to `gradle.properties` in the project's top-level folder and scan again:

```properties
android.useAndroidX=true
```

For the detection rules and the Java images, see [Ecosystems](../reference/ecosystems.md#android).
