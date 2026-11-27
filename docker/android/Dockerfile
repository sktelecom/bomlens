# ========================================================
# BomLens — Android SDK image (per compileSdk)
# Image: ghcr.io/sktelecom/bomlens-android-sdk<ANDROID_API>
#        (legacy alias: sbom-scanner-android-sdk<ANDROID_API>, same digest)
#
# cdxgen does NOT provide Android-SDK-bundled images and marks Android as
# "no transitive support" — so Android source (pre-build) cannot be delegated
# to cdxgen. This image adds an Android SDK platform on top of cdxgen's java
# image (which already has java21 + gradle + cdxgen), one compileSdk per image
# for lightness. scan-sbom.sh detects compileSdk and picks the matching tag.
#
# Build:  docker build --build-arg ANDROID_API=35 \
#           -t ghcr.io/sktelecom/sbom-scanner-android-sdk35 docker/android
# ========================================================

ARG ANDROID_API=35
# On a network that reaches only a registry mirror, pass
# --build-arg CDXGEN_IMAGE_PREFIX=<mirror path>/ (see CDXGEN_IMAGE_PREFIX).
ARG CDXGEN_IMAGE_PREFIX=ghcr.io/cdxgen/
# The base is the Java 21 image. A project whose Gradle wrapper is older than 8.5
# does not run on Java 21; to build the SDK image on an older JDK, pass a full
# image reference of the same cdxgen release, for example
#   --build-arg BASE_JDK_IMAGE=ghcr.io/cdxgen/cdxgen-java17:13.8.0@sha256:<digest>
# (digests: docker/lib/cdxgen-images.json) and tag the result with another
# ANDROID_IMAGE_PREFIX name, then scan with that ANDROID_IMAGE_PREFIX. The
# published recipe and the app's automatic build keep the Java 21 base.
ARG BASE_JDK_IMAGE=
FROM ${CDXGEN_IMAGE_PREFIX}cdxgen-temurin-java21:13.8.0@sha256:a060d6e913255c3aa0959d217dc705e1ed6712f6408e50ed56d2f4156831581b AS base-java21
FROM ${BASE_JDK_IMAGE:-base-java21}

ARG ANDROID_API=35
ARG ANDROID_BUILD_TOOLS=${ANDROID_API}.0.0
ARG CMDLINE_TOOLS=11076708

LABEL org.opencontainers.image.title="BomLens Android SDK"
LABEL org.opencontainers.image.vendor="SK Telecom"
# This image holds no BomLens code. Its contents are cdxgen's java image
# (Apache-2.0) plus Android SDK components installed by sdkmanager, and those
# are governed by Google's Android Software Development Kit License Agreement,
# not by Apache-2.0. The label said Apache-2.0, which described neither.
# LicenseRef- is the SPDX form for a licence with no SPDX identifier.
LABEL org.opencontainers.image.licenses="Apache-2.0 AND LicenseRef-Android-SDK"
LABEL org.opencontainers.image.description="cdxgen java image plus Android SDK platform, build-tools, and platform-tools for scanning Android projects. The SDK components are subject to the Android Software Development Kit License Agreement."
LABEL com.sktelecom.sbom.android-sdk-terms="https://developer.android.com/studio/terms"

USER root
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk

# unzip/curl for the command-line tools (install only if missing; base OS varies)
RUN (command -v unzip >/dev/null 2>&1 && command -v curl >/dev/null 2>&1) \
    || (apt-get update && apt-get install -y --no-install-recommends unzip curl ca-certificates && rm -rf /var/lib/apt/lists/*) \
    || (microdnf install -y unzip curl ca-certificates && microdnf clean all)

# Android command-line tools + the requested platform/build-tools only
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && curl -sSL "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip" -o /tmp/cmd.zip \
    && unzip -q /tmp/cmd.zip -d "$ANDROID_HOME/cmdline-tools" \
    && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
    && rm /tmp/cmd.zip
ENV PATH="${PATH}:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools"

# The build-tools version is a guess (<API>.0.0) and may not exist, so that step may
# fall back to the platform alone. The platform is what dependency resolution needs:
# if it is not installed (network, proxy, disk), the build fails here instead of
# producing an image that cannot resolve anything.
RUN yes | sdkmanager --licenses >/dev/null 2>&1 || true; \
    sdkmanager "platform-tools" "platforms;android-${ANDROID_API}" "build-tools;${ANDROID_BUILD_TOOLS}" >/dev/null 2>&1 \
      || sdkmanager "platform-tools" "platforms;android-${ANDROID_API}" >/dev/null 2>&1 \
      || true; \
    if [ ! -d "${ANDROID_HOME}/platforms/android-${ANDROID_API}" ]; then \
      echo "[build] ERROR: sdk-install: Android platform ${ANDROID_API} was not installed (sdkmanager failed)"; \
      sdkmanager "platforms;android-${ANDROID_API}" 2>&1 | tail -n 5; \
      exit 1; \
    fi

# cdxgen + gradle come from the base image; scan-sbom.sh mounts build-prep.sh
WORKDIR /app
