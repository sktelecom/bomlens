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
FROM ghcr.io/cyclonedx/cdxgen-temurin-java21:v12@sha256:88121c2c561c8d5f6bedf6d2c4777e9fffe9c7f4f18be105592072438370d0ec

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

RUN yes | sdkmanager --licenses >/dev/null 2>&1 || true; \
    sdkmanager "platform-tools" "platforms;android-${ANDROID_API}" "build-tools;${ANDROID_BUILD_TOOLS}" >/dev/null 2>&1 \
      || sdkmanager "platform-tools" "platforms;android-${ANDROID_API}" >/dev/null 2>&1 \
      || echo "[build] WARN: sdkmanager could not install all packages for API ${ANDROID_API}"

# cdxgen + gradle come from the base image; scan-sbom.sh mounts build-prep.sh
WORKDIR /app
