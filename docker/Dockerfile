# ========================================================
# SBOM Scanner - Optimized Multi-Language Support
# Image: ghcr.io/sktelecom/sbom-scanner
# Supports: Java(7-17), Python3, Node.js20, Ruby, PHP, Rust, Go, .NET, (Android opt-in)
# Tools: cdxgen, syft, Trivy (pinned versions), scancode (opt-in)
# ========================================================

FROM node:20-slim

LABEL org.opencontainers.image.title="SBOM Scanner"
LABEL org.opencontainers.image.description="Multi-language SBOM, license notice, and security report generator"
LABEL org.opencontainers.image.vendor="SK Telecom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------
# Pinned tool/runtime versions (supply-chain hygiene).
# Bump deliberately after verifying release signatures.
# --------------------------------------------------------
ARG CDXGEN_VERSION=11.2.2
ARG SYFT_VERSION=v1.18.1
ARG TRIVY_VERSION=v0.58.2
ARG SCANCODE_VERSION=32.3.0
ARG GO_VERSION=1.23.4
ARG DOTNET_CHANNEL=8.0
ARG GRADLE_VERSION=8.5
# Opt-in heavy components (kept out of the default image)
ARG SBOM_ANDROID_SDK=false
ARG SBOM_DEEP_LICENSE=false
# buildx-provided target architecture (amd64 / arm64)
ARG TARGETARCH=amd64

# Essential tools only (no build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl bash jq git wget ca-certificates gnupg software-properties-common \
    file procps unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Python 3 (+ poetry / pipenv via pip; PEP668 override on slim image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages poetry pipenv

# Node package managers: enable yarn & pnpm via corepack (bundled with node:20)
RUN corepack enable && corepack prepare yarn@stable pnpm@latest --activate

# Single JDK: Java 17 LTS
RUN mkdir -p /etc/apt/keyrings \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | tee /etc/apt/keyrings/adoptium.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    temurin-17-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/jvm/temurin-17-jdk-* /usr/lib/jvm/default-jvm

# Maven & Gradle
RUN apt-get update && apt-get install -y --no-install-recommends \
    maven \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && unzip -q "gradle-${GRADLE_VERSION}-bin.zip" -d /opt \
    && ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle \
    && rm "gradle-${GRADLE_VERSION}-bin.zip"

# Ruby
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby ruby-dev bundler \
    && rm -rf /var/lib/apt/lists/*

# PHP
RUN apt-get update && apt-get install -y --no-install-recommends \
    php-cli php-xml php-mbstring composer \
    && rm -rf /var/lib/apt/lists/*

# Rust (minimal profile)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable --profile minimal --no-modify-path

# Go (pinned, official tarball; matches buildx TARGETARCH)
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -O /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

# .NET SDK (pinned channel via official install script)
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --install-dir /usr/lib/dotnet \
    && rm /tmp/dotnet-install.sh

# Android SDK (opt-in: --build-arg SBOM_ANDROID_SDK=true) — adds ~1GB
RUN if [ "$SBOM_ANDROID_SDK" = "true" ]; then \
      mkdir -p /opt/android-sdk/cmdline-tools \
      && wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdtools.zip \
      && unzip -q /tmp/cmdtools.zip -d /opt/android-sdk/cmdline-tools \
      && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
      && rm /tmp/cmdtools.zip \
      && yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1 || true ; \
    else \
      echo "[build] Android SDK skipped (SBOM_ANDROID_SDK=false)"; \
    fi

# Docker CLI (for image scanning)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# SBOM + vulnerability tools (pinned)
RUN npm install -g "@cyclonedx/cdxgen@${CDXGEN_VERSION}" \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" \
    && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}"

# scancode-toolkit (opt-in deep license detection: --build-arg SBOM_DEEP_LICENSE=true) — heavy
RUN if [ "$SBOM_DEEP_LICENSE" = "true" ]; then \
      pip3 install --no-cache-dir --break-system-packages "scancode-toolkit==${SCANCODE_VERSION}"; \
    else \
      echo "[build] scancode-toolkit skipped (SBOM_DEEP_LICENSE=false)"; \
    fi

# Environment variables
ENV PATH="/root/.cargo/bin:/usr/local/go/bin:/usr/lib/dotnet:${PATH}"
ENV JAVA_HOME="/usr/lib/jvm/default-jvm"
ENV ANDROID_SDK_ROOT="/opt/android-sdk"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV GOFLAGS="-mod=mod"

# Copy entrypoint + helper library + web UI
COPY entrypoint.sh /usr/local/bin/run-scan
COPY lib/ /usr/local/lib/sbom/
COPY web/ /usr/local/lib/sbom-web/
RUN chmod +x /usr/local/bin/run-scan /usr/local/lib/sbom/*.sh

WORKDIR /src

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node --version && java -version 2>&1 | grep -q "openjdk"

ENTRYPOINT ["/usr/local/bin/run-scan"]
