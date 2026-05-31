# ========================================================
# SBOM Scanner — post-processing image (2-stage architecture)
# Image: ghcr.io/sktelecom/sbom-scanner
#
# In the redesigned pipeline (see docs/direction-study.md), SBOM GENERATION for
# source code is delegated to cdxgen's official per-language images (pulled
# on-demand by scripts/scan-sbom.sh). THIS image is the lightweight
# post-processor + syft scanner; it carries NO language toolchains.
#
# Responsibilities:
#   - syft scanning of container images / binaries / RootFS
#   - normalize, open-source notice, Trivy security report, cosign signing
#   - the local web UI (Python stdlib)
# ========================================================

FROM python:3.12-slim

LABEL org.opencontainers.image.title="SBOM Scanner (post-process)"
LABEL org.opencontainers.image.description="syft + Trivy + notice + signing + UI; SBOM generation delegated to cdxgen language images"
LABEL org.opencontainers.image.vendor="SK Telecom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

# Pinned tool versions (supply-chain hygiene)
ARG SYFT_VERSION=v1.18.1
ARG TRIVY_VERSION=v0.70.0
ARG COSIGN_VERSION=v2.4.1
ARG SCANCODE_VERSION=32.3.0
ARG SBOM_DEEP_LICENSE=false
ARG TARGETARCH=amd64

# jq (helper scripts), curl/tar (installers), file (binary mode).
# python3 + pip are already in the python:3.12-slim base (web UI + scancode).
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq curl wget ca-certificates bash tar file \
    && rm -rf /var/lib/apt/lists/*

# syft — image/binary/RootFS scanning (pinned)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" \
    && syft version

# Trivy — security report engine (pinned release tarball; arch-mapped)
RUN TRIVY_VER_NUM="${TRIVY_VERSION#v}" \
    && case "${TARGETARCH}" in \
         amd64) TRIVY_ARCH="Linux-64bit" ;; \
         arm64) TRIVY_ARCH="Linux-ARM64" ;; \
         *)     TRIVY_ARCH="Linux-64bit" ;; \
       esac \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VER_NUM}_${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tgz \
    && tar -C /usr/local/bin -xzf /tmp/trivy.tgz trivy \
    && rm /tmp/trivy.tgz \
    && trivy --version

# Cosign — optional SBOM signing (--sign), pinned
RUN curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    && cosign version

# scancode-toolkit (opt-in deep license: --build-arg SBOM_DEEP_LICENSE=true)
RUN if [ "$SBOM_DEEP_LICENSE" = "true" ]; then \
      pip3 install --no-cache-dir "scancode-toolkit==${SCANCODE_VERSION}"; \
    else \
      echo "[build] scancode-toolkit skipped (SBOM_DEEP_LICENSE=false)"; \
    fi

COPY entrypoint.sh /usr/local/bin/run-scan
COPY lib/ /usr/local/lib/sbom/
COPY web/ /usr/local/lib/sbom-web/
RUN chmod +x /usr/local/bin/run-scan /usr/local/lib/sbom/*.sh

WORKDIR /src

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD syft version >/dev/null 2>&1 && trivy --version >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/run-scan"]
