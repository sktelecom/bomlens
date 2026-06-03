# ========================================================
# SBOM Generator — post-processing image (2-stage architecture)
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
#   - the local web UI (React SPA, built in stage 1; served by Python stdlib)
# ========================================================

# ---- Stage 1: build the React SPA (Vite). node lives ONLY in this stage; the
#      runtime image copies just the static dist/, so it stays lightweight. ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/frontend/package.json web/frontend/package-lock.json* ./
RUN npm ci || npm install
COPY web/frontend/ ./
RUN npm run build

# ---- Stage 2: post-process runtime ----
FROM python:3.14-slim

LABEL org.opencontainers.image.title="SBOM Generator (post-process)"
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

# Firmware analysis (opt-in image `sbom-scanner-firmware`). GPL tools are isolated
# here so the base image stays permissive-only; see THIRD_PARTY_LICENSES.md.
ARG SBOM_FIRMWARE=false
ARG UNBLOB_VERSION=26.3.30
ARG CVE_BIN_TOOL_VERSION=3.4
ARG UBI_READER_VERSION=0.8.13

# jq (helper scripts), curl/tar (installers), file (binary mode),
# git (web UI 'GitHub URL' ingestion: server.py clones into a temp source tree).
# python3 + pip are already in the python:3.12-slim base (web UI + scancode).
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq curl wget ca-certificates bash tar file git \
    && rm -rf /var/lib/apt/lists/*

# syft — image/binary/RootFS scanning (pinned)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" \
    && syft version

# Trivy — security report engine (pinned release tarball; arch-mapped).
# Detect arch with `uname -m` (under buildx QEMU this reports the TARGET arch),
# not the TARGETARCH ARG whose Dockerfile default ("amd64") shadowed the
# per-platform value and pulled an amd64 binary into the arm64 image.
RUN TRIVY_VER_NUM="${TRIVY_VERSION#v}" \
    && case "$(uname -m)" in \
         x86_64)  TRIVY_ARCH="Linux-64bit" ;; \
         aarch64) TRIVY_ARCH="Linux-ARM64" ;; \
         *)       TRIVY_ARCH="Linux-64bit" ;; \
       esac \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VER_NUM}_${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tgz \
    && tar -C /usr/local/bin -xzf /tmp/trivy.tgz trivy \
    && rm /tmp/trivy.tgz \
    && trivy --version

# Cosign — optional SBOM signing (--sign), pinned (arch via uname -m, see above)
RUN case "$(uname -m)" in x86_64) CARCH=amd64 ;; aarch64) CARCH=arm64 ;; *) CARCH=amd64 ;; esac \
    && curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${CARCH}" -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    && cosign version

# scancode-toolkit (opt-in deep license: --build-arg SBOM_DEEP_LICENSE=true)
RUN if [ "$SBOM_DEEP_LICENSE" = "true" ]; then \
      pip3 install --no-cache-dir "scancode-toolkit==${SCANCODE_VERSION}"; \
    else \
      echo "[build] scancode-toolkit skipped (SBOM_DEEP_LICENSE=false)"; \
    fi

# Firmware unpack + binary identification (opt-in: --build-arg SBOM_FIRMWARE=true).
#   unblob = MIT (primary unpacker); cve-bin-tool/ubi_reader = GPL (binary ID, UBI).
#   squashfs-tools/e2fsprogs/p7zip/unar/jefferson/... are the extractor binaries
#   unblob shells out to; unsquashfs (squashfs-tools) is also the standard-squashfs
#   fallback used by scan-firmware.sh when unblob's sasquatch handler is absent.
#   Built only into ghcr.io/sktelecom/sbom-scanner-firmware so the base stays GPL-free.
#   NOTE: the PyPI `binwalk` 2.x dist is broken (no binwalk.core), so it is NOT
#   installed; unsquashfs covers the common squashfs case. vendor-modified
#   (non-standard) squashfs still needs sasquatch added on top of this.
RUN if [ "$SBOM_FIRMWARE" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        squashfs-tools e2fsprogs p7zip-full unar cpio cabextract \
        lzop zstd lz4 liblzo2-2 zlib1g \
      && pip3 install --no-cache-dir \
        "unblob==${UNBLOB_VERSION}" \
        "cve-bin-tool==${CVE_BIN_TOOL_VERSION}" \
        "ubi_reader==${UBI_READER_VERSION}" \
      && rm -rf /var/lib/apt/lists/* \
      && unblob --version && cve-bin-tool --version; \
    else \
      echo "[build] firmware tools skipped (SBOM_FIRMWARE=false)"; \
    fi

# Reflects the firmware build flavor. When SBOM_FIRMWARE=true the image bundles GPL
# tools (cve-bin-tool, ubi_reader); the source-offer label points to the inventory.
LABEL com.sktelecom.sbom.firmware-tools="${SBOM_FIRMWARE}" \
      com.sktelecom.sbom.gpl-source-offer="https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md"

COPY entrypoint.sh /usr/local/bin/run-scan
COPY lib/ /usr/local/lib/sbom/
COPY web/server.py /usr/local/lib/sbom-web/server.py
COPY --from=web /web/dist /usr/local/lib/sbom-web/dist
RUN chmod +x /usr/local/bin/run-scan /usr/local/lib/sbom/*.sh

WORKDIR /src

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD syft version >/dev/null 2>&1 && trivy --version >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/run-scan"]
