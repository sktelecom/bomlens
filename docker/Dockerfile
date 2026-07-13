# ========================================================
# BomLens — post-processing image (2-stage architecture)
# Image: ghcr.io/sktelecom/sbom-scanner
#
# In the redesigned pipeline, SBOM GENERATION for
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
FROM node:26-alpine@sha256:3ad34ca6292aec4a91d8ddeb9229e29d9c2f689efd0dd242860889ac71842eba AS web
WORKDIR /web
COPY web/frontend/package.json web/frontend/package-lock.json* ./
RUN npm ci || npm install
COPY web/frontend/ ./
RUN npm run build

# ---- Stage 2: post-process runtime ----
# python 3.12: the base only needs stdlib (web server.py), but the opt-in scancode/
# firmware tools (pinned) do not yet support newer Python, so we stay on 3.12.
FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

LABEL org.opencontainers.image.title="BomLens (post-process)"
LABEL org.opencontainers.image.description="syft + Trivy + notice + signing + UI; SBOM generation delegated to cdxgen language images"
LABEL org.opencontainers.image.vendor="SK Telecom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

# Pinned tool versions (supply-chain hygiene). The `# renovate:` comments let
# Renovate (renovate.json customManagers) track each upstream and open bump PRs;
# Dependabot cannot see these ARG-pinned, curl/pip-installed tools. See
# docs/internal/dependency-upgrade-policy.md.
# renovate: datasource=github-releases depName=anchore/syft
ARG SYFT_VERSION=v1.46.0
# renovate: datasource=github-releases depName=aquasecurity/trivy
ARG TRIVY_VERSION=v0.72.0
# renovate: datasource=github-releases depName=sigstore/cosign
ARG COSIGN_VERSION=v2.4.1
# renovate: datasource=pypi depName=scancode-toolkit
ARG SCANCODE_VERSION=32.5.0
ARG SBOM_DEEP_LICENSE=false
# Vendored-OSS identification (on by default; disable with --build-arg SBOM_SCANOSS=false).
# scanoss.py is MIT, so unlike the firmware GPL tools it can live in the base image.
# Runtime still gates the outbound OSSKB call behind the --identify-vendored flag,
# so shipping the client just makes the web-UI toggle available out of the box.
ARG SBOM_SCANOSS=true
# renovate: datasource=pypi depName=scanoss
ARG SCANOSS_VERSION=1.54.1
ARG TARGETARCH=amd64
# docker CLI (client only) — lets the web UI source scan launch cdxgen language
# images as sibling containers via the mounted host socket (transitive deps).
# renovate: datasource=github-tags depName=docker/cli extractVersion=^v(?<version>.+)$
ARG DOCKER_CLI_VERSION=27.5.1

# Firmware analysis (opt-in image `sbom-scanner-firmware`). GPL tools are isolated
# here so the base image stays permissive-only; see THIRD_PARTY_LICENSES.md.
ARG SBOM_FIRMWARE=false
# renovate: datasource=pypi depName=unblob
ARG UNBLOB_VERSION=26.3.30
# renovate: datasource=pypi depName=cve-bin-tool
ARG CVE_BIN_TOOL_VERSION=3.4
# renovate: datasource=pypi depName=ubi_reader
ARG UBI_READER_VERSION=0.8.14

# AI SBOM generation (opt-in image `bomlens-aibom`). owasp-aibom-generator is
# Apache-2.0 and fetches HuggingFace model-card metadata over the network at scan
# time. Kept opt-in (network + extra deps) like SCANOSS so the base image stays
# local-first. No PyPI release yet, so it is pinned to a commit; when the project
# tags releases, Renovate's github-tags datasource picks them up.
ARG SBOM_AIBOM=false
# renovate: datasource=github-tags depName=GenAI-Security-Project/aibom-generator
ARG AIBOM_GENERATOR_REF=c5a3f2f647b801ab4ab7569aade4a6cdaf1f9591
# cdxgen (Node) is installed alongside the AIBOM generator so enrich-aibom.sh can
# harvest model pedigree / performance metrics that the OWASP tool omits. Opt-in
# with the aibom image only; enrich-aibom.sh degrades gracefully when it is absent.
# renovate: datasource=npm depName=@cyclonedx/cdxgen
ARG CDXGEN_VERSION=12.7.1

# NOTICE PDF rendering (opt-in: --build-arg SBOM_PDF=true). weasyprint renders the
# generated _NOTICE.html to _NOTICE.pdf. It is Python-based (consistent with onot)
# but needs heavy native libraries (pango/cairo/gdk-pixbuf), so it is kept out of
# the lean base image and generate-notice.sh skips PDF gracefully when absent.
ARG SBOM_PDF=false
# renovate: datasource=pypi depName=weasyprint
ARG WEASYPRINT_VERSION=63.1

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

# docker CLI (client binary only; no daemon). The web UI source scan shells out
# to `docker run <cdxgen-language-image>` against the mounted host socket. Pulled
# from Docker's static builds, arch-mapped via uname -m (see Trivy note above).
RUN case "$(uname -m)" in \
         x86_64)  DOCKER_ARCH="x86_64" ;; \
         aarch64) DOCKER_ARCH="aarch64" ;; \
         *)       DOCKER_ARCH="x86_64" ;; \
       esac \
    && curl -sSfL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
    && tar -C /usr/local/bin --strip-components=1 -xzf /tmp/docker.tgz docker/docker \
    && rm /tmp/docker.tgz \
    && docker --version

# scancode-toolkit (opt-in deep license: --build-arg SBOM_DEEP_LICENSE=true).
# scancode has three native dependencies that a plain `pip install` does NOT satisfy
# on the slim base, so all three are handled here:
#   1. PyICU (transitive) is a C extension compiled against ICU headers, so the build
#      needs build-essential + libicu-dev + pkg-config + python3-dev. Those dev
#      packages are purged afterward; the runtime libicu is re-marked manual so
#      autoremove keeps it for the compiled PyICU to load.
#   2. extractcode loads libarchive via ctypes at import time. Its loader calls
#      find_library("libarchive"), which ALWAYS returns None on Linux (ctypes wants
#      the name WITHOUT the lib prefix), then loads the main program and dies with
#      "undefined symbol: archive_read_new". We install the system libarchive13 and
#      point EXTRACTCODE_LIBARCHIVE_PATH straight at it (the loader's first choice),
#      sidestepping the broken find_library path. The pip extractcode-libarchive
#      plugin is a no-arch stub here (ships no .so), so it does not help.
#   3. typecode loads libmagic the same way; TYPECODE_LIBMAGIC_PATH / _DB_PATH pin
#      the system libmagic1 and its compiled magic database.
# A real license scan runs as a build gate so any missing native dep fails the build
# instead of silently shipping a scancode that dies on the first scan.
ENV EXTRACTCODE_LIBARCHIVE_PATH=/usr/local/lib/libarchive.so \
    TYPECODE_LIBMAGIC_PATH=/usr/local/lib/libmagic.so \
    TYPECODE_LIBMAGIC_DB_PATH=/usr/share/misc/magic.mgc
RUN if [ "$SBOM_DEEP_LICENSE" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        build-essential libicu-dev pkg-config python3-dev \
        libarchive13 libmagic1 \
      && pip3 install --no-cache-dir "scancode-toolkit==${SCANCODE_VERSION}" \
      && ln -sf "$(find /usr/lib -name 'libarchive.so.13' | head -1)" /usr/local/lib/libarchive.so \
      && ln -sf "$(find /usr/lib -name 'libmagic.so.1' | head -1)" /usr/local/lib/libmagic.so \
      && mkdir -p /tmp/sc-probe \
      && printf 'Permission is hereby granted, free of charge (MIT License).\n' > /tmp/sc-probe/LICENSE \
      && scancode --license --json-pp /tmp/sc-probe.json /tmp/sc-probe \
      && rm -rf /tmp/sc-probe /tmp/sc-probe.json \
      && apt-mark manual $(dpkg-query -W -f='${Package}\n' 'libicu[0-9]*') \
      && apt-get purge -y build-essential libicu-dev pkg-config python3-dev \
      && apt-get autoremove -y \
      && rm -rf /var/lib/apt/lists/*; \
    else \
      echo "[build] scancode-toolkit skipped (SBOM_DEEP_LICENSE=false)"; \
    fi

# scanoss.py (vendored-OSS identification, on by default: --build-arg SBOM_SCANOSS=false to skip).
# MIT-licensed client; talks to the hosted OSSKB API (or SCANOSS_API_URL). It does
# NOT bundle the GPL-2.0 SCANOSS engine. See identify-vendored.sh and
# THIRD_PARTY_LICENSES.md for the OSSKB terms (identification-only, no redistribution).
RUN if [ "$SBOM_SCANOSS" = "true" ]; then \
      pip3 install --no-cache-dir "scanoss==${SCANOSS_VERSION}" \
      && scanoss-py --version; \
    else \
      echo "[build] scanoss skipped (SBOM_SCANOSS=false)"; \
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

# Firmware CVE matching data (Plan 2, rebuilt). cve-bin-tool identifies binaries
# (its signature checkers) and lib/firmware-cpe-match.py matches their CPEs against
# a distilled NVD index. Two artifacts are baked into the firmware image:
#   (1) a tiny STUB cve.db — cve-bin-tool refuses to run on an empty cache
#       (EmptyCache in cvedb.check_cve_entries), so we seed its schema with one
#       sentinel row. Identification never reads CVE data from it. (~57 KB)
#   (2) cpe_match.sqlite — the application-part CPE->CVE applicability index,
#       distilled by build-cpe-index.py from the fkie-cad NVD 2.0 JSON feeds. (~130 MB)
# The NVD data comes from a plain git clone (no api2 rate limit, no key, builds on
# GitHub cloud runners), replacing the old ~1.5 GB api2-fetched cve.db that NVD
# throttled into multi-hour stalls.
# RELEASE GATE: the build FAILS unless the index has a substantial row count AND a
# BusyBox 1.30.1 smoke match yields >=1 CVE. The smoke test runs the real matcher,
# so a broken distill or an empty feed cannot ship a silent 0-CVE firmware image.
ENV CVE_BIN_TOOL_HOME=/opt/cve-bin-tool-home
# Attribution + required notices for the bundled NVD-derived data. Shipped with it.
COPY CVE-DATA-NOTICE.txt /opt/cve-bin-tool-home/CVE-DATA-NOTICE.txt
# renovate: datasource=git-refs depName=fkie-cad/nvd-json-data-feeds
ARG NVD_FEED_REPO="https://github.com/fkie-cad/nvd-json-data-feeds"
COPY build-cpe-index.py /tmp/build-cpe-index.py
COPY lib/firmware-cpe-match.py /tmp/firmware-cpe-match.py
RUN if [ "$SBOM_FIRMWARE" = "true" ]; then \
      set -e; \
      echo "[build] seeding stub cve.db (cve-bin-tool EmptyCache guard) ..."; \
      mkdir -p "$CVE_BIN_TOOL_HOME/.cache/cve-bin-tool"; \
      HOME="$CVE_BIN_TOOL_HOME" python3 -c "import sqlite3, os; from cve_bin_tool.cvedb import CVEDB; CVEDB().init_database(); p=os.path.expanduser('~/.cache/cve-bin-tool/cve.db'); c=sqlite3.connect(p); c.execute(\"INSERT OR IGNORE INTO cve_severity VALUES (?,?,?,?,?,?,?,datetime('now'))\", ('CVE-0000-00000','UNKNOWN','stub row for cve-bin-tool EmptyCache check; not used for matching',0,3,'','STUB')); c.commit(); c.close()"; \
      echo "[build] cloning NVD data feeds (shallow) ..."; \
      git clone --quiet --depth 1 "$NVD_FEED_REPO" /tmp/nvd-feeds; \
      echo "[build] distilling CPE index ..."; \
      python3 /tmp/build-cpe-index.py /tmp/nvd-feeds "$CVE_BIN_TOOL_HOME/cpe_match.sqlite"; \
      rm -rf /tmp/nvd-feeds; \
      idx="$CVE_BIN_TOOL_HOME/cpe_match.sqlite"; \
      rows="$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("select count(*) from cpe_match").fetchone()[0])' "$idx" 2>/dev/null || echo 0)"; \
      printf '%s' '{"components":[{"type":"application","name":"busybox","version":"1.30.1","cpe":"cpe:/a:busybox:busybox:1.30.1"}]}' > /tmp/smoke.json; \
      nsmoke="$(python3 /tmp/firmware-cpe-match.py /tmp/smoke.json "$idx" 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"; \
      echo "[build] CPE index: rows=${rows:-0}, busybox-1.30.1 smoke CVEs=${nsmoke:-0} ($(du -h "$idx" | cut -f1))"; \
      if [ "${rows:-0}" -lt 500000 ] || [ "${nsmoke:-0}" -lt 1 ]; then \
        echo "[build] ERROR: CPE index looks broken (rows=${rows:-0}, busybox smoke=${nsmoke:-0}). Build aborted."; \
        exit 1; \
      fi; \
      rm -f /tmp/build-cpe-index.py /tmp/firmware-cpe-match.py /tmp/smoke.json; \
    fi

# OWASP AIBOM Generator (opt-in: --build-arg SBOM_AIBOM=true). Generates an AI
# SBOM (CycloneDX 1.7) for a HuggingFace model id; see scan-aibom.sh.
# Apache-2.0, pinned to a commit (no PyPI
# release yet). Cloned into /opt/aibom-generator and run as `python -m src.cli`
# from there: a bare `pip install` drops the tool's data files (model-field
# registry, SPDX schema), so we keep the repo layout. git is in the base layer.
RUN if [ "$SBOM_AIBOM" = "true" ]; then \
      git clone --quiet https://github.com/GenAI-Security-Project/aibom-generator /opt/aibom-generator \
      && git -C /opt/aibom-generator checkout --quiet "${AIBOM_GENERATOR_REF}" \
      && pip3 install --no-cache-dir -r /opt/aibom-generator/requirements.txt \
      && ( cd /opt/aibom-generator && python3 -m src.cli --help >/dev/null ) \
      && apt-get update && apt-get install -y --no-install-recommends nodejs npm \
      && npm install -g "@cyclonedx/cdxgen@${CDXGEN_VERSION}" \
      && rm -rf /var/lib/apt/lists/* \
      && cdxgen --version >/dev/null; \
    else \
      echo "[build] aibom generator skipped (SBOM_AIBOM=false)"; \
    fi

# NOTICE PDF renderer (opt-in: --build-arg SBOM_PDF=true). weasyprint (BSD-3-Clause)
# plus its native deps (libpango/cairo/gdk-pixbuf, ~50-60 MB). generate-notice.sh
# detects it via `command -v weasyprint` and skips the PDF step when it is absent,
# so the default image stays lean and a scan never fails for lack of the renderer.
RUN if [ "$SBOM_PDF" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 libffi8 \
        fonts-dejavu-core \
      && pip3 install --no-cache-dir "weasyprint==${WEASYPRINT_VERSION}" \
      && rm -rf /var/lib/apt/lists/* \
      && weasyprint --version; \
    else \
      echo "[build] PDF renderer (weasyprint) skipped (SBOM_PDF=false)"; \
    fi

# Reflects the firmware build flavor. When SBOM_FIRMWARE=true the image bundles GPL
# tools (cve-bin-tool, ubi_reader); the source-offer label points to the inventory.
LABEL com.sktelecom.sbom.firmware-tools="${SBOM_FIRMWARE}" \
      com.sktelecom.sbom.scanoss-tools="${SBOM_SCANOSS}" \
      com.sktelecom.sbom.aibom-tools="${SBOM_AIBOM}" \
      com.sktelecom.sbom.pdf-tools="${SBOM_PDF}" \
      com.sktelecom.sbom.gpl-source-offer="https://github.com/sktelecom/sbom-tools/blob/main/THIRD_PARTY_LICENSES.md"

COPY entrypoint.sh /usr/local/bin/run-scan
COPY lib/ /usr/local/lib/sbom/
COPY web/server.py /usr/local/lib/sbom-web/server.py
COPY --from=web /web/dist /usr/local/lib/sbom-web/dist
RUN chmod +x /usr/local/bin/run-scan /usr/local/lib/sbom/*.sh

# Bundle an endoflife.date snapshot beside enrich-eol.sh so component end-of-life
# flagging runs OFFLINE at scan time (no per-scan network, works air-gapped). The
# bundle holds only the products eol-purl-map.json references and is a few KB.
# Best-effort: if the fetch fails at build time no file is written and enrich-eol.sh
# skips cleanly at scan time (EOL flagging is optional, never a blocker). Attribution
# and snapshot date live in the bundle's _snapshot field. See build-eol-index.py.
COPY build-eol-index.py /tmp/build-eol-index.py
RUN timeout 120 python3 /tmp/build-eol-index.py \
        /usr/local/lib/sbom/eol-purl-map.json \
        /usr/local/lib/sbom/eol-data.json \
    || echo "[build] endoflife snapshot skipped; EOL flagging will be inactive at scan time" \
    ; rm -f /tmp/build-eol-index.py

WORKDIR /src

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD syft version >/dev/null 2>&1 && trivy --version >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/run-scan"]
