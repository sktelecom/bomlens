#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# cdx-version.sh: the CycloneDX specVersion this pipeline emits.
#
# 1.6 by default. CYCLONEDX_SPEC_VERSION=1.7 (the CLI's --spec-version 1.7)
# asks for 1.7 instead, and only these two values are accepted. syft's own -o
# selector, cdxgen's --spec-version, every script here that writes its own
# document header, and stamp-document-metadata.sh (which raises a 1.4, 1.5 or
# 1.6 document to the requested 1.7) all read the value from here. A 1.7
# document goes to Trivy as it is; when a Trivy build cannot decode it,
# scan-security.sh retries with a 1.6 copy and the delivered SBOM keeps its
# version.
#
# AI/dataset SBOMs (identify-model-file.py, scan-figshare.py,
# scan-hf-dataset.py, declare-ai-model.py) are 1.7 whatever this says, for the
# `data` component type and the richer machine-learning-model support that
# version added. That constant lives in each of those files rather than here,
# since nothing in bash needs it and there is no cross-language import
# convention in this codebase to introduce for a handful of call sites.
#
# Sourced by every bash script that either invokes syft/cdxgen with an
# explicit spec-version flag or writes a CycloneDX document header of its own.
# scripts/scan-sbom.sh (host-side, outside docker/lib/) sources this file too,
# by relative path from $REPO_DIR, so the value it passes into the cdxgen
# container's build-prep.sh matches what everything inside this image uses.
# shellcheck disable=SC2034  # used by every script that sources this file
CDX_SPEC_VERSION="${CYCLONEDX_SPEC_VERSION:-1.6}"
case "$CDX_SPEC_VERSION" in
    1.6|1.7) ;;
    *)
        echo "[ERROR] CYCLONEDX_SPEC_VERSION=$CDX_SPEC_VERSION is not a CycloneDX version this pipeline writes. Use 1.6 (the default) or 1.7." >&2
        CDX_SPEC_VERSION="1.6"
        return 2 2>/dev/null || exit 2
        ;;
esac
