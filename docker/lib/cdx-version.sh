#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# cdx-version.sh — the single CycloneDX specVersion this pipeline emits.
#
# 1.6, not the newest CycloneDX release: syft's own -o selector, cdxgen's
# --spec-version, every script here that writes its own document header, and
# the docs all have to agree, and the bundled Trivy 0.70 cannot decode 1.7
# ("invalid specification version"). AI/dataset SBOMs (identify-model-file.py,
# scan-figshare.py, scan-hf-dataset.py, declare-ai-model.py) use 1.7 instead,
# for the `data` component type and the richer machine-learning-model support
# that version added. That constant lives in each of those files rather than
# here, since nothing in bash needs it and there is no cross-language import
# convention in this codebase to introduce for a handful of call sites.
#
# Sourced by every bash script that either invokes syft/cdxgen with an
# explicit spec-version flag or writes a CycloneDX document header of its own.
# scripts/scan-sbom.sh (host-side, outside docker/lib/) sources this file too,
# by relative path from $REPO_DIR, so the value it passes into the cdxgen
# container's build-prep.sh matches what everything inside this image uses.
# shellcheck disable=SC2034  # used by every script that sources this file
CDX_SPEC_VERSION="1.6"
