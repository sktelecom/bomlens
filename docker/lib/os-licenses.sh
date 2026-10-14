#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# os-licenses.sh <sbom> <IMAGE|ROOTFS> <target>
#
# The licenses of Debian packages, from Trivy. syft reads a Debian package's
# licenses from its copyright file only when that file is machine-readable
# (DEP-5); for the others it writes the file's hash ("sha256:...") as the
# license. Trivy reads the license names and the common-licenses references
# in the copyright file, and with --license-full the license text in it too,
# so libc6 reads GPL-2.0-only and LGPL-2.1-only instead of a hash. It maps
# some of Debian's short names to SPDX ids (GFDL-NIV-1.3 to
# GFDL-1.3-no-invariants-only); names it does not know stay as they are. apk and rpm packages keep syft's licenses,
# which carry their AND/OR expressions (Trivy splits those into a list). The
# scan reads operating system packages only and needs no vulnerability or
# Java database.
#
# A package's licenses stay separate entries in `licenses`, one per license
# Trivy reports, never joined into one expression. Several licenses in a
# copyright file usually belong to different files, so for the package they
# all apply; license-flags.jq reads a deb package's entries that way. Trivy
# cannot keep a choice the copyright file states ("GPL-2+ or Artistic"): it
# splits "or" and "and" alike and merges every License: line into one list,
# so a stated choice is recorded as licenses that all apply, the safe side.
#
# Each deb package Trivy reports with licenses takes Trivy's, matched by name.
# A package Trivy does not report keeps syft's, less any hash. Prints
# "<replaced> <hashes dropped>" on stdout. Exits 1 when Trivy could not read
# the target, 3 when Trivy is not installed, 4 when it read the target but
# gave no Debian package a license (it did not recognise the system), 2 on
# any other failure; the hashes are dropped all the same when the SBOM can
# still be read.
set -uo pipefail

SBOM="$1"; MODE="$2"; TARGET="$3"
command -v jq >/dev/null 2>&1 || exit 2

has_deb="$(jq -r '[.components[]? | (.purl // "") | select(startswith("pkg:deb/"))] | length > 0' "$SBOM" 2>/dev/null)" || exit 2
has_hash="$(jq -r '[.components[]? | .licenses[]? | (.license.id // .license.name // .expression // "") | select(startswith("sha256:"))] | length > 0' "$SBOM" 2>/dev/null)" || exit 2
[ "$has_deb" = true ] || [ "$has_hash" = true ] || { echo "0 0"; exit 0; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
trivy_rc=0
# BOMLENS_OS_LICENSES=false: no Trivy, only the hash cleanup.
if [ "$has_deb" = true ] && [ "${BOMLENS_OS_LICENSES:-true}" != "false" ]; then
    trivy_rc=3
    if command -v trivy >/dev/null 2>&1; then
        set -- --quiet --skip-version-check --skip-db-update --skip-java-db-update \
            --scanners license --license-full --pkg-types os --format cyclonedx \
            --output "$TMP/trivy.cdx.json" --cache-dir "$TMP/cache"
        case "$MODE" in
            IMAGE)
                [ -n "${SYFT_PLATFORM:-}" ] && set -- "$@" --platform "$SYFT_PLATFORM"
                # The image's registry credentials are the ones syft was
                # given; TRIVY_USERNAME and the like may be set for a Trivy
                # database mirror, which this scan does not read.
                if [ -n "${SYFT_REGISTRY_AUTH_USERNAME:-}${SYFT_REGISTRY_AUTH_TOKEN:-}" ]; then
                    export TRIVY_USERNAME="${SYFT_REGISTRY_AUTH_USERNAME:-}"
                    export TRIVY_PASSWORD="${SYFT_REGISTRY_AUTH_PASSWORD:-}"
                    export TRIVY_REGISTRY_TOKEN="${SYFT_REGISTRY_AUTH_TOKEN:-}"
                fi
                export TRIVY_USERNAME="${TRIVY_USERNAME:-}" TRIVY_PASSWORD="${TRIVY_PASSWORD:-}" TRIVY_REGISTRY_TOKEN="${TRIVY_REGISTRY_TOKEN:-}"
                case "${SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY:-}${SYFT_REGISTRY_INSECURE_USE_HTTP:-}" in
                    *true*) export TRIVY_INSECURE="${TRIVY_INSECURE:-true}" ;;
                esac
                for v in TRIVY_USERNAME TRIVY_PASSWORD TRIVY_REGISTRY_TOKEN; do [ -n "${!v}" ] || unset "$v"; done
                # syft's source schemes, in Trivy's terms.
                case "$TARGET" in
                    docker-archive:*|oci-archive:*|oci-dir:*) set -- image "$@" --input "${TARGET#*:}" ;;
                    registry:*) set -- image "$@" --image-src remote "${TARGET#registry:}" ;;
                    docker:*)   set -- image "$@" --image-src docker "${TARGET#docker:}" ;;
                    podman:*)   set -- image "$@" --image-src podman "${TARGET#podman:}" ;;
                    *)          set -- image "$@" "$TARGET" ;;
                esac ;;
            ROOTFS)
                # Trivy takes these relative to nothing in particular: give
                # them under the target, as syft's ./proc excludes are.
                set -- rootfs "$@" --skip-dirs "${TARGET%/}/proc" --skip-dirs "${TARGET%/}/sys" \
                    --skip-dirs "${TARGET%/}/dev" --skip-dirs "${TARGET%/}/run" "$TARGET" ;;
        esac
        trivy "$@" 2>"$TMP/err"
        trivy_rc=$?
        [ "$trivy_rc" -eq 0 ] && [ ! -s "$TMP/trivy.cdx.json" ] && trivy_rc=1
        [ "$trivy_rc" -ne 0 ] && tail -3 "$TMP/err" >&2
    fi
fi
[ "$trivy_rc" -eq 0 ] && [ -s "$TMP/trivy.cdx.json" ] || echo '{"components":[]}' > "$TMP/trivy.cdx.json"

jq --slurpfile t "$TMP/trivy.cdx.json" '
    def isdeb: (.purl // "") | startswith("pkg:deb/");
    def hash: (.license.id // .license.name // .expression // "") | startswith("sha256:");
    ([$t[0].components[]? | select(isdeb and ((.licenses // []) | length > 0))
      | {key: .name, value: .licenses}] | from_entries) as $by
    | .components |= map(
        if isdeb and $by[.name] then .licenses = $by[.name] | .["bomlens:os-licenses"] = "trivy"
        elif ((.licenses // []) | any(hash)) then
            .licenses = [.licenses[] | select(hash | not)] | .["bomlens:os-licenses"] = "hash-dropped"
            | if (.licenses | length) == 0 then del(.licenses) else . end
        else . end)
    | ([.components[] | select(.["bomlens:os-licenses"] == "trivy")] | length) as $r
    | ([.components[] | select(.["bomlens:os-licenses"] == "hash-dropped")] | length) as $d
    | .components |= map(del(.["bomlens:os-licenses"]))
    | {doc: ., r: $r, d: $d}
' "$SBOM" > "$TMP/out.json" || exit 2
jq '.doc' "$TMP/out.json" > "$TMP/sbom.json" && mv "$TMP/sbom.json" "$SBOM" || exit 2
jq -r '"\(.r) \(.d)"' "$TMP/out.json"
case "$trivy_rc" in 0) ;; 3) exit 3 ;; *) exit 1 ;; esac
[ "$has_deb" = true ] && [ "${BOMLENS_OS_LICENSES:-true}" != "false" ] \
    && [ "$(jq -r '.r' "$TMP/out.json")" = 0 ] && exit 4
exit 0
