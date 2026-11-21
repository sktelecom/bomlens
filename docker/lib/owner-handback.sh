#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# Owner hand-back: should a file this container wrote be chowned to
# HOST_UID:HOST_GID? Sourced by engine-result.sh (and so entrypoint.sh), make-plan.sh
# and deep-license.sh. POSIX sh. build-prep.sh runs alone in a language image
# and carries its own copy of userns_remapped (tests/test-postprocess.sh keeps
# the two the same).

# userns_remapped: 0 when this process runs in a user namespace that maps its
# uid 0 to a non-zero host uid (rootless Docker, rootless Podman). Root in here
# is then the host user already, and a chown to HOST_UID would hand the file to
# a subordinate uid instead. BOMLENS_UID_MAP overrides the file read (tests).
userns_remapped() {
    _um_f="${BOMLENS_UID_MAP:-/proc/self/uid_map}"
    [ -r "$_um_f" ] || return 1
    awk '$1 == 0 { f = ($2 != 0) } END { exit !f }' "$_um_f" 2>/dev/null
}

# owner_handback_wanted: 0 when HOST_UID and HOST_GID are numbers and the
# container is not remapped. Says once on stderr why a remapped run skips it.
owner_handback_wanted() {
    case "${HOST_UID:-}" in ''|*[!0-9]*) return 1 ;; esac
    case "${HOST_GID:-}" in ''|*[!0-9]*) return 1 ;; esac
    if userns_remapped; then
        if [ -z "${_OWNER_HANDBACK_NOTED:-}" ]; then
            echo "[INFO] Rootless container engine: files written here already belong to you, so they are not chowned to HOST_UID ${HOST_UID}." >&2
            _OWNER_HANDBACK_NOTED=1
        fi
        return 1
    fi
    return 0
}
