#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# unpack-scan-target.sh — materialize a readable copy of a scan target that has
# no files on disk, so the file tree and the source snapshot can be built from it.
#
# Usage: unpack-scan-target.sh <IMAGE|BINARY> <target> [dest]
#   IMAGE  <target> is a Docker image reference (needs the docker socket)
#   BINARY <target> is an archive file (jar/war/ear/zip/whl, or a tar family)
#
# Prints the directory it unpacked into on stdout, and nothing at all when it
# could not unpack (an ELF binary, a missing docker socket, an unreadable
# archive). The CALLER owns the directory and must remove it — the scanner's
# entrypoint does that after the tree and snapshot are written, the same way
# scan-firmware.sh treats its own extraction.
#
# A Docker image is a stack of layers with no directory to walk; `docker export`
# of a container created (never started) from it flattens them into one tar,
# which is exactly the filesystem the image describes. An archive is unpacked
# with the tool for its format.
#
# Bounded and never fatal: extraction is capped in size and time, and any
# failure prints nothing so the caller simply skips the file views. Diagnostics
# go to stderr.
set -u

MODE="${1:-}"
TARGET="${2:-}"
DEST="${3:-}"

[ -n "$MODE" ] && [ -n "$TARGET" ] || exit 0

# Cap on the unpacked copy. An image or an archive can be far larger than the
# snapshot will ever keep, and the point here is to read text out of it, not to
# reproduce it. Override for testing.
MAX_KB="${UNPACK_MAX_KB:-2097152}"   # 2 GiB
TIMEOUT="${UNPACK_TIMEOUT:-300}"

_run() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$TIMEOUT" "$@"
    else
        "$@"
    fi
}

if [ -z "$DEST" ]; then
    DEST="$(mktemp -d 2>/dev/null)" || exit 0
else
    mkdir -p "$DEST" 2>/dev/null || exit 0
fi

# Give up cleanly: remove the half-unpacked directory and print nothing, so the
# caller sees "no readable copy" rather than a partial tree presented as whole.
give_up() {
    [ -n "${1:-}" ] && echo "[unpack] $1" >&2
    rm -rf "$DEST"
    exit 0
}

case "$MODE" in
    IMAGE)
        command -v docker >/dev/null 2>&1 || give_up "no docker CLI; skipping the file view."
        # Ask the daemon rather than testing for /var/run/docker.sock: inside the
        # scanner that socket is mounted, but the same check run anywhere else
        # (a developer's machine, a DOCKER_HOST setup) would refuse a daemon
        # that is plainly reachable.
        _run docker info >/dev/null 2>&1 \
            || give_up "no reachable Docker daemon; skipping the file view."
        # `create` makes a container without running anything in it; `export`
        # then streams its (unstarted) filesystem. Nothing from the image is
        # ever executed.
        CID="$(_run docker create --entrypoint /bin/true "$TARGET" 2>/dev/null | tail -1)"
        [ -n "$CID" ] || give_up "could not create a container from $TARGET; skipping the file view."
        # -m: never restore ownership/timestamps from the archive; the copy is
        # only read. Errors are tolerated (device nodes and the like fail to
        # extract as a non-root user) as long as something lands.
        _run docker export "$CID" 2>/dev/null | tar -x -m -C "$DEST" 2>/dev/null
        docker rm -f "$CID" >/dev/null 2>&1 || true
        ;;

    BINARY)
        [ -f "$TARGET" ] || give_up "target file not found; skipping the file view."
        case "$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')" in
            *.jar|*.war|*.ear|*.zip|*.whl|*.aar|*.nupkg)
                command -v unzip >/dev/null 2>&1 \
                    || give_up "no unzip in this image; skipping the file view."
                # -qq quiet, -o overwrite, -DD no timestamps. unzip refuses
                # absolute paths and strips "../" itself.
                _run unzip -qq -o -DD "$TARGET" -d "$DEST" >/dev/null 2>&1
                ;;
            *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.tar.zst)
                _run tar -xf "$TARGET" -m -C "$DEST" 2>/dev/null
                ;;
            *)
                # An ELF executable, a .deb, an .rpm: not an archive this step
                # can open. The scan itself still works; only the file view is
                # unavailable, and saying so beats an empty tree.
                give_up "$(basename "$TARGET") is not an archive this step can open; no file view."
                ;;
        esac
        ;;

    *)
        give_up "unsupported mode: $MODE"
        ;;
esac

# Nothing landed: treat it as a failure rather than publishing an empty tree.
if [ -z "$(find "$DEST" -mindepth 1 -print -quit 2>/dev/null)" ]; then
    give_up "nothing could be unpacked from $TARGET; no file view."
fi

# Over the cap: the copy is unusable as a faithful view, and keeping it would
# leave gigabytes in the container's filesystem for the rest of the run.
SIZE_KB="$(du -sk "$DEST" 2>/dev/null | awk '{print $1}')"
if [ -n "$SIZE_KB" ] && [ "$SIZE_KB" -gt "$MAX_KB" ]; then
    give_up "unpacked copy is $((SIZE_KB / 1024)) MiB (over the $((MAX_KB / 1024)) MiB limit); no file view."
fi

echo "$DEST"
