#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-disk-check.sh - No-Docker tests for the image size notes and the free
# disk check: the size table (docker/lib/image-sizes.json), the verdict function
# in source-detect.sh, the CLI stopping before a download, and check-setup.sh.
# A fake `docker` answers the few calls these paths make; BOMLENS_FAKE_FREE_MB
# stands in for the engine's free space.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/proj" "$WORK/home"
printf 'requests==2.31.0\n' > "$WORK/proj/requirements.txt"

# A docker that is up and has no image yet ($FAKE_HAVE_IMAGES=1: has them all).
# `image ls` lists two tags of one image and one cdxgen image; `inspect --format
# {{.Size}}` reports bytes; `run ... df` prints a df line with $FAKE_DF_MB free.
# Every call is logged to $WORK/docker.log.
cat > "$WORK/bin/docker" <<'MOCK'
#!/bin/bash
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
    info) exit 0 ;;
    image)
        case "$2" in
            inspect)
                case "$*" in
                    *"{{.Size}}"*) echo 1420000000; exit 0 ;;
                esac
                [ "${FAKE_HAVE_IMAGES:-0}" = 1 ] && exit 0
                exit 1 ;;
            ls)
                printf 'aaa111 ghcr.io/sktelecom/bomlens:1.15.0\naaa111 ghcr.io/sktelecom/bomlens:latest\nbbb222 ghcr.io/cdxgen/cdxgen-python312:13.5.0\nccc333 bomlens-retest:main\n'
                exit 0 ;;
        esac
        exit 0 ;;
    run)
        case "$*" in
            *" df "*|*"--entrypoint df"*)
                [ -n "${FAKE_DF_MB:-}" ] || exit 1
                # FAKE_MSYS=1: Git Bash, which turns the "/" argument into its
                # own install folder unless MSYS_NO_PATHCONV is set.
                [ "${FAKE_MSYS:-0}" != 1 ] || [ "${MSYS_NO_PATHCONV:-}" = 1 ] || exit 1
                printf 'Filesystem 1M-blocks Used Available Capacity Mounted on\noverlay 100000 1 %s 1%% /\n' "$FAKE_DF_MB"
                exit 0 ;;
        esac
        exit 0 ;;
    pull) exit 0 ;;
    *) exit 0 ;;
esac
MOCK
chmod +x "$WORK/bin/docker"
export FAKE_DOCKER_LOG="$WORK/docker.log"

# --- the size table
# shellcheck source=docker/lib/source-detect.sh
. "$ROOT_DIR/docker/lib/source-detect.sh"
for pair in "ghcr.io/cdxgen/cdxgen-debian-dotnet9:13.5.0=14700" \
            "registry.example/mirror/cdxgen/cdxgen-python312:13.5.0=4860" \
            "ghcr.io/cdxgen/cdxgen:13.5.0=16000" \
            "bomlens-android-sdk34:latest=6300" \
            "ghcr.io/sktelecom/bomlens@sha256:abc=1420"; do
    ref="${pair%=*}"; want="${pair#*=}"
    got="$(image_size_mb "$ref")"
    if [ "$got" = "$want" ]; then pass "size of $ref is $want MB"; else fail "size of $ref" "got '$got', want $want"; fi
done
if image_size_mb "ghcr.io/example/unknown:1" >/dev/null; then fail "an unlisted image has no size"; else pass "an unlisted image has no size"; fi
note="$(image_size_note ghcr.io/cdxgen/cdxgen-debian-dotnet9:13.5.0)"
case "$note" in *"about 14.7 GB"*"약 14.7GB"*) pass "the note gives the size in both languages" ;; *) fail "size note" "$note" ;; esac
if [ -z "$(image_size_note ghcr.io/example/unknown:1)" ]; then pass "no note for an unlisted image"; else fail "no note for an unlisted image"; fi

# --- the verdict
export PATH="$WORK/bin:$PATH"
# The host disk under the engine's VM is measured on macOS and Windows; a large
# stand-in keeps the cases below about the engine's own value.
export BOMLENS_FAKE_HOST_FREE_MB=999999999
verdict() {  # verdict <free MB or empty> [image]
    local rc=0
    BOMLENS_FAKE_FREE_MB="$1" disk_check_verdict "${2:-ghcr.io/cdxgen/cdxgen-python312:13.5.0}" || rc=$?
    echo "$rc"
}
[ "$(verdict 6000)" = 1 ] && pass "6000 MB free for a 4860 MB image (needs 6908): short" || fail "short verdict"
[ "$(verdict 7000)" = 0 ] && pass "7000 MB free for a 4860 MB image: enough" || fail "enough verdict"
[ "$(verdict 6908)" = 0 ] && pass "free space equal to size plus 2 GB: enough" || fail "boundary verdict"
[ "$(BOMLENS_SKIP_DISK_CHECK=1 verdict 100)" = 0 ] && pass "BOMLENS_SKIP_DISK_CHECK=1 skips the check" || fail "skip"
[ "$(verdict 100 ghcr.io/example/unknown:1)" = 0 ] && pass "an unlisted image is never blocked" || fail "unlisted verdict"
v="$(unset BOMLENS_FAKE_FREE_MB; FAKE_DF_MB='' verdict '')"
[ "$v" = 2 ] && pass "free space that cannot be measured is reported as unknown (2)" || fail "unknown verdict" "$v"
v="$(unset BOMLENS_FAKE_FREE_MB; FAKE_DF_MB=7000 verdict '')"
[ "$v" = 0 ] && pass "df through the engine is read when no override is set" || fail "df read" "$v"
v="$(BOMLENS_FAKE_HOST_FREE_MB=3000 verdict 900000)"
[ "$v" = 1 ] && pass "a host disk with less room than the engine's VM reports decides the verdict" || fail "host smaller verdict" "$v"
v="$(unset BOMLENS_FAKE_FREE_MB; BOMLENS_FAKE_HOST_FREE_MB=30000 FAKE_DF_MB=973220 engine_free_mb)"
[ "$v" = 30000 ] && pass "the VM disk's maximum size is not taken as free space when the host has less" || fail "host min" "$v"
v="$(unset BOMLENS_FAKE_FREE_MB; BOMLENS_FAKE_HOST_FREE_MB=999999 FAKE_DF_MB=7000 engine_free_mb)"
[ "$v" = 7000 ] && pass "the engine's value is kept when it is the smaller one" || fail "engine min" "$v"
v="$(unset BOMLENS_FAKE_HOST_FREE_MB; uname() { echo Linux; }; host_vm_disk_free_mb || echo none)"
[ "$v" = none ] && pass "on Linux the host disk is not measured (the engine's disk is the host's)" || fail "linux host" "$v"
v="$(FAKE_HAVE_IMAGES=1 verdict 10)"
[ "$v" = 0 ] && pass "an image that is already here needs no space" || fail "present image verdict" "$v"

# --- the CLI stops before the download
run_cli() {  # run_cli <free MB> [env...]; stdout in $WORK/out, stderr in $WORK/err
    local free="$1"; shift
    : > "$FAKE_DOCKER_LOG"
    ( cd "$WORK/proj" && env HOME="$WORK/home" BOMLENS_FAKE_FREE_MB="$free" "$@" \
        bash "$SCRIPT" --project p --version 1 --generate-only >"$WORK/out" 2>"$WORK/err" )
    RC=$?
}
run_cli 1000
if [ "$RC" = 1 ] && grep -q '^\[ERROR\] Not enough free disk space' "$WORK/err" \
   && grep -q 'BOMLENS_SKIP_DISK_CHECK=1' "$WORK/err" && grep -q 'docker image prune' "$WORK/err"; then
    pass "short disk stops the CLI with the cause, the way out and the cleanup on stderr"
else
    fail "short disk stops the CLI" "rc=$RC err=$(head -c 400 "$WORK/err")"
fi
if grep -q '^pull ' "$FAKE_DOCKER_LOG"; then fail "nothing is downloaded when the disk is short"; else pass "nothing is downloaded when the disk is short"; fi
grep -q 'about 4.9 GB' "$WORK/out" && pass "the expected size is printed before the stop" || fail "size printed" "$(head -c 300 "$WORK/out")"
run_cli 1000 BOMLENS_SKIP_DISK_CHECK=1
if grep -q 'Not enough free disk space' "$WORK/err"; then fail "BOMLENS_SKIP_DISK_CHECK=1 lets the scan go on"; else pass "BOMLENS_SKIP_DISK_CHECK=1 lets the scan go on"; fi
run_cli 50000
if grep -q 'Not enough free disk space' "$WORK/err"; then fail "enough disk lets the scan go on"; else pass "enough disk lets the scan go on"; fi
run_cli 1000 FAKE_HAVE_IMAGES=1
if grep -q 'Not enough free disk space' "$WORK/err"; then fail "images already here are not checked"; else pass "images already here are not checked"; fi

# --- check-setup.sh
setup() {  # setup <script> <free MB>
    PATH="$WORK/bin:$PATH" SBOM_LANG=en BOMLENS_FAKE_FREE_MB="$2" FAKE_HAVE_IMAGES=1 UI_PORT=1 \
        bash "$1" "$WORK/proj" 2>&1
}
out="$(setup "$ROOT_DIR/scripts/check-setup.sh" 30000)"
case "$out" in *"Total size of these images: 2.8 GB"*) pass "check-setup lists the images with a total (an image counted once)" ;; *) fail "check-setup total" "$out" ;; esac
case "$out" in *"Free disk space in the Docker engine: 30.0 GB"*"docker image prune -a"*"fstrim"*) pass "check-setup shows free space and the cleanup commands" ;; *) fail "check-setup free space" "$out" ;; esac
case "$out" in *"Scanner image is present: ghcr.io/sktelecom/bomlens:latest"*) pass "an unreleased checkout checks the latest tag" ;; *) fail "unstamped tag" "$out" ;; esac
out="$(setup "$ROOT_DIR/scripts/check-setup.sh" 3000)"
case "$out" in *"Free disk space in the Docker engine is low: 3.0 GB"*) pass "check-setup flags low free space" ;; *) fail "check-setup low space" "$out" ;; esac
out="$(BOMLENS_FAKE_HOST_FREE_MB=3000 setup "$ROOT_DIR/scripts/check-setup.sh" 900000)"
case "$out" in *"Free disk space in the Docker engine is low: 3.0 GB"*) pass "check-setup uses the host disk when it has less room than the VM reports" ;; *) fail "check-setup host disk" "$out" ;; esac
out="$(SBOM_SCANNER_IMAGE=bomlens-retest:main setup "$ROOT_DIR/scripts/check-setup.sh" 30000)"
if printf '%s\n' "$out" | grep -Eq '^ +bomlens-retest:main +1\.4 GB$'; then
    pass "check-setup lists the scanner image SBOM_SCANNER_IMAGE names in the image sizes"
else
    fail "check-setup own image" "$out"
fi
# Git Bash: the df probe reaches docker unconverted, so the free-disk line is
# there. A stand-in uname and cygpath make this shell look like Git Bash.
mkdir -p "$WORK/msysbin"
printf '#!/bin/sh\necho MINGW64_NT-10.0-19045\n' > "$WORK/msysbin/uname"
printf '#!/bin/sh\nshift; [ "$1" = -l ] && shift; [ "$1" = -- ] && shift; printf "C:%%s" "$1"\n' > "$WORK/msysbin/cygpath"
chmod +x "$WORK/msysbin/uname" "$WORK/msysbin/cygpath"
out="$(FAKE_MSYS=1 BOMLENS_FAKE_FREE_MB='' FAKE_DF_MB=30000 BOMLENS_FAKE_HOST_FREE_MB=900000 \
    PATH="$WORK/msysbin:$WORK/bin:$PATH" SBOM_LANG=en FAKE_HAVE_IMAGES=1 UI_PORT=1 bash "$ROOT_DIR/scripts/check-setup.sh" "$WORK/proj" 2>&1)"
case "$out" in *"Free disk space in the Docker engine: 30.0 GB"*) pass "check-setup reads the engine's free disk under Git Bash" ;; *) fail "check-setup free disk under Git Bash" "$out" ;; esac
sed 's/@BOMLENS_VERSION@/1.15.0/' "$ROOT_DIR/scripts/check-setup.sh" > "$WORK/check-setup-stamped.sh"
out="$(setup "$WORK/check-setup-stamped.sh" 30000)"
case "$out" in *"Scanner image is present: ghcr.io/sktelecom/bomlens:1.15.0"*) pass "a release bundle checks the image of its own version" ;; *) fail "stamped tag" "$out" ;; esac

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
