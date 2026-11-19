#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-image-refresh.sh — No-Docker unit tests for scan-sbom.sh's image
# freshness check (SBOM_PULL / ensure_image_fresh).
#
# The defect this guards: `docker run` only auto-pulls an image that is
# entirely ABSENT locally; once a floating tag like `:latest` has been pulled
# once, it is reused forever even after the registry publishes a newer image.
# A stale cached ghcr.io/sktelecom/bomlens:latest predated
# docker/lib/scan-figshare.py, and a real scan failed with "python3: can't
# open file scan-figshare.py" until someone thought to `docker pull` by hand.
#
# The functions are lifted out of scan-sbom.sh rather than re-implemented, so
# this tests the shipping code. `docker` itself is a stub script (no daemon,
# no network), driven by files this test drops under $WORK before each case.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

extract_fn() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$SCRIPT"
}

for fn in log_warn log_error ensure_image_fresh _refresh_image_quietly; do
    body="$(extract_fn "$fn")"
    if [ -z "$body" ]; then
        echo "[ERROR] could not lift $fn out of scan-sbom.sh (was it renamed?)"; exit 1
    fi
    eval "$body"
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# A fake docker answering only `image inspect <img>` and `pull <img>`, the two
# subcommands ensure_image_fresh/_refresh_image_quietly use. Behavior is
# chosen per case via two files this test writes under $WORK:
#   present     — touch to make `image inspect` report the image is local
#   pull-mode   — up-to-date | progress | stall | fail (default: up-to-date)
# Every invocation is appended to docker-calls.log so a case can assert
# whether `pull` was attempted at all (SBOM_PULL=missing on an absent image
# must never call it, and SBOM_PULL=never must not either).
cat > "$WORK/bin/docker" <<'MOCK'
#!/bin/bash
echo "$*" >> "$FAKE_DOCKER_DIR/docker-calls.log"
case "$1" in
    image)
        if [ "$2" = "inspect" ] && [ -f "$FAKE_DOCKER_DIR/present" ]; then exit 0; fi
        exit 1
        ;;
    pull)
        img="$2"
        mode="$(cat "$FAKE_DOCKER_DIR/pull-mode" 2>/dev/null || echo up-to-date)"
        case "$mode" in
            up-to-date)
                echo "Status: Image is up to date for $img"
                exit 0
                ;;
            progress)
                echo "Pulling fs layer"
                sleep 1
                echo "Downloading [==>       ] 10MB/50MB"
                sleep 1
                echo "Status: Downloaded newer image for $img"
                exit 0
                ;;
            stall)
                # No output, ever. exec (not a backgrounded child of this
                # script) so killing this PID actually stops the sleep
                # instead of orphaning it.
                exec sleep 60
                ;;
            fail)
                echo "Error response from daemon: fake network failure" >&2
                exit 1
                ;;
        esac
        ;;
esac
echo "fake docker: unhandled invocation: $*" >&2
exit 1
MOCK
chmod +x "$WORK/bin/docker"

export FAKE_DOCKER_DIR="$WORK"
PATH="$WORK/bin:$PATH"
export PATH

set_present() { touch "$WORK/present"; }
set_absent() { rm -f "$WORK/present"; }
set_pull_mode() { printf '%s' "$1" > "$WORK/pull-mode"; }
reset_log() { : > "$WORK/docker-calls.log"; }
pull_was_called() { grep -q '^pull ' "$WORK/docker-calls.log" 2>/dev/null; }

echo "== SBOM_PULL=missing (default), image absent: docker run's own pull is left alone =="
set_absent
set_pull_mode fail   # would be seen as a loud failure if ever invoked
reset_log
( SBOM_PULL=missing ensure_image_fresh "fake/image:latest" )
rc=$?
if [ "$rc" -eq 0 ] && ! pull_was_called; then
    pass "an absent image triggers no pull; docker run's implicit pull covers it"
else
    fail "ensure_image_fresh touched an absent image under SBOM_PULL=missing" \
         "rc=$rc calls=$(cat "$WORK/docker-calls.log" 2>/dev/null)"
fi

echo "== SBOM_PULL=missing, image present, registry says up to date: fast, quiet refresh =="
set_present
set_pull_mode up-to-date
reset_log
start=$(date +%s)
( SBOM_PULL=missing ensure_image_fresh "fake/image:latest" )
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$rc" -eq 0 ] && pull_was_called && [ "$elapsed" -le 5 ]; then
    pass "a present, up-to-date image refreshes without stalling the run (${elapsed}s)"
else
    fail "unexpected result for an up-to-date present image" "rc=$rc elapsed=${elapsed}s"
fi

echo "== SBOM_PULL=missing, image present, registry never answers: gives up on stall =="
set_present
set_pull_mode stall
reset_log
start=$(date +%s)
( _SBOM_PULL_STALL_SECS=2 SBOM_PULL=missing ensure_image_fresh "fake/image:latest" )
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$rc" -eq 0 ] && [ "$elapsed" -ge 2 ] && [ "$elapsed" -le 10 ]; then
    pass "a stalled pull is abandoned within the idle bound (${elapsed}s), local image still used"
else
    fail "ensure_image_fresh did not bound a fully stalled pull" "rc=$rc elapsed=${elapsed}s"
fi

echo "== SBOM_PULL=always, pull fails: the run fails loudly, unlike the default =="
set_present
set_pull_mode fail
reset_log
out="$( ( SBOM_PULL=always ensure_image_fresh "fake/image:latest" ) 2>&1 )"
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q '\[ERROR\]'; then
    pass "SBOM_PULL=always surfaces a pull failure instead of silently continuing"
else
    fail "SBOM_PULL=always did not fail loudly on a pull error" "rc=$rc out=$out"
fi

echo "== SBOM_PULL=never, image present: no network touched, returns immediately =="
set_present
set_pull_mode fail   # would be seen as a loud failure if ever invoked
reset_log
( SBOM_PULL=never ensure_image_fresh "fake/image:latest" )
rc=$?
if [ "$rc" -eq 0 ] && ! pull_was_called; then
    pass "SBOM_PULL=never never calls pull, even for a present image"
else
    fail "SBOM_PULL=never touched the network" "rc=$rc calls=$(cat "$WORK/docker-calls.log" 2>/dev/null)"
fi

echo "== SBOM_PULL=never, image absent: fails loudly instead of falling back to a pull =="
set_absent
set_pull_mode fail   # would be seen as a loud failure if ever invoked
reset_log
out="$( ( SBOM_PULL=never ensure_image_fresh "fake/image:latest" ) 2>&1 )"
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'SBOM_PULL=never' && ! pull_was_called; then
    pass "SBOM_PULL=never on a missing image errors out instead of touching the network"
else
    fail "SBOM_PULL=never did not fail correctly on a missing image" "rc=$rc out=$out"
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
