#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-verify-release.sh: No-Docker unit tests for
# scripts/verify-release.sh's check_secondary_image(), the step-3 loop that
# confirms the four opt-in images (firmware/aibom/deep-cve/deep-license) are pullable at
# a release's version tag.
#
# The rest of verify-release.sh needs a real `gh` CLI, a real network, and a
# 40-minute docs-walkthrough run, so it has no test coverage of its own; this
# function is the one piece cheap enough to lift out and drive against a
# stubbed `docker` on PATH, the same technique test-image-refresh.sh uses for
# scan-sbom.sh's functions.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/verify-release.sh"
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

body="$(extract_fn check_secondary_image)"
if [ -z "$body" ]; then
    echo "[ERROR] could not lift check_secondary_image out of verify-release.sh (was it renamed?)"; exit 1
fi
eval "$body"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# A fake docker answering only `pull <img>`, `image inspect <img>` and
# `rmi <img>`, the three subcommands check_secondary_image uses. Behavior
# per case via files this test writes under $WORK:
#   pull-mode   - ok | fail-then-ok | never (default: ok)
# Every call is appended to docker-calls.log so a case can assert exactly
# what ran (in particular, that rmi only follows a successful pull).
cat > "$WORK/bin/docker" <<'MOCK'
#!/bin/bash
echo "$*" >> "$FAKE_DOCKER_DIR/docker-calls.log"
mode="$(cat "$FAKE_DOCKER_DIR/pull-mode" 2>/dev/null || echo ok)"
case "$1" in
    pull)
        case "$mode" in
            ok) exit 0 ;;
            fail-then-ok)
                n="$(cat "$FAKE_DOCKER_DIR/pull-attempts" 2>/dev/null || echo 0)"
                n=$((n + 1))
                echo "$n" > "$FAKE_DOCKER_DIR/pull-attempts"
                [ "$n" -ge 2 ] && exit 0
                exit 1
                ;;
            never) exit 1 ;;
        esac
        ;;
    image)
        [ "$2" = "inspect" ] || { echo "unhandled: $*" >&2; exit 1; }
        case "$mode" in
            never) exit 1 ;;
            *) exit 0 ;;
        esac
        ;;
    rmi) exit 0 ;;
esac
echo "fake docker: unhandled invocation: $*" >&2
exit 1
MOCK
chmod +x "$WORK/bin/docker"

export FAKE_DOCKER_DIR="$WORK"
PATH="$WORK/bin:$PATH"
export PATH

echo "== a pullable image reports success and is removed again =="
echo ok > "$WORK/pull-mode"
: > "$WORK/docker-calls.log"
deadline=$(( $(date +%s) + 5 ))
if out="$(check_secondary_image ghcr.io/acme/bomlens-firmware:1.0 "$deadline" 2>&1)"; then
    echo "$out" | grep -qF '✓ pulled ghcr.io/acme/bomlens-firmware:1.0' \
        && pass "success line names the image" \
        || fail "success line missing or wrong" "$out"
    grep -qF 'rmi ghcr.io/acme/bomlens-firmware:1.0' "$WORK/docker-calls.log" \
        && pass "image removed again after a successful pull" \
        || fail "rmi was not called after success"
else
    fail "check_secondary_image reported failure for an always-succeeding pull" "$out"
fi

echo "== a pull that fails once then succeeds still passes, without waiting out the deadline =="
echo fail-then-ok > "$WORK/pull-mode"
rm -f "$WORK/pull-attempts"
: > "$WORK/docker-calls.log"
start=$(date +%s)
deadline=$(( start + 5 ))
if out="$(check_secondary_image ghcr.io/acme/bomlens-aibom:1.0 "$deadline" 1 2>&1)"; then
    pass "recovers before the deadline once a retry succeeds"
else
    fail "did not recover from a single failed pull" "$out"
fi
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 5 ] \
    && pass "did not wait out the full deadline once the pull succeeded" \
    || fail "took ${elapsed}s despite the second pull succeeding immediately"

echo "== a pull that never succeeds fails cleanly once the deadline passes =="
echo never > "$WORK/pull-mode"
: > "$WORK/docker-calls.log"
deadline=$(( $(date +%s) - 1 ))  # already past: exercises the deadline check without waiting
if out="$(check_secondary_image ghcr.io/acme/bomlens-deep-cve:1.0 "$deadline" 1 2>&1)"; then
    fail "reported success for an image that was never pullable" "$out"
else
    echo "$out" | grep -qF '❌ could not pull ghcr.io/acme/bomlens-deep-cve:1.0 before the shared deadline' \
        && pass "failure line names the image" \
        || fail "failure line missing or wrong" "$out"
fi
if grep -q '^rmi ' "$WORK/docker-calls.log"; then
    fail "rmi was called even though the pull never succeeded"
else
    pass "no rmi call for an image that was never actually pulled"
fi

echo "== a shared deadline is not reset per image in the real step-4 for-loop =="
# Reproduces verify-release.sh's actual usage: one deadline computed once,
# then passed unchanged to check_secondary_image for each of the three
# images in a for-loop. A regression here (e.g. recomputing "now + budget"
# inside the loop instead of reusing the shared variable) would silently
# give each image a fresh full budget again -- exactly the bug this shared-
# deadline design replaced. never mode never pulls, so the loop's own retry
# sleeps are what would reveal a reset: with a 2s shared deadline and a 1s
# retry interval, two images sharing it exhaust the deadline once, not twice.
echo never > "$WORK/pull-mode"
: > "$WORK/docker-calls.log"
start=$(date +%s)
shared_deadline=$(( start + 2 ))
for img in ghcr.io/acme/bomlens-firmware:1.0 ghcr.io/acme/bomlens-aibom:1.0; do
    check_secondary_image "$img" "$shared_deadline" 1 >/dev/null 2>&1
done
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 4 ] \
    && pass "second image in the loop did not get its own fresh 2s budget (took ${elapsed}s, not ~4s)" \
    || fail "loop took ${elapsed}s -- looks like the deadline was reset per image instead of shared"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
