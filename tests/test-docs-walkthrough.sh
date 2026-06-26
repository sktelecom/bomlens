#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-docs-walkthrough.sh — run the getting-started guide exactly as a reader
# would and prove the documented commands still work. A user copies the install
# and first-scan steps out of the docs and runs them verbatim; if a flag, an
# output name or a scan mode changed, the walkthrough breaks for them while every
# other test stays green. This harness executes the commands the docs mark as
# runnable and checks the promised artifact appears.
#
# Runnable blocks are opted in with an HTML comment on the line immediately
# before the fence (invisible in the rendered docs):
#
#     <!-- runnable -->
#     ```bash
#     ./scripts/scan-sbom.sh --project MyApp --version 1.0.0 --target examples/nodejs --all --generate-only
#     ```
#
# Blocks without the marker (placeholder URLs, `--ui` server, OS install steps)
# are left out. The marked blocks of a page run in order from the repo root in
# one shell, so a later block can read an earlier block's output.
#
# Usage:   bash tests/test-docs-walkthrough.sh
# Env:     SBOM_SCANNER_IMAGE  scanner image (default: sbom-scanner:test)
#          VERBOSE=true        echo the walkthrough script and scan log on failure
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
SCANNER_IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"

# Pages whose runnable blocks we execute, and the artifact each must produce.
# (page : expected-artifact-glob). Scans land in a per-run {Project}_{Version}/
# subfolder by default, which is what the documented command produces and what
# the docs show — so the artifact lives under that subfolder.
TARGETS=(
    "docs/start/first-scan.md:MyApp_1.0.0/MyApp_1.0.0_bom.json"
)

PASS=0; FAIL=0; SKIP=0
FAILED=()
pass() { echo "  PASS $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); FAILED+=("$1"); [ -n "${2:-}" ] && echo "       ↳ $2"; }
skip() { echo "  SKIP $1"; SKIP=$((SKIP + 1)); }

have_docker=0
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1
have_image=0
[ "$have_docker" = 1 ] && docker image inspect "$SCANNER_IMG" >/dev/null 2>&1 && have_image=1

# Emit the shell lines of every <!-- runnable --> bash block in a markdown file.
runnable_blocks() {
    awk '
        /^[[:space:]]*<!-- runnable -->[[:space:]]*$/ { armed = 1; next }
        armed { armed = 0; if ($0 ~ /^```bash[[:space:]]*$/) infence = 1; next }
        infence && /^```[[:space:]]*$/ { infence = 0; next }
        infence { print }
    ' "$1"
}

echo "=================================================="
echo " docs walkthrough (image: $SCANNER_IMG, present=$have_image)"
echo "=================================================="

for entry in "${TARGETS[@]}"; do
    page="${entry%%:*}"
    artifact="${entry##*:}"
    echo "- $page"

    if [ ! -f "$page" ]; then
        fail "$page: file missing"
        continue
    fi

    script="$(runnable_blocks "$page")"
    if [ -z "${script//[[:space:]]/}" ]; then
        # A page in TARGETS with no runnable block is a regression: someone
        # dropped the markers, silently removing the page from this guard.
        fail "$page: no <!-- runnable --> blocks found (markers lost?)"
        continue
    fi
    pass "$page: $(printf '%s\n' "$script" | grep -c .) runnable command line(s) extracted"

    if [ "$have_image" != 1 ]; then
        skip "$page: execution (scanner image '$SCANNER_IMG' not available)"
        continue
    fi

    # Run the marked blocks verbatim from the repo root, exactly where the guide
    # tells the reader to be. Outputs land in the repo root (cwd anchor), so the
    # later jq block reads them from the same place.
    [ "${VERBOSE:-}" = "true" ] && { echo "    --- walkthrough script ---"; printf '%s\n' "$script" | sed 's/^/    /'; }
    log="$(mktemp)"
    if ( cd "$ROOT" && set -e && eval "$script" ) >"$log" 2>&1; then
        pass "$page: documented commands ran clean"
    else
        fail "$page: documented commands failed" "$(tail -5 "$log")"
        [ "${VERBOSE:-}" = "true" ] && sed 's/^/       /' "$log"
    fi

    if compgen -G "$ROOT/$artifact" >/dev/null; then
        if jq -e '.bomFormat=="CycloneDX"' "$ROOT/$artifact" >/dev/null 2>&1; then
            pass "$page: produced valid CycloneDX $artifact"
        else
            fail "$page: $artifact is not valid CycloneDX"
        fi
    else
        fail "$page: expected artifact $artifact not produced"
    fi

    # Clean the artifacts the walkthrough wrote into the repo root.
    rm -f "$ROOT"/MyApp_1.0.0_* 2>/dev/null
    rm -f "$log"
done

echo ""
echo "=================================================="
echo " PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [ "$FAIL" -gt 0 ]; then
    echo " Failed:"
    for t in "${FAILED[@]}"; do echo "   - $t"; done
fi
echo "=================================================="
[ "$FAIL" -eq 0 ]
