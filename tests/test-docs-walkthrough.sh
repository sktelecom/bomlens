#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-docs-walkthrough.sh — run the user guides exactly as a reader would and
# prove the documented commands still work AND produce every artifact the page
# promises. A user copies commands out of the docs and runs them verbatim; if a
# flag, an output name, a spec version or a scan mode changed, the walkthrough
# breaks for them while every other test stays green.
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
# are left out. A page's marked blocks run in order in ONE shell, so a later
# block can read an earlier block's output. Where a page's prose names an input
# the reader is assumed to have (a supplier ZIP, an SBOM handed over by a team),
# the page's prep hook below materializes exactly that object — the doc text
# itself stays verbatim. The pairing rule: if a page's prose declares a
# placeholder, prep_page() must define it; renaming one without the other fails
# this harness. (See docs/maintainers/runnable-doc-blocks.md.)
#
# Usage:   bash tests/test-docs-walkthrough.sh
# Env:     SBOM_SCANNER_IMAGE  scanner image (default: sbom-scanner:test)
#          VERBOSE=true        echo the walkthrough script and scan log on failure
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
SCANNER_IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"
# docker-image.md's blocks name the published image verbatim — that is the whole
# point of running them (a reader pastes exactly this). The CI docs job tags its
# freshly built image with this name; the nightly user journey pulls the real one.
PUBLISHED_IMG="ghcr.io/sktelecom/bomlens:latest"

# Pages whose runnable blocks we execute.
#   page :: prep-key :: image-kind
#     prep-key    'root' = no prep, run from the repo root (the page's commands
#                 reference repo-relative paths); anything else = a fresh workdir
#                 under tests/test-workspace/docs/ plus that prep_page() case.
#     image-kind  'test'      the page runs scan-sbom.sh, honoring $SCANNER_IMG
#                 'published' the page's blocks name $PUBLISHED_IMG verbatim;
#                             executed only when that exact tag is present.
TARGETS=$(cat <<'EOF'
docs/start/first-scan.md       :: root      :: test
docs/reference/ecosystems.md   :: root      :: test
docs/guides/by-input.md        :: by-input  :: test
docs/guides/server-delivery.md :: merge     :: test
docs/reference/docker-image.md :: dockerimg :: published
EOF
)

# Every artifact a page's prose/tables promise for its runnable commands.
#   page :: artifact-glob (relative to the page's workdir) :: optional jq assert
EXPECT=$(cat <<'EOF'
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_bom.json        :: .bomFormat=="CycloneDX" and .specVersion=="1.6"
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_NOTICE.txt      ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_NOTICE.html     ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_security.json   ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_security.md     ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_security.html   ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_risk-report.md  ::
docs/start/first-scan.md :: MyApp_1.0.0/MyApp_1.0.0_risk-report.html ::
docs/reference/ecosystems.md :: NodeExample_1.0.0/NodeExample_1.0.0_bom.json :: .bomFormat=="CycloneDX" and .specVersion=="1.6"
docs/guides/by-input.md :: team1-app_1.0.0/team1-app_1.0.0_bom.json          :: .bomFormat=="CycloneDX"
docs/guides/by-input.md :: team1-app_1.0.0/team1-app_1.0.0_NOTICE.txt        ::
docs/guides/by-input.md :: team1-app_1.0.0/team1-app_1.0.0_risk-report.md    ::
docs/guides/by-input.md :: team2-app_1.0.0/team2-app_1.0.0_bom.json          :: .bomFormat=="CycloneDX"
docs/guides/by-input.md :: team2-app_1.0.0/team2-app_1.0.0_NOTICE.txt        ::
docs/guides/by-input.md :: team2-app_1.0.0/team2-app_1.0.0_risk-report.md    ::
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_bom.json        :: .bomFormat=="CycloneDX" and .specVersion=="1.6"
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_NOTICE.txt      ::
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_risk-report.md  ::
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_conformance.json ::
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_conformance.md   ::
docs/guides/by-input.md :: team4-proj_2.0.0/team4-proj_2.0.0_conformance.html ::
docs/guides/server-delivery.md :: mms-relay-server_1.0.0/mms-relay-server_1.0.0_bom.json :: [.components[]?.properties[]? | select(.name=="bomlens:layer")] | length > 0
docs/guides/server-delivery.md :: mms-relay-server_1.0.0/mms-relay-server_1.0.0_NOTICE.txt ::
docs/guides/server-delivery.md :: mms-relay-server_1.0.0/mms-relay-server_1.0.0_risk-report.md ::
docs/reference/docker-image.md :: MyApp_1.0.0_bom.json          :: .bomFormat=="CycloneDX"
docs/reference/docker-image.md :: Nginx_alpine_bom.json         :: .bomFormat=="CycloneDX"
docs/reference/docker-image.md :: Nginx_alpine_NOTICE.txt       ::
docs/reference/docker-image.md :: Nginx_alpine_security.json    ::
docs/reference/docker-image.md :: Nginx_alpine_risk-report.md   ::
EOF
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
have_published=0
[ "$have_docker" = 1 ] && docker image inspect "$PUBLISHED_IMG" >/dev/null 2>&1 && have_published=1

# Nth '::'-separated field of a manifest line, whitespace-trimmed.
field() { printf '%s' "$1" | awk -F'::' -v n="$2" '{gsub(/^[ \t]+|[ \t]+$/, "", $n); print $n}'; }

# Emit the shell lines of every <!-- runnable --> bash block in a markdown file.
runnable_blocks() {
    awk '
        /^[[:space:]]*<!-- runnable -->[[:space:]]*$/ { armed = 1; next }
        armed { armed = 0; if ($0 ~ /^```bash[[:space:]]*$/) infence = 1; next }
        infence && /^```[[:space:]]*$/ { infence = 0; next }
        infence { print }
    ' "$1"
}

# Materialize the placeholder inputs a page's prose names, into the workdir.
# $1 = prep-key, $2 = workdir. Runs in the harness shell so exports (the guide's
# "keep the script path in a variable" $SBOM convention) reach the eval below.
prep_page() {
    case "$1" in
        by-input)
            export SBOM="$ROOT/scripts/scan-sbom.sh"
            # Scenario 2: "a team handed you the source as a ZIP".
            if command -v zip >/dev/null 2>&1; then
                (cd "$ROOT/examples" && zip -qr "$2/team2-app.zip" nodejs -x 'nodejs/node_modules/*')
            else
                (cd "$ROOT/examples" && python3 -m zipfile -c "$2/team2-app.zip" nodejs)
            fi
            # Scenario 4: "a team handed you an SBOM (JSON)". An SPDX document,
            # so the page's "converted to CycloneDX internally" claim (and the
            # 1.6 specVersion of the converted output) is actually exercised —
            # a CycloneDX input would pass through keeping its own specVersion.
            cp "$ROOT/tests/fixtures/good-spdx.json" "$2/team4-sbom.json"
            ;;
        merge)
            export SBOM="$ROOT/scripts/scan-sbom.sh"
            # The three per-layer SBOMs the server guide's earlier steps produce.
            cp "$ROOT/tests/fixtures/good-cyclonedx.json"      "$2/mms-relay-os_6.10_bom.json"
            cp "$ROOT/tests/fixtures/cdxgen-node-managed.json" "$2/mms-relay-app_2.0.0_bom.json"
            cp "$ROOT/tests/fixtures/good-cyclonedx.json"      "$2/mms-relay-bin_2.0.0_bom.json"
            ;;
        dockerimg)
            # "Analyze a source directory" mounts $(pwd) as /src.
            cp -R "$ROOT/examples/nodejs/." "$2/"
            ;;
    esac
}

echo "=================================================="
echo " docs walkthrough (image: $SCANNER_IMG present=$have_image," \
     "published: $PUBLISHED_IMG present=$have_published)"
echo "=================================================="

while IFS= read -r entry; do
    [ -z "${entry//[[:space:]]/}" ] && continue
    page="$(field "$entry" 1)"
    prep="$(field "$entry" 2)"
    kind="$(field "$entry" 3)"
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

    if [ "$kind" = "published" ]; then
        if [ "$have_published" != 1 ]; then
            skip "$page: execution ($PUBLISHED_IMG not present — CI tags the built image as it; nightly pulls the real one)"
            continue
        fi
    elif [ "$have_image" != 1 ]; then
        skip "$page: execution (scanner image '$SCANNER_IMG' not available)"
        continue
    fi

    # Workdir: 'root' pages run at the repo root, exactly where the guide tells
    # the reader to be (their commands use repo-relative paths). Every other
    # page gets a fresh folder — Docker-shareable, since it lives in the tree.
    if [ "$prep" = "root" ]; then
        wd="$ROOT"
    else
        wd="$ROOT/tests/test-workspace/docs/$(basename "$page" .md)"
        rm -rf "$wd"; mkdir -p "$wd"
        prep_page "$prep" "$wd"
    fi

    [ "${VERBOSE:-}" = "true" ] && { echo "    --- walkthrough script ---"; printf '%s\n' "$script" | sed 's/^/    /'; }
    log="$(mktemp)"
    if ( cd "$wd" && set -e && eval "$script" ) >"$log" 2>&1; then
        pass "$page: documented commands ran clean"
    else
        fail "$page: documented commands failed" "$(tail -5 "$log")"
        [ "${VERBOSE:-}" = "true" ] && sed 's/^/       /' "$log"
    fi

    # Every artifact the page promises must exist (and satisfy its jq assert).
    while IFS= read -r exp; do
        [ -z "${exp//[[:space:]]/}" ] && continue
        [ "$(field "$exp" 1)" = "$page" ] || continue
        glob="$(field "$exp" 2)"
        assert="$(field "$exp" 3)"
        found=""
        for f in "$wd"/$glob; do [ -e "$f" ] && { found="$f"; break; }; done
        if [ -z "$found" ]; then
            fail "$page: promised artifact $glob not produced"
            continue
        fi
        # The docker-image.md blocks are raw `docker run` invocations: the
        # container writes artifacts as root, so on a rootful daemon (CI) they
        # land root-owned and this non-root harness cannot read them. Reclaim
        # readability only when needed (a no-op locally, where Docker Desktop
        # already maps them to the invoking user), so the jq assert can run.
        if [ ! -r "$found" ]; then
            sudo chown "$(id -u):$(id -g)" "$found" 2>/dev/null \
                || sudo chmod a+r "$found" 2>/dev/null || true
        fi
        if [ -n "$assert" ]; then
            if jq -e "$assert" "$found" >/dev/null 2>&1; then
                pass "$page: $glob (assert ok)"
            else
                # Dump what the file actually is (size, jq parse error, head) so
                # an environment-specific failure is self-diagnosing instead of
                # needing a local re-run to guess at.
                fail "$page: $glob exists but violates: $assert" \
                    "size=$(wc -c <"$found" 2>/dev/null) bytes; jq: $(jq -e "$assert" "$found" 2>&1 | head -1); head: $(head -c 200 "$found" 2>/dev/null | tr '\n' ' ')"
            fi
        else
            pass "$page: $glob"
        fi
    done <<< "$EXPECT"

    # Clean the artifacts the walkthrough wrote. Root-owned outputs from the
    # direct docker-run pages need sudo to remove on a rootful daemon; fall back
    # to it only if the plain rm leaves the tree behind (no-op locally).
    if [ "$prep" = "root" ]; then
        for out in "$ROOT/MyApp_1.0.0" "$ROOT/NodeExample_1.0.0"; do
            rm -rf "$out" 2>/dev/null || sudo rm -rf "$out" 2>/dev/null || true
        done
    else
        rm -rf "$wd" 2>/dev/null
        [ -d "$wd" ] && sudo rm -rf "$wd" 2>/dev/null || true
    fi
    rm -f "$log"
done <<< "$TARGETS"

echo ""
echo "=================================================="
echo " PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [ "$FAIL" -gt 0 ]; then
    echo " Failed:"
    for t in "${FAILED[@]}"; do echo "   - $t"; done
fi
echo "=================================================="
[ "$FAIL" -eq 0 ]
