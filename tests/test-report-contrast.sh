#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-report-contrast.sh - count axe color-contrast violations in the four
# generated HTML reports (risk, security, NOTICE, conformance).
#
# The reports are built hermetically from tests/fixtures/report-contrast: a
# stub `trivy` returns a canned result, grype and the EPSS/KEV lookups are
# switched off, so no network, Docker or vulnerability database is needed.
# Limitation: with the lookups off, the EPSS/KEV columns and badges are not
# rendered, so their colours are not covered by this check.
#
# Usage: tests/test-report-contrast.sh [--max-risk N] [--max-security N]
#                                      [--max-notice N] [--max-conformance N]
#   Without --max-* the run only reports the counts (always exits 0 unless the
#   reports or the browser cannot be set up). With a --max-* bound, a count
#   above it fails the run. Tighten to 0 once WP4-1 lands.
# Needs: bash, jq, node, and `npm ci` done in docker/web/frontend plus
#   `npx playwright install chromium`.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$ROOT/docker/web/frontend"
FIX="$ROOT/tests/fixtures/report-contrast"

MAX_RISK=""; MAX_SECURITY=""; MAX_NOTICE=""; MAX_CONFORMANCE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --max-risk) MAX_RISK="$2"; shift 2 ;;
        --max-security) MAX_SECURITY="$2"; shift 2 ;;
        --max-notice) MAX_NOTICE="$2"; shift 2 ;;
        --max-conformance) MAX_CONFORMANCE="$2"; shift 2 ;;
        *) echo "unknown option: $1 (see the usage header of $0)" >&2; exit 2 ;;
    esac
done

for tool in jq node; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing $tool; install it and retry" >&2; exit 2; }
done
if [ ! -d "$FRONTEND/node_modules/@axe-core/playwright" ]; then
    echo "frontend dependencies missing: run 'npm ci' in docker/web/frontend" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/out"
cat > "$WORK/bin/trivy" <<'STUB'
#!/bin/bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
cp "$RC_TRIVY_FIXTURE" "$out"
STUB
chmod +x "$WORK/bin/trivy"

export RC_TRIVY_FIXTURE="$FIX/trivy.json"
export PATH="$WORK/bin:$PATH"
export SECURITY_ENRICH=false DEEP_CVE=false
P="$WORK/out/sample_1.0"

bash "$ROOT/docker/lib/validate-sbom.sh" "$FIX/sbom.json" "$P" sample >/dev/null
bash "$ROOT/docker/lib/scan-security.sh" "$FIX/sbom.json" "$P" sample >/dev/null
bash "$ROOT/docker/lib/generate-notice.sh" "$FIX/sbom.json" "$P" sample >/dev/null 2>&1
bash "$ROOT/docker/lib/generate-risk-report.sh" "$P" sample >/dev/null
for f in risk-report security NOTICE conformance; do
    [ -s "${P}_$f.html" ] || { echo "report not generated: ${P}_$f.html" >&2; exit 1; }
done

OUT="$WORK/axe.out"
node "$ROOT/tests/report-contrast/axe-report-contrast.mjs" "$FRONTEND" \
    "${P}_risk-report.html" "${P}_security.html" "${P}_NOTICE.html" "${P}_conformance.html" \
    | tee "$OUT"
SUMMARY="$(sed -n 's/^SUMMARY //p' "$OUT")"
[ -n "$SUMMARY" ] || { echo "axe produced no summary" >&2; exit 1; }

count() { echo "$SUMMARY" | jq -r --arg k "sample_1.0_$1.html" '.[$k]'; }
RISK=$(count risk-report); SEC=$(count security); NOT=$(count NOTICE); CONF=$(count conformance)

TABLE="| Report | color-contrast violations |
|---|---|
| risk-report | $RISK |
| security | $SEC |
| NOTICE | $NOT |
| conformance | $CONF |"
echo
echo "$TABLE"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### Report color-contrast (axe)"; echo; echo "$TABLE"; } >> "$GITHUB_STEP_SUMMARY"
fi

rc=0
check() { # name count max
    if [ -n "$3" ] && [ "$2" -gt "$3" ]; then
        echo "FAIL: $1 has $2 contrast violations, limit $3" >&2
        rc=1
    fi
}
check risk "$RISK" "$MAX_RISK"
check security "$SEC" "$MAX_SECURITY"
check notice "$NOT" "$MAX_NOTICE"
check conformance "$CONF" "$MAX_CONFORMANCE"
exit "$rc"
