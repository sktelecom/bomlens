#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-engine-contract.sh - the engine contract (docs/reference/engine-contract.md).
#
# Runs docker/entrypoint.sh from this checkout (BOMLENS_LIBDIR points it at
# docker/lib), no Docker, and checks bomlens-result.json: it validates against
# schemas/engine-result-1.json, it is written when a run stops early, every step
# id is one the contract documents, and a Trivy failure is reported as a failed
# step and never as a successful run. That last check is shown to be able to
# fail: it is run once more against a copy of the scripts with the ScanError
# rule removed, and must then report the failure as hidden.
#
# Trivy is replaced by a stub on PATH, so the result does not depend on a
# vulnerability database or the network. Needs bash 4+, jq and python3;
# the full JSON Schema check also needs the jsonschema package.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The image settings of whoever runs this must not change what the plan names.
unset CDXGEN_IMAGE_PREFIX CDXGEN_ALLINONE CDXGEN_TAG
ENTRY="$ROOT_DIR/docker/entrypoint.sh"
SCHEMA="$ROOT_DIR/schemas/engine-result-1.json"
DOC="$ROOT_DIR/docs/reference/engine-contract.md"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[ERROR] bash 4 or later is required (this is $BASH_VERSION)"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Trivy stub ---------------------------------------------------------------
# TRIVY_STUB=ok writes a report with one finding; TRIVY_STUB=fail exits 1 with
# a database error on stderr, the way a missing or unreachable DB does.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/trivy" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "version" ]; then
    echo '{"Version":"0.0.0-stub","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-01-01T00:00:00Z","DownloadedAt":"2026-01-01T01:00:00Z"}}'
    exit 0
fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac
done
[ -n "${TRIVY_ENV_LOG:-}" ] && { env | grep '^TRIVY_' | grep -v '^TRIVY_ENV_LOG=' | sort > "$TRIVY_ENV_LOG"; }
[ -n "${TRIVY_HOME_LOG:-}" ] && { printf '%s\n' "$HOME" > "$TRIVY_HOME_LOG"; : > "$HOME/.written" 2>/dev/null && echo writable >> "$TRIVY_HOME_LOG"; }
if [ "${TRIVY_STUB:-ok}" = "sleep" ]; then
    : > "$TRIVY_STUB_STARTED"
    sleep 3
fi
if [ "${TRIVY_STUB:-ok}" = "fail" ]; then
    echo "FATAL	failed to download vulnerability DB: stub error" >&2
    exit 1
fi
cat > "$out" <<'JSON'
{"SchemaVersion":2,"Results":[{"Target":"bom","Type":"npm","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20",
  "PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.20"},"Severity":"HIGH","FixedVersion":"4.17.21"}]}]}
JSON
EOF
chmod +x "$WORK/bin/trivy"

# run_engine <dir> <libdir> [VAR=value ...] - a CLI-style POSTPROCESS run.
run_engine() {
    local dir="$1" lib="$2"; shift 2
    ( cd "$dir" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
        HOST_OUTPUT_DIR="$dir" BOMLENS_LIBDIR="$lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
        UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
        ENRICH_EOL=false ENRICH_MALICIOUS=false "$@" bash "$ENTRY" ) > "$dir.log" 2>&1
}

new_run() {
    local d="$WORK/$1"
    mkdir -p "$d"
    [ "${2:-}" = "empty" ] || cp "$FIX/good-cyclonedx.json" "$d/demo_1.0_bom.json"
    printf '%s' "$d"
}

# The one rule a consumer depends on most: a Trivy run that failed is a failed
# step, and the run is never reported as a plain success. Prints what is wrong.
trivy_failure_violation() {
    jq -r '
        ([.steps[] | select(.id == "scan-security")] | first) as $s
        | if $s == null then "no scan-security step"
          elif $s.status != "failed" then "scan-security is \($s.status), not failed"
          elif .run.status == "succeeded" then "run.status is succeeded"
          else empty end' "$1" 2>/dev/null || echo "manifest unreadable"
}

JSPY=""
for py in python3 python3.13 python3.12 python3.11; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c "import jsonschema" 2>/dev/null; then JSPY="$py"; break; fi
done
schema_errors() {
    [ -n "$JSPY" ] || return 0
    "$JSPY" - "$SCHEMA" "$1" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:10]))
PY
}

# Step ids and reasons the contract documents: the backticked first column of
# the step table, and the reason table, in docs/reference/engine-contract.md.
DOC_STEPS="$(sed -n '/^<!-- steps:begin -->/,/^<!-- steps:end -->/p' "$DOC" | grep -oE '^\| `[a-z0-9-]+`' | tr -d '|` ')"
DOC_REASONS="$(sed -n '/^<!-- reasons:begin -->/,/^<!-- reasons:end -->/p' "$DOC" | grep -oE '^\| `[a-z_]+`' | tr -d '|` ')"
vocab_violations() {
    local id out=""
    for id in $(jq -r '.steps[].id' "$1"); do
        printf '%s\n' "$DOC_STEPS" | grep -qx "$id" || out="$out step:$id"
    done
    for id in $(jq -r '.steps[].reason // empty' "$1"); do
        printf '%s\n' "$DOC_REASONS" | grep -qx "$id" || out="$out reason:$id"
    done
    printf '%s' "${out# }"
}

echo "== a successful run =="
OK="$(new_run ok)"
run_engine "$OK" "$ROOT_DIR/docker/lib"
rc=$?
M="$OK/bomlens-result.json"
[ "$rc" = 0 ] && pass "the run exits 0" || fail "the run exited $rc" "$(tail -5 "$OK.log")"
[ -f "$M" ] && pass "bomlens-result.json is written" || fail "no bomlens-result.json"
err="$(schema_errors "$M")"
if [ -z "$JSPY" ]; then
    echo "  SKIP: jsonschema is not installed; the field checks below still run"
else
    [ -z "$err" ] && pass "the manifest validates against schemas/engine-result-1.json" || fail "schema errors" "$err"
fi
[ "$(jq -r '.contract.name + " " + .run.status + " " + (.run.exit_code|tostring)' "$M")" = "bomlens-engine succeeded 0" ] \
    && pass "contract name, run status succeeded, exit code 0" \
    || fail "run summary is $(jq -c '[.contract, .run.status, .run.exit_code]' "$M")"
n_fix="$(jq '[.components[]?] | length' "$FIX/good-cyclonedx.json")"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.stage) \(.counts.components)"' "$M")" = "ok 1 $n_fix" ] \
    && pass "generate is a stage-1 step with the component count" \
    || fail "generate step is $(jq -c '[.steps[] | select(.id=="generate")]' "$M")"
[ "$(jq -r '[.steps[] | select(.id=="scan-security")][0].status' "$M")" = "ok" ] \
    && pass "scan-security is ok" || fail "scan-security is $(jq -c '[.steps[] | select(.id=="scan-security")]' "$M")"
for id in generate-notice sign enrich-eol enrich-malicious enrich-staleness; do
    st="$(jq -r --arg id "$id" '[.steps[] | select(.id==$id)][0].status // "missing"' "$M")"
    [ "$st" = "disabled" ] && pass "$id, turned off by a setting, is recorded as disabled" \
        || fail "$id is $st, expected disabled"
done
[ "$(jq -r '[.outputs[] | select(.role=="vulnerabilities.trivy")][0].path' "$M")" = "demo_1.0_security.json" ] \
    && pass "with no other engine, vulnerabilities.trivy is _security.json" \
    || fail "vulnerabilities.trivy is $(jq -c '[.outputs[] | select(.role=="vulnerabilities.trivy")]' "$M")"
[ "$(jq -c '.engines' "$M")" = '["trivy"]' ] && pass "engines lists trivy only" || fail "engines is $(jq -c .engines "$M")"
[ "$(jq -r '.data_sources.trivy_db.updated_at' "$M")" = "2026-01-01T00:00:00Z" ] \
    && pass "the Trivy database date is recorded" || fail "trivy_db is $(jq -c .data_sources "$M")"
bom_sha="$(jq -r '[.outputs[] | select(.role=="sbom.cyclonedx")][0].sha256' "$M")"
real_sha="$( (sha256sum "$OK/demo_1.0_bom.json" 2>/dev/null || shasum -a 256 "$OK/demo_1.0_bom.json") | cut -d' ' -f1)"
[ "$bom_sha" = "$real_sha" ] && pass "the SBOM output's sha256 matches the file" || fail "sha256 $bom_sha != $real_sha"
v="$(vocab_violations "$M")"
[ -z "$v" ] && pass "every step id and reason is in the contract document" || fail "undocumented:" "$v"
[ -n "$(trivy_failure_violation "$M")" ] \
    && pass "negative control: the Trivy-failure check reports a violation on a successful run" \
    || fail "the Trivy-failure check passed a run whose Trivy succeeded; it cannot fail"

echo "== Trivy fails (injected) =="
TF="$(new_run trivy-fail)"
run_engine "$TF" "$ROOT_DIR/docker/lib" TRIVY_STUB=fail
rc=$?
M="$TF/bomlens-result.json"
[ "$rc" = 0 ] && pass "the exit code is unchanged (0): the manifest carries the failure" || fail "the run exited $rc"
v="$(trivy_failure_violation "$M")"
[ -z "$v" ] && pass "scan-security is failed and the run is not succeeded" || fail "Trivy failure hidden: $v"
[ "$(jq -r '.run.status' "$M")" = "succeeded_degraded" ] && pass "run.status is succeeded_degraded" \
    || fail "run.status is $(jq -r .run.status "$M")"
jq -r '[.steps[] | select(.id=="scan-security")][0].detail' "$M" | grep -q "stub error" \
    && pass "the step detail carries Trivy's own message" || fail "detail is $(jq -c '[.steps[] | select(.id=="scan-security")][0].detail' "$M")"
err="$(schema_errors "$M")"
[ -z "$err" ] && pass "the failure manifest validates against the schema" || fail "schema errors" "$err"

echo "== the Trivy-failure check fails when the rule is removed =="
MUT="$WORK/lib-mutant"
cp -R "$ROOT_DIR/docker/lib" "$MUT"
# Turn off the rule that makes a ScanError a failed step, leaving the rest of
# the jq program intact, so the copy still writes a manifest.
sed -i.bak 's/and \$scanerr != ""/and false/' "$MUT/engine-result.sh"
if grep -q 'scanerr != ""' "$MUT/engine-result.sh"; then
    fail "could not remove the ScanError rule from the copy (did its text change?)"
else
    MR="$(new_run mutant)"
    run_engine "$MR" "$MUT" TRIVY_STUB=fail
    v="$(trivy_failure_violation "$MR/bomlens-result.json")"
    # Exactly this violation: a missing or unreadable manifest would also be
    # non-empty, and would not show that the rule is what the check tests.
    [ "$v" = "scan-security is ok, not failed" ] && pass "without the rule the check reports the hidden failure ($v)" \
        || fail "the check still passes without the ScanError rule; it does not test it"
fi

echo "== a run that stops early still writes the manifest =="
EA="$(new_run early empty)"
echo '{"stale":true}' > "$EA/bomlens-result.json"
run_engine "$EA" "$ROOT_DIR/docker/lib"
rc=$?
M="$EA/bomlens-result.json"
[ "$rc" != 0 ] && pass "the run fails (no SBOM to post-process)" || fail "the run exited 0"
[ "$(jq -r '.run.status + " " + (.run.exit_code|tostring)' "$M" 2>/dev/null)" = "failed $rc" ] \
    && pass "the manifest is this run's, with run.status failed and the exit code" \
    || fail "manifest is $(cat "$M" 2>/dev/null | head -c 200)"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.stage)"' "$M" 2>/dev/null)" = "failed 1" ] \
    && pass "the step it stopped in (generate) is recorded as failed" \
    || fail "generate is $(jq -c '[.steps[] | select(.id=="generate")]' "$M" 2>/dev/null)"
err="$(schema_errors "$M")"
[ -z "$err" ] && pass "the early-failure manifest validates against the schema" || fail "schema errors" "$err"

echo "== a run that stops before the project is known replaces the old manifest =="
NP="$(new_run no-project)"
cp "$OK/bomlens-result.json" "$NP/bomlens-result.json"
run_engine "$NP" "$ROOT_DIR/docker/lib" PROJECT_VERSION=
rc=$?
[ "$rc" != 0 ] && [ "$(jq -r '.run.status' "$NP/bomlens-result.json" 2>/dev/null)" = "failed" ] \
    && pass "a missing PROJECT_VERSION leaves a failed manifest, not the previous run's success" \
    || fail "rc=$rc, manifest run.status is $(jq -r '.run.status' "$NP/bomlens-result.json" 2>/dev/null)"

echo "== metadata.tools in the CycloneDX 1.4 array form =="
TA="$(new_run tools-array)"
jq '.metadata.tools = [{"vendor":"x","name":"cdxgen","version":"9.0.0"}]' "$FIX/good-cyclonedx.json" > "$TA/demo_1.0_bom.json"
run_engine "$TA" "$ROOT_DIR/docker/lib"
rc=$?
[ "$rc" = 0 ] && pass "the run still exits 0" || fail "the run exited $rc"
[ "$(jq -r '.tools.cdxgen' "$TA/bomlens-result.json" 2>/dev/null)" = "9.0.0" ] \
    && pass "the manifest is written and reads the generator from the array form" \
    || fail "tools is $(jq -c .tools "$TA/bomlens-result.json" 2>/dev/null)"

echo "== a run stopped by TERM is recorded as cancelled =="
CN="$(new_run cancel)"
( cd "$CN" && exec env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$CN" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
    UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false TRIVY_STUB=sleep TRIVY_STUB_STARTED="$WORK/stub-started" \
    bash "$ENTRY" ) > "$CN.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do [ -f "$WORK/stub-started" ] && break; sleep 0.1; done
kill -TERM "$pid" 2>/dev/null
wait "$pid"
rc=$?
[ "$rc" = 143 ] && pass "the run exits 143" || fail "the run exited $rc"
[ "$(jq -r '.run.status + " " + (.run.exit_code|tostring)' "$CN/bomlens-result.json" 2>/dev/null)" = "cancelled 143" ] \
    && pass "run.status is cancelled with exit code 143" \
    || fail "manifest run is $(jq -c .run "$CN/bomlens-result.json" 2>/dev/null)"

echo "== deep-license: disabled, not installed, no input, too large, timeout, ok =="
SRCT="$WORK/srctree"
mkdir -p "$SRCT/lib" "$SRCT/node_modules/dep"
printf 'MIT License\n' > "$SRCT/LICENSE"
printf 'x\n' > "$SRCT/lib/a.c"
printf 'x\n' > "$SRCT/lib/b.c"
printf 'x\n' > "$SRCT/node_modules/dep/index.js"
# Matched without regard to case, like scancode does: not counted either.
mkdir -p "$SRCT/Vendor"; printf 'x\n' > "$SRCT/Vendor/v.c"
cat > "$WORK/bin/scancode-stub" <<'EOF2'
#!/bin/bash
# Records its arguments and writes a minimal result; sleeps when asked.
printf '%s\n' "$@" > "$SCANCODE_STUB_ARGS"
out=""
while [ $# -gt 0 ]; do case "$1" in --json-pp) out="$2"; shift 2 ;; *) shift ;; esac; done
# A partial result first, as a scan that is stopped midway leaves behind.
echo '{"files":[' > "$out"
[ -n "${SCANCODE_STUB_SLEEP:-}" ] && sleep "$SCANCODE_STUB_SLEEP"
echo '{"files":[{"path":"LICENSE","type":"file"}]}' > "$out"
exit "${SCANCODE_STUB_RC:-0}"
EOF2
chmod +x "$WORK/bin/scancode-stub"
dl_step() { jq -r '[.steps[] | select(.id=="deep-license")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }

D="$(new_run dl-off)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT"
[ "$(dl_step "$D")" = "disabled null" ] && pass "without --deep-license the step is disabled" || fail "deep-license is $(dl_step "$D")"

D="$(new_run dl-missing)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode
[ "$(dl_step "$D")" = "skipped not_installed" ] && pass "requested on an image without scancode: skipped, not_installed" || fail "deep-license is $(dl_step "$D")"

[ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded_degraded" ] \
    && pass "a requested step that could not run makes the run succeeded_degraded, not succeeded" \
    || fail "run.status is $(jq -r .run.status "$D/bomlens-result.json") with deep-license skipped/not_installed"

D="$(new_run dl-fallback)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode BOMLENS_DEEP_LICENSE_FALLBACK=ghcr.io/example/bomlens-deep-license:latest
[ "$(dl_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped fallback succeeded_degraded" ] \
    && pass "the CLI fell back to the base image: skipped, fallback, and the run is succeeded_degraded" \
    || fail "deep-license is $(dl_step "$D"), run.status $(jq -r .run.status "$D/bomlens-result.json")"
# The same check against a copy whose run-status rule ignores skipped steps
# must fail: the assertion above is what catches "no detection, still a pass".
MUT2="$WORK/lib-mutant-skipped"
cp -R "$ROOT_DIR/docker/lib" "$MUT2"
sed -i.bak 's/or (.status == "skipped" and .reason != "no_input")//' "$MUT2/engine-result.sh"
if grep -q 'reason != "no_input"' "$MUT2/engine-result.sh"; then
    fail "could not remove the skipped rule from the copy (did its text change?)"
else
    D="$(new_run dl-fallback-mutant)"; run_engine "$D" "$MUT2" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode BOMLENS_DEEP_LICENSE_FALLBACK=x
    [ "$(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)" = "succeeded" ] \
        && pass "without that rule the same run reads succeeded, so the check above can fail" \
        || fail "the mutant run is $(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null); the check does not isolate the rule"
fi

D="$(new_run dl-noinput)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$WORK/no-such-tree" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub"
[ "$(dl_step "$D")" = "skipped no_input" ] && pass "no source tree: skipped, no_input" || fail "deep-license is $(dl_step "$D")"
[ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded" ] && pass "nothing to read (no_input) leaves the run succeeded" \
    || fail "run.status is $(jq -r .run.status "$D/bomlens-result.json") with only a no_input skip"

D="$(new_run dl-large)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-large" DEEP_LICENSE_MAX_FILES=2
[ "$(dl_step "$D")" = "skipped too_large" ] && pass "three own files over a limit of two: skipped, too_large" || fail "deep-license is $(dl_step "$D")"
[ ! -f "$WORK/args-large" ] && pass "scancode is not started for a tree over the limit" || fail "scancode ran on a tree over the limit"

D="$(new_run dl-ok)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-ok" DEEP_LICENSE_MAX_FILES=3
[ "$(dl_step "$D")" = "ok null" ] && pass "three own files at a limit of three (node_modules not counted): ok" || fail "deep-license is $(dl_step "$D")"
[ "$(jq -r '[.outputs[] | select(.role=="license-scan.scancode")][0].path' "$D/bomlens-result.json")" = "demo_1.0_scancode.json" ] \
    && pass "_scancode.json is listed as license-scan.scancode" || fail "outputs: $(jq -c '[.outputs[].role]' "$D/bomlens-result.json")"
grep -qx 'node_modules' "$WORK/args-ok" && pass "scancode is told to ignore node_modules" || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"
grep -q '^/tmp/scancode.json$' "$WORK/args-ok" && fail "scancode still writes the fixed /tmp/scancode.json" || pass "scancode writes to a per-run temporary file"
grep -qx -- '--strip-root' "$WORK/args-ok" && [ "$(tail -n 1 "$WORK/args-ok")" = "$(cd "$SRCT" && pwd)" ] \
    && pass "scancode reads the tree itself, with --strip-root" \
    || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"
grep -qx 'demo_1.0' "$WORK/args-ok" && pass "this run's own output folder is left out" || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-ok")"

DIST="$WORK/dist"; mkdir -p "$DIST/src"; printf 'x\n' > "$DIST/src/a.c"
D="$(new_run dl-distroot)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DIST" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-dist"
! grep -qx 'dist' "$WORK/args-dist" && grep -qx 'node_modules' "$WORK/args-dist" \
    && pass "a tree whose own folder is named dist: dist is not ignored, the other names still are" \
    || fail "scancode args: $(tr '\n' ' ' < "$WORK/args-dist")"

D="$(new_run dl-errors)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-err" SCANCODE_STUB_RC=1
[ "$(dl_step "$D")" = "degraded failed" ] && [ -s "$D/demo_1.0_scancode.json" ] \
    && pass "scancode errors on some files: the result is kept and the step is degraded" \
    || fail "deep-license is $(dl_step "$D"), _scancode.json present: $([ -f "$D/demo_1.0_scancode.json" ] && echo yes || echo no)"

D="$(new_run dl-broken)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-broken" SCANCODE_STUB_RC=2
[ "$(dl_step "$D")" = "failed failed" ] && [ ! -f "$D/demo_1.0_scancode.json" ] \
    && pass "scancode failing outright: failed, no result kept" || fail "deep-license is $(dl_step "$D")"

D="$(new_run dl-notsource)"; run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$FIX/good-cyclonedx.json" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub"
[ "$(dl_step "$D")" = "skipped no_input" ] && pass "asked for outside a source scan: skipped, no_input" || fail "deep-license is $(dl_step "$D")"

if command -v timeout >/dev/null 2>&1; then
    D="$(new_run dl-timeout)"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_LICENSE=true BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-to" SCANCODE_STUB_SLEEP=5 DEEP_LICENSE_TIMEOUT=1
    [ "$(dl_step "$D")" = "failed timeout" ] && pass "scancode over its time limit: failed, timeout" || fail "deep-license is $(dl_step "$D")"
    [ ! -f "$D/demo_1.0_scancode.json" ] && pass "a stopped scan leaves no partial _scancode.json" || fail "a partial _scancode.json was kept"
    [ -s "$WORK/args-to" ] && pass "(scancode had started and written part of its result)" || fail "the stub never ran"
else
    echo "  SKIP: no timeout command on this host"
fi

echo "== deep-cve: disabled, not installed, fallback, ok, failed =="
# A grype stub with no matches; GRYPE_STUB_RC=1 makes it fail as a broken
# database does. It is put on PATH only where a run should have grype.
mkdir -p "$WORK/grype-bin"
cat > "$WORK/grype-bin/grype" <<'EOF2'
#!/bin/bash
[ "${1:-}" = "db" ] && exit 1
[ "${GRYPE_STUB_RC:-0}" = 0 ] || exit "$GRYPE_STUB_RC"
echo '{"matches":[]}'
EOF2
chmod +x "$WORK/grype-bin/grype"
# PATH with any grype of this host left out, so "not installed" is tested as
# such on a host that has grype.
NOGRYPE_PATH=""
_old_ifs="$IFS"; IFS=:
for _d in $PATH; do
    if [ -x "$_d/grype" ]; then
        _nd="$WORK/nogrype$(printf '%s' "$_d" | tr '/' '_')"; mkdir -p "$_nd"
        for _f in "$_d"/*; do [ "${_f##*/}" = grype ] || ln -sf "$_f" "$_nd/"; done
        _d="$_nd"
    fi
    NOGRYPE_PATH="$NOGRYPE_PATH:$_d"
done
IFS="$_old_ifs"; NOGRYPE_PATH="${NOGRYPE_PATH#:}"
dc_step() { jq -r '[.steps[] | select(.id=="deep-cve")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }

D="$(new_run dc-off)"; PATH="$NOGRYPE_PATH" run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(dc_step "$D")" = "disabled null" ] && pass "without --deep-cve the step is disabled" || fail "deep-cve is $(dc_step "$D")"

D="$(new_run dc-missing)"; PATH="$NOGRYPE_PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true
[ "$(dc_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped not_installed succeeded_degraded" ] \
    && pass "asked for in an image without grype: skipped, not_installed, and the run is succeeded_degraded" \
    || fail "deep-cve is $(dc_step "$D"), run.status $(jq -r .run.status "$D/bomlens-result.json")"

D="$(new_run dc-fallback)"; PATH="$NOGRYPE_PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true BOMLENS_DEEP_CVE_FALLBACK="the grype image was not available: ghcr.io/example/bomlens-deep-cve:latest"
[ "$(dc_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped fallback succeeded_degraded" ] \
    && pass "the CLI fell back from the deep-cve image: skipped, fallback, and the run is succeeded_degraded" \
    || fail "deep-cve is $(dc_step "$D"), run.status $(jq -r .run.status "$D/bomlens-result.json")"

D="$(new_run dc-ok)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true
[ "$(dc_step "$D")" = "ok null" ] && [ -f "$D/demo_1.0_security_grype.json" ] \
    && pass "grype ran and wrote its result: ok" || fail "deep-cve is $(dc_step "$D")" "$(grep -i 'nvd-cpe\|grype' "$D.log" | head -3)"

D="$(new_run dc-failed)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true GRYPE_STUB_RC=1
[ "$(dc_step "$D")" = "failed failed" ] && pass "grype failed: failed" || fail "deep-cve is $(dc_step "$D")"

D="$(new_run dc-false)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=false
{ [ "$(dc_step "$D")" = "disabled null" ] && [ ! -f "$D/demo_1.0_security_grype.json" ]; } \
    && pass "DEEP_CVE=false in an image with grype: disabled, and grype does not run" || fail "deep-cve is $(dc_step "$D")"

D="$(new_run dc-nosec)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true GENERATE_SECURITY=false
[ "$(dc_step "$D")" = "disabled null" ] && pass "without --security the step is disabled, as scan-security is" || fail "deep-cve is $(dc_step "$D")"

D="$(new_run dc-reason)"; PATH="$NOGRYPE_PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true \
    BOMLENS_DEEP_CVE_FALLBACK="SBOM_SCANNER_IMAGE (bomlens:dev) is a local build and SBOM_DEEP_CVE_IMAGE is not set, so no deep-cve image of the same build was used"
[ "$(jq -r '[.steps[] | select(.id=="deep-cve")][0] | "\(.status) \(.reason) \(.detail)"' "$D/bomlens-result.json")" \
    = "skipped fallback SBOM_SCANNER_IMAGE (bomlens:dev) is a local build and SBOM_DEEP_CVE_IMAGE is not set, so no deep-cve image of the same build was used" ] \
    && pass "the CLI's reason for staying off the deep-cve image is the step's detail" \
    || fail "deep-cve is $(jq -c '[.steps[] | select(.id=="deep-cve")][0]' "$D/bomlens-result.json")"

# The CLI kept the stage on an image of the user's own that has grype (built
# with SBOM_DEEP_CVE=true): the match runs and its real outcome is recorded.
D="$(new_run dc-own-grype)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" DEEP_CVE=true \
    BOMLENS_DEEP_CVE_FALLBACK="SBOM_SCANNER_IMAGE (registry.example/team/scanner:2.0) is not a BomLens image name and SBOM_DEEP_CVE_IMAGE is not set, so no deep-cve image of the same build was used"
{ [ "$(dc_step "$D")" = "ok null" ] && [ -f "$D/demo_1.0_security_grype.json" ]; } \
    && pass "a kept image that has grype runs the match: ok, not skipped" || fail "deep-cve is $(dc_step "$D")"

# A firmware scan: the firmware image's own pipeline, stubbed here, with
# DEEP_CVE=true as an older CLI passed it. The step is disabled and the run
# is not degraded by it.
FWLIB="$WORK/lib-fw"; rm -rf "$FWLIB"; cp -R "$ROOT_DIR/docker/lib" "$FWLIB"
printf '#!/bin/bash\ncp "%s" "$2"\n' "$FIX/good-cyclonedx.json" > "$FWLIB/scan-firmware.sh"
printf 'FW\n' > "$WORK/fw.bin"
D="$(new_run dc-firmware empty)"; PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$FWLIB" MODE=FIRMWARE TARGET_FILE="$WORK/fw.bin" DEEP_CVE=true
[ "$(jq -r '[.steps[] | select(.id=="deep-cve")][0] | "\(.status) \(.detail)"' "$D/bomlens-result.json" 2>/dev/null)" = "disabled grype CPE matching does not apply to a FIRMWARE scan" ] \
    && pass "a firmware scan handed DEEP_CVE=true records deep-cve as disabled" \
    || fail "firmware deep-cve is $(jq -c '[.steps[] | select(.id=="deep-cve")][0]' "$D/bomlens-result.json" 2>&1)" "$(tail -3 "$D.log")"

echo "== deep-license run before stage 2 (BOMLENS_DEEP_LICENSE_RC) =="
# The CLI runs deep-license.sh in the deep-license image, then stage 2 on the
# deep-cve image: stage 2 keeps the file (also through the stale-artifact
# sweep) and records the step from the exit code.
D="$(new_run dl-handed)"; echo '{"files":[{"path":"LICENSE","type":"file"}]}' > "$D/demo_1.0_scancode.json"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true \
    BOMLENS_SCANCODE=/nonexistent/scancode BOMLENS_DEEP_LICENSE_RC=0 BOMLENS_DEEP_LICENSE_STARTED=2026-01-02T03:04:05Z \
    BOMLENS_DEEP_LICENSE_ENDED=2026-01-02T03:09:05Z
{ [ "$(dl_step "$D")" = "ok null" ] && [ "$(dc_step "$D")" = "ok null" ] && [ -f "$D/demo_1.0_scancode.json" ] \
    && [ "$(jq -r '[.steps[] | select(.id=="deep-license")][0] | "\(.started_at) \(.ended_at)"' "$D/bomlens-result.json")" = "2026-01-02T03:04:05Z 2026-01-02T03:09:05Z" ] \
    && jq -e '[.outputs[]? | select(.role=="license-scan.scancode")] | length == 1' "$D/bomlens-result.json" >/dev/null \
    && [ "$(jq -r .run.status "$D/bomlens-result.json")" = succeeded ]; } \
    && pass "a handed-on licence scan: deep-license and deep-cve both ok, _scancode.json kept and listed, the run succeeded" \
    || fail "handed deep-license: $(dl_step "$D") / $(dc_step "$D"), $(jq -r .run.status "$D/bomlens-result.json")" "$(jq -c '[.outputs[]?.role]' "$D/bomlens-result.json")"
D="$(new_run dl-handed-none)"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true BOMLENS_DEEP_LICENSE_RC=0
[ "$(dl_step "$D")" = "failed failed" ] && pass "exit code 0 handed on with no _scancode.json: failed" || fail "deep-license is $(dl_step "$D")"
D="$(new_run dl-handed-3)"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true BOMLENS_DEEP_LICENSE_RC=3
{ [ "$(dl_step "$D")" = "skipped not_installed" ] && grep -qF "scancode was not in the image the licence scan ran on" "$D.log"; } \
    && pass "exit code 3 handed on: not_installed, said of the image the licence scan ran on" || fail "deep-license is $(dl_step "$D")"
# A handed-on code other than 0 or 6: an earlier run's _scancode.json is
# removed with the other leftovers rather than reported as this run's.
D="$(new_run dl-handed-5)"; echo '{"files":[{"path":"OLD","type":"file"}]}' > "$D/demo_1.0_scancode.json"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true BOMLENS_DEEP_LICENSE_RC=5
{ [ "$(dl_step "$D")" = "failed timeout" ] && [ ! -f "$D/demo_1.0_scancode.json" ] \
    && jq -e '[.outputs[]? | select(.role=="license-scan.scancode")] | length == 0' "$D/bomlens-result.json" >/dev/null; } \
    && pass "exit code 5 handed on: failed (timeout), and an earlier _scancode.json is removed, not listed" \
    || fail "deep-license is $(dl_step "$D"), _scancode.json present: $([ -f "$D/demo_1.0_scancode.json" ] && echo yes || echo no)"
D="$(new_run dl-handed-bad)"; echo '{"files":[]}' > "$D/demo_1.0_scancode.json"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode \
    BOMLENS_DEEP_LICENSE_RC="$(printf '0\nx')"
{ [ "$(dl_step "$D")" = "skipped not_installed" ] && [ ! -f "$D/demo_1.0_scancode.json" ]; } \
    && pass "a handed-on code with a second line is not taken as one" || fail "deep-license is $(dl_step "$D")"

# deep-license.sh alone, as a caller runs it before stage 2: a run that does
# not finish removes the output file an earlier run left.
dl_alone() {
    local out="$WORK/dl-alone/out_scancode.json"
    mkdir -p "$WORK/dl-alone"; echo '{"files":[]}' > "$out"
    env BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-alone" "$@" \
        bash "$ROOT_DIR/docker/lib/deep-license.sh" "$SRCT" "$out" >/dev/null 2>&1
    DL_ALONE_RC=$?
    [ -f "$out" ] && DL_ALONE_LEFT=yes || DL_ALONE_LEFT=no
}
dl_alone SCANCODE_STUB_RC=2
[ "$DL_ALONE_RC $DL_ALONE_LEFT" = "1 no" ] && pass "deep-license.sh failing (1) removes an earlier output" || fail "exit $DL_ALONE_RC, earlier output left: $DL_ALONE_LEFT"
dl_alone DEEP_LICENSE_MAX_FILES=1
[ "$DL_ALONE_RC $DL_ALONE_LEFT" = "4 no" ] && pass "deep-license.sh over the file limit (4) removes an earlier output" || fail "exit $DL_ALONE_RC, earlier output left: $DL_ALONE_LEFT"
if command -v timeout >/dev/null 2>&1; then
    dl_alone SCANCODE_STUB_SLEEP=5 DEEP_LICENSE_TIMEOUT=1
    [ "$DL_ALONE_RC $DL_ALONE_LEFT" = "5 no" ] && pass "deep-license.sh timed out (5) removes an earlier output" || fail "exit $DL_ALONE_RC, earlier output left: $DL_ALONE_LEFT"
else
    echo "  SKIP: no timeout command on this host"
fi
dl_alone
[ "$DL_ALONE_RC $DL_ALONE_LEFT" = "0 yes" ] && pass "deep-license.sh done (0) writes its output" || fail "exit $DL_ALONE_RC, output: $DL_ALONE_LEFT"
# SIGTERM (docker stop with --init, a web UI cancel): the script stops
# scancode at once, exits 143 and leaves no output.
mkdir -p "$WORK/dl-term"; echo '{"files":[]}' > "$WORK/dl-term/out.json"
env BOMLENS_SCANCODE="$WORK/bin/scancode-stub" SCANCODE_STUB_ARGS="$WORK/args-term" SCANCODE_STUB_SLEEP=20 \
    bash "$ROOT_DIR/docker/lib/deep-license.sh" "$SRCT" "$WORK/dl-term/out.json" >/dev/null 2>&1 &
_term_pid=$!
for _i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/args-term" ] && break; sleep 0.5; done
_term_t0=$(date +%s); kill -TERM "$_term_pid"; wait "$_term_pid"; _term_rc=$?; _term_t1=$(date +%s)
{ [ "$_term_rc" = 143 ] && [ $((_term_t1 - _term_t0)) -lt 5 ] && [ ! -f "$WORK/dl-term/out.json" ]; } \
    && pass "deep-license.sh stops on SIGTERM at once with exit 143 and no output" \
    || fail "SIGTERM: exit $_term_rc after $((_term_t1 - _term_t0))s, output left: $([ -f "$WORK/dl-term/out.json" ] && echo yes || echo no)"

# Stage 2 on the deep-cve image with no licence scan handed on: the message
# and the manifest name the deep-cve image, not a missing deep-license image.
D="$(new_run dl-on-dc)"
PATH="$WORK/grype-bin:$PATH" run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$SRCT" DEEP_CVE=true DEEP_LICENSE=true BOMLENS_SCANCODE=/nonexistent/scancode
{ [ "$(dl_step "$D")" = "skipped not_installed" ] && grep -qF "runs on the deep-cve image, which has grype but not scancode" "$D.log" \
    && jq -e '[.steps[] | select(.id=="deep-license")][0].detail | test("deep-cve image")' "$D/bomlens-result.json" >/dev/null; } \
    && pass "deep-license asked for on the deep-cve image says so" \
    || fail "deep-license on the deep-cve image: $(jq -c '[.steps[] | select(.id=="deep-license")][0]' "$D/bomlens-result.json")" "$(grep -F 'deep-license' "$D.log" | head -2)"

echo "== license-registry: fill, replace, confirm, no answer, lookup failed (fixtures, no network) =="
LRF="$WORK/lr-fixtures"
mkdir -p "$LRF"
echo '{"licenses":["MIT"]}' > "$LRF/npm_lodash_4.17.21.json"
echo '{"licenses":["MIT"]}' > "$LRF/maven_org.slf4j_slf4j-api_2.0.13.json"
echo '{"licenses":["GPL-3.0-only"]}' > "$LRF/pypi_gplpkg_1.0.json"
cat > "$WORK/lr-bom.json" <<'EOF2'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"demo","version":"1.0","bom-ref":"root"}},
 "components":[
  {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","bom-ref":"a"},
  {"type":"library","name":"slf4j-api","version":"2.0.13","purl":"pkg:maven/org.slf4j/slf4j-api@2.0.13","bom-ref":"b","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"mysql-connector-java","version":"8.0.33","purl":"pkg:maven/mysql/mysql-connector-java@8.0.33","bom-ref":"c","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"gplpkg","version":"1.0","purl":"pkg:pypi/gplpkg@1.0","bom-ref":"d","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
  {"type":"library","name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0","bom-ref":"e","licenses":[{"license":{"id":"Apache-2.0"}}]}
 ]}
EOF2
lic() { jq -r --arg n "$2" '[.components[] | select(.name==$n)][0] | [(.licenses[]? | .expression // .license.id), ((.properties // []) | map(select(.name=="bomlens:license:superseded"))[0].value // "-")] | join(" ")' "$1/demo_1.0_bom.json"; }

D="$(new_run lr-off)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"; run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0].status' "$D/bomlens-result.json")" = "disabled" ] \
    && pass "off by default: recorded as disabled" || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "off by default: nothing is filled" || fail "lodash is '$(lic "$D" lodash)'"

D="$(new_run lr-on)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(lic "$D" lodash)" = "MIT -" ] && pass "a component with no licence is filled from the registry" || fail "lodash is '$(lic "$D" lodash)'"
jq -e '[.components[] | select(.name=="lodash")][0].properties | any(.name=="bomlens:licenseSource" and .value=="registry (deps.dev)")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "the filled licence is marked as coming from the registry" || fail "no bomlens:licenseSource on lodash"
[ "$(lic "$D" slf4j-api)" = "MIT GPL-2.0-only" ] && pass "a single GPL the registry contradicts is replaced, the old value kept" || fail "slf4j-api is '$(lic "$D" slf4j-api)'"
[ "$(lic "$D" mysql-connector-java)" = "GPL-2.0-only -" ] && pass "a GPL the registry has no answer for is kept" || fail "mysql-connector-java is '$(lic "$D" mysql-connector-java)'"
[ "$(lic "$D" gplpkg)" = "GPL-3.0-only -" ] && pass "a GPL the registry confirms is kept, with no superseded mark" || fail "gplpkg is '$(lic "$D" gplpkg)'"
[ "$(lic "$D" requests)" = "Apache-2.0 -" ] && pass "a licence not on the verify list is not asked about" || fail "requests is '$(lic "$D" requests)'"
[ "$(jq -c '[.steps[] | select(.id=="license-registry")][0] | [.status, .counts.candidates, .counts.filled, .counts.superseded, .counts.confirmed, .counts.not_found]' "$D/bomlens-result.json")" = '["ok",4,1,1,1,1]' ] \
    && pass "the manifest records the step as ok with its counts" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"

D="$(new_run lr-err)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
mkdir -p "$WORK/lr-bad"; cp "$LRF"/*.json "$WORK/lr-bad/"; echo 'not json' > "$WORK/lr-bad/npm_lodash_4.17.21.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$WORK/lr-bad"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.lookup_failed)"' "$D/bomlens-result.json")" = "degraded unavailable 1" ] \
    && pass "a lookup that failed leaves the step degraded (unavailable)" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "a failed lookup changes nothing for that component" || fail "lodash is '$(lic "$D" lodash)'"

D="$(new_run lr-unreachable)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_API=http://127.0.0.1:9/v3
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.lookup_failed)"' "$D/bomlens-result.json")" = "degraded unavailable 4" ] \
    && pass "an endpoint that does not answer (LICENSE_REGISTRY_API): degraded, unavailable, every lookup counted as failed" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" slf4j-api)" = "GPL-2.0-only -" ] \
    && pass "with no answer the recorded licences are left as they were" || fail "slf4j-api is '$(lic "$D" slf4j-api)'"

echo "== license-registry: evidence, deprecated ids, mixed answers, nesting, supplier SBOMs, budget =="
echo '{"licenses":["MIT"]}' > "$LRF/npm_withtext_1.0.json"
echo '{"licenses":["MIT"]}' > "$LRF/npm_concluded_1.0.json"
echo '{"licenses":["GPL-2.0-or-later"]}' > "$LRF/npm_oldid_1.0.json"
echo '{"licenses":["GPL-2.0-only","MIT"]}' > "$LRF/maven_org.x_dual_1.0.json"
echo '{"licenses":["MIT","non-standard"]}' > "$LRF/npm_nonstd_1.0.json"
echo '{"licenses":["MIT"]}' > "$LRF/npm_freetext_1.0.json"
echo '{"licenses":["Apache-2.0"]}' > "$LRF/npm_inner_1.0.json"
cat > "$WORK/lr-bom2.json" <<'EOF2'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"demo","version":"1.0","bom-ref":"root"}},
 "components":[
  {"type":"library","name":"withtext","version":"1.0","purl":"pkg:npm/withtext@1.0","bom-ref":"a","licenses":[{"license":{"url":"https://example.com/LICENSE","text":{"content":"Proprietary terms"}}}]},
  {"type":"library","name":"concluded","version":"1.0","purl":"pkg:npm/concluded@1.0","bom-ref":"b","licenses":[{"license":{"id":"GPL-3.0-only","acknowledgement":"concluded"}}]},
  {"type":"library","name":"oldid","version":"1.0","purl":"pkg:npm/oldid@1.0","bom-ref":"c","licenses":[{"license":{"id":"GPL-2.0+"}}]},
  {"type":"library","name":"dual","version":"1.0","purl":"pkg:maven/org.x/dual@1.0","bom-ref":"d","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"library","name":"nonstd","version":"1.0","purl":"pkg:npm/nonstd@1.0","bom-ref":"e","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
  {"type":"library","name":"freetext","version":"1.0","purl":"pkg:npm/freetext@1.0","bom-ref":"f","licenses":[{"license":{"name":"GNU General Public License v2.0"}}]},
  {"type":"library","name":"outer","version":"1.0","purl":"pkg:npm/outer@1.0","bom-ref":"g","licenses":[{"license":{"id":"MIT"}}],
   "components":[{"type":"library","name":"inner","version":"1.0","purl":"pkg:npm/inner@1.0","bom-ref":"h"}]}
 ]}
EOF2
D="$(new_run lr-edge)"; cp "$WORK/lr-bom2.json" "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
jq -e '[.components[] | select(.name=="withtext")][0].licenses[0].license.text.content == "Proprietary terms"' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a licence given only as text and url is kept, not filled over" || fail "withtext is $(jq -c '[.components[] | select(.name=="withtext")][0].licenses' "$D/demo_1.0_bom.json")"
[ "$(lic "$D" concluded)" = "GPL-3.0-only -" ] && pass "a concluded licence is not checked against the registry" || fail "concluded is '$(lic "$D" concluded)'"
[ "$(lic "$D" oldid)" = "GPL-2.0+ -" ] && pass "GPL-2.0+ against GPL-2.0-or-later is a confirmation, not a replacement" || fail "oldid is '$(lic "$D" oldid)'"
[ "$(lic "$D" dual)" = "GPL-2.0-only -" ] && pass "an answer that lists the recorded licence among others confirms it" || fail "dual is '$(lic "$D" dual)'"
[ "$(lic "$D" nonstd)" = "GPL-3.0-only -" ] && pass "an answer with a non-standard licence is not used" || fail "nonstd is '$(lic "$D" nonstd)'"
[ "$(lic "$D" freetext)" = "MIT GPL-2.0-only" ] && pass "a GPL written as free text is normalized first, then checked" || fail "freetext is '$(lic "$D" freetext)'"
jq -e '[.components[] | select(.name=="outer")][0].components[0].licenses[0] | (.expression // .license.id) == "Apache-2.0"' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a nested component is filled" || fail "inner is $(jq -c '[.components[] | select(.name=="outer")][0].components' "$D/demo_1.0_bom.json")"
jq -e '[.components[] | select(.name=="freetext")][0].properties | any(.name=="bomlens:licenseClass" and .value=="permissive")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a replaced licence is classified again (normalize runs after a change)" || fail "freetext props $(jq -c '[.components[] | select(.name=="freetext")][0].properties' "$D/demo_1.0_bom.json")"
run_again="$(new_run lr-again)"; cp "$D/demo_1.0_bom.json" "$run_again/demo_1.0_bom.json"
run_engine "$run_again" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.counts.filled) \(.counts.superseded)"' "$run_again/bomlens-result.json")" = "0 0" ] \
    && pass "a second run over its own output changes nothing" || fail "second run: $(jq -c '[.steps[] | select(.id=="license-registry")][0].counts' "$run_again/bomlens-result.json")"

D="$(new_run lr-analyze)"
run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$WORK/lr-bom.json" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF"
[ "$(lic "$D" slf4j-api)" = "GPL-2.0-only -" ] && [ "$(lic "$D" lodash)" = "MIT -" ] \
    && pass "a supplier's SBOM (ANALYZE): a missing licence is filled, a declared one is never replaced" \
    || fail "slf4j-api '$(lic "$D" slf4j-api)', lodash '$(lic "$D" lodash)'"

D="$(new_run lr-budget)"; cp "$WORK/lr-bom.json" "$D/demo_1.0_bom.json"
_t0=$(date +%s)
run_engine "$D" "$ROOT_DIR/docker/lib" LICENSE_REGISTRY=true LICENSE_REGISTRY_FIXTURE_DIR="$LRF" LICENSE_REGISTRY_FIXTURE_DELAY=6 LICENSE_REGISTRY_BUDGET=1
_t1=$(date +%s)
[ "$(jq -r '[.steps[] | select(.id=="license-registry")][0] | "\(.status) \(.reason) \(.counts.budget_reached)"' "$D/bomlens-result.json")" = "degraded budget_exhausted 4" ] \
    && pass "answers slower than the budget: degraded, budget_exhausted, all four counted" \
    || fail "license-registry is $(jq -c '[.steps[] | select(.id=="license-registry")]' "$D/bomlens-result.json")"
[ "$(lic "$D" lodash)" = "-" ] && pass "what did not answer in time is left as it was" || fail "lodash is '$(lic "$D" lodash)'"
echo "  (license-registry with a 1 s budget and 6 s answers took $((_t1 - _t0)) s for the whole run)"

echo "== a source that declares dependencies but yields no component =="
DECL="$WORK/declares"; mkdir -p "$DECL"
printf '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "2.31.0"\n' > "$DECL/pyproject.toml"
NODECL="$WORK/declares-nothing"; mkdir -p "$NODECL"
printf '[tool.poetry.dependencies]\npython = "^3.11"\n' > "$NODECL/pyproject.toml"
empty_bom() { echo '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"x","version":"1"}},"components":[]}' > "$1/demo_1.0_bom.json"; }
gen_of() { jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }
D="$(new_run empty-declared empty)"; empty_bom "$D"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DECL"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "degraded no_components succeeded_degraded" ] \
    && pass "generate is degraded (no_components) and the run succeeded_degraded" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json")"
jq -r '.metadata.properties[]? | select(.name=="bomlens:sbom-empty-with-manifests") | .value' "$D/demo_1.0_bom.json" | grep -qx 'pyproject.toml' \
    && pass "the SBOM names the manifest in bomlens:sbom-empty-with-manifests" \
    || fail "SBOM properties: $(jq -c '.metadata.properties' "$D/demo_1.0_bom.json")"
err="$(schema_errors "$D/bomlens-result.json")"
[ -z "$err" ] && pass "the no_components manifest validates against the schema" || fail "schema errors" "$err"
# A resolver step that failed is the likely reason, and is named.
D="$(new_run empty-step-failed empty)"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"x","version":"1"},"properties":[{"name":"bomlens:pipeline-step-failed","value":"gradle-dependencies"}]},"components":[]}' > "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DECL"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0].detail' "$D/bomlens-result.json")" = "manifests found: pyproject.toml; steps that failed: gradle-dependencies" ] \
    && pass "the no_components detail names the resolver steps that failed" \
    || fail "no_components detail: $(jq -r '[.steps[] | select(.id=="generate")][0].detail' "$D/bomlens-result.json")"
# A later step that fills the SBOM (here the conda sidecar build-prep leaves
# for the merge) means the scan did find the dependencies: no flag.
D="$(new_run empty-then-filled empty)"; empty_bom "$D"
printf 'dependencies:\n  - numpy=1.26.4\n' > "$DECL/environment.yml"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"numpy","version":"1.26.4","purl":"pkg:conda/numpy@1.26.4","properties":[{"name":"bomlens:layer","value":"conda"}]}]}' > "$D/demo_1.0_conda.cdx.json"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$DECL"
rm -f "$DECL/environment.yml"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "ok null succeeded" ] \
    && ! jq -e 'any(.metadata.properties[]?; .name=="bomlens:sbom-empty-with-manifests")' "$D/demo_1.0_bom.json" >/dev/null \
    && pass "a component added by a later step (conda merge) leaves no empty-manifest flag" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json"), components $(jq '.components | length' "$D/demo_1.0_bom.json")"
D="$(new_run empty-undeclared empty)"; empty_bom "$D"; run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$NODECL"
[ "$(gen_of "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "ok null succeeded" ] \
    && pass "a manifest with nothing declared and no component is a plain success" \
    || fail "generate is $(gen_of "$D"), run $(jq -r .run.status "$D/bomlens-result.json")"
# Against a copy whose manifest finder finds nothing, the declared case must
# read succeeded: that is the "no detection, still a pass" the check catches.
MUT3="$WORK/lib-mutant-manifests"
cp -R "$ROOT_DIR/docker/lib" "$MUT3"
printf '\nsource_manifests() { printf ""; }\n' >> "$MUT3/source-detect.sh"
D="$(new_run empty-declared-mutant empty)"; empty_bom "$D"; run_engine "$D" "$MUT3" SOURCE_ROOT="$DECL"
[ "$(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)" = "succeeded" ] \
    && pass "without the manifest check the same run reads succeeded, so the check above can fail" \
    || fail "the mutant run is $(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)"

echo "== MODE=PLAN: the execution plan of a source scan =="
PLAN_SCHEMA="$ROOT_DIR/schemas/engine-plan-1.json"
plan_schema_errors() {
    if [ -z "$JSPY" ]; then
        # Locally a missing jsonschema skips the check; in CI it must run.
        [ -n "${CI:-}" ] && echo "jsonschema is not installed, so the plan was not validated"
        return 0
    fi
    "$JSPY" - "$PLAN_SCHEMA" "$1" <<'PY'
import json, sys
import jsonschema
v = jsonschema.Draft202012Validator(json.load(open(sys.argv[1])))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in v.iter_errors(json.load(open(sys.argv[2])))))
PY
}
plan_run() {  # plan_run <case> <source-dir> [VAR=value ...]
    local d="$WORK/plan-$1" src="$2"; shift 2; mkdir -p "$d"
    ( cd "$d" && env MODE=PLAN PROJECT_NAME=demo PROJECT_VERSION=1.0 SOURCE_ROOT="$src" HOST_OUTPUT_DIR="$d" \
        BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_IMAGE_REF=ghcr.io/example/bomlens:1 \
        BOMLENS_IMAGE_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
        "$@" bash "$ENTRY" ) > "$d.log" 2>&1
    echo $? > "$d.rc"
    printf '%s' "$d"
}
PSRC="$WORK/plan-src-node"; mkdir -p "$PSRC"; echo '{"name":"x","dependencies":{"lodash":"^4"}}' > "$PSRC/package.json"
P="$(plan_run node "$PSRC")"
[ -f "$P/bomlens-plan.json" ] && pass "MODE=PLAN writes bomlens-plan.json" || fail "no plan" "$(tail -5 "$P.log")"
err="$(plan_schema_errors "$P/bomlens-plan.json")"
[ -z "$err" ] && pass "the plan validates against schemas/engine-plan-1.json" || fail "plan schema errors" "$err"
[ "$(jq -r '.status + " " + .input.detected_ecosystem + " " + .stages[0].image' "$P/bomlens-plan.json")" = "ok node ghcr.io/cdxgen/cdxgen-alpine-node24:13.5.0" ] \
    && pass "a Node.js source plans the cdxgen Node.js image" || fail "plan: $(jq -c '[.status, .input, .stages[0].image]' "$P/bomlens-plan.json")"
[ "$(jq -r '.stages[0].image_digest' "$P/bomlens-plan.json")" = "$(jq -r '.digests["ghcr.io/cdxgen/cdxgen-alpine-node24"]' "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
    && pass "stage 1 is pinned by digest" || fail "stage 1 digest is $(jq -r '.stages[0].image_digest' "$P/bomlens-plan.json")"
[ "$(jq -r '.stages[0].args | join(" ")' "$P/bomlens-plan.json")" = "/tmp/build-prep.sh /app /out/demo_1.0_bom.json 1.6" ] \
    && pass "stage 1 runs build-prep.sh with the CLI's arguments" || fail "stage 1 args: $(jq -c '.stages[0].args' "$P/bomlens-plan.json")"
cmp -s "$P/bomlens-plan/build-prep.sh" "$ROOT_DIR/docker/lib/build-prep.sh" && [ -f "$P/bomlens-plan/identify-conda.py" ] \
    && pass "the files stage 1 mounts are copied next to the plan" || fail "bomlens-plan/ holds: $(ls "$P/bomlens-plan" 2>&1)"
[ "$(jq -r '.stages[1] | .image + " " + .env.MODE + " " + .env.BOMLENS_RUN_INPUT' "$P/bomlens-plan.json")" = "ghcr.io/example/bomlens:1 POSTPROCESS demo_1.0_bom.json" ] \
    && pass "stage 2 is this image in POSTPROCESS mode on stage 1's SBOM" || fail "stage 2: $(jq -c '.stages[1] | [.image, .env]' "$P/bomlens-plan.json")"
[ "$(jq -r '[.stages[0].mounts[] | select(.role=="source") | .mode] | first' "$P/bomlens-plan.json") $(jq -r '[.stages[1].mounts[] | select(.role=="source") | .mode] | first' "$P/bomlens-plan.json")" = "rw ro" ] \
    && pass "the source is writable in stage 1 only" || fail "source mounts: $(jq -c '[.stages[].mounts[] | select(.role=="source")]' "$P/bomlens-plan.json")"
PSRC2="$WORK/plan-src-android"; mkdir -p "$PSRC2/app"
printf 'plugins { id "com.android.application" }\nandroid { compileSdk 34 }\n' > "$PSRC2/app/build.gradle"; : > "$PSRC2/settings.gradle"
printf 'plugins { id "com.android.application" }\n' > "$PSRC2/build.gradle"
P="$(plan_run android "$PSRC2")"
[ "$(jq -r '.status + " " + .reason + " " + (.stages | length | tostring)' "$P/bomlens-plan.json")" = "unsupported android-sdk-image 0" ] \
    && pass "an Android source is unsupported (the SDK image is not published), with no stages" \
    || fail "android plan: $(jq -c '[.status, .reason, .detail]' "$P/bomlens-plan.json")"
[ "$(cat "$P.rc") $(jq -r '[.steps[] | select(.id=="plan")][0] | "\(.status) \(.reason)"' "$P/bomlens-result.json") $(jq -r .run.status "$P/bomlens-result.json")" = "0 skipped not_installed succeeded_degraded" ] \
    && pass "an unsupported plan exits 0 and the manifest says plan skipped (not_installed), run succeeded_degraded" \
    || fail "rc $(cat "$P.rc"), manifest $(jq -c '[.run.status, .steps]' "$P/bomlens-result.json")"

P="$(plan_run node-opts "$PSRC" BYTE_STABLE=true GOTOOLCHAIN=local HOST_UID=501 HOST_GID=20)"
[ "$(jq -r '.stages[0].env | "\(.FETCH_LICENSE) \(.HOST_GOTOOLCHAIN)"' "$P/bomlens-plan.json")" = "false local" ] \
    && pass "BYTE_STABLE turns stage 1's license lookup off; GOTOOLCHAIN reaches it as HOST_GOTOOLCHAIN" \
    || fail "stage 1 env: $(jq -c '.stages[0].env' "$P/bomlens-plan.json")"
[ "$(jq -r '.stages[0].env | "\(.GOPATH) \(.GOMODCACHE) \(.GOCACHE)"' "$P/bomlens-plan.json")" = "/tmp/sbomhome/go /tmp/sbomhome/go/pkg/mod /tmp/sbomhome/go-build" ] \
    && pass "stage 1 env keeps the Go module and build caches under /tmp/sbomhome (a read-only root filesystem has no /go/pkg)" \
    || fail "stage 1 Go cache env: $(jq -c '.stages[0].env' "$P/bomlens-plan.json")"
if command -v go >/dev/null 2>&1; then
    # No Docker needed: the plan's env alone decides where go puts its caches.
    # HOME and the default GOPATH are made unusable, as in a read-only root.
    go_plan_env=()
    while IFS= read -r _l; do go_plan_env+=("$_l"); done < <(jq -r '.stages[0].env | to_entries[] | select(.key | test("^GO(PATH|MODCACHE|CACHE)$")) | "\(.key)=\(.value)"' "$P/bomlens-plan.json")
    go_env_out="$(env -i PATH="$PATH" HOME=/nonexistent GOTOOLCHAIN=local "${go_plan_env[@]}" go env GOMODCACHE GOPATH GOCACHE 2>&1 | tr '\n' ' ')"
    [ "$go_env_out" = "/tmp/sbomhome/go/pkg/mod /tmp/sbomhome/go /tmp/sbomhome/go-build " ] \
        && pass "go resolves GOMODCACHE, GOPATH and GOCACHE from the stage 1 env alone, not under /go or HOME" \
        || fail "go env under the plan's stage 1 env: $go_env_out"
else
    echo "  SKIP: go is not installed here, so go env under the plan's stage 1 env was not checked"
fi
P="$(plan_run node-badtc "$PSRC" GOTOOLCHAIN='local;rm -rf /')"
[ "$(jq -r '.stages[0].env.HOST_GOTOOLCHAIN // "absent"' "$P/bomlens-plan.json")" = "absent" ] \
    && pass "a GOTOOLCHAIN that is not a toolchain name is not passed on" || fail "HOST_GOTOOLCHAIN: $(jq -r '.stages[0].env.HOST_GOTOOLCHAIN' "$P/bomlens-plan.json")"
[ "$(jq -r '[.stages[0].mounts[] | select(.role=="guard-state") | .target] | first' "$P/bomlens-plan.json") $(jq -r '.stages[0].env_from_caller | has("BOMLENS_GUARD_ID")' "$P/bomlens-plan.json")" = "/bomlens-state true" ] \
    && pass "stage 1 offers the guard-state mount and BOMLENS_GUARD_ID, so a killed stage 1 can be undone" \
    || fail "guard state: $(jq -c '[.stages[0].mounts, .stages[0].env_from_caller]' "$P/bomlens-plan.json")"
jq -e '[.stages[0].mounts[] | select(.role | test("maven|gradle")) | "\(.role) \(.target) \(.mode)"]
    == ["cache-maven /tmp/sbomhome/.m2 rw", "maven-settings /bomlens-settings/m2/settings.xml ro",
        "maven-settings-security /bomlens-settings/m2/settings-security.xml ro", "cache-gradle /root/.gradle rw",
        "gradle-properties /bomlens-settings/gradle/gradle.properties ro",
        "gradle-init-script /bomlens-settings/gradle/init.gradle ro",
        "gradle-init-script-kts /bomlens-settings/gradle/init.gradle.kts ro",
        "gradle-init /bomlens-settings/gradle/init.d ro"]' "$P/bomlens-plan.json" >/dev/null \
    && pass "stage 1 takes the Maven and Gradle caches read-write and the settings files read-only, outside them" \
    || fail "cache mounts: $(jq -c '[.stages[0].mounts[] | select(.role | test("maven|gradle"))]' "$P/bomlens-plan.json")"
jq -e '(.stages[0].env_passthrough | index("HOST_UID")) and (.stages[1].env_passthrough | index("HOST_UID")) and (.stages[1].env_passthrough | index("BOMLENS_INCLUDE_NON_SHIPPED"))' "$P/bomlens-plan.json" >/dev/null \
    && pass "HOST_UID/HOST_GID pass to both stages, BOMLENS_INCLUDE_NON_SHIPPED to stage 2 (its fallback reads it)" \
    || fail "passthrough: $(jq -c '[.stages[].env_passthrough]' "$P/bomlens-plan.json")"
[ "$(jq -r '[.outputs[] | select(.role=="plan") | .path] | first' "$P/bomlens-result.json")" = "bomlens-plan.json" ] \
    && pass "the result manifest lists bomlens-plan.json as the plan output" || fail "outputs: $(jq -c '.outputs' "$P/bomlens-result.json")"

# A re-plan in the same folder removes the earlier run's stage 1 outputs.
P="$WORK/plan-stale"; mkdir -p "$P"
echo stale > "$P/demo_1.0_bom.json"; echo stale > "$P/demo_1.0_conda.cdx.json"; echo stale > "$P/bomlens-plan.json"
P="$(plan_run stale "$PSRC")"
[ ! -e "$P/demo_1.0_bom.json" ] && [ ! -e "$P/demo_1.0_conda.cdx.json" ] && [ "$(jq -r .status "$P/bomlens-plan.json" 2>/dev/null)" = "ok" ] \
    && pass "PLAN removes an earlier run's SBOM and conda sidecar, and replaces the plan" \
    || fail "left: $(ls "$P")"

# The CycloneDX version (--spec-version): stage 1 gets it as build-prep.sh's
# argument and stage 2 as CYCLONEDX_SPEC_VERSION, so its fallback and its own
# input fingerprint use the version the plan was made for.
P="$(plan_run spec17 "$PSRC" CYCLONEDX_SPEC_VERSION=1.7)"
P16="$WORK/plan-node"
[ "$(jq -r '"\(.stages[0].args[3]) \(.stages[1].env.CYCLONEDX_SPEC_VERSION)"' "$P/bomlens-plan.json")" = "1.7 1.7" ] \
    && [ "$(jq -r '.stages[1].env.CYCLONEDX_SPEC_VERSION' "$P16/bomlens-plan.json")" = "1.6" ] \
    && [ "$(jq -r '.input_fingerprint.components[] | select(.name == "CDX_SPEC_VERSION") | .sha256' "$P/bomlens-plan.json")" \
         != "$(jq -r '.input_fingerprint.components[] | select(.name == "CDX_SPEC_VERSION") | .sha256' "$P16/bomlens-plan.json")" ] \
    && pass "CYCLONEDX_SPEC_VERSION reaches both stages of the plan and its input fingerprint" \
    || fail "spec in plan: $(jq -c '[.stages[0].args, .stages[1].env, .input_fingerprint]' "$P/bomlens-plan.json")"
err="$(plan_schema_errors "$P/bomlens-plan.json")"
[ -z "$err" ] && pass "the 1.7 plan validates against schemas/engine-plan-1.json" || fail "1.7 plan schema errors" "$err"

# A registry mirror: the image is named from it, the digest is the published one.
P0="$(plan_run mirror-default "$PSRC")"
for pfx in registry.example/mirror/cdxgen/ registry.example/mirror/cdxgen; do
    P="$(plan_run "mirror-${pfx//\//-}" "$PSRC" CDXGEN_IMAGE_PREFIX="$pfx")"
    [ "$(jq -r '.stages[0].image' "$P/bomlens-plan.json")" = "registry.example/mirror/cdxgen/cdxgen-alpine-node24:$(jq -r .tag "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
        && [ "$(jq -r '.stages[0].image_digest' "$P/bomlens-plan.json")" = "$(jq -r '.stages[0].image_digest' "$P0/bomlens-plan.json")" ] \
        && [ "$(jq -r .status "$P/bomlens-plan.json")" = ok ] \
        && pass "CDXGEN_IMAGE_PREFIX=$pfx names the image from the mirror, with the published digest" \
        || fail "mirror $pfx: $(jq -c '{status, s: .stages[0] | {image, image_digest}}' "$P/bomlens-plan.json" 2>&1)"
done
# A mixed source uses the all-in-one image: from the mirror too, with its digest.
MIXSRC="$WORK/plan-src-mixed"; mkdir -p "$MIXSRC"
echo '{"dependencies":{"a":"1"}}' > "$MIXSRC/package.json"; echo 'requests==2.31.0' > "$MIXSRC/requirements.txt"
P="$(plan_run mirror-mixed "$MIXSRC" CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/)"
[ "$(jq -r '.stages[0] | .image + " " + .image_digest' "$P/bomlens-plan.json")" = "registry.example/mirror/cdxgen/cdxgen:$(jq -r '.tag + " " + .digests["ghcr.io/cdxgen/cdxgen"]' "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
    && pass "a mixed source's all-in-one image is named from the mirror, with its published digest" \
    || fail "mixed mirror: $(jq -c '{status, s: .stages[0] | {image, image_digest}}' "$P/bomlens-plan.json" 2>&1)"
# The Android SDK image builds on the cdxgen Java image; its FROM is kept at
# CDXGEN_TAG by hand, since the ARG in the name hides it from the updaters.
and_tag="$(sed -n 's/^FROM \${CDXGEN_IMAGE_PREFIX}cdxgen-temurin-java21:\([^@]*\)@.*/\1/p' "$ROOT_DIR/docker/android/Dockerfile")"
[ -n "$and_tag" ] && [ "$and_tag" = "$(jq -r .tag "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
    && pass "the Android SDK image's base is at CDXGEN_TAG ($and_tag)" \
    || fail "docker/android/Dockerfile base tag '$and_tag' is not CDXGEN_TAG $(jq -r .tag "$ROOT_DIR/docker/lib/cdxgen-images.json")"
# Under the bash that runs scan-sbom.sh on macOS (3.2), the all-in-one name too.
if [ -x /bin/bash ]; then
    [ "$(/bin/bash -c ". '$ROOT_DIR/docker/lib/source-detect.sh'; img_for_lang mixed" 2>&1)" = "ghcr.io/cdxgen/cdxgen:$(jq -r .tag "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
        && [ "$(/bin/bash -c "CDXGEN_IMAGE_PREFIX=reg.example/m/; . '$ROOT_DIR/docker/lib/source-detect.sh'; img_for_lang mixed" 2>&1)" = "reg.example/m/cdxgen:$(jq -r .tag "$ROOT_DIR/docker/lib/cdxgen-images.json")" ] \
        && pass "/bin/bash ($(/bin/bash -c 'echo $BASH_VERSION')) names the all-in-one image, with and without a mirror" \
        || fail "/bin/bash all-in-one name: $(/bin/bash -c ". '$ROOT_DIR/docker/lib/source-detect.sh'; img_for_lang mixed" 2>&1)"
fi
EMPTYSRC="$WORK/plan-src-empty"; mkdir -p "$EMPTYSRC"
P="$(plan_run empty "$EMPTYSRC")"
[ "$(cat "$P.rc") $(jq -r '.run.status + " " + ([.steps[] | select(.id=="plan")][0].status)' "$P/bomlens-result.json")" != "0 succeeded ok" ] \
    && [ ! -f "$P/bomlens-plan.json" ] && [ "$(jq -r '[.steps[] | select(.id=="plan")][0].status' "$P/bomlens-result.json")" = "failed" ] \
    && pass "an empty source is refused: no plan, plan step failed" \
    || fail "empty source: rc $(cat "$P.rc"), $(jq -c '[.run.status, .steps]' "$P/bomlens-result.json")"
missing=""
for lang in rust go ruby java python node php dotnet swift unknown; do
    img="$(bash -c ". '$ROOT_DIR/docker/lib/source-detect.sh' >/dev/null 2>&1; img_for_lang $lang")"
    jq -e --arg i "${img%:*}" --arg t "${img##*:}" '.tag == $t and (.digests[$i] // "" | startswith("sha256:"))' \
        "$ROOT_DIR/docker/lib/cdxgen-images.json" >/dev/null || missing="$missing $img"
done
[ -z "$missing" ] && pass "cdxgen-images.json pins every image img_for_lang returns, at CDXGEN_TAG" \
    || fail "no pinned digest for:$missing (run scripts/update-cdxgen-digests.sh)"

echo "== POSTPROCESS takes over the manifest-only fallback when told stage 1 failed =="
if ! command -v syft >/dev/null 2>&1 && [ -n "${CI:-}" ]; then
    fail "syft is not installed on this CI runner, so the stage 2 fallback is not tested"
elif command -v syft >/dev/null 2>&1; then
    FB="$WORK/fb-src"; mkdir -p "$FB"; printf 'requests==2.31.0\n' > "$FB/requirements.txt"
    D="$(new_run fallback empty)"
    printf 'npm ERR! getaddrinfo ENOTFOUND registry.npmjs.org\n' > "$D/bomlens-stage1.log"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_LOG=bomlens-stage1.log
    [ "$(jq -r '[.components[] | select(.type=="library") | .name] | join(",")' "$D/demo_1.0_bom.json" 2>/dev/null)" = "requests" ] \
        && pass "a failed stage 1 is replaced by the syft scan of the source" \
        || fail "fallback SBOM: $(jq -c '[.components[]?.name]' "$D/demo_1.0_bom.json" 2>&1)" "$(tail -8 "$D.log")"
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "network" ] \
        && pass "the reason is read from the stage 1 log (network)" \
        || fail "sbom-tool-degraded is $(jq -c '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded")]' "$D/demo_1.0_bom.json" 2>&1)"
    [ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason) \(.stage)"' "$D/bomlens-result.json")" = "degraded fallback 1" ] \
        && pass "generate is recorded as degraded (fallback)" \
        || fail "generate is $(jq -c '[.steps[] | select(.id=="generate")]' "$D/bomlens-result.json")"
    # The image's syft (and CI's, pinned to it) writes 1.7; an older local syft
    # does not, and the case is skipped there.
    if syft "dir:$FB" -o cyclonedx-json@1.7 >/dev/null 2>&1; then
        D="$(new_run fallback-spec17 empty)"
        run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 CYCLONEDX_SPEC_VERSION=1.7
        [ "$(jq -r '"\(.specVersion) \([.components[] | select(.type=="library") | .name] | join(","))"' "$D/demo_1.0_bom.json" 2>/dev/null)" = "1.7 requests" ] \
            && pass "the stage 2 fallback writes the CycloneDX version it is asked for (1.7)" \
            || fail "fallback 1.7: $(jq -c '[.specVersion, [.components[]?.name]]' "$D/demo_1.0_bom.json" 2>&1)" "$(tail -5 "$D.log")"
    elif [ -n "${CI:-}" ]; then
        fail "this runner's syft cannot write CycloneDX 1.7, so the 1.7 fallback is not tested"
    else
        echo "  SKIP: the local syft ($(syft version 2>/dev/null | awk '/^Version/{print $2}')) cannot write CycloneDX 1.7"
    fi
    D="$(new_run fallback-oom empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=137 BOMLENS_STAGE1_OOM=true
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "oom" ] \
        && pass "a stage 1 killed for memory is recorded as oom" || fail "oom case: $(tail -5 "$D.log")"
    D="$(new_run fallback-traversal empty)"
    printf 'getaddrinfo ENOTFOUND\n' > "$WORK/outside.log"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_LOG=../outside.log
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "cdxgen-crash" ] \
        && pass "a stage 1 log path outside the output folder is not read" || fail "traversal case: $(jq -c '[.metadata.properties[]?]' "$D/demo_1.0_bom.json" 2>&1)"
    D="$(new_run fallback-fails empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$WORK/no-such-source" BOMLENS_STAGE1_EXIT=1
    rc=$?
    [ "$rc" = 1 ] && [ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "failed" ] \
        && pass "when the fallback fails too, the run exits 1 with generate failed" \
        || fail "rc $rc, generate $(jq -c '[.steps[] | select(.id=="generate")]' "$D/bomlens-result.json")"
    # The CLI classifies the reason itself and prints its own guidance: a
    # known reason is taken as it is, an unknown one is not, and the
    # engine's own warning stays quiet.
    D="$(new_run fallback-reason empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_REASON=disk-space _BOMLENS_CLI_FALLBACK=1
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "disk-space" ] \
        && ! grep -q 'stage 1 (cdxgen) did not produce an SBOM' "$D.log" \
        && pass "a reason passed in is used, and the engine leaves the warning to the CLI" \
        || fail "reason passed in: $(jq -c '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded")]' "$D/demo_1.0_bom.json" 2>&1)" "$(grep -i stage "$D.log")"
    D="$(new_run fallback-bad-reason empty)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 'BOMLENS_STAGE1_REASON=x;y'
    [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "cdxgen-crash" ] \
        && grep -q 'stage 1 (cdxgen) did not produce an SBOM' "$D.log" \
        && pass "an unknown reason is ignored and classified as usual" \
        || fail "unknown reason: $(jq -c '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded")]' "$D/demo_1.0_bom.json" 2>&1)"
    # No stage 1 at all (an unsupported plan): exit 127 or the reason itself.
    for how in exit reason; do
        D="$(new_run "fallback-no-stage1-$how" empty)"
        if [ "$how" = exit ]; then
            run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=127
        else
            run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=1 BOMLENS_STAGE1_REASON=cdxgen-unavailable
        fi
        [ "$(jq -r '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded") | .value] | first' "$D/demo_1.0_bom.json" 2>/dev/null)" = "cdxgen-unavailable" ] \
            && [ "$(jq -r '[.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason) \(.detail)"' "$D/bomlens-result.json")" = "degraded fallback cdxgen-unavailable" ] \
            && pass "no stage 1 ($how) is recorded as cdxgen-unavailable, not a crash" \
            || fail "no stage 1 ($how): $(jq -c '[.metadata.properties[]? | select(.name=="bomlens:sbom-tool-degraded")]' "$D/demo_1.0_bom.json" 2>&1)"
    done
    D="$(new_run stage1-ok)"
    run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FB" BOMLENS_STAGE1_EXIT=0
    [ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "ok" ] \
        && [ "$(jq -r '[.components[] | .name] | sort | join(",")' "$D/demo_1.0_bom.json")" != "requests" ] \
        && pass "a stage 1 that succeeded is post-processed as it is (no fallback)" || fail "stage1-ok: $(tail -5 "$D.log")"
else
    echo "  SKIP: syft is not installed on this host"
fi

echo "== progress events (BOMLENS_EVENTS) =="
EV_SCHEMA="$ROOT_DIR/schemas/engine-event-1.json"
event_errors() {  # event_errors <jsonl>: schema errors, one per bad line
    if [ -z "$JSPY" ]; then
        [ -n "${CI:-}" ] && echo "jsonschema is not installed, so the events were not validated"
        return 0
    fi
    "$JSPY" - "$EV_SCHEMA" "$1" <<'PY'
import json, sys
import jsonschema
v = jsonschema.Draft202012Validator(json.load(open(sys.argv[1])))
for n, line in enumerate(open(sys.argv[2]), 1):
    try:
        doc = json.loads(line)
    except ValueError:
        print(f"line {n}: not JSON"); continue
    for e in v.iter_errors(doc):
        print(f"line {n}: {list(e.path)}: {e.message[:150]}")
PY
}
D="$(new_run events-file)"
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_EVENTS=file
EVF="$D/bomlens-events.jsonl"
[ -s "$EVF" ] && pass "BOMLENS_EVENTS=file writes bomlens-events.jsonl" || fail "no events file"
err="$(event_errors "$EVF")"
[ -z "$err" ] && pass "every event line validates against schemas/engine-event-1.json" || fail "event schema errors" "$err"
[ "$(jq -s '[.[].seq] == [range(1; length + 1)]' "$EVF")" = "true" ] && pass "seq counts 1, 2, 3, ... with no gap" || fail "seq: $(jq -s -c '[.[].seq]' "$EVF")"
[ "$(jq -s -r '.[0].type + " " + .[-1].type' "$EVF")" = "run.start run.end" ] && pass "the first event is run.start, the last run.end" || fail "first/last: $(jq -s -c '[.[0].type, .[-1].type]' "$EVF")"
[ "$(jq -s -r '.[-1].status' "$EVF")" = "$(jq -r .run.status "$D/bomlens-result.json")" ] \
    && pass "run.end carries the manifest's run.status" || fail "run.end $(jq -s -r '.[-1].status' "$EVF") vs manifest $(jq -r .run.status "$D/bomlens-result.json")"
[ "$(jq -s -r '[.[] | select(.type=="step.end") | .step] | unique | sort | join(",")' "$EVF")" = "$(jq -r '[.steps[].id] | unique | sort | join(",")' "$D/bomlens-result.json")" ] \
    && pass "the steps that end in the events are the manifest's steps" \
    || fail "events vs manifest steps" "$(jq -s -c '[.[] | select(.type=="step.end") | .step] | unique' "$EVF") / $(jq -c '[.steps[].id] | unique' "$D/bomlens-result.json")"
jq -s -e '(map(select(.step=="normalize")) | map(.type)) as $t | ($t | index("step.start")) < ($t | index("step.end"))' "$EVF" >/dev/null \
    && pass "a step starts before it ends (normalize)" || fail "normalize events: $(jq -s -c 'map(select(.step=="normalize"))' "$EVF")"
jq -s -e '[.[] | select(.type=="step.end" and .step=="generate")][0].stage == 1' "$EVF" >/dev/null \
    && pass "generate is reported as stage 1 in POSTPROCESS" || fail "generate event: $(jq -s -c 'map(select(.step=="generate"))' "$EVF")"
ev_sha="$( (sha256sum "$EVF" 2>/dev/null || shasum -a 256 "$EVF") | cut -d' ' -f1)"
[ "$(jq -r '[.outputs[] | select(.role=="events")][0] | .path + " " + (.bytes | tostring) + " " + .sha256' "$D/bomlens-result.json")" = "bomlens-events.jsonl $(wc -c < "$EVF" | tr -d ' ') $ev_sha" ] \
    && pass "the manifest lists the events file with its final size and hash (run.end included)" \
    || fail "events output: $(jq -c '[.outputs[] | select(.role=="events")]' "$D/bomlens-result.json")"
err="$(schema_errors "$D/bomlens-result.json")"
[ -z "$err" ] && pass "the manifest of an events run validates against the schema" || fail "schema errors" "$err"
# A later run in the same folder without events removes the earlier file.
run_engine "$D" "$ROOT_DIR/docker/lib"
[ ! -e "$EVF" ] && pass "an earlier run's events file is removed by a run without events" || fail "stale events file kept"
D="$(new_run events-stderr)"
( cd "$D" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$D" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
    UPLOAD_ENABLED=false ENRICH_EOL=false ENRICH_MALICIOUS=false BOMLENS_EVENTS=stderr bash "$ENTRY" ) \
    > "$D.out" 2> "$D.err"
grep '^{"v":1,' "$D.err" > "$D.events"
[ -s "$D.events" ] && [ "$(jq -s -r '.[-1].type' "$D.events")" = "run.end" ] && ! grep -q '^{"v":1,' "$D.out" \
    && [ ! -e "$D/bomlens-events.jsonl" ] \
    && pass "BOMLENS_EVENTS=stderr writes the events to stderr only" || fail "stderr mode: $(head -3 "$D.events")"
CE="$(new_run events-cancel)"
( cd "$CE" && exec env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$CE" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
    UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false TRIVY_STUB=sleep TRIVY_STUB_STARTED="$WORK/stub-started-ev" \
    BOMLENS_EVENTS=file bash "$ENTRY" ) > "$CE.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do [ -f "$WORK/stub-started-ev" ] && break; sleep 0.1; done
kill -TERM "$pid" 2>/dev/null; wait "$pid"
[ "$(jq -s -r '.[-1] | .type + " " + .status' "$CE/bomlens-events.jsonl" 2>/dev/null)" = "run.end cancelled" ] \
    && [ "$(jq -r .run.status "$CE/bomlens-result.json")" = "cancelled" ] \
    && pass "a stopped run ends its events with run.end cancelled, matching the manifest" \
    || fail "cancelled events end: $(tail -2 "$CE/bomlens-events.jsonl" 2>&1)"
D="$(new_run events-off)"; run_engine "$D" "$ROOT_DIR/docker/lib"
[ ! -e "$D/bomlens-events.jsonl" ] && ! jq -e 'any(.outputs[]; .role=="events")' "$D/bomlens-result.json" >/dev/null \
    && pass "without BOMLENS_EVENTS nothing is written" || fail "events written without being asked"

echo "== the plan passes on the network settings =="
P="$(plan_run netenv "$PSRC")"
jq -e '(.stages[0].env_passthrough | index("HTTPS_PROXY") != null)
       and (.stages[1].env_passthrough as $p | ["HTTPS_PROXY", "NO_PROXY", "TRIVY_DB_REPOSITORY", "TRIVY_SKIP_DB_UPDATE", "KEV_URL", "EPSS_API"] | all(. as $n | $p | index($n) != null))
       and (.stages[1].env_passthrough | index("TRIVY_CACHE_DIR") == null)
       and (.stages[1].env.SECURITY_ENRICH == "false")
       and ([.stages[1].mounts[] | select(.role == "trivy-db")] == [{role: "trivy-db", target: "/trivy-db", mode: "ro", optional: true}])' "$P/bomlens-plan.json" >/dev/null \
    && pass "stage 1 passes on the proxy, stage 2 the proxy, Trivy and EPSS/KEV settings; EPSS/KEV off, trivy-db mount read-only" \
    || fail "plan passthrough" "$(jq -c '[.stages[].env_passthrough]' "$P/bomlens-plan.json" 2>&1)"

echo "== the CLI's stage 1 is the one the execution plan describes =="
# scripts/scan-sbom.sh and make-plan.sh both build stage 1; this keeps them the
# same. A docker stub records the arguments the CLI really passes to its stage
# 1 container, and they are compared with the plan for the same source:
# image, user, entrypoint, arguments, the plan's environment and mount targets.
# The one allowed difference: the CLI names the image by tag, the plan also by
# digest.
CMP="$WORK/cli-vs-plan"; mkdir -p "$CMP/bin" "$CMP/out"
cat > "$CMP/bin/docker" <<'STUB'
#!/bin/bash
case "$1" in
    info|rm|pull|stop|kill) exit 0 ;;
    image)
        case "$*" in
            *engine-contract*) [ -n "${STUB_OLD_IMAGE:-}" ] || echo 1.0.0 ;;
            *RepoDigests*) [ -n "${STUB_REPO_DIGEST:-}" ] && echo "$STUB_REPO_DIGEST" ;;
        esac
        exit 0 ;;
    inspect) echo false; exit 0 ;;
    wait) echo 0; exit 0 ;;
    ps) exit 0 ;;
    run)
        for a in "$@"; do [ "$a" = "/tmp/build-prep.sh" ] && { printf '%s\n' "$@" > "$CLI_ARGV_LOG"; exit 0; }; done
        # Stage 2: the stub's stage 1 wrote no SBOM, so this is the fallback hand-off.
        printf '%s\n' "$@" > "$CLI_ARGV_LOG.stage2"
        exit 0 ;;
esac
exit 0
STUB
chmod +x "$CMP/bin/docker"
CLI_SRC="$WORK/plan-src-node"
mkdir -p "$CMP/tmp"
NODE_DIGEST="$(jq -r '.digests["ghcr.io/cdxgen/cdxgen-alpine-node24"]' "$ROOT_DIR/docker/lib/cdxgen-images.json")"
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" \
    STUB_REPO_DIGEST="ghcr.io/cdxgen/cdxgen-alpine-node24@$NODE_DIGEST" \
    bash "$ROOT_DIR/scripts/scan-sbom.sh" --project demo --version 1.0 --target "$CLI_SRC" \
    --generate-only --output-dir "$CMP/out" ) > "$CMP/log" 2>&1
P="$(plan_run cli-compare "$CLI_SRC")"
if [ ! -s "$CMP/argv" ]; then
    fail "the CLI's stage 1 docker run was not recorded" "$(tail -8 "$CMP/log")"
elif [ "$(cat "$P.rc")" != 0 ] || ! jq -e '.stages[0] | type == "object" and (.env | type == "object") and (.env_passthrough | type == "array") and (.mounts | type == "array")' "$P/bomlens-plan.json" >/dev/null 2>&1; then
    fail "no stage 1 in the plan to compare the CLI with" "$(tail -5 "$P.log")"
else
    cli_json="$(python3 - "$CMP/argv" <<'PY'
import json, sys
a = [l.rstrip("\n") for l in open(sys.argv[1])]
out = {"user": None, "entrypoint": None, "image": None, "args": [], "env": {}, "envnames": [], "mounts": []}
i = 1
while i < len(a):
    x = a[i]
    if x in ("-u", "--user"): out["user"] = a[i + 1]; i += 2; continue
    if x in ("--name", "--label", "-w"): i += 2; continue
    if x == "-v": out["mounts"].append(a[i + 1].split(":")[1] if ":" in a[i + 1] else a[i + 1]); i += 2; continue
    if x == "-e":
        k, sep, v = a[i + 1].partition("=")
        if sep: out["env"][k] = v
        else: out["envnames"].append(k)
        i += 2; continue
    if x == "--entrypoint": out["entrypoint"] = a[i + 1]; i += 2; continue
    if x.startswith("-"): i += 1; continue
    out["image"] = x; out["args"] = a[i + 1:]; break
print(json.dumps(out))
PY
)"
    plan_stage1="$(jq -c '.stages[0]' "$P/bomlens-plan.json")"
    diffs="$(jq -n -r --argjson c "$cli_json" --argjson p "$plan_stage1" '
        [ (if $c.image != $p.image then "image: CLI \($c.image), plan \($p.image)" else empty end),
          (if $c.user != $p.user then "user: CLI \($c.user), plan \($p.user)" else empty end),
          (if [$c.entrypoint] != $p.entrypoint then "entrypoint: CLI \($c.entrypoint), plan \($p.entrypoint)" else empty end),
          (if $c.args != $p.args then "args: CLI \($c.args), plan \($p.args)" else empty end),
          ($p.env | to_entries[] | select($c.env[.key] != .value) | "env \(.key): CLI \($c.env[.key]), plan \(.value)"),
          ($p.env_passthrough[] | select((($c.envnames + ($c.env | keys)) | index(.)) | not) | "env \(.): passed by the plan, not by the CLI"),
          ($p.mounts[] | select((.optional // false) | not) | .target | select(($c.mounts | index(.)) | not) | "mount \(.): in the plan, not in the CLI")
        ] | join("\n")')"; diffs_rc=$?
    if [ "$diffs_rc" -ne 0 ] || [ -z "$cli_json" ]; then
        fail "the CLI and plan stage 1 could not be compared" "jq exit $diffs_rc"
    elif [ -z "$diffs" ]; then
        pass "the CLI runs stage 1 as the plan describes it (image, user, entrypoint, arguments, environment, mounts)"
    else
        fail "the CLI's stage 1 differs from the plan" "$diffs"
    fi
fi
# Stage 1 left no SBOM, so stage 2 got the hand-off the fallback needs.
s2="$(tr '\n' ' ' < "$CMP/argv.stage2" 2>/dev/null)"
case "$s2" in
    *"-e BOMLENS_STAGE1_EXIT=0 "*"-e _BOMLENS_CLI_FALLBACK=1 "*"-e BOMLENS_STAGE1_REASON=cdxgen-crash "*) ;;
    *) s2="" ;;
esac
[ -n "$s2" ] && case "$s2" in *"-e BOMLENS_INCLUDE_NON_SHIPPED "*) true ;; *) false ;; esac \
    && pass "a stage 1 with no SBOM hands stage 2 its exit code, the reason and BOMLENS_INCLUDE_NON_SHIPPED" \
    || fail "stage 2 hand-off" "$(tr '\n' ' ' < "$CMP/argv.stage2" 2>&1)"
# What stage 1 ran, for the input fingerprint: the image's RepoDigest and the
# sha256 of the files the CLI mounted and of scan-sbom.sh itself.
want_s2=""
for kv in "BOMLENS_STAGE1_DIGEST=$NODE_DIGEST" \
          "BOMLENS_STAGE1_PREP_SHA256=$(shasum -a 256 < "$ROOT_DIR/docker/lib/build-prep.sh" | cut -d' ' -f1)" \
          "BOMLENS_STAGE1_CONDA_SHA256=$(shasum -a 256 < "$ROOT_DIR/docker/lib/identify-conda.py" | cut -d' ' -f1)" \
          "BOMLENS_STAGE1_CLI_SHA256=$(shasum -a 256 < "$ROOT_DIR/scripts/scan-sbom.sh" | cut -d' ' -f1)" \
          "BOMLENS_STAGE1_SPEC_VERSION=1.6"; do
    grep -qxF -- "$kv" "$CMP/argv.stage2" 2>/dev/null || want_s2="$want_s2 $kv"
done
[ -z "$want_s2" ] && pass "the CLI hands stage 2 the stage 1 image digest and the sha256 of the files it ran" \
    || fail "stage 2 is missing:$want_s2" "$(grep BOMLENS_STAGE1 "$CMP/argv.stage2" 2>&1)"
grep -q '^BOMLENS_FINGERPRINT_EXCLUDE=' "$CMP/argv.stage2" 2>/dev/null \
    && fail "an output folder outside the source is passed as BOMLENS_FINGERPRINT_EXCLUDE" || pass "an output folder outside the source is not excluded"
CLI_IN="$WORK/cli-in-src"; mkdir -p "$CLI_IN"; cp "$CLI_SRC/package.json" "$CLI_IN/"; rm -f "$CMP/argv.stage2"
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" \
    STUB_REPO_DIGEST="ghcr.io/cdxgen/cdxgen-alpine-node24@$NODE_DIGEST" \
    bash "$ROOT_DIR/scripts/scan-sbom.sh" --project demo --version 1.0 --target "$CLI_IN" \
    --generate-only --output-dir "$CLI_IN/out" ) > "$CMP/log-in" 2>&1
grep -qxF 'BOMLENS_FINGERPRINT_EXCLUDE=out/demo_1.0' "$CMP/argv.stage2" 2>/dev/null \
    && pass "an output folder inside the source is passed to stage 2 as BOMLENS_FINGERPRINT_EXCLUDE" \
    || fail "output inside the source: $(grep FINGERPRINT "$CMP/argv.stage2" 2>&1)" "$(tail -3 "$CMP/log-in")"
rm -f "$CMP/argv.stage2"
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" SBOM_OUTPUT_FLAT=1 \
    STUB_REPO_DIGEST="ghcr.io/cdxgen/cdxgen-alpine-node24@$NODE_DIGEST" \
    bash "$ROOT_DIR/scripts/scan-sbom.sh" --project demo --version 1.0 --target "$CLI_IN" \
    --generate-only --output-dir "$CLI_IN" ) > "$CMP/log-flat" 2>&1
grep -qxF 'BOMLENS_FINGERPRINT_EXCLUDE=.' "$CMP/argv.stage2" 2>/dev/null \
    && pass "a flat output into the source itself is passed to stage 2 as BOMLENS_FINGERPRINT_EXCLUDE=." \
    || fail "flat output: $(grep FINGERPRINT "$CMP/argv.stage2" 2>&1)" "$(tail -3 "$CMP/log-flat")"
# The same failure with a post-processing image older than the contract
# label: a clear error instead of stage 2 stopping on a missing SBOM.
rm -f "$CMP/argv.stage2"
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" STUB_OLD_IMAGE=1 \
    bash "$ROOT_DIR/scripts/scan-sbom.sh" --project demo --version 1.0 --target "$CLI_SRC" \
    --generate-only --output-dir "$CMP/out" ) > "$CMP/log-old" 2>&1
old_rc=$?
[ "$old_rc" -ne 0 ] && [ ! -e "$CMP/argv.stage2" ] \
    && grep -q 'is older than this CLI: it cannot run the manifest-only fallback' "$CMP/log-old" \
    && pass "an image without the engine-contract label is refused with a clear error when the fallback is needed" \
    || fail "old image: rc $old_rc, stage 2 run: $([ -e "$CMP/argv.stage2" ] && echo yes || echo no)" "$(tail -4 "$CMP/log-old")"
# The CLI refuses an image name starting with - before any container runs.
rm -f "$CMP/argv.stage2"
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" \
    bash "$ROOT_DIR/scripts/scan-sbom.sh" --project demo --version 1.0 --target "--output=/tmp/x:1" \
    --generate-only --output-dir "$CMP/out-dash" ) > "$CMP/log-dash" 2>&1
dash_rc=$?
[ "$dash_rc" -ne 0 ] && grep -q "\-\-target '--output=/tmp/x:1' starts with '-'" "$CMP/log-dash" \
    && [ ! -e "$CMP/argv.stage2" ] \
    && pass "the CLI refuses an image name starting with - before running a container" \
    || fail "CLI dash: rc $dash_rc, container run: $([ -e "$CMP/argv.stage2" ] && echo yes || echo no)" "$(tail -3 "$CMP/log-dash")"
dlabel="$(sed -n 's/^LABEL com\.sktelecom\.sbom\.engine-contract="\(.*\)"$/\1/p' "$ROOT_DIR/docker/Dockerfile")"
cver="$(sed -n 's/^ENGINE_CONTRACT_VERSION="\(.*\)"$/\1/p' "$ROOT_DIR/docker/lib/engine-result.sh")"
pver="$(jq -r '.contract.version' "$(plan_run contract-version "$PSRC")/bomlens-plan.json" 2>/dev/null)"
mver="$(jq -r '.contract.version' "$D/bomlens-result.json" 2>/dev/null)"
docver="$(sed -n 's/^.*This page describes contract version `\([^`]*\)`.*$/\1/p' "$ROOT_DIR/docs/reference/engine-contract.md")"
[ -n "$cver" ] && [ "$dlabel" = "$cver" ] && [ "$pver" = "$cver" ] && [ "$mver" = "$cver" ] && [ "$docver" = "$cver" ] \
    && pass "one engine contract version ($cver): the image label, the plan, the result manifest and the contract page" \
    || fail "contract versions differ: label '$dlabel', ENGINE_CONTRACT_VERSION '$cver', plan '$pver', manifest '$mver', docs '$docver'"

echo "== IMAGE mode without the Docker socket =="
# syft reads the image from the registry when no daemon is there (a
# Kubernetes job). A stub stands in for it: it records its arguments and
# writes an SBOM, or fails like an image it cannot reach.
IMG="$WORK/image-mode"; mkdir -p "$IMG/bin" "$IMG/ok" "$IMG/bad"
cat > "$IMG/bin/syft" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" > "$SYFT_ARGV_LOG"
[ "$1" = "registry.example/denied:1" ] && { echo "GET https://registry.example/v2/denied/manifests/1: UNAUTHORIZED" >&2; exit 1; }
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":"x"}},"components":[{"type":"library","name":"busybox","version":"1.36.1","purl":"pkg:apk/alpine/busybox@1.36.1"}]}\n'
STUB
chmod +x "$IMG/bin/syft"
# No real daemon for the later steps either (the file view asks docker).
printf '#!/bin/sh\nexit 1\n' > "$IMG/bin/docker"; chmod +x "$IMG/bin/docker"
# A copy of entrypoint.sh that looks for the socket where none is, so the
# no-socket path runs whether or not this host has Docker.
NOSOCK_ENTRY="$IMG/entrypoint-nosock.sh"
sed "s#/var/run/docker.sock#$IMG/no-docker.sock#g" "$ENTRY" > "$NOSOCK_ENTRY"
image_run() {  # image_run <dir> <image>
    ( cd "$1" && env PATH="$IMG/bin:$WORK/bin:$PATH" MODE=IMAGE TARGET_IMAGE="$2" SYFT_ARGV_LOG="$1/argv" \
        PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$1" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false \
        bash "$NOSOCK_ENTRY" ) > "$1.log" 2>&1
}
if ! grep -q "$IMG/no-docker.sock" "$NOSOCK_ENTRY"; then
    fail "entrypoint.sh no longer names /var/run/docker.sock; update this test's socket substitution"
else
    image_run "$IMG/ok" registry.example/app:1
    rc=$?
    [ "$rc" = 0 ] && [ "$(head -1 "$IMG/ok/argv" 2>/dev/null)" = "registry.example/app:1" ] \
        && grep -q 'no Docker socket: read from the registry' "$IMG/ok.log" \
        && [ "$(jq -r '.components[0].name' "$IMG/ok/demo_1.0_bom.json" 2>/dev/null)" = "busybox" ] \
        && pass "with no socket the image is read by syft from the registry" \
        || fail "no-socket image scan: rc $rc" "$(tail -6 "$IMG/ok.log")"
    image_run "$IMG/bad" registry.example/denied:1
    rc=$?
    [ "$rc" = 1 ] && grep -q 'registry needs credentials (SYFT_REGISTRY_AUTH_USERNAME' "$IMG/bad.log" \
        && grep -q 'UNAUTHORIZED' "$IMG/bad.log" \
        && [ "$(jq -r '.run.status' "$IMG/bad/bomlens-result.json" 2>/dev/null)" = "failed" ] \
        && pass "an unreachable image fails with the credentials hint, syft's own error and a failed run" \
        || fail "unreachable image: rc $rc, $(jq -c .run "$IMG/bad/bomlens-result.json" 2>&1)" "$(tail -6 "$IMG/bad.log")"
fi

echo "== a lock-less Poetry SBOM whose pins could not be resolved further =="
D="$(new_run poetry-analyze)"
jq '.metadata.properties = ((.metadata.properties // []) + [{"name":"bomlens:pipeline-step-failed","value":"poetry-graph"}])' "$D/demo_1.0_bom.json" > "$D/supplier.json" && rm -f "$D/demo_1.0_bom.json"
run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$D/supplier.json"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0].status // "none"' "$D/bomlens-result.json" 2>/dev/null)" != "degraded" ] \
    && pass "a supplier SBOM under ANALYZE that carries the Poetry mark does not degrade this run's generate" \
    || fail "ANALYZE took the supplier's Poetry mark: $(jq -c '[.steps[] | select(.id=="generate")]' "$D/bomlens-result.json")" "$(tail -5 "$D.log")"
# build-prep.sh records poetry-graph as failed on the SBOM (no network); the
# manifest says the same on generate, so the run is not a plain success.
for case in graph-failed partial both; do
    D="$(new_run "poetry-$case")"
    if [ "$case" = graph-failed ]; then
        prop='[{"name":"bomlens:prep-step-applied","value":"poetry-requirements"},{"name":"bomlens:prep-step-applied","value":"poetry-graph"},{"name":"bomlens:pipeline-step-failed","value":"poetry-graph"}]'
    elif [ "$case" = partial ]; then
        prop='[{"name":"bomlens:prep-step-applied","value":"poetry-requirements"},{"name":"bomlens:prep-step-applied","value":"poetry-requirements-partial"},{"name":"bomlens:prep-step-applied","value":"poetry-graph"}]'
    else
        prop='[{"name":"bomlens:prep-step-applied","value":"poetry-requirements-partial"},{"name":"bomlens:pipeline-step-failed","value":"poetry-graph"}]'
    fi
    jq --argjson p "$prop" '.metadata.properties = ((.metadata.properties // []) + $p)' "$D/demo_1.0_bom.json" > "$D/x" && mv "$D/x" "$D/demo_1.0_bom.json"
    run_engine "$D" "$ROOT_DIR/docker/lib"
    got="$(jq -r '.run.status + " " + ([.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason) \(.detail)")' "$D/bomlens-result.json")"
    case "$case:$got" in
        "graph-failed:succeeded_degraded degraded fallback "*"poetry-graph failed)"|"partial:succeeded_degraded degraded fallback "*"ranged and table dependencies are missing"|"both:succeeded_degraded degraded fallback "*"dependencies are missing; the dependencies of the pins could not be resolved (poetry-graph failed)") pass "Poetry $case: generate degraded (fallback), run succeeded_degraded" ;;
        *) fail "Poetry $case: $got" ;;
    esac
done

echo "== a Trivy database mounted read-only (the plan's trivy-db mount) =="
# entrypoint.sh looks for it at /trivy-db; a copy looks in this test's folder.
TDB="$WORK/trivy-db-case"; mkdir -p "$TDB"
TDB_ENTRY="$TDB/entrypoint.sh"
sed "s#\"/trivy-db\"#\"$TDB/mount\"#" "$ENTRY" > "$TDB_ENTRY"
tdb_run() {  # tdb_run <dir>: POSTPROCESS with the copied entrypoint
    ( cd "$1" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
        HOST_OUTPUT_DIR="$1" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
        UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
        ENRICH_EOL=false ENRICH_MALICIOUS=false TRIVY_ENV_LOG="$1/trivy-env" bash "$TDB_ENTRY" ) > "$1.log" 2>&1
}
tdb_db() {  # tdb_db <days old>: a database in the mount
    rm -rf "$TDB/mount"; mkdir -p "$TDB/mount/db"; : > "$TDB/mount/db/trivy.db"
    # Trivy writes UpdatedAt with nanoseconds.
    jq -n --argjson d "$1" '{Version: 2, UpdatedAt: ((now - $d * 86400) | todateiso8601 | sub("Z$"; ".103977313Z"))}' > "$TDB/mount/db/metadata.json"
}
sec_step() { jq -r '[.steps[] | select(.id=="scan-security")][0] | "\(.status) \(.reason) \(.detail)"' "$1/bomlens-result.json"; }
if ! grep -q "$TDB/mount" "$TDB_ENTRY"; then
    fail "entrypoint.sh no longer names \"/trivy-db\"; update this test's substitution"
else
    tdb_db 2; D="$(new_run trivy-db-fresh)"; tdb_run "$D"
    [ "$(grep -c 'TRIVY_CACHE_DIR='"$TDB"'/mount\|TRIVY_SKIP_DB_UPDATE=true\|TRIVY_SKIP_JAVA_DB_UPDATE=true\|TRIVY_OFFLINE_SCAN=true' "$D/trivy-env" 2>/dev/null)" = 4 ] \
        && [ "$(sec_step "$D")" = "ok null null" ] \
        && pass "a mounted database is read as it is: cache dir, no update, offline; the step is ok" \
        || fail "fresh database: $(sec_step "$D"), env $(tr '\n' ' ' < "$D/trivy-env" 2>&1)" "$(tail -4 "$D.log")"
    tdb_db 30; D="$(new_run trivy-db-old)"; tdb_run "$D"
    [ "$(sec_step "$D")" = "degraded unavailable the Trivy database is 30 days old (over 7)" ] \
        && [ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded_degraded" ] \
        && pass "a database 30 days old degrades the step (unavailable), the run is succeeded_degraded" \
        || fail "old database: $(sec_step "$D")" "$(tail -4 "$D.log")"
    rm -f "$TDB/mount/db/metadata.json"; D="$(new_run trivy-db-no-metadata)"; tdb_run "$D"
    [ "$(sec_step "$D")" = "ok null null" ] \
        && pass "with no metadata.json the age is unknown and the step stays ok" \
        || fail "no metadata: $(sec_step "$D")"
    tdb_db 30; D="$(new_run trivy-db-old-fail)"; ( export TRIVY_STUB=fail; tdb_run "$D" )
    [ "$(sec_step "$D" | cut -d' ' -f1-2)" = "failed failed" ] \
        && pass "an old database with a failed scan stays failed, not degraded" \
        || fail "old database + scan error: $(sec_step "$D")"
    rm -rf "$TDB/mount"; mkdir -p "$TDB/mount"; D="$(new_run trivy-db-empty)"; tdb_run "$D"
    [ "$(sec_step "$D")" = "failed failed no Trivy database in the trivy-db mount ($TDB/mount/db/trivy.db)" ] \
        && [ ! -e "$D/trivy-env" ] && [ "$(jq -r .run.status "$D/bomlens-result.json")" = "succeeded_degraded" ] \
        && pass "a mount with no database fails the step with that reason, without running Trivy" \
        || fail "empty mount: $(sec_step "$D"), run $(jq -r .run.status "$D/bomlens-result.json")" "$(tail -4 "$D.log")"
    rm -rf "$TDB/mount"; D="$(new_run trivy-db-none)"; tdb_run "$D"
    ! grep -q 'TRIVY_SKIP_DB_UPDATE\|TRIVY_OFFLINE_SCAN' "$D/trivy-env" 2>/dev/null && [ -e "$D/trivy-env" ] \
        && pass "with no mount Trivy is left to its own settings" \
        || fail "no mount: env $(tr '\n' ' ' < "$D/trivy-env" 2>&1)"
fi

echo "== a user with no writable home (any UID, read-only root) =="
RH="$WORK/readonly-home"; mkdir -p "$RH" "$WORK/tmp-home"; chmod 555 "$RH"
if [ "$(id -u)" = 0 ]; then
    echo "  SKIP: running as root, which can write any folder"
else
    D="$(new_run no-home)"; run_engine "$D" "$ROOT_DIR/docker/lib" HOME="$RH" TMPDIR="$WORK/tmp-home" TRIVY_HOME_LOG="$D/home"
    [ "$(sed -n 2p "$D/home" 2>/dev/null)" = writable ] && [ "$(head -1 "$D/home")" != "$RH" ] \
        && case "$(head -1 "$D/home")" in "$WORK/tmp-home/bomlens-home."*) true ;; *) false ;; esac \
        && [ "$(jq -r '[.steps[] | select(.id=="scan-security")][0].status' "$D/bomlens-result.json")" = ok ] \
        && pass "a home it cannot write is replaced with a writable folder in TMPDIR" \
        || fail "home: $(cat "$D/home" 2>&1 | tr '\n' ' ')" "$(tail -4 "$D.log")"
fi
chmod 755 "$RH"
D="$(new_run own-home)"; mkdir -p "$WORK/own-home"; run_engine "$D" "$ROOT_DIR/docker/lib" HOME="$WORK/own-home" TRIVY_HOME_LOG="$D/home"
[ "$(head -1 "$D/home" 2>/dev/null)" = "$WORK/own-home" ] \
    && pass "a writable home is left as it is" || fail "own home replaced: $(head -1 "$D/home" 2>&1)"

echo "== Debian package licenses from Trivy (os-licenses) =="
OSL="$WORK/os-licenses"; mkdir -p "$OSL/bin" "$OSL/rootfs"
cat > "$OSL/bin/syft" <<'STUB'
#!/bin/bash
cat <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":"x"}},"components":[
 {"type":"library","name":"libc6","version":"2.36-9","purl":"pkg:deb/debian/libc6@2.36-9?arch=arm64","licenses":[{"license":{"name":"sha256:40c7e1f2118531f038ca22999bd976901254e1bc5cd1b0f0211bdd064c599987"}}]},
 {"type":"library","name":"libgcc-s1","version":"12.2.0","purl":"pkg:deb/debian/libgcc-s1@12.2.0?arch=arm64","licenses":[{"license":{"name":"sha256:da8191658b3452ce9caf31638ba61dab31a38c619fa39df119812e050f592fd3"}},{"license":{"id":"GPL-3.0-only"}}]},
 {"type":"library","name":"ca-certificates","version":"20240705","purl":"pkg:apk/alpine/ca-certificates@20240705","licenses":[{"expression":"MPL-2.0 OR MIT"}]},
 {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","licenses":[{"license":{"id":"MIT"}}]}]}
JSON
STUB
cat > "$OSL/bin/trivy" <<'STUB'
#!/bin/bash
[ "${1:-}" = version ] && { echo '{"Version":"0.0.0-stub"}'; exit 0; }
out=""; prev=""; for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
printf '%s\n' "$@" > "$OSL_TRIVY_ARGV"
env | grep '^TRIVY_' | sort > "$OSL_TRIVY_ARGV.env"
[ -n "${OSL_TRIVY_FAIL:-}" ] && { echo "FATAL unable to inspect the image" >&2; exit 1; }
[ -n "${OSL_TRIVY_EMPTY:-}" ] && { echo '{"components":[{"name":"libc6","purl":"pkg:deb/debian/libc6@2.36-9"}]}' > "$out"; exit 0; }
cat > "$out" <<'JSON'
{"components":[{"name":"libc6","purl":"pkg:deb/debian/libc6@2.36-9?arch=amd64","licenses":[{"license":{"id":"LGPL-2.1-only"}},{"license":{"id":"GPL-2.0-only"}}]},
 {"name":"libgcc-s1","purl":"pkg:deb/debian/libgcc-s1@12.2.0?arch=amd64"},
 {"name":"ca-certificates","purl":"pkg:apk/alpine/ca-certificates@20240705","licenses":[{"license":{"id":"MPL-2.0"}},{"license":{"id":"MIT"}}]}]}
JSON
STUB
# No real daemon for the file view either.
printf '#!/bin/sh\nexit 1\n' > "$OSL/bin/docker"
chmod +x "$OSL/bin/syft" "$OSL/bin/trivy" "$OSL/bin/docker"
osl_run() {  # osl_run <dir> [VAR=value ...]
    local d="$1"; shift
    ( cd "$d" && env PATH="$OSL/bin:$WORK/bin:$PATH" MODE=IMAGE TARGET_IMAGE=debian:bookworm-slim OSL_TRIVY_ARGV="$d/trivy-argv" \
        PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$d" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false \
        "$@" bash "$ENTRY" ) > "$d.log" 2>&1
}
lic() { jq -c --arg n "$2" '[.components[] | select(.name == $n) | .licenses[]? | (.license.id // .license.name // .expression)]' "$1/demo_1.0_bom.json"; }
osl_step() { jq -c '[.steps[] | select(.id=="os-licenses")][0] | [.status, .reason, .counts]' "$1/bomlens-result.json"; }
D="$WORK/osl-ok"; mkdir -p "$D"; osl_run "$D" SYFT_REGISTRY_AUTH_USERNAME=u SYFT_REGISTRY_AUTH_PASSWORD=p TRIVY_USERNAME=dbmirror SYFT_REGISTRY_INSECURE_USE_HTTP=true
[ "$(lic "$D" libc6)" = '["LGPL-2.1-only","GPL-2.0-only"]' ] && [ "$(lic "$D" libgcc-s1)" = '["GPL-3.0-only"]' ] \
    && [ "$(lic "$D" ca-certificates)" = '["MPL-2.0 OR MIT"]' ] && [ "$(lic "$D" lodash)" = '["MIT"]' ] \
    && [ "$(osl_step "$D")" = '["ok",null,{"replaced":1,"hashes_dropped":1}]' ] \
    && pass "deb packages take Trivy's licenses, a hash Trivy cannot replace is dropped, apk keeps its OR expression" \
    || fail "os-licenses: libc6 $(lic "$D" libc6), libgcc-s1 $(lic "$D" libgcc-s1), apk $(lic "$D" ca-certificates)" "$(osl_step "$D")"
grep -qx -- '--pkg-types' "$D/trivy-argv" && grep -qx 'os' "$D/trivy-argv" && grep -qx 'image' "$D/trivy-argv" \
    && grep -qx -- '--license-full' "$D/trivy-argv" \
    && grep -qx 'TRIVY_USERNAME=u' "$D/trivy-argv.env" && grep -qx 'TRIVY_PASSWORD=p' "$D/trivy-argv.env" && grep -qx 'TRIVY_INSECURE=true' "$D/trivy-argv.env" \
    && [ "$(jq -r '[.steps[].id] | (index("generate") < index("os-licenses"))' "$D/bomlens-result.json")" = true ] \
    && [ "$(jq -r '.tools.trivy' "$D/bomlens-result.json")" = 0.0.0-stub ] \
    && pass "Trivy reads OS packages only (with license text), using syft's registry credentials and options; recorded after generate" \
    || fail "trivy call: $(tr '\n' ' ' < "$D/trivy-argv") env: $(tr '\n' ' ' < "$D/trivy-argv.env")"
D="$WORK/osl-registry"; mkdir -p "$D"; osl_run "$D" TARGET_IMAGE=registry:debian:12
[ "$(tail -1 "$D/trivy-argv")" = "debian:12" ] && grep -qx 'remote' "$D/trivy-argv" \
    && pass "syft's registry: scheme becomes Trivy's --image-src remote" || fail "registry scheme: $(tr '\n' ' ' < "$D/trivy-argv")"
D="$WORK/osl-rootfs"; mkdir -p "$D"; osl_run "$D" MODE=ROOTFS TARGET_DIR="$OSL/rootfs"
grep -qx 'rootfs' "$D/trivy-argv" && grep -qx "$OSL/rootfs/proc" "$D/trivy-argv" && grep -qx "$OSL/rootfs/run" "$D/trivy-argv" \
    && [ "$(tail -1 "$D/trivy-argv")" = "$OSL/rootfs" ] \
    && pass "a root filesystem is read with its pseudo filesystems left out, by their paths under it" \
    || fail "rootfs call: $(tr '\n' ' ' < "$D/trivy-argv")"
D="$WORK/osl-fail"; mkdir -p "$D"; osl_run "$D" OSL_TRIVY_FAIL=1
[ "$(lic "$D" libc6)" = '[]' ] && [ "$(osl_step "$D" | jq -c '.[0:2]')" = '["degraded","unavailable"]' ] \
    && [ "$(jq -r .run.status "$D/bomlens-result.json")" = succeeded_degraded ] \
    && pass "when Trivy cannot read the target, hashes are still dropped and the step is degraded" \
    || fail "os-licenses failure: libc6 $(lic "$D" libc6)" "$(osl_step "$D")"
D="$WORK/osl-empty"; mkdir -p "$D"; osl_run "$D" OSL_TRIVY_EMPTY=1
[ "$(osl_step "$D" | jq -c '.[0:2]')" = '["degraded","unavailable"]' ] && [ "$(lic "$D" libc6)" = '[]' ] \
    && pass "Trivy reading the target but licensing no Debian package is degraded, not ok" \
    || fail "os-licenses empty: $(osl_step "$D")"
D="$WORK/osl-off"; mkdir -p "$D"; osl_run "$D" BOMLENS_OS_LICENSES=false
[ ! -e "$D/trivy-argv" ] && [ "$(lic "$D" libc6)" = '[]' ] && [ "$(osl_step "$D" | jq -c '.[0]')" = '"disabled"' ] \
    && pass "BOMLENS_OS_LICENSES=false: no Trivy, the hashes are still dropped, the step is disabled" \
    || fail "off: trivy run $([ -e "$D/trivy-argv" ] && echo yes || echo no), libc6 $(lic "$D" libc6)" "$(osl_step "$D")"

echo "== IMAGE mode pins the later reads to the digest syft read =="
# syft writes its source record through a template output; the stub copies a
# recorded one (tests/fixtures/syft-source-*.json, from a real registry and a
# real daemon read) there, and prints the Debian SBOM above so Trivy runs.
PIN="$WORK/image-pin"; mkdir -p "$PIN/bin"
# PIN_SYFT_FAIL makes the source record fail the way syft does: "after" writes
# the SBOM, then exits 1 (a template it cannot render); "before" exits 1 with
# no output (a template path it cannot write). Each call appends its arguments
# and a "--end--" line.
cat > "$PIN/bin/syft" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" --end-- >> "$PIN_SYFT_ARGV"
tpl=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && case "$a" in template=*) tpl="${a#template=}" ;; esac; prev="$a"; done
if [ -n "$tpl" ]; then
    case "${PIN_SYFT_FAIL:-}" in
        after) bash "$PIN_OSL_SYFT"; echo "template: executing: bad function" >&2; exit 1 ;;
        before) echo "unable to create report file: permission denied" >&2; exit 1 ;;
    esac
    [ -n "${PIN_SOURCE:-}" ] && cp "$PIN_SOURCE" "$tpl"
fi
exec bash "$PIN_OSL_SYFT"
STUB
# The file view asks the daemon: info succeeds, create logs its reference and
# fails, so the view gives up after naming the image it would read.
cat > "$PIN/bin/docker" <<'STUB'
#!/bin/bash
[ "${1:-}" = info ] && exit 0
[ "${1:-}" = create ] && printf '%s\n' "${@: -1}" >> "$PIN_DOCKER_LOG"
exit 1
STUB
chmod +x "$PIN/bin/syft" "$PIN/bin/docker"
REG_DIGEST=sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
REG_INDEX=sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
DMN_DIGEST=sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
# Copies of entrypoint.sh that look for the socket where the test says, so
# both paths run whether or not this host has Docker.
sed "s#/var/run/docker.sock#$PIN/none.sock#g" "$ENTRY" > "$PIN/entry-nosock.sh"
sed "s#/var/run/docker.sock#$PIN/d.sock#g" "$ENTRY" > "$PIN/entry-sock.sh"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$PIN/d.sock" 2>/dev/null
pin_run() {  # pin_run <dir> <sock|nosock> <image> <source fixture or ""> [VAR=value ...]
    local d="$1" e="$PIN/entry-$2.sh" t="$3" src="$4"; shift 4
    mkdir -p "$d"
    ( cd "$d" && env PATH="$PIN/bin:$OSL/bin:$WORK/bin:$PATH" MODE=IMAGE TARGET_IMAGE="$t" PIN_SOURCE="$src" \
        PIN_SYFT_ARGV="$d/syft-argv" PIN_OSL_SYFT="$OSL/bin/syft" OSL_TRIVY_ARGV="$d/trivy-argv" PIN_DOCKER_LOG="$d/docker-create" \
        PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$d" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false \
        "$@" bash "$e" ) > "$d.log" 2>&1
}
pin_image() { jq -c '.input.image' "$1/bomlens-result.json" 2>/dev/null; }
if ! grep -q "$PIN/d.sock" "$PIN/entry-sock.sh" || [ ! -S "$PIN/d.sock" ]; then
    fail "could not set up the socket copies of entrypoint.sh (no /var/run/docker.sock in it, or no socket made)"
else
    D="$WORK/pin-registry"; pin_run "$D" nosock alpine:3.20 "$FIX/syft-source-registry.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "alpine@$REG_DIGEST" ] \
        && grep -q '^template=' "$D/syft-argv" \
        && [ "$(pin_image "$D")" = "{\"reference\":\"alpine:3.20\",\"source\":\"registry\",\"digest\":\"$REG_DIGEST\",\"platform\":\"linux/arm64\",\"index_digest\":\"$REG_INDEX\"}" ] \
        && grep -q "image digest: $REG_DIGEST (linux/arm64)" "$D.log" \
        && pass "registry read: Trivy reads the platform manifest syft read, the manifest records digest, index and platform" \
        || fail "registry pin: trivy $(tail -1 "$D/trivy-argv" 2>&1), image $(pin_image "$D")" "$(tail -4 "$D.log")"
    err="$(schema_errors "$D/bomlens-result.json")"
    [ -z "$err" ] && pass "a manifest with input.image validates against schemas/engine-result-1.json" || fail "schema errors" "$err"
    D="$WORK/pin-registry-scheme"; pin_run "$D" sock registry:alpine:3.20 "$FIX/syft-source-registry.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "alpine@$REG_DIGEST" ] && grep -qx 'remote' "$D/trivy-argv" \
        && [ "$(jq -r '.input.image.source' "$D/bomlens-result.json")" = registry ] \
        && pass "registry: scheme with the socket mounted is still a registry read, pinned" \
        || fail "registry: scheme: $(tr '\n' ' ' < "$D/trivy-argv" 2>&1)"
    D="$WORK/pin-daemon"; pin_run "$D" sock busybox:latest "$FIX/syft-source-daemon.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "busybox@$DMN_DIGEST" ] \
        && [ "$(pin_image "$D")" = "{\"reference\":\"busybox:latest\",\"source\":\"daemon\",\"digest\":\"$DMN_DIGEST\",\"platform\":\"linux/arm64\"}" ] \
        && pass "daemon read: Trivy reads the repository digest the daemon holds, not syft's computed manifest digest" \
        || fail "daemon pin: trivy $(tail -1 "$D/trivy-argv" 2>&1), image $(pin_image "$D")" "$(tail -4 "$D.log")"
    D="$WORK/pin-daemon-qualified"; pin_run "$D" sock docker.io/library/busybox:latest "$FIX/syft-source-daemon.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "docker.io/library/busybox@$DMN_DIGEST" ] \
        && pass "a fully qualified name matches the daemon's short repository digest" \
        || fail "qualified daemon pin: $(tail -1 "$D/trivy-argv" 2>&1)"
    D="$WORK/pin-daemon-nomatch"; pin_run "$D" sock myapp:dev "$FIX/syft-source-daemon.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "myapp:dev" ] \
        && [ "$(jq -c '.input.image | [.source, .digest, .platform]' "$D/bomlens-result.json")" = '["daemon",null,"linux/arm64"]' ] \
        && grep -q 'could not resolve the digest of myapp:dev' "$D.log" \
        && [ "$(jq -r .run.status "$D/bomlens-result.json")" = succeeded ] \
        && pass "no repository digest for this name: the reference is read as given, digest null, with a warning" \
        || fail "no match: trivy $(tail -1 "$D/trivy-argv" 2>&1), image $(pin_image "$D")" "$(tail -4 "$D.log")"
    D="$WORK/pin-archive"; pin_run "$D" sock docker-archive:/in/app.tar "$FIX/syft-source-registry.json"
    grep -qx -- '--input' "$D/trivy-argv" && grep -qx '/in/app.tar' "$D/trivy-argv" \
        && [ "$(jq -c '.input.image | [.reference, .source, .digest]' "$D/bomlens-result.json")" = '["docker-archive:/in/app.tar","archive",null]' ] \
        && ! grep -q 'image digest:\|could not resolve the digest' "$D.log" \
        && pass "an archive is read as it is, with no digest" \
        || fail "archive: $(tr '\n' ' ' < "$D/trivy-argv" 2>&1), image $(pin_image "$D")"
    jq '.metadata.manifestDigest = "sha256:45e0;touch /tmp/pwned" | .metadata.repoDigests = ["alpine@sha256:$(id)"]' \
        "$FIX/syft-source-registry.json" > "$PIN/bad-digest.json"
    D="$WORK/pin-bad-digest"; pin_run "$D" nosock alpine:3.20 "$PIN/bad-digest.json"
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "alpine:3.20" ] \
        && [ "$(jq -c '.input.image | [.digest, has("index_digest")]' "$D/bomlens-result.json")" = '[null,false]' ] \
        && pass "a digest that is not sha256:<64 hex> is never used" \
        || fail "bad digest: trivy $(tail -1 "$D/trivy-argv" 2>&1), image $(pin_image "$D")"
    D="$WORK/pin-none"; pin_run "$D" nosock alpine:3.20 ""
    [ "$(tail -1 "$D/trivy-argv" 2>/dev/null)" = "alpine:3.20" ] \
        && [ "$(pin_image "$D")" = '{"reference":"alpine:3.20","source":"registry","digest":null,"platform":null}' ] \
        && pass "no source record from syft: the reference is read as given, digest and platform null" \
        || fail "no record: trivy $(tail -1 "$D/trivy-argv" 2>&1), image $(pin_image "$D")"
    # More reference forms, the schemes and the file view.
    pin_last() { tail -1 "$1/trivy-argv" 2>/dev/null; }
    D="$WORK/pin-port"; pin_run "$D" nosock localhost:5000/team/app:1.2 "$FIX/syft-source-registry.json"
    [ "$(pin_last "$D")" = "localhost:5000/team/app@$REG_DIGEST" ] \
        && pass "a registry with a port keeps the port, loses the tag" || fail "port: $(pin_last "$D")"
    D="$WORK/pin-has-digest"; pin_run "$D" nosock "alpine:3.20@$REG_INDEX" "$FIX/syft-source-registry.json"
    [ "$(pin_last "$D")" = "alpine@$REG_DIGEST" ] && [ "$(jq -r .input.image.reference "$D/bomlens-result.json")" = "alpine:3.20@$REG_INDEX" ] \
        && pass "a reference that already names a digest is pinned to the platform manifest syft read" || fail "has digest: $(pin_last "$D")"
    D="$WORK/pin-no-tag"; pin_run "$D" nosock alpine "$FIX/syft-source-registry.json"
    [ "$(pin_last "$D")" = "alpine@$REG_DIGEST" ] && pass "a name with no tag is pinned" || fail "no tag: $(pin_last "$D")"
    for sch in docker podman; do
        D="$WORK/pin-$sch"; pin_run "$D" sock "$sch:busybox:latest" "$FIX/syft-source-daemon.json"
        [ "$(pin_last "$D")" = "busybox@$DMN_DIGEST" ] && grep -qx -- '--image-src' "$D/trivy-argv" && grep -qx "$sch" "$D/trivy-argv" \
            && [ "$(jq -r .input.image.source "$D/bomlens-result.json")" = daemon ] \
            && pass "$sch: gives Trivy --image-src $sch with the pinned reference" \
            || fail "$sch: scheme: $(tr '\n' ' ' < "$D/trivy-argv" 2>&1)"
    done
    D="$WORK/pin-file-view"; pin_run "$D" sock busybox:latest "$FIX/syft-source-daemon.json"
    [ "$(cat "$D/docker-create" 2>/dev/null)" = "busybox@$DMN_DIGEST" ] \
        && pass "the file view creates its container from the pinned reference" || fail "file view: $(cat "$D/docker-create" 2>&1)"
    for bad in "alpine 3.20" "x:1 --output=/tmp/y"; do
        D="$WORK/pin-inject-$(printf '%s' "$bad" | tr -c 'a-z0-9' '_')"; pin_run "$D" nosock "$bad" "$FIX/syft-source-registry.json"
        [ "$(pin_last "$D")" = "$bad" ] && [ "$(jq -c '.input.image | [.digest, .source]' "$D/bomlens-result.json")" = '[null,"registry"]' ] \
            && pass "a name that is not a plain image name ('$bad') is never pinned" \
            || fail "inject '$bad': trivy $(pin_last "$D"), image $(pin_image "$D")"
    done

    # A name starting with - would be an option to syft, Trivy and docker.
    for bad in "-alpine:3.20" "--output=/tmp/x:1"; do
        D="$WORK/pin-dash-$(printf '%s' "$bad" | tr -c 'a-z0-9' '_')"; pin_run "$D" sock "$bad" "$FIX/syft-source-registry.json"
        rc=$?
        [ "$rc" = 1 ] && [ ! -e "$D/syft-argv" ] && [ ! -e "$D/trivy-argv" ] && [ ! -e "$D/docker-create" ] \
            && grep -q "TARGET_IMAGE '$bad' starts with '-'" "$D.log" \
            && [ "$(jq -r .run.status "$D/bomlens-result.json")" = failed ] \
            && pass "an image name starting with - ('$bad') is refused before any tool reads it" \
            || fail "dash '$bad': rc $rc, syft run $([ -e "$D/syft-argv" ] && echo yes || echo no)" "$(tail -3 "$D.log")"
    done

    # Where syft read a plain name with the socket mounted, from its record.
    D="$WORK/pin-fallback"; pin_run "$D" sock busybox:latest "$FIX/syft-source-registry-fallback.json"
    [ "$(jq -c '.input.image | [.source, .digest, .index_digest]' "$D/bomlens-result.json")" = '["registry","sha256:365a051f12e05767b598e643676f14a450fb678a75ccf2beb0052c95d5c73b83","'"$DMN_DIGEST"'"]' ] \
        && [ "$(pin_last "$D")" = "busybox@sha256:365a051f12e05767b598e643676f14a450fb678a75ccf2beb0052c95d5c73b83" ] \
        && pass "with the socket, a record written by the registry read (syft fell back) is a registry read" \
        || fail "fallback: $(pin_image "$D"), trivy $(pin_last "$D")"
    jq '.metadata.tags = [] | .metadata.repoDigests = ["ghcr.io/team/app@'"$DMN_DIGEST"'"]' "$FIX/syft-source-daemon.json" > "$PIN/unknown.json"
    D="$WORK/pin-unknown"; pin_run "$D" sock ghcr.io/team/app:1 "$PIN/unknown.json"
    [ "$(jq -c '.input.image | [.source, .digest]' "$D/bomlens-result.json")" = '["unknown","'"$DMN_DIGEST"'"]' ] \
        && [ "$(pin_last "$D")" = "ghcr.io/team/app@$DMN_DIGEST" ] \
        && [ -z "$(schema_errors "$D/bomlens-result.json")" ] \
        && pass "a record that does not show the provider is unknown, pinned by the repository digest" \
        || fail "unknown: $(pin_image "$D"), trivy $(pin_last "$D")"

    # The variant: architectureVariant in syft's record, else the image config.
    D="$WORK/pin-armv7"; pin_run "$D" nosock alpine:3.20 "$FIX/syft-source-registry-armv7.json"
    [ "$(jq -r .input.image.platform "$D/bomlens-result.json")" = linux/arm/v7 ] \
        && pass "an arm/v7 image records linux/arm/v7" || fail "armv7: $(pin_image "$D")"
    jq '.metadata |= del(.architectureVariant)' "$FIX/syft-source-registry-armv7.json" > "$PIN/armv7-config.json"
    D="$WORK/pin-armv7-config"; pin_run "$D" nosock alpine:3.20 "$PIN/armv7-config.json"
    [ "$(jq -r .input.image.platform "$D/bomlens-result.json")" = linux/arm/v7 ] \
        && pass "with no architectureVariant the variant comes from the image config" || fail "armv7 config: $(pin_image "$D")"

    # The source record is an extra: when syft cannot write it, the scan goes on.
    D="$WORK/pin-record-after"; pin_run "$D" nosock alpine:3.20 "$FIX/syft-source-registry.json" PIN_SYFT_FAIL=after
    rc=$?
    [ "$rc" = 0 ] && [ "$(grep -c -- '--end--' "$D/syft-argv")" = 1 ] && [ "$(pin_last "$D")" = "alpine:3.20" ] \
        && [ "$(jq -c '[.run.status, .input.image.digest]' "$D/bomlens-result.json")" = '["succeeded",null]' ] \
        && grep -q 'syft could not write its source record' "$D.log" && ! grep -q 'registry needs credentials' "$D.log" \
        && pass "a source record that fails after the SBOM is written: one read, the scan goes on, digest null" \
        || fail "record after: rc $rc, calls $(grep -c -- '--end--' "$D/syft-argv" 2>&1), $(pin_image "$D")" "$(tail -4 "$D.log")"
    D="$WORK/pin-record-before"; pin_run "$D" nosock alpine:3.20 "$FIX/syft-source-registry.json" PIN_SYFT_FAIL=before
    rc=$?
    [ "$rc" = 0 ] && [ "$(grep -c -- '--end--' "$D/syft-argv")" = 2 ] && ! sed -n '/--end--/,$p' "$D/syft-argv" | grep -q '^-t$' \
        && [ "$(jq -r '.components | length' "$D/demo_1.0_bom.json")" -gt 0 ] \
        && [ "$(jq -c '[.run.status, .input.image.digest]' "$D/bomlens-result.json")" = '["succeeded",null]' ] \
        && grep -q 'syft could not write its source record' "$D.log" \
        && pass "a source record that fails before any output: read once more without it, the scan goes on" \
        || fail "record before: rc $rc, calls $(grep -c -- '--end--' "$D/syft-argv" 2>&1), $(pin_image "$D")" "$(tail -4 "$D.log")"
    D="$WORK/pin-failed"; mkdir -p "$D"
    ( cd "$D" && env PATH="$IMG/bin:$WORK/bin:$PATH" MODE=IMAGE TARGET_IMAGE=registry.example/denied:1 SYFT_ARGV_LOG="$D/argv" \
        PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$D" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false bash "$PIN/entry-nosock.sh" ) > "$D.log" 2>&1
    [ "$(pin_image "$D")" = '{"reference":"registry.example/denied:1","source":null,"digest":null,"platform":null}' ] \
        && [ -z "$(schema_errors "$D/bomlens-result.json")" ] \
        && pass "a run that stopped before syft read the image records the reference only" \
        || fail "failed run: image $(pin_image "$D")"
fi
D="$(new_run pin-not-image)"; run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(jq -r '.input | has("image")' "$D/bomlens-result.json")" = false ] \
    && pass "a run that is not an image scan has no input.image" || fail "input: $(jq -c .input "$D/bomlens-result.json")"

echo "== a package cdxgen could not name is said in generate's detail =="
for case in ok poetry; do
    D="$(new_run "unnamed-$case")"
    if [ "$case" = ok ]; then prop='[{"name":"bomlens:unnamed-packages-dropped","value":"1"}]'
    else prop='[{"name":"bomlens:unnamed-packages-dropped","value":"1"},{"name":"bomlens:prep-step-applied","value":"poetry-requirements-partial"}]'; fi
    jq --argjson p "$prop" '.metadata.properties = ((.metadata.properties // []) + $p)' "$D/demo_1.0_bom.json" > "$D/x" && mv "$D/x" "$D/demo_1.0_bom.json"
    run_engine "$D" "$ROOT_DIR/docker/lib"
    got="$(jq -c '[.steps[] | select(.id=="generate")][0] | [.status, .counts.unresolved, (.detail // "" | test("1 package\\(s\\) cdxgen could not name were left out"))]' "$D/bomlens-result.json")"
    case "$case:$got" in
        'ok:["ok",1,true]'|'poetry:["degraded",1,true]') pass "unresolved packages are counted and said in the detail ($case)" ;;
        *) fail "unnamed $case: $got" ;;
    esac
done
err="$(schema_errors "$D/bomlens-result.json")"
[ -z "$err" ] && pass "a manifest with unresolved packages validates" || fail "schema errors" "$err"

echo "== a project named app, nothing uploaded =="
D="$(new_run name-app)"; mv "$D/demo_1.0_bom.json" "$D/app_1.0_bom.json"
( cd "$D" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=app PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$D" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=app_1.0_bom.json \
    UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false \
    bash "$ENTRY" ) > "$D.log" 2>&1
rc=$?
[ "$rc" = 0 ] && jq -e '[.steps[] | select(.id=="stamp-metadata")][0] | .status == "ok" and (.detail // "" | startswith("the project name '"'"'app'"'"' is also the name scanners give"))' "$D/bomlens-result.json" >/dev/null \
    && [ "$(jq -r .run.status "$D/bomlens-result.json")" = succeeded ] \
    && pass "a project named app runs through: stamp-metadata ok with the warning in its detail" \
    || fail "name app: rc $rc, $(jq -c '[.steps[] | select(.id=="stamp-metadata")], .run.status' "$D/bomlens-result.json" 2>&1)" "$(grep -i 'stamp' "$D.log")"

echo "== the input fingerprint of stage 1 =="
# plan_fp <plan dir> [field]: the generate stage's input_fingerprint (or the
# top-level one when there are no stages), or one field of it.
plan_fp() {
    jq -r --arg f "${2:-}" '(([.stages[]? | select(.id == "generate") | .input_fingerprint] | first) // .input_fingerprint)
        | if $f == "" then tojson else (.[$f] | if type == "string" then . else tojson end) end' "$1/bomlens-plan.json" 2>/dev/null
}
# fp_tree <dir> [reverse]: a Node.js workspace with a lock file, a resolver
# setting file and members; "reverse" writes the files in the other order.
fp_tree() {
    local d="$1" f
    mkdir -p "$d/packages/a" "$d/node_modules/x" "$d/test"
    local -a order=(package.json package-lock.json .npmrc packages/a/package.json node_modules/x/package.json test/package.json)
    [ "${2:-}" = reverse ] && order=(test/package.json node_modules/x/package.json packages/a/package.json .npmrc package-lock.json package.json)
    for f in "${order[@]}"; do
        case "$f" in
            package.json) echo '{"name":"x","workspaces":["packages/*","test"],"dependencies":{"lodash":"^4"}}' > "$d/$f" ;;
            package-lock.json) echo '{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4"}},"packages/a":{"dependencies":{"left-pad":"1.3.0"}},"test":{"dependencies":{"left-pad":"1.3.0"}},"node_modules/lodash":{"version":"4.17.21"}}}' > "$d/$f" ;;
            .npmrc) echo 'save-exact=true' > "$d/$f" ;;
            *) echo '{"dependencies":{"left-pad":"1.3.0"}}' > "$d/$f" ;;
        esac
        sleep 0.01
    done
}
FPA="$WORK/fp-a/src"; FPB="$WORK/fp-elsewhere/deeper/src"; FPC="$WORK/fp-c"
fp_tree "$FPA"; mkdir -p "$(dirname "$FPB")"; cp -R "$FPA" "$FPB"; fp_tree "$FPC" reverse
PA="$(plan_run fp-a "$FPA")"; PB="$(plan_run fp-b "$FPB")"; PC="$(plan_run fp-c "$FPC")"
sa="$(plan_fp "$PA" sha256)"
err="$(plan_schema_errors "$PA/bomlens-plan.json")"
[ -z "$err" ] && pass "a plan with an input fingerprint validates against schemas/engine-plan-1.json" || fail "plan schema errors" "$err"
[ "$(plan_fp "$PA" | jq -r '"\(.algorithm) \(.reusable) \(.reasons | length) \(.sha256 | test("^[0-9a-f]{64}$"))"')" = "bomlens-input-1 true 0 true" ] \
    && pass "a Node.js tree with a lock file has a reusable fingerprint" || fail "fingerprint: $(plan_fp "$PA")"
[ "$(plan_fp "$PA")" = "$(jq -c .input_fingerprint "$PA/bomlens-plan.json")" ] \
    && pass "the plan's top-level input_fingerprint is the generate stage's" || fail "top-level: $(jq -c .input_fingerprint "$PA/bomlens-plan.json")"
[ -n "$sa" ] && [ "$sa" = "$(plan_fp "$PB" sha256)" ] \
    && pass "the same tree at another absolute path has the same fingerprint" || fail "paths: $sa vs $(plan_fp "$PB" sha256)"
[ -n "$sa" ] && [ "$sa" = "$(plan_fp "$PC" sha256)" ] \
    && pass "the order the files were written in does not change it" || fail "order: $sa vs $(plan_fp "$PC" sha256)"
# tree_sha <plan dir>: the whole-tree component's sha256 (and count).
tree_sha() { plan_fp "$1" | jq -r '.components[] | select(.kind == "file" and .name == ".") | "\(.sha256) \(.count)"'; }
[ "$(plan_fp "$PA" | jq -c '[.components[] | select(.kind == "file") | {name, count}]')" = '[{"name":".","count":6}]' ] \
    && pass "the whole tree, node_modules and the non-shipped test folder included, is one file component of 6 files" \
    || fail "file components: $(plan_fp "$PA" | jq -c '[.components[] | select(.kind == "file")]')"
grep -qF "$FPA" "$PA/bomlens-plan.json" && fail "the plan holds the source's absolute path" || pass "no absolute path in the plan"
PI="$(plan_run fp-a-ns "$FPA" BOMLENS_INCLUDE_NON_SHIPPED=1)"
[ "$(plan_fp "$PI" sha256)" != "$sa" ] && [ "$(tree_sha "$PI")" = "$(tree_sha "$PA")" ] \
    && pass "BOMLENS_INCLUDE_NON_SHIPPED=1 changes the value through its setting; the tree is the same" \
    || fail "include non-shipped: $(plan_fp "$PI" sha256), tree $(tree_sha "$PI") vs $(tree_sha "$PA")"
PX="$(plan_run fp-a-proxy "$FPA" HTTPS_PROXY=http://user:secret@proxy:3128 http_proxy=http://user:secret@proxy:3128 \
    GOPROXY=https://goproxy.example GOSUMDB=off TRIVY_DB_REPOSITORY=mirror.example/trivy-db CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ HOST_UID=501 HOST_GID=20)"
! grep -qE 'secret|user:|proxy:3128|goproxy\.example|mirror\.example/trivy' "$PX/bomlens-plan.json" \
    && pass "a proxy value with credentials appears nowhere in bomlens-plan.json" || fail "the plan holds a proxy value" "$(grep -oE '.{30}(secret|proxy:3128).{10}' "$PX/bomlens-plan.json" | head -3)"
[ "$(plan_fp "$PX" sha256)" = "$sa" ] \
    && pass "proxies, GOPROXY, GOSUMDB, TRIVY_*, CDXGEN_IMAGE_PREFIX and HOST_UID/GID do not change it" || fail "excluded settings changed it: $(plan_fp "$PX" sha256) vs $sa"
PS="$(plan_run fp-a-setting "$FPA" BOMLENS_NODE_FULL_GRAPH=1)"
[ "$(plan_fp "$PS" sha256)" != "$sa" ] && [ "$(plan_fp "$PS" reusable)" = true ] \
    && pass "a build-prep option changes it" || fail "BOMLENS_NODE_FULL_GRAPH: $(plan_fp "$PS" sha256)"
# The files stage 1 runs from this image count, also with no image digest.
FPLIB="$WORK/fp-lib"; cp -R "$ROOT_DIR/docker/lib" "$FPLIB"; echo '# changed' >> "$FPLIB/build-prep.sh"
PE="$(plan_run fp-a-engine "$FPA" BOMLENS_LIBDIR="$FPLIB")"
ediff="$(jq -n -c --argjson a "$(plan_fp "$PA")" --argjson b "$(plan_fp "$PE")" \
    '[range($a.components | length) | select($a.components[.] != $b.components[.]) | $a.components[.] | "\(.kind):\(.name)"]' 2>&1)"
[ "$(plan_fp "$PE" sha256)" != "$sa" ] && [ "$(plan_fp "$PE" reusable)" = true ] && [ "$ediff" = '["engine:build-prep.sh"]' ] \
    && pass "a changed build-prep.sh changes it, and only its engine component differs" \
    || fail "build-prep.sh change: sha $(plan_fp "$PE" sha256), differing components $ediff"
plan_fp "$PA" | jq -e --arg h "$(shasum -a 256 < "$PA/bomlens-plan/identify-conda.py" | cut -d' ' -f1)" \
    'any(.components[]; .kind == "engine" and .name == "identify-conda.py" and .sha256 == $h)' >/dev/null \
    && pass "the engine components hash the files copied into bomlens-plan/" \
    || fail "engine components: $(plan_fp "$PA" | jq -c '[.components[] | select(.kind == "engine")]')"
jq '.packages["node_modules/lodash"].version = "4.17.20"' "$FPA/package-lock.json" > "$FPB/package-lock.json"
PB2="$(plan_run fp-b2 "$FPB")"
[ "$(plan_fp "$PB2" sha256)" != "$sa" ] && [ "$(plan_fp "$PB2" reusable)" = true ] \
    && pass "a changed lock file changes the fingerprint" || fail "changed lock: $(plan_fp "$PB2" sha256)"
rm -f "$FPB/package-lock.json"
PN="$(plan_run fp-nolock "$FPB")"
[ "$(plan_fp "$PN" | jq -c '[.sha256, .reusable, .reasons]')" = '[null,false,["no-lockfile"]]' ] \
    && pass "no lock file: sha256 null, not reusable, no-lockfile" || fail "no lock: $(plan_fp "$PN")"
MV="$WORK/fp-maven"; mkdir -p "$MV"
maven_pom() {  # maven_pom <dependency version>
    cat > "$MV/pom.xml" <<POM
<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId><version>1.0</version>
<properties><guava.version>$1</guava.version></properties>
<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>\${guava.version}</version></dependency></dependencies></project>
POM
}
for v in '[30.0,33.0)' '33.0-SNAPSHOT' 'LATEST' '33.3.1-jre'; do
    maven_pom "$v"
    P="$(plan_run "fp-maven-${v//[^A-Za-z0-9.-]/_}" "$MV")"
    got="$(plan_fp "$P" | jq -c '[.reusable, .reasons]')"
    case "$v:$got" in
        '33.3.1-jre:[false,["registry-resolution"]]') pass "a Maven tree with fixed versions is still registry-resolution (no lock covers the transitive graph)" ;;
        *'-jre:'*) fail "fixed Maven versions: $got" ;;
        *':[false,["registry-resolution","unpinned-versions"]]') pass "a Maven dependency version $v is unpinned-versions" ;;
        *) fail "Maven $v: $got" ;;
    esac
done
UK="$WORK/fp-unknown"; mkdir -p "$UK"; echo 'project(x)' > "$UK/CMakeLists.txt"
P="$(plan_run fp-unknown "$UK")"
[ "$(plan_fp "$P" | jq -c '[.sha256, .reasons]')" = '[null,["unsupported-ecosystem"]]' ] \
    && pass "an unrecognised tree is unsupported-ecosystem" || fail "unknown: $(plan_fp "$P")"
MX="$WORK/fp-mixed"; fp_tree "$MX"; echo 'requests==2.31.0' > "$MX/requirements.txt"
P="$(plan_run fp-mixed "$MX")"
[ "$(plan_fp "$P" | jq -c '[.reusable, .reasons]')" = '[false,["no-lockfile"]]' ] \
    && pass "a mixed tree needs every language locked (Python without a lock file)" || fail "mixed: $(plan_fp "$P")"
# fp_case <case> <dir> [VAR=value ...]: [reusable, reasons] of the plan.
fp_case() { local c="$1" d="$2"; shift 2; plan_fp "$(plan_run "fpc-$c" "$d" "$@")" | jq -c '[.reusable, .reasons]'; }
expect_fp() {  # expect_fp <want> <got> <what>
    [ "$2" = "$1" ] && pass "$3" || fail "$3: got $2"
}
NL='{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1"}}}}'
FX="$WORK/fpx"
# Requirements files: stage 1 runs pip against the registry.
mkdir -p "$FX/req-inc"; printf -- '-r base.txt\n' > "$FX/req-inc/requirements.txt"; echo 'requests==2.31.0' > "$FX/req-inc/base.txt"
P="$(plan_run fpc-req-inc "$FX/req-inc")"
expect_fp '[false,["no-lockfile"]]' "$(plan_fp "$P" | jq -c '[.reusable, .reasons]')" "a requirements file that only includes another is no-lockfile"
t1="$(tree_sha "$P")"; echo 'requests==2.32.0' > "$FX/req-inc/base.txt"
[ "$(tree_sha "$(plan_run fpc-req-inc2 "$FX/req-inc")")" != "$t1" ] \
    && pass "the included requirements file is part of the tree value" || fail "include: tree unchanged ($t1)"
mkdir -p "$FX/req-var"; printf 'requests==${REQ_VERSION} --hash=sha256:%064d\n' 0 > "$FX/req-var/requirements.txt"
expect_fp '[false,["no-lockfile"]]' "$(fp_case req-var "$FX/req-var")" "a requirements file using an environment variable is no-lockfile"
mkdir -p "$FX/req-out"; printf -- '--requirement=../../outside.txt\n' > "$FX/req-out/requirements.txt"
expect_fp '[false,["no-lockfile","unhashable-input"]]' "$(fp_case req-out "$FX/req-out")" "an include outside the source is unhashable-input"
mkdir -p "$FX/req-pin"; echo 'requests==2.31.0' > "$FX/req-pin/requirements.txt"; : > "$FX/req-pin/poetry.lock"
expect_fp '[false,["no-lockfile"]]' "$(fp_case req-pin "$FX/req-pin")" "exact pins without --hash are no-lockfile, and poetry.lock does not cover requirements.txt"
mkdir -p "$FX/req-url"; printf 'pkg @ https://example.invalid/pkg.whl --hash=sha256:%064d\n' 0 > "$FX/req-url/requirements.txt"
expect_fp '[false,["no-lockfile"]]' "$(fp_case req-url "$FX/req-url")" "a URL requirement is no-lockfile"
mkdir -p "$FX/req-hash"; printf 'requests==2.31.0 \\\n    --hash=sha256:%064d\n' 0 > "$FX/req-hash/requirements.txt"
expect_fp '[true,[]]' "$(fp_case req-hash "$FX/req-hash")" "a requirements file in hash-checking mode is reusable"
# A lock above a manifest covers it only as a declared workspace member.
mkdir -p "$FX/ws-no/sub"; echo '{"dependencies":{"a":"1"}}' > "$FX/ws-no/package.json"; echo "$NL" > "$FX/ws-no/package-lock.json"
echo '{"dependencies":{"b":"1"}}' > "$FX/ws-no/sub/package.json"
expect_fp '[false,["no-lockfile"]]' "$(fp_case ws-no "$FX/ws-no")" "a lock in a parent folder does not cover a package that is not a workspace member"
mkdir -p "$FX/ws-cargo/crates/a" "$FX/ws-cargo/other"
printf '[workspace]\nmembers = ["crates/*"]\n[dependencies]\nserde = "1"\n' > "$FX/ws-cargo/Cargo.toml"; echo x > "$FX/ws-cargo/Cargo.lock"
printf '[package]\nname="a"\n[dependencies]\nlog = "0.4"\n' > "$FX/ws-cargo/crates/a/Cargo.toml"
expect_fp '[true,[]]' "$(fp_case ws-cargo "$FX/ws-cargo")" "a Cargo workspace member is covered by the root Cargo.lock"
printf '[package]\nname="o"\n[dependencies]\nlog = "0.4"\n' > "$FX/ws-cargo/other/Cargo.toml"
expect_fp '[false,["no-lockfile"]]' "$(fp_case ws-cargo-out "$FX/ws-cargo")" "a crate outside the workspace members is not"
mkdir -p "$FX/gradle/app"; echo "dependencies { implementation 'a:b:1' }" > "$FX/gradle/app/build.gradle"
echo "dependencies { implementation 'a:b:1' }" > "$FX/gradle/build.gradle"; : > "$FX/gradle/gradle.lockfile"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gradle "$FX/gradle")" "gradle.lockfile is per project: the root's does not cover app/"
# Every manifest in the tree is judged, not only the root language.
mkdir -p "$FX/nested/tools/gen"; echo '{"dependencies":{"a":"1"}}' > "$FX/nested/package.json"; echo "$NL" > "$FX/nested/package-lock.json"
printf 'module x\nrequire golang.org/x/text v0.3.0\n' > "$FX/nested/tools/gen/go.mod"
expect_fp '[false,["no-lockfile"]]' "$(fp_case nested "$FX/nested")" "a nested go.mod without go.sum in a Node.js tree is no-lockfile"
# Maven: versions from a parent pom in the tree, nested dependencies, unknown properties.
mkdir -p "$FX/mvn-parent/child"
cat > "$FX/mvn-parent/pom.xml" <<'POM'
<project><groupId>g</groupId><artifactId>root</artifactId><version>1</version><properties><x.version>[1.0,2.0)</x.version></properties></project>
POM
cat > "$FX/mvn-parent/child/pom.xml" <<'POM'
<project><parent><groupId>g</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>c</artifactId>
<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${x.version}</version></dependency></dependencies></project>
POM
expect_fp '[false,["registry-resolution","unpinned-versions"]]' "$(fp_case mvn-parent "$FX/mvn-parent")" "a range in a parent pom's property, used in a child, is unpinned-versions"
mkdir -p "$FX/mvn-plugin"
cat > "$FX/mvn-plugin/pom.xml" <<'POM'
<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version><build><plugins><plugin><artifactId>p</artifactId><version>1.0</version>
<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>2.0-SNAPSHOT</version></dependency></dependencies></plugin></plugins></build></project>
POM
expect_fp '[false,["registry-resolution","unpinned-versions"]]' "$(fp_case mvn-plugin "$FX/mvn-plugin")" "a SNAPSHOT dependency inside a plugin is unpinned-versions"
mkdir -p "$FX/mvn-bom"
cat > "$FX/mvn-bom/pom.xml" <<'POM'
<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version><dependencyManagement><dependencies>
<dependency><groupId>x</groupId><artifactId>bom</artifactId><version>${bom.version}</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement></project>
POM
expect_fp '[false,["registry-resolution"]]' "$(fp_case mvn-bom "$FX/mvn-bom")" "an imported BOM at a property defined nowhere is registry-resolution, as every Maven tree"
mvn_one() {  # mvn_one <dir> <extra project xml> <dependency version>
    mkdir -p "$1"
    printf '<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>%s<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>%s</version></dependency></dependencies></project>\n' "$2" "$3" > "$1/pom.xml"
}
mvn_one "$FX/mvn-profile" '<properties><y.v>1.0</y.v></properties><profiles><profile><id>p</id><properties><y.v>1.1-SNAPSHOT</y.v></properties></profile></profiles>' '${y.v}'
expect_fp '[false,["registry-resolution","unpinned-versions"]]' "$(fp_case mvn-profile "$FX/mvn-profile")" "a SNAPSHOT a profile gives a property is unpinned-versions"
mvn_one "$FX/mvn-config" '' '${revision}'; mkdir -p "$FX/mvn-config/.mvn"; echo '-Drevision=2.0-SNAPSHOT' > "$FX/mvn-config/.mvn/maven.config"
expect_fp '[false,["registry-resolution"]]' "$(fp_case mvn-config "$FX/mvn-config")" "a SNAPSHOT from .mvn/maven.config -D is registry-resolution, as every Maven tree"
echo '-Drevision=2.0' > "$FX/mvn-config/.mvn/maven.config"
expect_fp '[false,["registry-resolution"]]' "$(fp_case mvn-config-fixed "$FX/mvn-config")" "a fixed version from .mvn/maven.config -D is registry-resolution, as every Maven tree"
mvn_one "$FX/mvn-cdata" '' '<![CDATA[[1.0,2.0)]]>'
expect_fp '[false,["registry-resolution"]]' "$(fp_case mvn-cdata "$FX/mvn-cdata")" "a range written as CDATA is registry-resolution, as every Maven tree"
mvn_one "$FX/mvn-remote" '<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>3.0.0</version></parent>' '1.0'
expect_fp '[false,["registry-resolution"]]' "$(fp_case mvn-remote "$FX/mvn-remote")" "a parent pom from the registry (not in the tree) is registry-resolution, as every Maven tree"
mkdir -p "$FX/mvn-child/sub"
printf '<project><groupId>g</groupId><artifactId>root</artifactId><version>1</version><properties><y.v>1.0</y.v></properties></project>\n' > "$FX/mvn-child/pom.xml"
printf '<project><parent><groupId>g</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>c</artifactId><properties><y.v>[1,2)</y.v></properties><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${y.v}</version></dependency></dependencies></project>\n' > "$FX/mvn-child/sub/pom.xml"
expect_fp '[false,["registry-resolution","unpinned-versions"]]' "$(fp_case mvn-child "$FX/mvn-child")" "a child pom overriding a parent property with a range is unpinned-versions"
# Links: followed to a file inside the source only.
mkdir -p "$FX/link-out" "$FX/link-in"; echo '{"dependencies":{"a":"1"}}' | tee "$FX/link-out/package.json" > "$FX/link-in/package.json"
echo "$NL" > "$WORK/fpx-outside-lock.json"; ln -s "$WORK/fpx-outside-lock.json" "$FX/link-out/package-lock.json"
echo "$NL" > "$FX/link-in/real-lock.json"; ln -s real-lock.json "$FX/link-in/package-lock.json"
fp_case link-out "$FX/link-out" | jq -e 'first == false and (last | index("unhashable-input"))' >/dev/null \
    && pass "a lock file linked to outside the source is unhashable-input" || fail "link out: $(fp_case link-out2 "$FX/link-out")"
expect_fp '[true,[]]' "$(fp_case link-in "$FX/link-in")" "a lock file linked inside the source is hashed through the link"
mkdir -p "$FX/link-dir/real"; cp "$FX/link-in/package.json" "$FX/link-in/real-lock.json" "$FX/link-dir/"; mv "$FX/link-dir/real-lock.json" "$FX/link-dir/package-lock.json"
ln -s real "$FX/link-dir/linked"
expect_fp '[false,["unhashable-input"]]' "$(fp_case link-dir "$FX/link-dir")" "a folder link in the tree is unhashable-input"
# Go: go mod tidy reads the imports, so the code counts.
mkdir -p "$FX/go/pkg"; printf 'module x\nrequire golang.org/x/text v0.3.0\n' > "$FX/go/go.mod"; echo h > "$FX/go/go.sum"
echo 'package main' > "$FX/go/main.go"; echo 'package pkg' > "$FX/go/pkg/a_test.go"
P="$(plan_run fpc-go "$FX/go")"; g1="$(plan_fp "$P" sha256)"
[ "$(plan_fp "$P" reusable)" = true ] \
    && { echo 'package pkg // changed' > "$FX/go/pkg/a_test.go"; [ "$(plan_fp "$(plan_run fpc-go2 "$FX/go")" sha256)" != "$g1" ]; } \
    && pass "a Go module with go.sum and only covered imports is reusable, and a change in a .go file changes the value" \
    || fail "go: $(plan_fp "$P" | jq -c '[.reusable, .reasons]')"
mkdir -p "$FX/go-noreq"; printf 'module x\n' > "$FX/go-noreq/go.mod"
printf 'package main\nimport (\n  "fmt"\n  "github.com/example/lib"\n)\n' > "$FX/go-noreq/main.go"
expect_fp '[false,["registry-resolution"]]' "$(fp_case go-noreq "$FX/go-noreq")" "a Go import go.mod does not require is registry-resolution"
mkdir -p "$FX/go-v2"; printf 'module x\nrequire github.com/example/lib v1.0.0\n' > "$FX/go-v2/go.mod"; echo h > "$FX/go-v2/go.sum"
printf 'package main\nimport "github.com/example/lib/v2/sub"\n' > "$FX/go-v2/main.go"
expect_fp '[false,["registry-resolution"]]' "$(fp_case go-v2 "$FX/go-v2")" "a /v2 import with only v1 required is registry-resolution"
printf 'package main\nimport "github.com/example/lib/sub"\n' > "$FX/go-v2/main.go"
expect_fp '[true,[]]' "$(fp_case go-v1 "$FX/go-v2")" "an import the require list covers is reusable"
# Go: back-quoted import paths count like double-quoted ones.
mkdir -p "$FX/go-raw"; printf 'module x\nrequire golang.org/x/text v0.3.0\n' > "$FX/go-raw/go.mod"; echo h > "$FX/go-raw/go.sum"
printf 'package main\nimport `evil.example/newpkg`\n' > "$FX/go-raw/main.go"
expect_fp '[false,["registry-resolution"]]' "$(fp_case go-raw "$FX/go-raw")" "a back-quoted Go import go.mod does not cover is registry-resolution"
printf 'package main\nimport (\n\t"golang.org/x/text"\n\tx `evil.example/newpkg`\n)\n' > "$FX/go-raw/main.go"
expect_fp '[false,["registry-resolution"]]' "$(fp_case go-raw-block "$FX/go-raw")" "a back-quoted Go import in an import block is registry-resolution"
# Inputs that made the checks slow are read in time linear in their size.
mkdir -p "$FX/slow-go" "$FX/slow-pom" "$FX/slow-gradle" "$FX/mvn-chain"
printf 'module x\n' > "$FX/slow-go/go.mod"
python3 -c "import sys; open(sys.argv[1], 'w').write(' \n' * 60000 + 'import (\n' * 2000)" "$FX/slow-go/a.go"
python3 -c "import sys; open(sys.argv[1], 'w').write('<project>' + '<!--' * 100000 + '</project>')" "$FX/slow-pom/pom.xml"
printf "dependencies { implementation 'a:b:1' }\n" > "$FX/slow-gradle/build.gradle"
python3 -c "import sys; open(sys.argv[1], 'w').write('/*' * 200000)" "$FX/slow-gradle/x.gradle"
python3 - "$FX/mvn-chain/pom.xml" <<'PY'
import sys
props = "".join(f"<p{i}>${{p{i + 1}}}</p{i}>" for i in range(20))
prof = "".join(f"<profile><properties>{props}</properties></profile>" for _ in range(4))
open(sys.argv[1], "w").write("<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
    f"<properties>{props}</properties><profiles>{prof}</profiles><dependencies><dependency><groupId>x</groupId>"
    "<artifactId>y</artifactId><version>${p0}</version></dependency></dependencies></project>")
PY
for c in slow-go:'[true,[]]' slow-pom:'[false,["registry-resolution"]]' slow-gradle:'[false,["no-lockfile"]]' mvn-chain:'[false,["registry-resolution"]]'; do
    t0=$SECONDS; got="$(fp_case "${c%%:*}" "$FX/${c%%:*}")"; t=$((SECONDS - t0))
    [ "$got" = "${c#*:}" ] && [ "$t" -lt 30 ] && pass "${c%%:*}: checked in ${t}s, $got" || fail "${c%%:*}: $got in ${t}s"
done
# A manifest or Go source over 4 MiB cannot be judged: unhashable-input.
mkdir -p "$FX/big-go"; printf 'module x\n' > "$FX/big-go/go.mod"
python3 -c "import sys; open(sys.argv[1], 'w').write('package a\n' + '// x\n' * 1200000)" "$FX/big-go/a.go"
expect_fp '[false,["unhashable-input"]]' "$(fp_case big-go "$FX/big-go")" "a Go source over 4 MiB is unhashable-input"
# Folders count toward BOMLENS_FINGERPRINT_MAX_FILES, so empty ones stop the walk too.
mkdir -p "$FX/folders"; for i in $(seq 1 300); do mkdir -p "$FX/folders/d$i"; done
P="$(plan_run fpc-folders "$FX/folders" BOMLENS_FINGERPRINT_MAX_FILES=100)"
[ "$(plan_fp "$P" | jq -c '[(.reasons | index("unhashable-input") != null), (.components[] | select(.name == ".") | .truncated)]')" = '[true,true]' ] \
    && pass "300 empty folders over a limit of 100 stop the walk (truncated)" || fail "folders: $(plan_fp "$P" | jq -c '[.reasons, (.components[] | select(.name == "."))]')"
# Every file counts, a cdxgen config or a README as much as a lock file; .git does not.
mkdir -p "$FX/whole/.git" "$FX/whole/src"; cp "$FX/link-in/package.json" "$FX/whole/"; echo "$NL" > "$FX/whole/package-lock.json"
echo '// app' > "$FX/whole/src/app.js"; echo readme > "$FX/whole/README.md"; echo ref > "$FX/whole/.git/HEAD"
w0="$(plan_fp "$(plan_run fpc-whole0 "$FX/whole")" sha256)"
echo ref2 > "$FX/whole/.git/HEAD"; echo 'x' > "$FX/whole/.git/new-object"
[ "$(plan_fp "$(plan_run fpc-whole1 "$FX/whole")" sha256)" = "$w0" ] && [ "$w0" != null ] \
    && pass "a change under .git/ does not change the value" || fail ".git change: $w0"
for f in src/app.js README.md .cdxgenrc; do
    echo "changed $f" >> "$FX/whole/$f"
    w1="$(plan_fp "$(plan_run "fpc-whole-${f//[^a-z]/}" "$FX/whole")" sha256)"
    [ "$w1" != "$w0" ] && [ "$w1" != null ] && pass "a change to $f changes the value" || fail "$f change: $w1 vs $w0"
    w0="$w1"
done
# Node: without package-lock.json the production filter asks npm to resolve again.
mkdir -p "$FX/yarn"; cp "$FX/link-in/package.json" "$FX/yarn/"; echo '# yarn lockfile v1' > "$FX/yarn/yarn.lock"
expect_fp '[false,["registry-resolution"]]' "$(fp_case yarn "$FX/yarn")" "a yarn project with no package-lock.json is registry-resolution (npm re-resolves for the production set)"
expect_fp '[true,[]]' "$(fp_case yarn-full "$FX/yarn" BOMLENS_NODE_FULL_GRAPH=1)" "with BOMLENS_NODE_FULL_GRAPH=1 the yarn project is reusable"
# Gradle: a lock file counts only when locking is on.
mkdir -p "$FX/gl/app"; printf "include 'app'\n" > "$FX/gl/settings.gradle"
printf "dependencies { implementation 'a:b:1.+' }\ndependencyLocking { lockAllConfigurations() }\n" | tee "$FX/gl/build.gradle" > "$FX/gl/app/build.gradle"
echo 'a:b:1.0=compileClasspath,runtimeClasspath' | tee "$FX/gl/gradle.lockfile" > "$FX/gl/app/gradle.lockfile"
expect_fp '[true,[]]' "$(fp_case gl-on "$FX/gl")" "Gradle projects with locking on and a gradle.lockfile each are reusable"
printf "dependencies { implementation 'a:b:1.+' }\n" > "$FX/gl/app/build.gradle"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gl-off "$FX/gl")" "locking at the top of the root build file does not lock a subproject"
printf "dependencies { implementation 'a:b:1.+' }\ndependencyLocking { lockAllConfigurations() }\nsubprojects { dependencyLocking { lockAllConfigurations() } }\n" > "$FX/gl/build.gradle"
expect_fp '[true,[]]' "$(fp_case gl-sub "$FX/gl")" "locking in the root's subprojects {} block locks a subproject"
echo 'empty=annotationProcessor' > "$FX/gl/app/gradle.lockfile"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gl-empty "$FX/gl")" "a gradle.lockfile with no group:artifact:version entry is no-lockfile"
mkdir -p "$FX/gs/lib"; printf "include 'lib'\n" > "$FX/gs/settings.gradle"
printf "subprojects { dependencies { implementation 'a:b:1' } }\ndependencyLocking { lockAllConfigurations() }\n" > "$FX/gs/build.gradle"
: > "$FX/gs/gradle.lockfile"; echo src > "$FX/gs/lib/Lib.java"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gs "$FX/gs")" "a subproject with no build file of its own still needs a gradle.lockfile"
# .NET: floating versions, and a restore with no lock.
mkdir -p "$FX/net"; echo '<Project><ItemGroup><PackageReference Include="A" Version="1.0.0" /></ItemGroup></Project>' > "$FX/net/App.csproj"
expect_fp '[false,["no-lockfile"]]' "$(fp_case net-nolock "$FX/net")" "a .NET project with no packages.lock.json is no-lockfile"
echo '{}' > "$FX/net/packages.lock.json"
expect_fp '[true,[]]' "$(fp_case net-lock "$FX/net")" "a .NET project with packages.lock.json and fixed versions is reusable"
echo '<Project><ItemGroup><PackageVersion Include="A" Version="1.*" /></ItemGroup></Project>' > "$FX/net/Directory.Packages.props"
expect_fp '[false,["unpinned-versions"]]' "$(fp_case net-float "$FX/net")" "a floating version in Directory.Packages.props is unpinned-versions"
# SRC_TREE_EXCLUDE is not something stage 1 sees.
P="$(plan_run fpc-ste "$FPA" SRC_TREE_EXCLUDE=packages)"
[ "$(plan_fp "$P" sha256)" = "$sa" ] && plan_fp "$P" | jq -e '[.components[].name] | index("SRC_TREE_EXCLUDE") | not' >/dev/null \
    && pass "SRC_TREE_EXCLUDE neither prunes the tree nor changes the value" || fail "SRC_TREE_EXCLUDE: $(plan_fp "$P" sha256) vs $sa"
# A file that cannot be read leaves the value blind to it.
if [ "$(id -u)" != 0 ]; then
    mkdir -p "$FX/unread"; cp "$FX/link-in/package.json" "$FX/unread/"; echo "$NL" > "$FX/unread/package-lock.json"; chmod 000 "$FX/unread/package-lock.json"
    fp_case unread "$FX/unread" | jq -e 'first == false and (last | index("unhashable-input"))' >/dev/null \
        && pass "an unreadable lock file is unhashable-input" || fail "unreadable lock: $(fp_case unread2 "$FX/unread")"
    chmod 644 "$FX/unread/package-lock.json"
fi
# A folder that cannot be read leaves the value blind to it.
if [ "$(id -u)" != 0 ]; then
    mkdir -p "$FX/unread-dir/secret"; cp "$FX/link-in/package.json" "$FX/unread-dir/"; echo "$NL" > "$FX/unread-dir/package-lock.json"
    echo x > "$FX/unread-dir/secret/a"; chmod 000 "$FX/unread-dir/secret"
    expect_fp '[false,["unhashable-input"]]' "$(fp_case unread-dir "$FX/unread-dir")" "an unreadable folder is unhashable-input"
    chmod 755 "$FX/unread-dir/secret"
fi
# 5,000 small files hash in well under a minute (about a second on an idle
# machine; a file scanner on a desktop adds a lot to every open).
mkdir -p "$FX/files"; cp "$FX/link-in/package.json" "$FX/files/"; echo "$NL" > "$FX/files/package-lock.json"
for i in $(seq 1 50); do mkdir -p "$FX/files/node_modules/m$i"; for j in $(seq 1 100); do echo "$i $j" > "$FX/files/node_modules/m$i/f$j.js"; done; done
t0=$SECONDS; got="$(plan_fp "$(plan_run fpc-files "$FX/files")" | jq -c '[.reusable, (.components[] | select(.name == ".") | .count)]')"; t=$((SECONDS - t0))
[ "$got" = '[true,5002]' ] && [ "$t" -lt 60 ] && pass "a tree of 5,002 files takes ${t}s (under 60)" || fail "5,000 files: $got in ${t}s"
# A FIFO, socket or device is never opened: a FIFO would block the walk.
mkdir -p "$FX/fifo"; cp "$FX/link-in/package.json" "$FX/fifo/"; echo "$NL" > "$FX/fifo/package-lock.json"; mkfifo "$FX/fifo/pipe"
if command -v timeout >/dev/null 2>&1; then
got="$(timeout 60 bash -c "$(declare -f plan_run plan_fp); WORK='$WORK' ROOT_DIR='$ROOT_DIR' ENTRY='$ENTRY'; plan_fp \"\$(plan_run fpc-fifo '$FX/fifo')\" | jq -c '[.reusable, .reasons]'" 2>&1)"
expect_fp '[false,["unhashable-input"]]' "$got" "a FIFO in the tree is unhashable-input and does not block"
else
    echo "  SKIP: timeout is not installed, so the FIFO case is not run"
fi
# The execute bit and links are part of the value; a .git file is not.
mkdir -p "$FX/mode"; cp "$FX/link-in/package.json" "$FX/mode/"; echo "$NL" > "$FX/mode/package-lock.json"; echo x > "$FX/mode/gradlew"
m0="$(plan_fp "$(plan_run fpc-mode0 "$FX/mode")" sha256)"; chmod +x "$FX/mode/gradlew"
m1="$(plan_fp "$(plan_run fpc-mode1 "$FX/mode")" sha256)"
[ "$m0" != null ] && [ "$m1" != null ] && [ "$m0" != "$m1" ] && pass "the execute bit changes the value" || fail "execute bit: $m0 $m1"
cp "$FX/mode/gradlew" "$FX/mode/copy"; c0="$(plan_fp "$(plan_run fpc-copy "$FX/mode")" sha256)"
rm "$FX/mode/copy"; ln -s gradlew "$FX/mode/copy"; c1="$(plan_fp "$(plan_run fpc-link "$FX/mode")" sha256)"
[ "$c0" != null ] && [ "$c0" != "$c1" ] && pass "a link and a copy of the same file give different values" || fail "link vs copy: $c0 $c1"
echo 'gitdir: /somewhere/worktrees/a' > "$FX/mode/.git"; g0="$(plan_fp "$(plan_run fpc-gitfile0 "$FX/mode")" sha256)"
echo 'gitdir: /elsewhere/worktrees/b' > "$FX/mode/.git"; g1="$(plan_fp "$(plan_run fpc-gitfile1 "$FX/mode")" sha256)"
[ "$g0" = "$c1" ] && [ "$g1" = "$c1" ] && pass "a .git file (a worktree's gitlink) is not part of the value" || fail ".git file: $g0 $g1 vs $c1"
# Go, Maven and Gradle resolve the non-shipped folders from the root too.
mkdir -p "$FX/go-ex/examples/demo" "$FX/go-ex/testdata/x"; printf 'module x\nrequire golang.org/x/text v0.3.0\n' > "$FX/go-ex/go.mod"; echo h > "$FX/go-ex/go.sum"
printf 'package x\nimport "golang.org/x/text/language"\n' > "$FX/go-ex/x.go"
printf 'package x\nimport "github.com/other/thing"\n' > "$FX/go-ex/testdata/x/t.go"
expect_fp '[true,[]]' "$(fp_case go-ex-ok "$FX/go-ex")" "Go code under testdata is left out, as go leaves it out"
printf 'package demo\nimport "github.com/other/thing"\n' > "$FX/go-ex/examples/demo/d.go"
expect_fp '[false,["registry-resolution"]]' "$(fp_case go-ex "$FX/go-ex")" "an uncovered Go import under examples/ is registry-resolution (go mod tidy sees it)"
mkdir -p "$FX/gr-ex/examples/demo"; printf "include 'examples:demo'\n" > "$FX/gr-ex/settings.gradle"
printf "dependencyLocking { lockAllConfigurations() }\ndependencies { implementation 'a:b:1' }\n" > "$FX/gr-ex/build.gradle"; : > "$FX/gr-ex/gradle.lockfile"
printf "dependencies { implementation 'a:b:1.+' }\n" > "$FX/gr-ex/examples/demo/build.gradle"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gr-ex "$FX/gr-ex")" "a Gradle project under examples/ is judged"
# Gradle: a commented-out locking line does not turn locking on.
printf "dependencies { implementation 'a:b:1.+' }\n// dependencyLocking { lockAllConfigurations() }\n/* resolutionStrategy.activateDependencyLocking() */\n" > "$FX/gr-ex/build.gradle"
rm -rf "$FX/gr-ex/examples" "$FX/gr-ex/settings.gradle"
expect_fp '[false,["no-lockfile"]]' "$(fp_case gr-comment "$FX/gr-ex")" "Gradle locking only in a comment does not count"
# An npm lock that does not match package.json is resolved again.
mkdir -p "$FX/npm-sync"; echo '{"dependencies":{"a":"1","b":"2"}}' > "$FX/npm-sync/package.json"; echo "$NL" > "$FX/npm-sync/package-lock.json"
expect_fp '[false,["registry-resolution"]]' "$(fp_case npm-sync "$FX/npm-sync")" "a package-lock.json that does not list every dependency of package.json is registry-resolution"
mkdir -p "$FX/npm-ws/packages/a"; echo '{"workspaces":["packages/*"],"dependencies":{"a":"1"}}' > "$FX/npm-ws/package.json"; echo "$NL" > "$FX/npm-ws/package-lock.json"
echo '{"dependencies":{"b":"1"}}' > "$FX/npm-ws/packages/a/package.json"
expect_fp '[false,["registry-resolution"]]' "$(fp_case npm-ws "$FX/npm-ws")" "a workspace member the root lock does not record is registry-resolution"
mkdir -p "$FX/gem"; printf "source 'https://rubygems.org'\ngem 'rack'\ngem 'puma'\n" > "$FX/gem/Gemfile"
printf 'GEM\n  specs:\n    rack (3.0.0)\n\nDEPENDENCIES\n  rack\n\nBUNDLED WITH\n   2.5.0\n' > "$FX/gem/Gemfile.lock"
expect_fp '[false,["registry-resolution"]]' "$(fp_case gem "$FX/gem")" "a Gemfile.lock missing a gem the Gemfile names is registry-resolution"
mkdir -p "$FX/spm"; printf 'let package = Package(name: "x", dependencies: [.package(url: "https://github.com/a/b.git", from: "1.0.0"), .package(url: "https://github.com/c/d", from: "2.0.0")])\n' > "$FX/spm/Package.swift"
echo '{"pins":[{"identity":"b","location":"https://github.com/a/b","state":{"version":"1.0.0"}}],"version":2}' > "$FX/spm/Package.resolved"
expect_fp '[false,["registry-resolution"]]' "$(fp_case spm "$FX/spm")" "a Package.resolved missing a package Package.swift names is registry-resolution"
# The file count and time limits stop the walk.
P="$(plan_run fpc-cap "$FPA" BOMLENS_FINGERPRINT_MAX_FILES=3)"
[ "$(plan_fp "$P" | jq -c '[.reusable, .reasons, (.components[] | select(.name == ".") | [.sha256, .truncated])]')" = '[false,["unhashable-input"],[null,true]]' ] \
    && pass "over BOMLENS_FINGERPRINT_MAX_FILES the walk stops: truncated, unhashable-input" || fail "cap: $(plan_fp "$P" | jq -c '[.reasons, (.components[] | select(.name == "."))]')"
# 500 workspace members in well under 30 seconds.
mkdir -p "$FX/many"; echo '{"workspaces":["packages/*"],"dependencies":{"a":"1"}}' > "$FX/many/package.json"
jq -n '{lockfileVersion: 3, packages: ({"": {dependencies: {a: "1"}}} + ([range(1; 501)] | map({key: "packages/p\(.)", value: {dependencies: {b: "1"}}}) | from_entries))}' > "$FX/many/package-lock.json"
for i in $(seq 1 500); do mkdir -p "$FX/many/packages/p$i"; echo '{"dependencies":{"b":"1"}}' > "$FX/many/packages/p$i/package.json"; done
t0=$SECONDS; got="$(fp_case many "$FX/many")"; t=$((SECONDS - t0))
[ "$got" = '[true,[]]' ] && [ "$t" -lt 30 ] && pass "500 workspace members take ${t}s (under 30)" || fail "500 members: $got in ${t}s"
P="$(plan_run fp-android "$PSRC2")"
[ "$(jq -c '[(.stages | length), .input_fingerprint.reusable, .input_fingerprint.sha256, (.input_fingerprint.reasons | index("plan-unsupported") != null)]' "$P/bomlens-plan.json")" = '[0,false,null,true]' ] \
    && pass "an unsupported plan has the fingerprint at the top level, with plan-unsupported" \
    || fail "unsupported plan: $(jq -c '{stages: (.stages | length), input_fingerprint}' "$P/bomlens-plan.json")"
err="$(plan_schema_errors "$P/bomlens-plan.json")"
[ -z "$err" ] && pass "the unsupported plan validates" || fail "plan schema errors" "$err"
# Stage 2 after the plan computes the value again from the source, with the
# plan's stage 1 image, settings and bomlens-plan/ copies, and finds the plan's
# own. BOMLENS_IMAGE_DIGEST is not given to stage 2 here: it comes from the plan.
P="$(plan_run fp-pp "$FPA")"
cp "$FIX/good-cyclonedx.json" "$P/demo_1.0_bom.json"
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 BOMLENS_STAGE1_REUSED=1
g="$(jq -c '[.steps[] | select(.id == "generate")][0]' "$P/bomlens-result.json" 2>/dev/null)"
[ -n "$g" ] && [ "$(jq -c .input_fingerprint <<<"$g")" = "$(plan_fp "$P")" ] \
    && [ "$(jq -c '[.reused, .reuse_unsafe, .plan_mismatch]' <<<"$g")" = '[true,false,false]' ] \
    && pass "after a plan, the manifest's value is the plan's, computed again: reused, not unsafe, no mismatch" \
    || fail "manifest generate: $g" "$(tail -5 "$P.log")"
err="$(schema_errors "$P/bomlens-result.json")"
[ -z "$err" ] && pass "a manifest with an input fingerprint validates against schemas/engine-result-1.json" || fail "schema errors" "$err"
# A plan whose value does not fit this source (a leftover from another tree,
# or edited) is not trusted: the manifest has the computed value, plan_mismatch,
# and the reuse the caller made on it is unsafe.
P="$(plan_run fp-pp-stale "$FPA")"
jq '.stages[0].input_fingerprint.sha256 = ("f" * 64) | .input_fingerprint = .stages[0].input_fingerprint' "$P/bomlens-plan.json" > "$P/x" && mv "$P/x" "$P/bomlens-plan.json"
cp "$FIX/good-cyclonedx.json" "$P/demo_1.0_bom.json"
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 BOMLENS_STAGE1_REUSED=1
g="$(jq -c '[.steps[] | select(.id == "generate")][0]' "$P/bomlens-result.json" 2>/dev/null)"
[ "$(jq -c '[.input_fingerprint.sha256, .plan_mismatch, .reuse_unsafe]' <<<"$g")" = "[\"$sa\",true,true]" ] \
    && pass "a plan value that does not fit the source is not adopted: computed value, plan_mismatch, reuse_unsafe" \
    || fail "stale plan: $(jq -c '[.input_fingerprint.sha256, .plan_mismatch, .reuse_unsafe]' <<<"$g")"
# Reuse of a stage 1 whose input is not reproducible is recorded as unsafe.
P="$(plan_run fp-pp-nolock "$FPB")"
cp "$FIX/good-cyclonedx.json" "$P/demo_1.0_bom.json"
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPB" BOMLENS_STAGE1_EXIT=0 BOMLENS_STAGE1_REUSED=1
[ "$(jq -c '[.steps[] | select(.id == "generate")][0] | [.reused, .reuse_unsafe, .input_fingerprint.reusable]' "$P/bomlens-result.json")" = '[true,true,false]' ] \
    && pass "reuse with a fingerprint that is not reusable is reuse_unsafe" \
    || fail "unsafe reuse: $(jq -c '[.steps[] | select(.id == "generate")][0]' "$P/bomlens-result.json")"
# The CLI's stage 2 (no plan in the folder): what the CLI says stage 1 ran.
cli_env=(BOMLENS_STAGE1_DIGEST="$(jq -r '.stages[0].image_digest' "$PA/bomlens-plan.json")"
    BOMLENS_STAGE1_PREP_SHA256="$(shasum -a 256 < "$ROOT_DIR/docker/lib/build-prep.sh" | cut -d' ' -f1)"
    BOMLENS_STAGE1_CONDA_SHA256="$(shasum -a 256 < "$ROOT_DIR/docker/lib/identify-conda.py" | cut -d' ' -f1)"
    BOMLENS_STAGE1_CLI_SHA256="$(shasum -a 256 < "$ROOT_DIR/scripts/scan-sbom.sh" | cut -d' ' -f1)"
    BOMLENS_STAGE1_SPEC_VERSION=1.6 FETCH_LICENSE=true)
D="$(new_run fp-cli)"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 "${cli_env[@]}"
g="$(jq -c '[.steps[] | select(.id == "generate")][0]' "$D/bomlens-result.json" 2>/dev/null)"
[ "$(jq -c '[.input_fingerprint.reusable, .reused, ([.input_fingerprint.components[] | select(.kind == "engine") | .name] | sort)]' <<<"$g")" = '[true,false,["build-prep.sh","identify-conda.py","scan-sbom.sh"]]' ] \
    && [ "$(jq -r '.input_fingerprint.components[] | select(.kind == "engine" and .name == "build-prep.sh") | .sha256' <<<"$g")" = "${cli_env[1]#*=}" ] \
    && pass "the CLI path records the files and image the CLI says stage 1 ran, and reused is false" \
    || fail "CLI path: $(jq -c '.input_fingerprint | [.reusable, .reasons, [.components[] | select(.kind != "file")]]' <<<"$g")" "$(tail -5 "$D.log")"
# A stage 1 that exited 0 but recorded a failed step is not one to keep.
P="$(plan_run fp-pp-deg "$FPA")"
jq '.metadata.properties = ((.metadata.properties // []) + [{"name": "bomlens:pipeline-step-failed", "value": "npm-production-set"}])' \
    "$FIX/good-cyclonedx.json" > "$P/demo_1.0_bom.json"
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 BOMLENS_STAGE1_REUSED=1
[ "$(jq -c '[.steps[] | select(.id == "generate")][0] | [.input_fingerprint.reusable, .input_fingerprint.sha256, .input_fingerprint.reasons, .reuse_unsafe]' "$P/bomlens-result.json")" = '[false,null,["stage1-degraded"],true]' ] \
    && pass "a stage 1 SBOM with a failed step makes the recorded value stage1-degraded, and its reuse unsafe" \
    || fail "stage1-degraded: $(jq -c '[.steps[] | select(.id == "generate")][0] | [.input_fingerprint.reasons, .reuse_unsafe, .plan_mismatch]' "$P/bomlens-result.json")"
err="$(schema_errors "$P/bomlens-result.json")"
[ -z "$err" ] && pass "a stage1-degraded manifest validates" || fail "schema errors" "$err"
# The CLI's default output folder sits inside the source: it is left out.
CS="$WORK/fp-cli-src"; fp_tree "$CS"
t_before="$(tree_sha "$(plan_run fp-cli-src "$CS")")"
CO="$CS/demo_1.0"; mkdir -p "$CO"; cp "$FIX/good-cyclonedx.json" "$CO/demo_1.0_bom.json"
( cd "$CO" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$CO" \
    BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" BOMLENS_RUN_INPUT=demo_1.0_bom.json UPLOAD_ENABLED=false GENERATE_SECURITY=false \
    SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false SOURCE_ROOT="$CS" BOMLENS_STAGE1_EXIT=0 \
    BOMLENS_FINGERPRINT_EXCLUDE=demo_1.0 "${cli_env[@]}" bash "$ENTRY" ) > "$WORK/fp-cli-src-run.log" 2>&1
[ "$(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint | [.reusable, .reasons, (.components[] | select(.name == ".") | .count), [.components[] | select(.kind == "file" and .sha256 == null and .name != ".") | .name]]' "$CO/bomlens-result.json" 2>/dev/null)" = "[false,[\"unhashable-input\"],${t_before##* },[\"demo_1.0\"]]" ] \
    && pass "on the CLI path an output folder inside the source is left out of the walk and makes the value unhashable-input" \
    || fail "CLI exclude: $(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint.components[] | select(.name == ".")' "$CO/bomlens-result.json" 2>&1) vs $t_before" "$(tail -3 "$WORK/fp-cli-src-run.log")"
D="$(new_run fp-cli-flat)"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 BOMLENS_FINGERPRINT_EXCLUDE=. "${cli_env[@]}"
[ "$(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint | [.reusable, .reasons]' "$D/bomlens-result.json" 2>/dev/null)" = '[false,["unhashable-input"]]' ] \
    && pass "a CLI output written into the source root itself makes the value unhashable-input" \
    || fail "flat CLI output: $(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint | [.reusable, .reasons]' "$D/bomlens-result.json" 2>&1)"
D="$(new_run fp-cli-bare)"
run_engine "$D" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0
[ "$(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint | [.reusable, .reasons]' "$D/bomlens-result.json" 2>/dev/null)" = '[false,["unhashable-input","unknown-stage1-image"]]' ] \
    && pass "a CLI path that does not say what stage 1 ran is not reusable (unknown-stage1-image, unhashable-input)" \
    || fail "CLI path without the stage 1 record: $(jq -c '[.steps[] | select(.id == "generate")][0].input_fingerprint | [.reusable, .reasons]' "$D/bomlens-result.json" 2>&1)"
D="$(new_run fp-image)"
( cd "$D" && env PATH="$WORK/bin:$PATH" MODE=ANALYZE ANALYZE_SBOM="$D/demo_1.0_bom.json" PROJECT_NAME=demo PROJECT_VERSION=1.0 \
    HOST_OUTPUT_DIR="$D" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" UPLOAD_ENABLED=false GENERATE_SECURITY=false \
    SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false bash "$ENTRY" ) > "$D.log" 2>&1
jq -e '[.steps[] | select(.id == "generate")][0] | has("input_fingerprint") or has("reused") | not' "$D/bomlens-result.json" >/dev/null 2>&1 \
    && pass "a run that is not stage 2 of a source scan has no fingerprint" \
    || fail "ANALYZE generate: $(jq -c '[.steps[] | select(.id == "generate")]' "$D/bomlens-result.json" 2>&1)"
# The reasons the contract page lists are the schema's.
doc_fp_reasons="$(sed -n '/^<!-- fingerprint-reasons:begin -->/,/^<!-- fingerprint-reasons:end -->/p' "$DOC" | grep -v '^| `reasons`' | grep -oE '^\| `[a-z0-9-]+`' | tr -d '|` ' | sort | tr '\n' ' ')"
schema_fp_reasons="$(jq -r '."$defs".input_fingerprint.properties.reasons.items.enum[]' "$PLAN_SCHEMA" | sort | tr '\n' ' ')"
[ -n "$doc_fp_reasons" ] && [ "$doc_fp_reasons" = "$schema_fp_reasons" ] \
    && [ "$schema_fp_reasons" = "$(jq -r '."$defs".input_fingerprint.properties.reasons.items.enum[]' "$SCHEMA" | sort | tr '\n' ' ')" ] \
    && pass "the fingerprint reasons in the contract page and both schemas agree ($doc_fp_reasons)" \
    || fail "fingerprint reasons: docs '$doc_fp_reasons', schema '$schema_fp_reasons'"

echo "== a binary scan: supplied versions, upstream purls and the submission rows =="
# syft is stubbed to return a firmware-shaped SBOM; the rest of the pipeline is real.
mkdir -p "$WORK/bin-syft"
cat > "$WORK/bin-syft/syft" <<EOF
#!/bin/bash
[ "\${1:-}" = "version" ] && { echo "Version: 0.0.0-stub"; exit 0; }
cat "$FIX/firmware-upstream-purl.json"
EOF
chmod +x "$WORK/bin-syft/syft"
UB="$(new_run upstream-binary empty)"
printf 'x' > "$WORK/upstream-fw.bin"
printf 'name,version,reason\nncurses,5.7,\nlibxml2,,version-unknown\n' > "$WORK/upstream-versions.csv"
( cd "$UB" && env PATH="$WORK/bin-syft:$WORK/bin:$PATH" MODE=BINARY TARGET_FILE="$WORK/upstream-fw.bin" \
    PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$UB" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
    BOMLENS_ARTIFACT_CLEANUP=1 UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false CONFORMANCE_PROFILE=skt-submission \
    COMPONENT_VERSIONS_FILE="$WORK/upstream-versions.csv" bash "$ENTRY" ) > "$UB.log" 2>&1
[ "$(jq -c '[.steps[] | select(.id == "component-versions" or .id == "upstream-purl") | "\(.id)=\(.status)"]' "$UB/bomlens-result.json" 2>/dev/null)" = '["component-versions=ok","upstream-purl=ok"]' ] \
    && pass "the two steps run in order and are recorded" \
    || fail "steps: $(jq -c '[.steps[] | {id, status}]' "$UB/bomlens-result.json" 2>&1)" "$(tail -5 "$UB.log")"
[ "$(jq -r '.components[] | select(.name == "ncurses") | "\(.version) \(.purl)"' "$UB/demo_1.0_bom.json" 2>/dev/null)" = "5.7 pkg:github/mirror/ncurses@v5.7" ] \
    && pass "a version from the file reaches the SBOM with its upstream purl" \
    || fail "ncurses: $(jq -c '.components[] | select(.name == "ncurses")' "$UB/demo_1.0_bom.json" 2>&1)"
[ "$(grep -v '^#' "$UB/demo_1.0_component-versions.template.csv" 2>/dev/null | tr '\n' ' ')" = "name,version,reason 3c59x,, " ] \
    && jq -e 'any(.outputs[]; .path == "demo_1.0_component-versions.template.csv")' "$UB/bomlens-result.json" >/dev/null \
    && pass "the template of what is still missing is written and listed in the outputs" \
    || fail "template: $(cat "$UB/demo_1.0_component-versions.template.csv" 2>&1)"
[ "$(jq -c '[.checks[] | select(.id == "versions-needed" or .id == "upstream-purl") | .missing] + [.submitFile]' "$UB/demo_1.0_conformance.json" 2>/dev/null)" = '[["Vendor Utility","3c59x"],["gcc@9.3.0","openssl@0.9.8zh"],"demo_1.0_bom.json"]' ] \
    && pass "the submission profile names what is missing and the file to submit" \
    || fail "conformance: $(jq -c '[.checks[] | select(.id == "versions-needed" or .id == "upstream-purl")] + [.submitFile]' "$UB/demo_1.0_conformance.json" 2>&1)"
# A reason the supplier gave survives the rest of the pipeline (normalize,
# upstream purl) and the submission profile lists it as explained.
[ "$(jq -c '[.components[] | select(.name == "libxml2") | (.version // null), ([.properties[]? | select(.name == "bomlens:versionReason") | .value][0])]' "$UB/demo_1.0_bom.json" 2>/dev/null)" = '[null,"version-unknown"]' ] \
    && [ "$(jq -c '.checks[] | select(.id == "versions-needed") | .explained' "$UB/demo_1.0_conformance.json" 2>/dev/null)" = '[{"name":"libxml2","reason":"version-unknown"}]' ] \
    && [ "$(jq -r '.metadata.properties[]? | select(.name == "bomlens:scanMode") | .value' "$UB/demo_1.0_bom.json" 2>/dev/null)" = BINARY ] \
    && pass "a reason from the file reaches the SBOM and the version-needed row; the SBOM states its scan mode" \
    || fail "reason: $(jq -c '.components[] | select(.name == "libxml2")' "$UB/demo_1.0_bom.json" 2>&1)"
# The template filled in place and passed back is the supplier's record: the
# run reads it, and neither sweeps nor rewrites it.
printf '# filled\nname,version\n3c59x,\nlibxml2,2.9.14\n' > "$UB/demo_1.0_component-versions.template.csv"
cp "$UB/demo_1.0_component-versions.template.csv" "$WORK/upstream-filled.csv"
( cd "$UB" && env PATH="$WORK/bin-syft:$WORK/bin:$PATH" MODE=BINARY TARGET_FILE="$WORK/upstream-fw.bin" \
    PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$UB" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
    BOMLENS_ARTIFACT_CLEANUP=1 UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false \
    COMPONENT_VERSIONS_FILE="$UB/demo_1.0_component-versions.template.csv" bash "$ENTRY" ) > "$UB.2.log" 2>&1
cmp -s "$WORK/upstream-filled.csv" "$UB/demo_1.0_component-versions.template.csv" \
    && [ "$(jq -r '.components[] | select(.name == "libxml2") | .purl' "$UB/demo_1.0_bom.json" 2>/dev/null)" = "pkg:github/gnome/libxml2@v2.9.14" ] \
    && grep -q "Add them to the file passed with --component-versions" "$UB.2.log" \
    && pass "a filled-in template passed back is applied and left as the supplier wrote it" \
    || fail "template passed back: $(cat "$UB/demo_1.0_component-versions.template.csv" 2>&1)" "$(grep component-versions "$UB.2.log")"
# A refused file: the step fails, every file is still written, and the run
# ends with the reason and exit 1, since the versions asked for were not applied.
UB3="$(new_run upstream-binary-refused empty)"
printf 'name,version\nncurses,$(id)\n' > "$WORK/upstream-bad.csv"
( cd "$UB3" && env PATH="$WORK/bin-syft:$WORK/bin:$PATH" MODE=BINARY TARGET_FILE="$WORK/upstream-fw.bin" \
    PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$UB3" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
    BOMLENS_ARTIFACT_CLEANUP=1 UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false \
    COMPONENT_VERSIONS_FILE="$WORK/upstream-bad.csv" bash "$ENTRY" ) > "$UB3.log" 2>&1; ub3_rc=$?
[ "$ub3_rc" = 1 ] && [ -s "$UB3/demo_1.0_bom.json" ] \
    && [ "$(jq -c '[.steps[] | select(.id == "component-versions") | [.status, .reason]][0]' "$UB3/bomlens-result.json" 2>/dev/null)" = '["failed","failed"]' ] \
    && jq -e '.steps[] | select(.id == "component-versions") | .detail | contains("is not a version")' "$UB3/bomlens-result.json" >/dev/null 2>&1 \
    && [ "$(jq -r '.run.status' "$UB3/bomlens-result.json" 2>/dev/null)" = failed ] \
    && tail -n 2 "$UB3.log" | head -n 1 | grep -q '^\[ERROR\] --component-versions: the file was refused, so none of its versions were applied: line 2' \
    && pass "a refused file fails the step, keeps the outputs, and ends the run with the reason and exit 1" \
    || fail "refused file: rc=$ub3_rc $(jq -c '[.run.status] + [.steps[] | select(.id == "component-versions")]' "$UB3/bomlens-result.json" 2>&1)" "$(tail -4 "$UB3.log")"
UB2="$(new_run upstream-binary-off empty)"
( cd "$UB2" && env PATH="$WORK/bin-syft:$WORK/bin:$PATH" MODE=BINARY TARGET_FILE="$WORK/upstream-fw.bin" \
    PROJECT_NAME=demo PROJECT_VERSION=1.0 HOST_OUTPUT_DIR="$UB2" BOMLENS_LIBDIR="$ROOT_DIR/docker/lib" \
    BOMLENS_ARTIFACT_CLEANUP=1 UPLOAD_ENABLED=false GENERATE_SECURITY=false SECURITY_ENRICH=false \
    ENRICH_EOL=false ENRICH_MALICIOUS=false ENRICH_UPSTREAM_PURL=false bash "$ENTRY" ) > "$UB2.log" 2>&1
[ "$(jq -r '.steps[] | select(.id == "upstream-purl") | .status' "$UB2/bomlens-result.json" 2>/dev/null)" = disabled ] \
    && ! jq -e 'any(.components[]; (.purl // "") | startswith("pkg:github/"))' "$UB2/demo_1.0_bom.json" >/dev/null \
    && pass "ENRICH_UPSTREAM_PURL=false leaves the purls alone and records the step as disabled" \
    || fail "upstream-purl off: $(jq -c '[.steps[] | select(.id == "upstream-purl")]' "$UB2/bomlens-result.json" 2>&1)"

echo "== a step that failed during generation degrades generate =="
# A firmware syft pass or a resolver in build-prep.sh that failed is recorded
# only in the SBOM (bomlens:pipeline-step-failed); the run must not read
# succeeded. The normal run at the top of this file stays succeeded.
add_props() { jq --argjson p "$2" '.metadata.properties = ((.metadata.properties // []) + $p)' "$1" > "$1.x" && mv "$1.x" "$1"; }
gen_line() { jq -r '.run.status + " " + ([.steps[] | select(.id=="generate")][0] | "\(.status) \(.reason) \(.detail)")' "$1/bomlens-result.json" 2>/dev/null; }
D="$(new_run gen-step-failed)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"},{"name":"bomlens:pipeline-step-failed","value":"cargo-lockfile"},{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}]'
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_UNAME_M=aarch64
[ "$(gen_line "$D")" = "succeeded_degraded degraded failed steps that failed: cargo-lockfile, firmware-packages" ] \
    && pass "generate is degraded (failed) with the failed steps named, and the run succeeded_degraded" \
    || fail "got: $(gen_line "$D")" "$(tail -5 "$D.log")"
err="$(schema_errors "$D/bomlens-result.json")"
[ -z "$err" ] && pass "that manifest validates against the schema" || fail "schema errors" "$err"
v="$(vocab_violations "$D/bomlens-result.json")"
[ -z "$v" ] && pass "its reason is in the contract document" || fail "undocumented:" "$v"
# The same, inside an amd64 image emulated on an arm64 host: the detail says so.
printf 'processor\t: 0\nCPU implementer\t: 0x61\nCPU architecture: 8\n' > "$WORK/cpuinfo-arm"
D="$(new_run gen-step-failed-emulated)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}]'
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_UNAME_M=x86_64 BOMLENS_CPUINFO_FILE="$WORK/cpuinfo-arm"
case "$(gen_line "$D")" in
    "succeeded_degraded degraded failed steps that failed: firmware-packages; this amd64 image ran under emulation on an arm64 host"*) pass "under amd64 emulation the detail says so" ;;
    *) fail "emulated: $(gen_line "$D")" ;;
esac
# A post-process step that failed is its own step, not a generation failure.
D="$(new_run gen-postprocess-failed)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"normalize"}]'
run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "ok" ] \
    && pass "a failed label that is a step of its own (normalize) leaves generate ok" \
    || fail "generate: $(gen_line "$D")"
# The generator's own fallback, recorded only in the SBOM, is the same.
D="$(new_run gen-tool-degraded)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:sbom-tool-degraded","value":"cdxgen-crash"}]'
run_engine "$D" "$ROOT_DIR/docker/lib"
[ "$(gen_line "$D")" = "succeeded_degraded degraded fallback cdxgen-crash" ] \
    && pass "bomlens:sbom-tool-degraded: generate degraded (fallback), run succeeded_degraded" \
    || fail "sbom-tool-degraded: $(gen_line "$D")"
# A supplier's SBOM carries its own run's record, not this run's.
D="$(new_run gen-step-failed-analyze)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}]'
mv "$D/demo_1.0_bom.json" "$D/supplier.json"
run_engine "$D" "$ROOT_DIR/docker/lib" MODE=ANALYZE ANALYZE_SBOM="$D/supplier.json"
[ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json")" = "ok" ] \
    && pass "ANALYZE: a failed label in the supplier's SBOM leaves generate ok" \
    || fail "ANALYZE: $(gen_line "$D")" "$(tail -5 "$D.log")"
# Against a copy without the rule, the failed-step run reads succeeded.
MUT4="$WORK/lib-mutant-genfailed"
cp -R "$ROOT_DIR/docker/lib" "$MUT4"
sed -i.bak 's/and (\$genfailed | length) > 0 then/and false then/' "$MUT4/engine-result.sh"
D="$(new_run gen-step-failed-mutant)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}]'
run_engine "$D" "$MUT4"
[ "$(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null)" = "succeeded" ] \
    && pass "negative control: without the rule the same run reads succeeded" \
    || fail "the mutant run is $(jq -r .run.status "$D/bomlens-result.json" 2>/dev/null); the check does not isolate the rule"

# The emulation notice is about the firmware syft passes: a resolver step that
# failed in the same container says nothing about it.
D="$(new_run gen-step-failed-emulated-nonfw)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"cargo-lockfile"}]'
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_UNAME_M=x86_64 BOMLENS_CPUINFO_FILE="$WORK/cpuinfo-arm"
[ "$(gen_line "$D")" = "succeeded_degraded degraded failed steps that failed: cargo-lockfile" ] \
    && pass "under emulation, a failed cargo-lockfile alone gets no emulation notice" \
    || fail "non-firmware label under emulation: $(gen_line "$D")"
# On an armv7 host there is no linux/arm64 image to point to: the detail says
# the image ran under emulation and nothing more.
printf 'processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nCPU implementer\t: 0x41\nCPU architecture: 7\n' > "$WORK/cpuinfo-armv7"
D="$(new_run gen-step-failed-armv7)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-extra-roots"}]'
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_UNAME_M=x86_64 BOMLENS_CPUINFO_FILE="$WORK/cpuinfo-armv7"
[ "$(gen_line "$D")" = "succeeded_degraded degraded failed steps that failed: firmware-extra-roots; this amd64 image ran under emulation on an arm host" ] \
    && pass "on an armv7 host the detail names the emulation without pointing to linux/arm64" \
    || fail "armv7: $(gen_line "$D")"
D="$(new_run gen-step-failed-arm64-hint)"
add_props "$D/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}]'
run_engine "$D" "$ROOT_DIR/docker/lib" BOMLENS_UNAME_M=x86_64 BOMLENS_CPUINFO_FILE="$WORK/cpuinfo-arm"
case "$(gen_line "$D")" in
    *"on an arm64 host, use the linux/arm64 image instead") pass "on an arm64 host the detail points to the linux/arm64 image" ;;
    *) fail "arm64 hint: $(gen_line "$D")" ;;
esac
# POSTPROCESS: a build-prep label from stage 1 makes generate degraded and the
# run succeeded_degraded, and the recorded fingerprint says stage1-degraded.
P="$(plan_run gen-pp-prep "$FPA")"
cp "$FIX/good-cyclonedx.json" "$P/demo_1.0_bom.json"
add_props "$P/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"go-mod-tidy"}]'
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0
[ "$(jq -c '[.run.status, ([.steps[] | select(.id == "generate")][0] | .status, .reason, .detail, .stage, .input_fingerprint.reasons)]' "$P/bomlens-result.json" 2>/dev/null)" \
    = '["succeeded_degraded","degraded","failed","steps that failed: go-mod-tidy",1,["stage1-degraded"]]' ] \
    && pass "POSTPROCESS: a stage-1 build-prep label reaches both run.status and input_fingerprint.reasons" \
    || fail "POSTPROCESS build-prep: $(jq -c '[.run.status, [.steps[] | select(.id == "generate")][0]]' "$P/bomlens-result.json" 2>&1)" "$(tail -5 "$P.log")"
# A reused SBOM carries the post-process record of the run that left it. A
# label of a post-process step this run did not run (resolve-purl is opt-in)
# is neither a generation failure nor a short stage 1.
P="$(plan_run gen-pp-reused-postprocess "$FPA")"
cp "$FIX/good-cyclonedx.json" "$P/demo_1.0_bom.json"
add_props "$P/demo_1.0_bom.json" '[{"name":"bomlens:pipeline-step-failed","value":"resolve-purl"},{"name":"bomlens:pipeline-step-failed","value":"verify-weights"}]'
run_engine "$P" "$ROOT_DIR/docker/lib" SOURCE_ROOT="$FPA" BOMLENS_STAGE1_EXIT=0 BOMLENS_STAGE1_REUSED=1
[ "$(jq -c '[.run.status, ([.steps[] | select(.id == "generate")][0] | .status, (.input_fingerprint.reasons | index("stage1-degraded")), .reuse_unsafe)]' "$P/bomlens-result.json" 2>/dev/null)" \
    = '["succeeded","ok",null,false]' ] \
    && pass "a reused SBOM's post-process labels (resolve-purl) leave generate ok and stage 1 reusable" \
    || fail "reused post-process label: $(jq -c '[.run.status, [.steps[] | select(.id == "generate")][0]]' "$P/bomlens-result.json" 2>&1)" "$(tail -5 "$P.log")"
# MERGE reads supplier SBOMs: their labels are their own runs' records.
# merge-sbom.sh writes fresh metadata, so a copy of the library whose merge
# keeps the first input as it is puts the label in front of the rule.
MERGE_LIB="$WORK/lib-merge-keeps-metadata"
cp -R "$ROOT_DIR/docker/lib" "$MERGE_LIB"
printf '#!/bin/bash\ncp "$4" "$1"\n' > "$MERGE_LIB/merge-sbom.sh"
D="$(new_run gen-step-failed-merge empty)"
jq '.metadata.properties = ((.metadata.properties // []) + [{"name":"bomlens:pipeline-step-failed","value":"firmware-packages"}])' \
    "$FIX/good-cyclonedx.json" > "$D/part-a.json"
cp "$FIX/good-cyclonedx.json" "$D/part-b.json"
run_engine "$D" "$MERGE_LIB" MODE=MERGE MERGE_FILES="$D/part-a.json $D/part-b.json"
jq -e 'any(.metadata.properties[]?; .name == "bomlens:pipeline-step-failed" and .value == "firmware-packages")' "$D/demo_1.0_bom.json" >/dev/null 2>&1 \
    && [ "$(jq -r '[.steps[] | select(.id=="generate")][0].status' "$D/bomlens-result.json" 2>/dev/null)" = "ok" ] \
    && pass "MERGE: a failed label carried into the merged SBOM leaves generate ok" \
    || fail "MERGE: $(gen_line "$D")" "$(tail -5 "$D.log")"

echo "== the post-process step list in engine-result.sh matches entrypoint.sh =="
# shellcheck disable=SC1091
pp_listed="$( . "$ROOT_DIR/docker/lib/engine-result.sh"; printf '%s\n' $ER_POSTPROCESS_STEPS | sort -u)"
pp_used="$(grep -v '^[[:space:]]*#' "$ENTRY" | grep -oE '(run_optional_step|er_record|er_phase) [a-z][a-z0-9-]+' | awk '{print $2}' | grep -vxE 'generate|plan' | sort -u)"
[ "$pp_listed" = "$pp_used" ] \
    && pass "ER_POSTPROCESS_STEPS lists every step entrypoint.sh records after generation, and no other" \
    || fail "ER_POSTPROCESS_STEPS differs from entrypoint.sh" "$(diff <(printf '%s\n' "$pp_listed") <(printf '%s\n' "$pp_used"))"

echo "== --spec-version 1.7: the delivered SBOM is CycloneDX 1.7 =="
# CYCLONEDX_SPEC_VERSION is what scan-sbom.sh --spec-version sets. A 1.6 stage-1
# document leaves as 1.7, and NOTICE, the security report and the conformance
# check all read it; without the variable the same input stays 1.6.
for sv in 1.6 1.7; do
    D="$(new_run "spec-$sv")"
    jq '.specVersion = "1.6" | ."$schema" = "http://cyclonedx.org/schema/bom-1.6.schema.json"' \
        "$FIX/good-cyclonedx.json" > "$D/demo_1.0_bom.json"
    if [ "$sv" = 1.7 ]; then
        run_engine "$D" "$ROOT_DIR/docker/lib" GENERATE_NOTICE=true GENERATE_REPORT=true CYCLONEDX_SPEC_VERSION=1.7
    else
        run_engine "$D" "$ROOT_DIR/docker/lib" GENERATE_NOTICE=true GENERATE_REPORT=true
    fi
done
S16="$WORK/spec-1.6"; S17="$WORK/spec-1.7"
[ "$(jq -r '"\(.specVersion) \(."$schema")"' "$S17/demo_1.0_bom.json")" = "1.7 http://cyclonedx.org/schema/bom-1.7.schema.json" ] \
    && pass "CYCLONEDX_SPEC_VERSION=1.7 writes specVersion 1.7 and the 1.7 schema" \
    || fail "1.7 run: $(jq -c '[.specVersion, ."$schema"]' "$S17/demo_1.0_bom.json" 2>&1)" "$(tail -5 "$S17.log")"
[ "$(jq -r '.specVersion' "$S16/demo_1.0_bom.json")" = "1.6" ] \
    && pass "without it the SBOM stays 1.6" || fail "default run: $(jq -r '.specVersion' "$S16/demo_1.0_bom.json" 2>&1)"
[ "$(jq -r '.run.status' "$S17/bomlens-result.json" 2>/dev/null)" = succeeded ] \
    && grep -q 'lodash' "$S17/demo_1.0_NOTICE.txt" \
    && [ "$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$S17/demo_1.0_security.json" 2>/dev/null)" = 1 ] \
    && [ "$(jq -r '.checks[] | select(.id == "spec-version") | "\(.status) \(.detail)"' "$S17/demo_1.0_conformance.json" 2>/dev/null)" = "pass CycloneDX 1.7" ] \
    && pass "NOTICE, the security report and the conformance check read the 1.7 SBOM" \
    || fail "1.7 consumers: $(jq -c '[.run.status] + [.steps[] | select(.status != "ok" and .status != "disabled")]' "$S17/bomlens-result.json" 2>&1)" "$(tail -5 "$S17.log")"
# A 1.5 document (the fixture as it is) and a 1.4 one with the older flat
# tools array are raised to 1.7 as well. A property without a name (allowed
# before 1.6) is removed as the document is raised.
S15="$(new_run spec-from-1.5)"
cp "$FIX/good-cyclonedx.json" "$S15/demo_1.0_bom.json"
run_engine "$S15" "$ROOT_DIR/docker/lib" CYCLONEDX_SPEC_VERSION=1.7
S14="$(new_run spec-from-1.4)"
jq '.specVersion = "1.4" | .metadata.tools = [{vendor: "Example", name: "generator", version: "1.0"}]
    | .components[0].properties = [{"value":"no name"},{"name":"example:kept","value":"y"}]' \
    "$FIX/good-cyclonedx.json" > "$S14/demo_1.0_bom.json"
run_engine "$S14" "$ROOT_DIR/docker/lib" CYCLONEDX_SPEC_VERSION=1.7
[ "$(jq -r .specVersion "$S15/demo_1.0_bom.json") $(jq -r .specVersion "$S14/demo_1.0_bom.json")" = "1.7 1.7" ] \
    && pass "1.5 and 1.4 SBOMs leave as 1.7 when 1.7 is asked for" \
    || fail "raised: $(jq -r .specVersion "$S15/demo_1.0_bom.json" "$S14/demo_1.0_bom.json" | tr '\n' ' ')" "$(tail -5 "$S14.log")"
[ "$(jq -c '[.. | objects | select(has("properties")) | .properties[]? | select(has("name") | not)] | length' "$S14/demo_1.0_bom.json")" = 0 ] \
    && jq -e 'any(.components[].properties[]?; .name == "example:kept")' "$S14/demo_1.0_bom.json" >/dev/null \
    && pass "raising 1.4 to 1.7 removes a property without a name and keeps the named ones" \
    || fail "nameless property: $(jq -c '[.components[].properties]' "$S14/demo_1.0_bom.json" 2>&1)"
# At the default 1.6 a 1.4 document keeps its version and gets only what 1.4
# defines: no metadata.lifecycles (1.5), and BomLens in the flat tools array.
S14D="$(new_run spec-1.4-default)"
jq '.specVersion = "1.4" | ."$schema" = "http://cyclonedx.org/schema/bom-1.4.schema.json" | del(.metadata.tools, .metadata.lifecycles)
    | .components[0].properties = [{"value":"no name"}]' \
    "$FIX/good-cyclonedx.json" > "$S14D/demo_1.0_bom.json"
run_engine "$S14D" "$ROOT_DIR/docker/lib"
[ "$(jq -c '[.specVersion, (.metadata | has("lifecycles")), (.metadata.tools | type), ([.metadata.tools[]? | .name] | index("BomLens") != null)]' "$S14D/demo_1.0_bom.json" 2>/dev/null)" = '["1.4",false,"array",true]' ] \
    && pass "a 1.4 SBOM at the default stays 1.4, without lifecycles and with BomLens in the tools array" \
    || fail "1.4 default: $(jq -c '[.specVersion, .metadata.lifecycles, .metadata.tools]' "$S14D/demo_1.0_bom.json" 2>&1)" "$(tail -5 "$S14D.log")"
SBAD="$(new_run spec-bad)"
run_engine "$SBAD" "$ROOT_DIR/docker/lib" CYCLONEDX_SPEC_VERSION=2.0
grep -q 'CYCLONEDX_SPEC_VERSION=2.0 is not a CycloneDX version this pipeline writes' "$SBAD.log" \
    && [ "$(jq -r '.specVersion' "$SBAD/demo_1.0_bom.json")" = "1.5" ] \
    && pass "an unsupported CYCLONEDX_SPEC_VERSION stops the run with the accepted values" \
    || fail "bad spec: $(tail -3 "$SBAD.log")"
# Upload: a Dependency-Track that predates 1.7 (4.14.4, 5.1.0) answers 400; the
# BOM is sent again as a 1.6 copy, and the delivered SBOM stays 1.7. A server
# that reads 1.7 gets no second try, and one whose version is not known gets
# the same second try as an old one. The stub server answers /api/version with
# DT_STUB_VERSION (or a page that is not JSON when it is "none"), accepts only
# 1.6 unless DT_STUB_ACCEPT=none, and keeps a copy of each BOM it was sent.
mkdir -p "$WORK/dtbin"
cat > "$WORK/dtbin/curl" <<'EOF'
#!/bin/bash
url=""; bom=""
for a in "$@"; do
    case "$a" in http*) url="$a" ;; bom=@*) bom="${a#bom=@}" ;; esac
done
case "$url" in
    */api/version)
        if [ "${DT_STUB_VERSION:-4.13.0}" = none ]; then echo '<html>login</html>'
        else echo "{\"version\":\"${DT_STUB_VERSION:-4.13.0}\"}"; fi ;;
    */api/v1/bom)
        v="$(jq -r .specVersion "$bom")"; echo "$v" >> "$DT_STUB_LOG"
        cp "$bom" "$DT_STUB_LOG.$v.json"
        if [ "$v" = "1.6" ] && [ "${DT_STUB_ACCEPT:-1.6}" = 1.6 ]; then printf '{"token":"t-1"}\n200'
        else printf 'refused a %s BOM\n400' "$v"; fi ;;
esac
EOF
chmod +x "$WORK/dtbin/curl"
# A 1.7 BOM whose root license list mixes a license and an expression, which
# 1.6 does not allow, and an external reference with a field only 1.7 has.
jq '.specVersion = "1.6"
    | .metadata.component.licenses = [{"license":{"id":"MIT"}},{"expression":"Apache-2.0 OR GPL-2.0-only"}]
    | .components[0].externalReferences = [{"type":"website","url":"https://example.org","properties":[{"name":"k","value":"v"}]}]' \
    "$FIX/good-cyclonedx.json" > "$WORK/upload-mixed.json"
dt_run() {  # dt_run <name> <spec-version> [VAR=value ...]
    local name="$1" sv="$2" d; shift 2
    d="$(new_run "spec-upload-$name")"
    cp "$WORK/upload-mixed.json" "$d/demo_1.0_bom.json"
    run_engine "$d" "$ROOT_DIR/docker/lib" PATH="$WORK/dtbin:$WORK/bin:$PATH" DT_STUB_LOG="$d.dt" \
        UPLOAD_ENABLED=true API_URL=http://dt.example API_KEY=k GENERATE_SECURITY=false CYCLONEDX_SPEC_VERSION="$sv" "$@"
}
dt_run 1.7 1.7 DT_STUB_VERSION=4.13.0
dt_run 1.6 1.6
dt_run 5.0 1.7 DT_STUB_VERSION=5.0.2
dt_run new 1.7 DT_STUB_VERSION=4.14.4
dt_run unknown 1.7 DT_STUB_VERSION=none
dt_run unknown-refused 1.7 DT_STUB_VERSION=none DT_STUB_ACCEPT=none
U17="$WORK/spec-upload-1.7"; U16="$WORK/spec-upload-1.6"
[ "$(tr '\n' ' ' < "$U17.dt")" = "1.7 1.6 " ] && grep -q 'Upload complete' "$U17.log" \
    && grep -q 'Dependency-Track 4.13.0 refused the CycloneDX 1.7 SBOM (HTTP 400).*Sending a CycloneDX 1.6 copy instead' "$U17.log" \
    && [ "$(jq -r .specVersion "$U17/demo_1.0_bom.json")" = "1.7" ] \
    && pass "a 1.7 BOM refused by Dependency-Track 4.13.0 is sent again as a 1.6 copy, and the delivered SBOM stays 1.7" \
    || fail "1.7 upload: sent $(tr '\n' ' ' < "$U17.dt" 2>&1)" "$(tail -5 "$U17.log")"
[ "$(jq -c '.metadata.component.licenses' "$U17.dt.1.6.json" 2>/dev/null)" = '[{"expression":"(Apache-2.0 OR GPL-2.0-only) AND MIT"}]' ] \
    && [ "$(jq -c '.components[0].externalReferences' "$U17.dt.1.6.json" 2>/dev/null)" = '[{"type":"website","url":"https://example.org"}]' ] \
    && [ "$(jq -r '."$schema" // "none"' "$U17.dt.1.6.json")" != "http://cyclonedx.org/schema/bom-1.7.schema.json" ] \
    && pass "the 1.6 copy joins a mixed license list into one expression and drops a 1.7-only field" \
    || fail "1.6 copy: $(jq -c '[.metadata.component.licenses, .components[0].externalReferences]' "$U17.dt.1.6.json" 2>&1)"
[ "$(tr '\n' ' ' < "$U16.dt")" = "1.6 " ] && grep -q 'Upload complete' "$U16.log" \
    && pass "a 1.6 BOM is uploaded once" || fail "1.6 upload: sent $(tr '\n' ' ' < "$U16.dt" 2>&1)" "$(tail -5 "$U16.log")"
[ "$(tr '\n' ' ' < "$WORK/spec-upload-5.0.dt")" = "1.7 1.6 " ] && grep -q 'Upload complete' "$WORK/spec-upload-5.0.log" \
    && pass "Dependency-Track 5.0.2 also gets the 1.6 copy" \
    || fail "5.0 upload: sent $(tr '\n' ' ' < "$WORK/spec-upload-5.0.dt" 2>&1)" "$(tail -5 "$WORK/spec-upload-5.0.log")"
UN="$WORK/spec-upload-new"
[ "$(tr '\n' ' ' < "$UN.dt")" = "1.7 " ] && ! grep -q 'Upload complete' "$UN.log" \
    && grep -q 'Dependency-Track 4.14.4 reads CycloneDX 1.7, so the refusal (HTTP 400) is not about the version' "$UN.log" \
    && grep -q 'refused a 1.7 BOM' "$UN.log" \
    && pass "a server that reads 1.7 (4.14.4) is not sent a 1.6 copy, and its refusal is shown" \
    || fail "4.14.4 upload: sent $(tr '\n' ' ' < "$UN.dt" 2>&1)" "$(tail -5 "$UN.log")"
UU="$WORK/spec-upload-unknown"
[ "$(tr '\n' ' ' < "$UU.dt")" = "1.7 1.6 " ] && grep -q 'Upload complete' "$UU.log" \
    && grep -q 'its version is not known' "$UU.log" \
    && pass "when /api/version gives no version, a 400 still gets one 1.6 copy" \
    || fail "unknown-version upload: sent $(tr '\n' ' ' < "$UU.dt" 2>&1)" "$(tail -5 "$UU.log")"
UR="$WORK/spec-upload-unknown-refused"
[ "$(tr '\n' ' ' < "$UR.dt")" = "1.7 1.6 " ] && ! grep -q 'Upload complete' "$UR.log" \
    && grep -q 'Response to the 1.7 SBOM: refused a 1.7 BOM' "$UR.log" \
    && grep -q 'Response: refused a 1.6 BOM' "$UR.log" \
    && pass "when the 1.6 copy is refused too, both responses are shown" \
    || fail "both refused: sent $(tr '\n' ' ' < "$UR.dt" 2>&1)" "$(tail -6 "$UR.log")"
# The pinned CycloneDX CLI (scripts/check-cdx-schema.sh); BOMLENS_CDX_SCHEMA=1
# downloads it when it is not installed.
if [ "${BOMLENS_CDX_SCHEMA:-}" = "1" ] || command -v cyclonedx >/dev/null 2>&1 || [ -n "${CYCLONEDX_CLI:-}" ]; then
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$S17/demo_1.0_bom.json" "$S16/demo_1.0_bom.json" 2>&1); then
        pass "the 1.7 and 1.6 SBOMs validate against their CycloneDX schemas"
    else
        fail "an SBOM fails its CycloneDX schema" "$cdxout"
    fi
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$S15/demo_1.0_bom.json" "$S14/demo_1.0_bom.json" 2>&1); then
        pass "1.5 and 1.4 SBOMs raised to 1.7 validate against the 1.7 schema"
    else
        fail "a raised SBOM fails the 1.7 schema" "$cdxout"
    fi
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$S14D/demo_1.0_bom.json" 2>&1); then
        pass "a 1.4 SBOM kept at 1.4 validates against the 1.4 schema"
    else
        fail "a 1.4 SBOM kept at 1.4 fails the 1.4 schema" "$cdxout"
    fi
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$U17.dt.1.6.json" 2>&1); then
        pass "the 1.6 copy sent to Dependency-Track validates against the 1.6 schema"
    else
        fail "the 1.6 copy fails the 1.6 schema" "$cdxout"
    fi
else
    echo "  SKIP: CycloneDX CLI not available (set BOMLENS_CDX_SCHEMA=1 to download the pinned one)"
fi

echo "== every step label in entrypoint.sh is documented =="
missing=""
for id in $(grep -v '^[[:space:]]*#' "$ENTRY" | grep -oE '(run_optional_step|er_record|er_phase) [a-z][a-z0-9-]+' | awk '{print $2}' | sort -u); do
    printf '%s\n' "$DOC_STEPS" | grep -qx "$id" || missing="$missing $id"
done
[ -z "$missing" ] && pass "all step ids used in entrypoint.sh are in the contract's step table" \
    || fail "step ids missing from docs/reference/engine-contract.md:$missing"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
