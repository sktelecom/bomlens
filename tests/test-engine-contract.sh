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
[ "$(jq -r '.status + " " + .input.detected_ecosystem + " " + .stages[0].image' "$P/bomlens-plan.json")" = "ok node ghcr.io/cdxgen/cdxgen-alpine-node24:13.2.0" ] \
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
P="$(plan_run node-badtc "$PSRC" GOTOOLCHAIN='local;rm -rf /')"
[ "$(jq -r '.stages[0].env.HOST_GOTOOLCHAIN // "absent"' "$P/bomlens-plan.json")" = "absent" ] \
    && pass "a GOTOOLCHAIN that is not a toolchain name is not passed on" || fail "HOST_GOTOOLCHAIN: $(jq -r '.stages[0].env.HOST_GOTOOLCHAIN' "$P/bomlens-plan.json")"
[ "$(jq -r '[.stages[0].mounts[] | select(.role=="guard-state") | .target] | first' "$P/bomlens-plan.json") $(jq -r '.stages[0].env_from_caller | has("BOMLENS_GUARD_ID")' "$P/bomlens-plan.json")" = "/bomlens-state true" ] \
    && pass "stage 1 offers the guard-state mount and BOMLENS_GUARD_ID, so a killed stage 1 can be undone" \
    || fail "guard state: $(jq -c '[.stages[0].mounts, .stages[0].env_from_caller]' "$P/bomlens-plan.json")"
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
        case "$*" in *engine-contract*) [ -n "${STUB_OLD_IMAGE:-}" ] || echo 1.0.0 ;; esac
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
( cd "$CMP" && env PATH="$CMP/bin:$PATH" CLI_ARGV_LOG="$CMP/argv" HOME="$CMP/home" TMPDIR="$CMP/tmp" \
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
