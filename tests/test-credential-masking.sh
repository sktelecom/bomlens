#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-credential-masking.sh - No-Docker tests that credentials never reach the
# console, the kept cdxgen log or the SBOM: npm tokens, pip index URLs with a
# user and password, and Maven settings.xml passwords.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fake credentials. None of them may appear in any output below.
SECRETS="NPMTOKEN-4f9a1c ZGVtbzpwYXNzd29yZA== PIPPASS-77x MVNPASS-91q hunter2-secret ENCPASS-88z AUTHTOK-5512 pass@word"

echo "== credentials do not reach the console, the cdxgen log or the SBOM =="
cat > "$WORK/fake.log" <<'LOG'
npm http fetch GET 401 https://npm.internal.example/left-pad
//npm.internal.example/:_authToken=NPMTOKEN-4f9a1c
//npm.internal.example/:_auth=ZGVtbzpwYXNzd29yZA==
_auth = ZGVtbzpwYXNzd29yZA==
npm_config__authToken="NPMTOKEN-4f9a1c"
Looking in indexes: https://deploy:PIPPASS-77x@pypi.internal.example/simple
WARNING: Retrying after connection broken: https://deploy:pass@word@pypi.internal.example/simple/flask/
  index-url = https://deploy:PIPPASS-77x@pypi.internal.example/simple
pip install --extra-index-url=https://deploy:PIPPASS-77x@pypi2.internal.example/simple flask
[WARNING] Could not transfer from https://mvn.internal.example/repo (id=corp): 401
<server><id>corp</id><username>deploy</username><password>MVNPASS-91q</password></server>
<password>{ENCPASS-88z}</password>
<passphrase>hunter2-secret</passphrase>
-Dpassword=hunter2-secret
Authorization: Basic ZGVtbzpwYXNzd29yZA==
Proxy-Authorization: Bearer AUTHTOK-5512xx
npm ERR! code E401 for https://npm.internal.example/left-pad
LOG
check_clean() { # <label> <file>
    local sec bad=0
    for sec in $SECRETS; do
        if grep -qF -- "$sec" "$2"; then bad=1; fail "$1 still holds '$sec'" "$(grep -F -- "$sec" "$2" | head -2)"; fi
    done
    [ "$bad" = 0 ] && pass "$1 holds none of the fake credentials"
    return 0
}
MASKER="$(sed -n '/^mask_log_stream() {/,/^}/p;/^mask_log_secrets() {/,/^}/p' "$LIB/source-detect.sh")"
if [ -z "$MASKER" ]; then
    fail "could not extract the log masker from source-detect.sh"
else
    # The kept cdxgen log copy (scan-sbom.sh keeps it only through mask_log_secrets).
    bash -c "$MASKER; mask_log_secrets '$WORK/fake.log' '$WORK/kept.log'" || fail "mask_log_secrets failed"
    check_clean "the kept cdxgen log copy" "$WORK/kept.log"
    # The live console of the web UI scan (entrypoint.sh: tee | mask_log_stream -u).
    bash -c "$MASKER; cat '$WORK/fake.log' | tee '$WORK/raw.log' | mask_log_stream -u" > "$WORK/console.log"
    check_clean "the console stream" "$WORK/console.log"
    grep -q 'https://\*\*\*@pypi.internal.example/simple' "$WORK/kept.log" \
        && grep -q 'https://npm.internal.example/left-pad' "$WORK/kept.log" \
        && pass "hosts and paths stay readable, only the credential part is replaced" \
        || fail "the masker removed more than the credentials" "$(cat "$WORK/kept.log")"
    grep -q 'Could not transfer from https://mvn.internal.example/repo' "$WORK/kept.log" \
        && pass "ordinary error lines are untouched" || fail "an ordinary line changed"
fi
grep -q '| tee "\$logf" | mask_log_stream -u &' "$ROOT_DIR/docker/entrypoint.sh" \
    && pass "entrypoint.sh sends the cdxgen sibling's output through the masker before the console" \
    || fail "entrypoint.sh no longer masks the cdxgen console stream"
# Every write of the kept <prefix>_cdxgen.log goes through the masker.
if [ "$(grep -c '_s1_kept' "$ROOT_DIR/scripts/scan-sbom.sh")" -gt 0 ] \
   && ! grep -E '(>|cp|mv|tee)[^|]*_s1_kept' "$ROOT_DIR/scripts/scan-sbom.sh" | grep -vq 'mask_log_secrets\|rm -f'; then
    pass "scan-sbom.sh writes the kept cdxgen log only through mask_log_secrets"
else
    fail "scan-sbom.sh writes the kept cdxgen log some other way"
fi

grep -q 'mask_log_secrets "\$STAGE1_LOG" "\$STAGE1_LOG.masked"' "$ROOT_DIR/scripts/scan-sbom.sh" \
    && pass "scan-sbom.sh masks the temp cdxgen log in place before it prints the path" \
    || fail "scan-sbom.sh leaves the temp cdxgen log unmasked after a failed scan"

# The SBOM: a URL in a lock file or a purl qualifier may carry a user and password.
cat > "$WORK/sbom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
 {"type":"library","name":"a","version":"1",
  "purl":"pkg:npm/a@1?repository_url=https%3A%2F%2Fdeploy%3APIPPASS-77x%40npm.internal.example%2F",
  "externalReferences":[
    {"type":"distribution","url":"https://deploy:PIPPASS-77x@npm.internal.example/a/-/a-1.tgz"},
    {"type":"vcs","url":"https://AUTHTOK-5512@git.internal.example/a.git"},
    {"type":"vcs","url":"ssh://deploy:pass@word@git.internal.example/a.git"},
    {"type":"vcs","url":"git+ssh://git@github.com/org/a.git"}]}]}
JSON
cp "$WORK/sbom.json" "$WORK/sbom-stable.json"
bash "$LIB/normalize-sbom.sh" "$WORK/sbom.json" >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/sbom-stable.json" --stable >/dev/null 2>&1
check_clean "the normalized SBOM" "$WORK/sbom.json"
check_clean "the byte-stable SBOM" "$WORK/sbom-stable.json"
grep -q 'git+ssh://git@github.com/org/a.git' "$WORK/sbom.json" && grep -q 'https://npm.internal.example/a/-/a-1.tgz' "$WORK/sbom.json" \
    && pass "a plain git user and the rest of each URL are kept" || fail "normalize changed more than credentials" "$(jq -c '.components[0].externalReferences' "$WORK/sbom.json")"

echo ""
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
