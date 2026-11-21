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
always-auth=true
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
    grep -qx 'always-auth=true' "$WORK/kept.log" && grep -qx 'always-auth=true' "$WORK/console.log" \
        && pass "always-auth=true is not a credential and stays in the log" \
        || fail "the log masker masked always-auth=true"
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
echo "== credentials do not reach the source snapshot (<prefix>_source.json) =="
SNAP="$LIB/source-snapshot.py"
# The snapshot masker and the log masker give the same output for the log lines.
if [ -n "$MASKER" ]; then
    python3 -I - "$SNAP" "$WORK/fake.log" > "$WORK/py-masked.log" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("snap", sys.argv[1])
snap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snap)
with open(sys.argv[2], encoding="utf-8") as fh:
    sys.stdout.write(snap.mask_secrets(fh.read()))
PY
    if diff -u "$WORK/kept.log" "$WORK/py-masked.log" > "$WORK/mask.diff"; then
        pass "source-snapshot.py masks the log lines exactly as mask_log_stream does"
    else
        fail "source-snapshot.py and mask_log_stream mask differently" "$(head -20 "$WORK/mask.diff")"
    fi
fi

T="$WORK/tree"
mkdir -p "$T/.docker" "$T/.m2" "$T/src"
cat > "$T/.npmrc" <<'EOF'
registry=https://npm.internal.example/
//registry.npmjs.org/:_authToken=NPMTOKEN-4f9a1c
//npm.internal.example/:_auth=ZGVtbzpwYXNzd29yZA==
//npm.internal.example/:_password="RkFLRVBBU1M="
always-auth=true
auth-type=legacy
strict-ssl=false
EOF
cat > "$T/.yarnrc.yml" <<'EOF'
npmRegistryServer: "https://npm.internal.example"
npmAuthToken: NPMTOKEN-4f9a1c
npmAuthIdent: "deploy:FAKEIDENT-31k"
npmAlwaysAuth: true
npmAuthType: web
EOF
printf '[global]\nindex-url = https://deploy:PIPPASS-77x@pypi.internal.example/simple\n' > "$T/pip.conf"
printf '[pypi]\nusername = __token__\npassword = FAKEPYPI-66t\n' > "$T/.pypirc"
printf '<settings><servers><server><id>corp</id><password>MVNPASS-91q</password></server></servers></settings>\n' > "$T/.m2/settings.xml"
printf 'org.gradle.jvmargs=-Xmx2g\nmavenPassword=FAKEGRADLE-12g\n' > "$T/gradle.properties"
printf 'machine git.internal.example login deploy password FAKENETRC-40n\n' > "$T/.netrc"
printf '{"auths":{"registry.internal.example":{"auth":"RkFLRURPQ0tFUi1hdXRo"}}}\n' > "$T/.docker/config.json"
cat > "$T/nuget.config" <<'EOF'
<configuration><packageSourceCredentials><corp>
<add key="Username" value="deploy" />
<add key="ClearTextPassword" value="FAKENUGET-25u" />
</corp></packageSourceCredentials></configuration>
EOF
printf 'DATABASE_URL=postgres://app:FAKEDB-90d@db.internal.example/app\nAWS_SECRET_ACCESS_KEY=FAKEAWS-73a\nLOG_LEVEL=debug\n' > "$T/.env"
printf 'url = "https://deploy:PIPPASS-77x@git.internal.example/a.git"\nprint("hello")\n' > "$T/src/app.py"
printf '{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}\n' > "$T/package.json"
(cd "$T" && find . -type f | sed 's#^\./##' | sort) \
    | jq -R '{path: ., type: "file"}' | jq -s '{files: .}' > "$WORK/snap_files.json"
python3 -I "$SNAP" "$T" "$WORK/snap_files.json" "$WORK/snap_source.json" > "$WORK/snap.out" 2>&1
SNAP_SECRETS="$SECRETS RkFLRVBBU1M= FAKEIDENT-31k FAKEPYPI-66t FAKEGRADLE-12g FAKENETRC-40n RkFLRURPQ0tFUi1hdXRo FAKENUGET-25u FAKEDB-90d FAKEAWS-73a"
if [ -s "$WORK/snap_source.json" ]; then
    SECRETS="$SNAP_SECRETS" check_clean "the source snapshot" "$WORK/snap_source.json"
    got=$(jq -r '[.files[] | select(.masked) | .path] | sort | join(",")' "$WORK/snap_source.json")
    want=".docker/config.json,.env,.m2/settings.xml,.netrc,.npmrc,.pypirc,.yarnrc.yml,gradle.properties,nuget.config,pip.conf,src/app.py"
    [ "$got" = "$want" ] && pass "every file that held a credential is marked masked, and only those" \
        || fail "masked files: got '$got', want '$want'"
    [ "$(jq -r '.totals.maskedFiles' "$WORK/snap_source.json")" = 11 ] \
        && pass "totals.maskedFiles counts them" || fail "totals.maskedFiles is wrong"
    npmrc=$(jq -r '.files[] | select(.path == ".npmrc") | .content' "$WORK/snap_source.json")
    case "$npmrc" in
        *"registry=https://npm.internal.example/"*"//registry.npmjs.org/:_authToken=***"*)
            pass "the rest of .npmrc stays readable, only the token is replaced" ;;
        *) fail ".npmrc lost more than the credential" "$npmrc" ;;
    esac
    case "$npmrc" in
        *"always-auth=true"*"auth-type=legacy"*"strict-ssl=false"*)
            pass "always-auth, auth-type and a true/false setting in .npmrc are not masked" ;;
        *) fail ".npmrc settings that hold no credential were masked" "$npmrc" ;;
    esac
    yarnrc=$(jq -r '.files[] | select(.path == ".yarnrc.yml") | .content' "$WORK/snap_source.json")
    case "$yarnrc" in
        *"npmAuthToken: ***"*"npmAlwaysAuth: true"*"npmAuthType: web"*)
            pass "npmAlwaysAuth and npmAuthType in .yarnrc.yml are not masked, npmAuthToken is" ;;
        *) fail ".yarnrc.yml masking is wrong" "$yarnrc" ;;
    esac
    jq -e '.files[] | select(.path == ".env") | .content | test("LOG_LEVEL=debug")' "$WORK/snap_source.json" >/dev/null \
        && jq -e '.files[] | select(.path == "package.json") | (.masked | not) and (.content | test("left-pad"))' "$WORK/snap_source.json" >/dev/null \
        && pass "lines and files without a credential are untouched" \
        || fail "the snapshot changed text that holds no credential"
else
    fail "source-snapshot.py wrote no snapshot" "$(cat "$WORK/snap.out")"
fi

echo ""
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
