#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-node-installed-lock.sh: No-Docker checks for a Node.js tree installed
# with no lock file committed (docker/lib/build-prep.sh, "node installed lock").
#
#   - node_modules/.package-lock.json becomes a package-lock.json beside
#     package.json, with a root entry from package.json; node_modules/.pnpm/lock.yaml
#     is copied as pnpm-lock.yaml.
#   - Not used: a committed lock file (here or above), a lock that lacks a
#     dependency package.json declares, a workspace, a non-shipped folder, the
#     BOMLENS_NODE_INSTALLED_LOCK=false opt-out.
#   - The written files are removed again; the production set is read from the
#     written lock with no npm run; bomlens:node-lock-source is written on the
#     SBOM; static detection names the installed lock in its reason.
#
# The fixtures are written here by hand (no npm or pnpm install).
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREP="$ROOT_DIR/docker/lib/build-prep.sh"
DETECT="$ROOT_DIR/docker/lib/source-detect.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

if ! command -v node >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: node and jq are needed"
    exit 0
fi

# --- the sections under test ------------------------------------------------
_sec="$WORK/section.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    printf '%s\n' 'mark_prep_applied() { PREP_APPLIED="${PREP_APPLIED:+$PREP_APPLIED }$1"; }'
    printf '%s\n' 'mark_prep_failed() { PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$1"; }'
    printf '%s\n' 'PREP_APPLIED=""; PREP_FAILED=""'
    printf '%s\n' 'NON_SHIPPED_DIRS="test tests spec fixtures testdata __tests__ e2e example examples sample samples bench benches benchmark benchmarks demo demos playground"'
    printf '%s\n' 'EXCLUDE_NON_SHIPPED=1'
    printf '%s\n' 'SRC="$(pwd)"'
    sed -n '/^NODE_INSTALLED_LOCKS=""$/,/^}$/p' "$PREP"
    sed -n '/^# --- node installed lock ---$/,/^# --- end node installed lock ---$/p' "$PREP"
    # shellcheck disable=SC2016
    printf '%s\n' 'echo "ROOT:$NODE_INSTALLED_ROOT"; echo "APPLIED:$PREP_APPLIED"; echo "FAILED:$PREP_FAILED"' \
        'printf "%s\n" "$NODE_INSTALLED_LOCK_SOURCES" | sed "s/^/SOURCE:/"' \
        'printf "%s\n" "$NODE_INSTALLED_LOCKS" | sed "s/^/WROTE:/"' \
        '[ -z "${REMOVE:-}" ] || node_installed_lock_remove'
} > "$_sec"
grep -q 'NODE_INSTALLED_LOCK_JS' "$_sec" && grep -q '^node_installed_lock_remove() {' "$_sec" \
    || fail "could not extract the node installed lock section from build-prep.sh"
line() { printf '%s\n' "$1" | sed -n "s/^$2://p"; }
run_section() {  # <project dir> [VAR=value ...]
    local p="$1"; shift
    ( cd "$p" && env -u BOMLENS_NODE_INSTALLED_LOCK "$@" sh "$_sec" ) 2>&1
}

# --- fixtures ---------------------------------------------------------------
# npm_project DIR: package.json (debug and left-pad, is-number for development),
# the lock npm 7+ writes at install and each installed package.json.
npm_project() {
    local d="$1"
    mkdir -p "$d/node_modules/debug" "$d/node_modules/ms" "$d/node_modules/left-pad" "$d/node_modules/is-number"
    cat > "$d/package.json" <<'EOF'
{
  "name": "app",
  "version": "1.0.0",
  "dependencies": { "debug": "^4.3.4", "left-pad": "^1.3.0" },
  "devDependencies": { "is-number": "^7.0.0" }
}
EOF
    cat > "$d/node_modules/.package-lock.json" <<'EOF'
{
  "name": "app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/debug": {
      "version": "4.3.4",
      "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
      "license": "MIT",
      "dependencies": { "ms": "2.1.2" }
    },
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "license": "WTFPL"
    },
    "node_modules/ms": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.2.tgz",
      "license": "MIT"
    }
  }
}
EOF
    printf '{ "name": "debug", "version": "4.3.4", "license": "MIT" }\n' > "$d/node_modules/debug/package.json"
    printf '{ "name": "ms", "version": "2.1.2", "license": "MIT" }\n' > "$d/node_modules/ms/package.json"
    printf '{ "name": "left-pad", "version": "1.3.0", "license": "WTFPL" }\n' > "$d/node_modules/left-pad/package.json"
    printf '{ "name": "is-number", "version": "7.0.0", "license": "MIT" }\n' > "$d/node_modules/is-number/package.json"
}
# pnpm_project DIR: package.json and the lock pnpm writes at install (lockfile 9).
pnpm_project() {
    local d="$1"
    mkdir -p "$d/node_modules/.pnpm"
    printf '{ "name": "papp", "version": "2.0.0", "dependencies": { "@scope/a": "^1.0.0", "ms": "^2.1.2" } }\n' > "$d/package.json"
    cat > "$d/node_modules/.pnpm/lock.yaml" <<'EOF'
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@scope/a':
        specifier: ^1.0.0
        version: 1.0.1
      ms:
        specifier: ^2.1.2
        version: 2.1.3

packages:

  '@scope/a@1.0.1':
    resolution: {integrity: sha512-AAAA}

  ms@2.1.3:
    resolution: {integrity: sha512-BBBB}

snapshots:

  '@scope/a@1.0.1':
    dependencies:
      ms: 2.1.3

  ms@2.1.3: {}
EOF
}

echo "== npm: node_modules/.package-lock.json at the project root =="
p="$WORK/npm"; npm_project "$p"
o=$(run_section "$p")
check "a package-lock.json is written beside package.json" "$( [ -f "$p/package-lock.json" ] && echo yes)" "yes"
check "its root entry comes from package.json" \
    "$(jq -c '.packages[""] | [.name, .version, (.dependencies | keys), (.devDependencies | keys)]' "$p/package-lock.json" 2>/dev/null)" \
    '["app","1.0.0",["debug","left-pad"],["is-number"]]'
check "the installed entries are kept as they are" \
    "$(jq -c '[.lockfileVersion, (.packages | keys), .packages["node_modules/is-number"].dev, .packages["node_modules/left-pad"].license]' "$p/package-lock.json" 2>/dev/null)" \
    '[3,["","node_modules/debug","node_modules/is-number","node_modules/left-pad","node_modules/ms"],true,"WTFPL"]'
check "the root is recorded as npm, the step as npm-installed-lock" "$(line "$o" ROOT)|$(line "$o" APPLIED)" "npm|npm-installed-lock"
check "the source is node_modules/.package-lock.json" "$(line "$o" SOURCE)" "node_modules/.package-lock.json"
if printf '%s\n' "$o" | grep -qF "node: no lock file in the project root; reading the lock file npm wrote at install (node_modules/.package-lock.json)"; then
    pass "one log line names the installed lock"
else
    fail "the log line is missing" "$o"
fi

echo "== the production set is read from the written lock, with no npm run =="
_ps="$WORK/prodset.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    printf '%s\n' 'mark_prep_applied() { PREP_APPLIED="${PREP_APPLIED:+$PREP_APPLIED }$1"; }'
    printf '%s\n' 'opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }'
    printf '%s\n' 'prep_step() { echo "PREP_STEP_CALLED:$1"; return 1; }'
    printf '%s\n' 'npm() { echo "NPM_CALLED"; return 1; }'
    printf '%s\n' 'PREP_APPLIED=""; PREP_TIMEOUT_DEFAULT=60; NODE_INSTALLED_ROOT=npm'
    sed -n '/^NODE_PROD_SET=""$/,/^# --- build the cdxgen argument list/p' "$PREP"
    # shellcheck disable=SC2016
    printf '%s\n' 'echo "APPLIED:$PREP_APPLIED"; [ -n "$NODE_PROD_SET" ] && sort "$NODE_PROD_SET" | tr "\n" " " | sed "s/^/SET:/"; echo'
} > "$_ps"
grep -q 'production set read from the installed lock file' "$_ps" || fail "could not extract the production set section from build-prep.sh"
o=$( (cd "$p" && sh "$_ps") 2>&1)
check "the set holds the runtime packages at their versions, not is-number" "$(line "$o" SET)" "debug@4.3.4 left-pad@1.3.0 ms@2.1.2 "
check "npm-production-set is recorded as applied" "$(line "$o" APPLIED)" "npm-production-set"
if printf '%s\n' "$o" | grep -qE 'PREP_STEP_CALLED|NPM_CALLED'; then
    fail "npm was run for the production set" "$o"
else
    pass "npm is not run"
fi

echo "== the written files are removed again =="
p="$WORK/npm-rm"; npm_project "$p"
o=$(run_section "$p" REMOVE=1)
check "package-lock.json is gone, node_modules/.package-lock.json stays" \
    "$( [ -f "$p/package-lock.json" ] && echo left)|$( [ -f "$p/node_modules/.package-lock.json" ] && echo kept)" "|kept"

echo "== cases where the installed lock is not read =="
p="$WORK/committed"; npm_project "$p"; printf '{"lockfileVersion":3,"packages":{"":{}}}\n' > "$p/package-lock.json"
cp "$p/package-lock.json" "$WORK/committed.before"
o=$(run_section "$p")
check "a committed package-lock.json is left as it is" "$(cmp -s "$p/package-lock.json" "$WORK/committed.before" && echo same)|$(line "$o" APPLIED)" "same|"
p="$WORK/yarn"; npm_project "$p"; printf '# yarn lockfile v1\n' > "$p/yarn.lock"
o=$(run_section "$p")
check "a committed yarn.lock: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"

p="$WORK/stale"; npm_project "$p"
jq '.dependencies.chalk = "^5.0.0"' "$p/package.json" > "$p/p.json" && mv "$p/p.json" "$p/package.json"
o=$(run_section "$p")
check "a dependency added after the install: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"
if printf '%s\n' "$o" | grep -q "does not list chalk from package.json"; then
    pass "the log names the dependency the lock lacks"
else
    fail "the stale lock is not explained" "$o"
fi

p="$WORK/ws"; npm_project "$p"
jq '.workspaces = ["packages/*"]' "$p/package.json" > "$p/p.json" && mv "$p/p.json" "$p/package.json"
o=$(run_section "$p")
check "an npm workspace root: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"
printf '%s\n' "$o" | grep -q "npm workspace root with no lock file" \
    && pass "the workspace root is logged" || fail "the workspace root is not logged" "$o"
check "an npm workspace root: npm-installed-lock is recorded as failed" "$(line "$o" FAILED)" "npm-installed-lock"
o=$( (cd "$p" && sh "$_ps") 2>&1)
printf '%s\n' "$o" | grep -q "workspace root with no lock file; dependency relations are not available and the production filter is not applied" \
    && pass "with no lock file, the log does not claim a full graph" || fail "the no-lock workspace log line is wrong" "$o"
printf '# yarn lockfile v1\n' > "$p/yarn.lock"
o=$( (cd "$p" && sh "$_ps") 2>&1)
printf '%s\n' "$o" | grep -q "keeping the full graph from yarn.lock" \
    && pass "with a yarn.lock, the log names the lock the full graph comes from" || fail "the yarn workspace log line is wrong" "$o"
rm -f "$p/yarn.lock"
p="$WORK/ws-lock"; npm_project "$p"
jq '.packages["packages/a"] = {"name":"a","version":"1.0.0"} | .packages["node_modules/a"] = {"resolved":"packages/a","link":true}' \
    "$p/node_modules/.package-lock.json" > "$p/l.json" && mv "$p/l.json" "$p/node_modules/.package-lock.json"
o=$(run_section "$p")
check "a lock with workspace members: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"
check "a lock with workspace members: npm-installed-lock is recorded as failed" "$(line "$o" FAILED)" "npm-installed-lock"

p="$WORK/member"; mkdir -p "$p/packages"; printf '{"lockfileVersion":3,"packages":{"":{}}}\n' > "$p/package-lock.json"
printf '{"name":"root","private":true}\n' > "$p/package.json"; npm_project "$p/packages/a"
o=$(run_section "$p")
check "a folder under a root with a lock file: nothing written" "$( [ -f "$p/packages/a/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"

p="$WORK/nonshipped"; mkdir -p "$p"; npm_project "$p/examples/demo"
o=$(run_section "$p")
check "a project under examples/: nothing written" "$( [ -f "$p/examples/demo/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"

p="$WORK/optout"; npm_project "$p"
o=$(run_section "$p" BOMLENS_NODE_INSTALLED_LOCK=false)
check "BOMLENS_NODE_INSTALLED_LOCK=false: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"
printf '%s\n' "$o" | grep -q "BOMLENS_NODE_INSTALLED_LOCK=false" \
    && pass "the opt-out is logged" || fail "the opt-out is not logged" "$o"

p="$WORK/broken"; npm_project "$p"; printf '{ not json\n' > "$p/node_modules/.package-lock.json"
o=$(run_section "$p")
check "an unreadable lock: nothing written" "$( [ -f "$p/package-lock.json" ] && echo written)|$(line "$o" APPLIED)" "|"

echo "== a project in a subfolder =="
p="$WORK/nested"; mkdir -p "$p"; npm_project "$p/web"
o=$(run_section "$p")
check "web/package-lock.json is written; the root is not marked" \
    "$( [ -f "$p/web/package-lock.json" ] && echo yes)|$(line "$o" ROOT)|$(line "$o" SOURCE)" "yes||web/node_modules/.package-lock.json"
check "the written path is absolute" "$(line "$o" WROTE)" "$p/web/package-lock.json"

echo "== pnpm: node_modules/.pnpm/lock.yaml =="
p="$WORK/pnpm"; pnpm_project "$p"
o=$(run_section "$p")
check "pnpm-lock.yaml is a copy of the installed lock" "$(cmp -s "$p/pnpm-lock.yaml" "$p/node_modules/.pnpm/lock.yaml" && echo same)" "same"
check "the root is pnpm, the step pnpm-installed-lock" "$(line "$o" ROOT)|$(line "$o" APPLIED)|$(line "$o" SOURCE)" \
    "pnpm|pnpm-installed-lock|node_modules/.pnpm/lock.yaml"
p="$WORK/pnpm-stale"; pnpm_project "$p"
jq '.dependencies.chalk = "^5.0.0"' "$p/package.json" > "$p/p.json" && mv "$p/p.json" "$p/package.json"
o=$(run_section "$p")
check "pnpm, a dependency added after the install: nothing written" "$( [ -f "$p/pnpm-lock.yaml" ] && echo written)|$(line "$o" APPLIED)" "|"
check "a stale lock is not a failed step" "$(line "$o" FAILED)" ""
p="$WORK/pnpm-ws"; pnpm_project "$p"
awk '{print} /^importers:/{print ""; print "  packages/a:"; print "    dependencies: {}"}' "$p/node_modules/.pnpm/lock.yaml" > "$p/l.yaml" \
    && mv "$p/l.yaml" "$p/node_modules/.pnpm/lock.yaml"
o=$(run_section "$p")
check "pnpm workspace (a second importer): nothing written" "$( [ -f "$p/pnpm-lock.yaml" ] && echo written)|$(line "$o" APPLIED)" "|"
check "pnpm workspace (a second importer): pnpm-installed-lock is recorded as failed" "$(line "$o" FAILED)" "pnpm-installed-lock"
p="$WORK/both"; npm_project "$p"; pnpm_project "$p"
jq '.dependencies = {"ms": "^2.1.2"}' "$p/package.json" > "$p/p.json" && mv "$p/p.json" "$p/package.json"
touch -t 202601010000 "$p/node_modules/.pnpm/lock.yaml"
o=$(run_section "$p")
check "both locks: the newer (npm) one is read" "$(line "$o" APPLIED)|$( [ -f "$p/pnpm-lock.yaml" ] && echo pnpm)" "npm-installed-lock|"

echo "== bomlens:node-lock-source on the SBOM =="
_rec="$WORK/record.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    sed -n '/^# Record the lock files npm or pnpm wrote/,/^fi$/p' "$PREP"
} > "$_rec"
printf '{"bomFormat":"CycloneDX","metadata":{"properties":[{"name":"x","value":"y"}]},"components":[]}\n' > "$WORK/bom.json"
OUT="$WORK/bom.json" rc=0 NODE_INSTALLED_LOCK_SOURCES="node_modules/.package-lock.json
web/node_modules/.pnpm/lock.yaml" sh -c '. "$1"' _ "$_rec" >/dev/null 2>&1
check "one property per installed lock, others kept" \
    "$(jq -c '[.metadata.properties[] | [.name, .value]]' "$WORK/bom.json")" \
    '[["x","y"],["bomlens:node-lock-source","node_modules/.package-lock.json"],["bomlens:node-lock-source","web/node_modules/.pnpm/lock.yaml"]]'

echo "== static detection =="
p="$WORK/static"; npm_project "$p"
why=$(bash -c '. "$1" >/dev/null 2>&1; static_detection_check "$2" node; echo "$?|$STATIC_DETECTION_WHY"' _ "$DETECT" "$p")
check "an installed lock alone does not qualify, and the reason says so" "$why" \
    "1|no package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml or bun.lock (the lock file written at install under node_modules is read in a build)"

echo
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
