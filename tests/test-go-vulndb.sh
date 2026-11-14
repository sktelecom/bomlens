#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-go-vulndb.sh - the Go vulnerability database match (go-vulndb step).
#
# No Docker, no network. Runs docker/lib/scan-go-vulndb.py against a small
# fixture export (tests/fixtures/go-vulndb/db, also zipped here as vulndb.zip
# is published) and a fixture SBOM, then scan-security.sh with Trivy stubbed,
# then entrypoint.sh (POSTPROCESS) for the step the result manifest records.
#
# The fixture covers: a module recorded with +incompatible versions, an
# advisory on a package path of a module, an advisory Trivy already reports
# under its CVE (written once), a withdrawn record, the standard library with
# a Go release name, a pseudo-version with last_affected, a /v2 module that
# must not match its v1 path, one module in three entries (the fixed version
# is the one no entry still marks as affected), the toolchain with a build
# suffix, a stdlib advisory Trivy reports under another version form, and a
# module whose version cannot be read. The database age checks use a stale
# snapshot and file:// URLs in place of vuln.go.dev.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/go-vulndb"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# The fixture database is from 2026-11-01: the age checks below set their own
# limit, and a downloaded replacement goes into this folder.
export BOMLENS_GO_VULNDB_MAX_AGE_DAYS=100000
mkdir -p "$WORK/tmp"
export TMPDIR="$WORK/tmp"

# The fixture folder as vulndb.zip is published: index/ and ID/ at the top.
python3 - "$FIX/db" "$WORK/vulndb.zip" <<'PY'
import os, sys, zipfile
root, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w") as z:
    for d, _, files in os.walk(root):
        for f in sorted(files):
            full = os.path.join(d, f)
            z.write(full, os.path.relpath(full, root).replace(os.sep, "/"))
PY

summary() {
    jq -r '[.Results[].Vulnerabilities[] | "\(.PkgName) \(.InstalledVersion) \(.VulnerabilityID) \(.Severity) \(.FixedVersion // "-") \(.["bomlens:goVulnDB"].match)"] | sort | .[]' "$1"
}
EXPECTED='github.com/docker/docker v20.10.7+incompatible CVE-2099-1001 HIGH 20.10.11+incompatible module
github.com/example/pseudo v0.0.0-20210601000000-abcdefabcdef GO-2099-0006 UNKNOWN - module
github.com/klauspost/compress/zstd v1.17.0 CVE-2099-1002 UNKNOWN 1.20.2 package
github.com/redis/go-redis/v9 v9.5.3 CVE-2099-1007 UNKNOWN 9.6.3 module
stdlib go1.21.3 CVE-2099-1005 UNKNOWN 1.21.5 module
toolchain go1.21.3 X:boringcrypto CVE-2099-1008 UNKNOWN 1.21.5 module'

echo "== scan-go-vulndb.py: matching rules =="
python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/dir" "$FIX/db" "$FIX/trivy-report.json" > "$WORK/dir.log" 2>&1
rc=$?
[ "$rc" = 0 ] && [ -f "$WORK/dir_security_govulndb.json" ] \
    && pass "a folder export: exit 0 and the sidecar is written" || fail "exit $rc" "$(cat "$WORK/dir.log")"
got="$(summary "$WORK/dir_security_govulndb.json" 2>&1)"
[ "$got" = "$EXPECTED" ] \
    && pass "+incompatible, package path, stdlib and toolchain release names and pseudo-version are matched; go-redis/v9 9.5.3 is fixed in 9.6.3, not 9.5.5; the fixed docker/cli, compress@v1.15.15 and pseudo/v2 are not" \
    || fail "findings differ" "$(diff <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$got"))"
[ "$(jq -r '[.Results[].Vulnerabilities[] | select(.PkgName == "github.com/aws/aws-sdk-go")] | length' "$WORK/dir_security_govulndb.json")" = 0 ] \
    && [ "$(jq -r '.GoVulnDB.AlreadyReported' "$WORK/dir_security_govulndb.json")" = 2 ] \
    && jq -e '[.Results[].Vulnerabilities[] | .VulnerabilityID] | index("CVE-2099-1009") | not' "$WORK/dir_security_govulndb.json" >/dev/null \
    && pass "an advisory Trivy reports under its CVE for the same module is not written again, also for stdlib v1.21.3 against go1.21.3" \
    || fail "aws-sdk-go: $(jq -c '.GoVulnDB' "$WORK/dir_security_govulndb.json")"
jq -e '[.Results[].Vulnerabilities[] | .VulnerabilityID] | index("CVE-2099-1004") | not' "$WORK/dir_security_govulndb.json" >/dev/null \
    && pass "a withdrawn record is not reported" || fail "the withdrawn GO-2099-0004 was reported"
jq -e '[.Results[].Vulnerabilities[] | select(.VulnerabilityID == "CVE-2099-1001")][0]
       | .VendorIDs == ["GO-2099-0001", "GHSA-aaaa-bbbb-cccc"] and .SeveritySource == "ghsa"
         and .CVSS.ghsa.V3Score == 8.8 and .PrimaryURL == "https://pkg.go.dev/vuln/GO-2099-0001"
         and .DataSource.ID == "go-vulndb" and .PkgIdentifier.BOMRef == "docker" and .Status == "fixed"' \
    "$WORK/dir_security_govulndb.json" >/dev/null \
    && pass "the finding is filed under its CVE, lists its GO and GHSA ids, and takes the rating Trivy gives the CVE on another module" \
    || fail "docker finding: $(jq -c '[.Results[].Vulnerabilities[] | select(.VulnerabilityID == "CVE-2099-1001")][0] | del(.Description)' "$WORK/dir_security_govulndb.json")"
jq -e '.GoVulnDB | .Modified == "2026-11-01T00:00:00Z" and .Records == 8 and .Components == 11 and .New == 6 and .Source == "named" and (.AgeDays | type) == "number"' \
    "$WORK/dir_security_govulndb.json" >/dev/null \
    && pass "the sidecar records the database date, the records read and the counts" \
    || fail "GoVulnDB: $(jq -c '.GoVulnDB' "$WORK/dir_security_govulndb.json")"

grep -qF "[go-vulndb] WARN: 1 Go module(s) skipped: their version is not a semantic version or a Go release (e.g. pkg:golang/example.com/main@(devel))" "$WORK/dir.log" \
    && pass "one WARN line counts the Go modules whose version could not be read" || fail "no WARN line" "$(cat "$WORK/dir.log")"

python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/zip" "$WORK/vulndb.zip" "$FIX/trivy-report.json" > "$WORK/zip.log" 2>&1
[ "$(summary "$WORK/zip_security_govulndb.json" 2>&1)" = "$EXPECTED" ] \
    && pass "vulndb.zip gives the same findings as the unpacked folder" || fail "zip: $(cat "$WORK/zip.log")"

python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/alone" "$FIX/db" > /dev/null 2>&1
jq -e '[.Results[].Vulnerabilities[] | .VulnerabilityID] | (index("CVE-2099-1003") != null) and (index("CVE-2099-1009") != null) and length == 8' "$WORK/alone_security_govulndb.json" >/dev/null \
    && pass "without a report to compare with, the advisory Trivy had is reported here" \
    || fail "no reports: $(summary "$WORK/alone_security_govulndb.json")"

echo "== scan-go-vulndb.py: exit codes and unsafe input =="
jq '.components |= map(select(.purl | startswith("pkg:golang/") | not))' "$FIX/sbom.json" > "$WORK/npm-only.json"
python3 "$LIB/scan-go-vulndb.py" "$WORK/npm-only.json" "$WORK/npm" "$FIX/db" > /dev/null 2>&1
rc=$?
{ [ "$rc" = 11 ] && [ ! -f "$WORK/npm_security_govulndb.json" ]; } \
    && pass "no Go module in the SBOM: exit 11, no sidecar" || fail "exit $rc for an SBOM with no Go module"
jq '.components = [{"type":"library","name":"example.com/main","version":"(devel)","purl":"pkg:golang/example.com/main@(devel)"}]' "$FIX/sbom.json" > "$WORK/devel.json"
python3 "$LIB/scan-go-vulndb.py" "$WORK/devel.json" "$WORK/devel" "$FIX/db" > /dev/null 2>&1
rc=$?
{ [ "$rc" = 0 ] && [ "$(jq -r '.GoVulnDB.Components' "$WORK/devel_security_govulndb.json")" = 0 ]; } \
    && pass "a Go module with no semantic version: the sidecar says no component was matched" || fail "exit $rc for (devel)"
printf 'not a zip' > "$WORK/broken.zip"
python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/broken" "$WORK/broken.zip" > /dev/null 2>&1
rc=$?
{ [ "$rc" = 3 ] && [ ! -f "$WORK/broken_security_govulndb.json" ]; } \
    && pass "an unreadable database: exit 3, no sidecar" || fail "exit $rc for a broken database"
python3 - "$WORK/slip.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("index/db.json", '{"modified":"2026-11-01T00:00:00Z"}')
    z.writestr("../../ID/GO-2099-9999.json", '{"id":"GO-2099-9999","affected":[]}')
    z.writestr("ID/../../escape.json", "{}")
PY
python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/slip" "$WORK/slip.zip" > /dev/null 2>&1
rc=$?
{ [ "$rc" = 3 ] && [ ! -e "$WORK/escape.json" ] && [ ! -e "$ROOT_DIR/../escape.json" ]; } \
    && pass "an archive whose only records have traversal names is read as empty (exit 3) and nothing is written outside" \
    || fail "traversal archive: exit $rc"
mkdir -p "$WORK/linkdb/index" "$WORK/linkdb/ID"
cp "$FIX/db/index/db.json" "$WORK/linkdb/index/"
ln -s "$FIX/db/ID/GO-2099-0001.json" "$WORK/linkdb/ID/GO-2099-0001.json"
python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/link" "$WORK/linkdb" > /dev/null 2>&1
rc=$?
[ "$rc" = 3 ] && pass "a folder record that links outside the folder is refused" || fail "exit $rc for a symbolic link out of the folder"

echo "== scan-go-vulndb.py: version order =="
if python3 - "$LIB/scan-go-vulndb.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("gv", sys.argv[1])
gv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gv)
p, c = gv.parse_semver, gv.compare
cases = [
    ("v20.10.7+incompatible", "20.10.7", 0),
    ("1.2.3-0", "1.2.3-alpha", -1),
    ("1.2.3-alpha.1", "1.2.3-alpha.beta", -1),
    ("1.2.3-rc.2", "1.2.3-rc.10", -1),
    ("1.2.3-rc.1", "1.2.3", -1),
    ("0.0.0-20210101000000-abcdefabcdef", "0.0.0-20220101000000-0123456789ab", -1),
    ("1.2.4-0.20210101000000-abcdefabcdef", "1.2.3", 1),
]
bad = [(a, b, want, c(p(a), p(b))) for a, b, want in cases if c(p(a), p(b)) != want]
assert gv.stdlib_version("go1.21") == "1.21.0", gv.stdlib_version("go1.21")
assert gv.stdlib_version("go1.22rc1") == "1.22.0-rc.1", gv.stdlib_version("go1.22rc1")
assert p("(devel)") is None and p("latest") is None
for given, want in [("go1.21.3 X:boringcrypto", "1.21.3"), ("go1.21.3-bigcorp", "1.21.3"),
                    ("v1.21.3", "1.21.3"), ("1.21.0-rc.2", "1.21.0-rc.2"), ("1.21.3-bigcorp", "1.21.3"),
                    ("(devel)", None)]:
    assert gv.stdlib_version(given) == want, (given, gv.stdlib_version(given))
assert gv.component_key("stdlib", "go1.21.3") == gv.component_key("stdlib", "v1.21.3") == "stdlib@1.21.3"
assert gv.component_key("toolchain", "go1.21.3 X:boringcrypto") == "toolchain@1.21.3"
if bad:
    print(bad)
    sys.exit(1)
PY
then pass "semver order: build metadata ignored, pre-releases and pseudo-versions in order, Go release names with build suffixes dropped, one stdlib key for every version form"
else fail "version order"
fi

echo "== scan-go-vulndb.py: an old database =="
# A fresh export (dated now) to download, and the fixture zip as the stale
# bundled snapshot. file:// URLs stand in for vuln.go.dev.
python3 - "$FIX/db" "$WORK/fresh.zip" <<'PY'
import datetime, os, sys, zipfile
root, out = sys.argv[1], sys.argv[2]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with zipfile.ZipFile(out, "w") as z:
    z.writestr("index/db.json", '{"modified":"%s"}' % now)
    for f in sorted(os.listdir(os.path.join(root, "ID"))):
        z.write(os.path.join(root, "ID", f), "ID/" + f)
PY
python3 - "$WORK/evil.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("index/db.json", '{"modified":"2099-01-01T00:00:00Z"}')
    z.writestr("ID/GO-2099-0001.json", '{"id":"GO-2099-0001","affected":[]}')
    z.writestr("../../escape.json", "{}")
PY
gv_age() {  # gv_age <name> [VAR=value ...]: a run with --bundled and a 7-day limit
    local name="$1"; shift
    : > "$WORK/$name.status"
    env BOMLENS_GO_VULNDB_MAX_AGE_DAYS=7 BOMLENS_GO_VULNDB_STATUS_FILE="$WORK/$name.status" "$@" \
        python3 "$LIB/scan-go-vulndb.py" --bundled "$FIX/sbom.json" "$WORK/$name" "$WORK/vulndb.zip" "$FIX/trivy-report.json" > "$WORK/$name.log" 2>&1
}
gv_meta() { jq -r '"\(.GoVulnDB.Source) \(.GoVulnDB.Degraded // "-")"' "$WORK/$1_security_govulndb.json" 2>/dev/null; }
gv_stat() { jq -r '"\(.status) \(.detail)"' "$WORK/$1.status" 2>/dev/null; }

gv_age fresh BOMLENS_GO_VULNDB_URL="file://$WORK/fresh.zip"
{ [ "$(gv_meta fresh)" = "downloaded -" ] && [ "$(gv_stat fresh)" = "ok " ] \
  && [ -z "$(ls "$WORK/tmp")" ] && [ "$(summary "$WORK/fresh_security_govulndb.json")" = "$EXPECTED" ]; } \
    && pass "a stale bundled snapshot is replaced by a download for the scan, the result is ok, and the download is removed afterwards" \
    || fail "refresh: $(gv_meta fresh) / $(gv_stat fresh) / tmp: $(ls "$WORK/tmp")" "$(cat "$WORK/fresh.log")"

gv_age nodl BOMLENS_GO_VULNDB_URL="file://$WORK/no-such.zip"
{ [ "$(gv_meta nodl | cut -d' ' -f1)" = bundled ] && gv_stat nodl | grep -q '^degraded the Go vulnerability database is [0-9]* days old (over 7); the download of a newer one failed: ' \
  && [ "$(summary "$WORK/nodl_security_govulndb.json")" = "$EXPECTED" ] && [ -z "$(ls "$WORK/tmp")" ]; } \
    && pass "the download fails: the old snapshot is read, and the step is degraded with its age and the cause" \
    || fail "failed download: $(gv_stat nodl)" "$(cat "$WORK/nodl.log")"

gv_age evil BOMLENS_GO_VULNDB_URL="file://$WORK/evil.zip"
{ gv_stat evil | grep -q "the download of a newer one failed: unexpected entries in the export" \
  && [ ! -e "$WORK/escape.json" ] && [ -z "$(ls "$WORK/tmp")" ]; } \
    && pass "a downloaded export with a name outside the export's layout is refused, as at image build" \
    || fail "unsafe download: $(gv_stat evil)"

gv_age offline BOMLENS_GO_VULNDB_URL="file://$WORK/fresh.zip" TRIVY_OFFLINE_SCAN=true
gv_age skipupd BOMLENS_GO_VULNDB_URL="file://$WORK/fresh.zip" TRIVY_SKIP_DB_UPDATE=true
{ gv_stat offline | grep -q "not refreshed, the scan is offline" && [ "$(gv_meta offline | cut -d' ' -f1)" = bundled ] \
  && gv_stat skipupd | grep -q "not refreshed, the scan is offline"; } \
    && pass "an offline scan (TRIVY_OFFLINE_SCAN or TRIVY_SKIP_DB_UPDATE) reads the old snapshot and is degraded" \
    || fail "offline: $(gv_stat offline) / $(gv_stat skipupd)"

: > "$WORK/named.status"
BOMLENS_GO_VULNDB_MAX_AGE_DAYS=7 BOMLENS_GO_VULNDB_STATUS_FILE="$WORK/named.status" BOMLENS_GO_VULNDB_URL="file://$WORK/fresh.zip" \
    python3 "$LIB/scan-go-vulndb.py" "$FIX/sbom.json" "$WORK/named" "$WORK/vulndb.zip" > "$WORK/named.log" 2>&1
{ [ "$(gv_meta named | cut -d' ' -f1)" = named ] && gv_stat named | grep -q "BOMLENS_GO_VULNDB_PATH names, so it is not replaced"; } \
    && pass "a database the caller named is never replaced, only degraded" \
    || fail "named: $(gv_stat named)"

gv_age young BOMLENS_GO_VULNDB_MAX_AGE_DAYS=100000 BOMLENS_GO_VULNDB_URL="file://$WORK/no-such.zip"
[ "$(gv_meta young)" = "bundled -" ] && [ "$(gv_stat young)" = "ok " ] \
    && pass "a snapshot within the limit is read as it is, without a download" || fail "young: $(gv_meta young) / $(gv_stat young)"

# SIGTERM while the download waits: the temporary folder is still removed.
if command -v mkfifo >/dev/null 2>&1; then
    mkfifo "$WORK/stuck.zip"
    env BOMLENS_GO_VULNDB_MAX_AGE_DAYS=7 BOMLENS_GO_VULNDB_URL="file://$WORK/stuck.zip" \
        python3 "$LIB/scan-go-vulndb.py" --bundled "$FIX/sbom.json" "$WORK/stuck" "$WORK/vulndb.zip" > "$WORK/stuck.log" 2>&1 &
    pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -n "$(ls "$WORK/tmp")" ] && break
        sleep 0.2
    done
    seen="$(ls "$WORK/tmp")"
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    rc=$?
    { [ -n "$seen" ] && [ "$rc" = 143 ] && [ -z "$(ls "$WORK/tmp")" ]; } \
        && pass "SIGTERM during the download: exit 143 and the temporary folder is removed" \
        || fail "SIGTERM: started '$seen', exit $rc, left '$(ls "$WORK/tmp")'"
else
    echo "  SKIP: no mkfifo on this host"
fi

echo "== scan-security.sh: the sidecar is merged and the report names the source =="
mkdir -p "$WORK/bin"
cat > "$WORK/bin/trivy" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do case "\$1" in --output) out="\$2"; shift 2 ;; *) shift ;; esac; done
cp "$FIX/trivy-report.json" "\$out"
EOF
chmod +x "$WORK/bin/trivy"
mkdir -p "$WORK/sec"
cp "$FIX/sbom.json" "$WORK/sec/demo_1.0_bom.json"
( cd "$WORK/sec" && PATH="$WORK/bin:$PATH" SECURITY_ENRICH=false DEEP_CVE=false BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" \
    bash "$LIB/scan-security.sh" demo_1.0_bom.json "$WORK/sec/demo_1.0" demo ) > "$WORK/sec.log" 2>&1
S="$WORK/sec/demo_1.0_security.json"
jq -e '[.Results[].Vulnerabilities[]] | length == 10' "$S" >/dev/null 2>&1 \
    && jq -e '[.Results[].Vulnerabilities[] | select(.VulnerabilityID == "CVE-2099-1003")] | length == 1' "$S" >/dev/null 2>&1 \
    && [ -f "$WORK/sec/demo_1.0_security_trivy.json" ] \
    && pass "_security.json holds Trivy's four findings and the six new ones, CVE-2099-1003 once, and Trivy's own result is kept apart" \
    || fail "merged report: $(jq -c '[.Results[].Vulnerabilities[] | [.PkgName, .VulnerabilityID]]' "$S" 2>&1)" "$(tail -5 "$WORK/sec.log")"
grep -qF -- "- Engine: Trivy (SBOM scan), Go vulnerability database (snapshot 2026-11-01)" "$WORK/sec/demo_1.0_security.md" \
    && grep -qF "Engine: Trivy, Go vulnerability database (snapshot 2026-11-01)</span></p>" "$WORK/sec/demo_1.0_security.html" \
    && pass "the Markdown and HTML reports name the Go vulnerability database and its date" \
    || fail "report header: $(grep -F 'Engine:' "$WORK/sec/demo_1.0_security.md")"

mkdir -p "$WORK/sec-off"
cp "$FIX/sbom.json" "$WORK/sec-off/demo_1.0_bom.json"
: > "$WORK/sec-off/demo_1.0_security_govulndb.json"
( cd "$WORK/sec-off" && PATH="$WORK/bin:$PATH" SECURITY_ENRICH=false DEEP_CVE=false BOMLENS_GO_VULNDB=false BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" \
    bash "$LIB/scan-security.sh" demo_1.0_bom.json "$WORK/sec-off/demo_1.0" demo ) > "$WORK/sec-off.log" 2>&1
{ [ ! -e "$WORK/sec-off/demo_1.0_security_govulndb.json" ] \
  && jq -e '[.Results[].Vulnerabilities[]] | length == 4' "$WORK/sec-off/demo_1.0_security.json" >/dev/null 2>&1 \
  && ! grep -qF "Go vulnerability database" "$WORK/sec-off/demo_1.0_security.md"; } \
    && pass "BOMLENS_GO_VULNDB=false: no match, an earlier sidecar is removed, the report is Trivy's alone" \
    || fail "disabled: $(ls "$WORK/sec-off")"

echo "== entrypoint.sh: the go-vulndb step in bomlens-result.json =="
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "  SKIP: entrypoint.sh needs bash 4 or later (this is $BASH_VERSION)"
else
    cat > "$WORK/bin/trivy" <<EOF
#!/bin/bash
if [ "\${1:-}" = "version" ]; then
    echo '{"Version":"0.0.0-stub","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-01-01T00:00:00Z","DownloadedAt":"2026-01-01T01:00:00Z"}}'
    exit 0
fi
out=""
while [ \$# -gt 0 ]; do case "\$1" in --output) out="\$2"; shift 2 ;; *) shift ;; esac; done
cp "$FIX/trivy-report.json" "\$out"
EOF
    chmod +x "$WORK/bin/trivy"
    run_engine() {
        local dir="$1" sbom="$2"; shift 2
        mkdir -p "$dir"
        cp "$sbom" "$dir/demo_1.0_bom.json"
        ( cd "$dir" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=demo PROJECT_VERSION=1.0 \
            HOST_OUTPUT_DIR="$dir" BOMLENS_LIBDIR="$LIB" BOMLENS_RUN_INPUT=demo_1.0_bom.json \
            UPLOAD_ENABLED=false GENERATE_SECURITY=true DEEP_CVE=false SECURITY_ENRICH=false \
            ENRICH_EOL=false ENRICH_MALICIOUS=false "$@" bash "$ROOT_DIR/docker/entrypoint.sh" ) > "$dir.log" 2>&1
    }
    gv_step() { jq -r '[.steps[] | select(.id == "go-vulndb")][0] | "\(.status) \(.reason)"' "$1/bomlens-result.json" 2>/dev/null; }

    D="$WORK/e-ok"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" BOMLENS_GO_VULNDB_MAX_AGE_DAYS=100000
    { [ "$(gv_step "$D")" = "ok null" ] \
      && jq -e '([.steps[] | select(.id == "go-vulndb")][0].counts == {components: 11, findings: 6, already_reported: 2})
                and (.engines | index("go-vulndb") != null)
                and .data_sources.go_vulndb.updated_at == "2026-11-01T00:00:00Z"
                and ([.outputs[] | select(.path == "demo_1.0_security_govulndb.json")][0].role == "vulnerabilities.other")' \
            "$D/bomlens-result.json" >/dev/null; } \
        && pass "ok, with counts, go-vulndb among the engines, the database date and the sidecar's role" \
        || fail "go-vulndb is $(gv_step "$D"): $(jq -c '{engines, data_sources, s: [.steps[] | select(.id == "go-vulndb")]}' "$D/bomlens-result.json" 2>&1)" "$(grep -i 'go-vulndb\|go vulnerability' "$D.log" | head -3)"

    D="$WORK/e-old"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" BOMLENS_GO_VULNDB_MAX_AGE_DAYS=0
    [ "$(gv_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "degraded unavailable succeeded_degraded" ] \
        && pass "a database older than BOMLENS_GO_VULNDB_MAX_AGE_DAYS: degraded, unavailable" \
        || fail "go-vulndb is $(gv_step "$D")"

    D="$WORK/e-off"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" BOMLENS_GO_VULNDB=false
    { [ "$(gv_step "$D")" = "disabled null" ] && [ ! -f "$D/demo_1.0_security_govulndb.json" ] \
      && jq -e '(.engines | index("go-vulndb") | not) and .data_sources.go_vulndb == null' "$D/bomlens-result.json" >/dev/null; } \
        && pass "BOMLENS_GO_VULNDB=false: disabled" || fail "go-vulndb is $(gv_step "$D")"

    D="$WORK/e-missing"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/no-such.zip"
    [ "$(gv_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped not_installed succeeded_degraded" ] \
        && grep -qF "BOMLENS_GO_VULNDB_PATH ($WORK/no-such.zip) does not exist" "$D.log" \
        && pass "a database path that does not exist: skipped, not_installed, with the path named" \
        || fail "go-vulndb is $(gv_step "$D")" "$(grep -F 'Go vulnerability' "$D.log" | head -2)"

    D="$WORK/e-broken"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/broken.zip"
    [ "$(gv_step "$D")" = "failed failed" ] \
        && pass "an unreadable database: failed" || fail "go-vulndb is $(gv_step "$D")"

    D="$WORK/e-npm"; run_engine "$D" "$WORK/npm-only.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip"
    [ "$(gv_step "$D") $(jq -r .run.status "$D/bomlens-result.json")" = "skipped no_input succeeded" ] \
        && pass "no Go module in the SBOM: skipped, no_input, and the run is not degraded" \
        || fail "go-vulndb is $(gv_step "$D"), run.status $(jq -r .run.status "$D/bomlens-result.json")"

    D="$WORK/e-nosec"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" GENERATE_SECURITY=false
    [ "$(gv_step "$D")" = "disabled null" ] && pass "without --security: disabled" || fail "go-vulndb is $(gv_step "$D")"

    D="$WORK/e-devel"; run_engine "$D" "$WORK/devel.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip"
    { [ "$(gv_step "$D")" = "skipped no_input" ] \
      && jq -e '(.engines | index("go-vulndb") | not) and .data_sources.go_vulndb == null' "$D/bomlens-result.json" >/dev/null; } \
        && pass "Go modules with no version it can read: skipped, and go-vulndb is not among the engines" \
        || fail "go-vulndb is $(gv_step "$D"): $(jq -c '{engines, data_sources}' "$D/bomlens-result.json")"

    # No trivy on PATH: scan-security.sh stops before the Go match.
    NOTRIVY_PATH=""
    _old_ifs="$IFS"; IFS=:
    for _d in $PATH; do
        if [ -x "$_d/trivy" ]; then
            _nd="$WORK/notrivy$(printf '%s' "$_d" | tr '/' '_')"; mkdir -p "$_nd"
            for _f in "$_d"/*; do [ "${_f##*/}" = trivy ] || ln -sf "$_f" "$_nd/"; done
            _d="$_nd"
        fi
        NOTRIVY_PATH="$NOTRIVY_PATH:$_d"
    done
    IFS="$_old_ifs"; NOTRIVY_PATH="${NOTRIVY_PATH#:}"
    D="$WORK/e-notrivy"; run_engine "$D" "$FIX/sbom.json" BOMLENS_GO_VULNDB_PATH="$WORK/vulndb.zip" PATH="$NOTRIVY_PATH"
    [ "$(jq -r '[.steps[] | select(.id == "go-vulndb")][0] | "\(.status) \(.reason) \(.detail)"' "$D/bomlens-result.json" 2>/dev/null)" \
        = "skipped no_input the security scan did not run: trivy is not in this image" ] \
        && pass "without trivy the Go match is not reached: skipped, no_input, and the detail says why" \
        || fail "go-vulndb is $(jq -c '[.steps[] | select(.id == "go-vulndb")][0]' "$D/bomlens-result.json" 2>&1)"

    jq -r '[.steps[] | select(.id == "go-vulndb")][0].detail' "$WORK/e-old/bomlens-result.json" 2>/dev/null \
        | grep -q "days old (over 0); it is the one BOMLENS_GO_VULNDB_PATH names, so it is not replaced" \
        && pass "the degraded detail gives the age and the cause" \
        || fail "e-old detail: $(jq -r '[.steps[] | select(.id == "go-vulndb")][0].detail' "$WORK/e-old/bomlens-result.json")"

    JSPY=""
    for py in python3 python3.13 python3.12 python3.11; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c "import jsonschema" 2>/dev/null; then JSPY="$py"; break; fi
    done
    if [ -n "$JSPY" ]; then
        errs="$("$JSPY" - "$ROOT_DIR/schemas/engine-result-1.json" "$WORK/e-ok/bomlens-result.json" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in v.iter_errors(doc)))
PY
)"
        [ -z "$errs" ] && pass "the manifest with go-vulndb validates against schemas/engine-result-1.json" || fail "schema" "$errs"
    else
        echo "  SKIP: the jsonschema package is not installed"
    fi
fi

echo ""
echo "go-vulndb: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
