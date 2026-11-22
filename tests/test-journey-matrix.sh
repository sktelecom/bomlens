#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-journey-matrix.sh: a fixed-input matrix. Every input is judged only by
# the report files it leaves behind, with two rules:
#
#   1. An incomplete result (grade partial or unreliable) never carries the
#      sentence "No known vulnerabilities found" in a report that reads
#      vulnerabilities, and a complete one still does.
#   2. The completeness grade and its reasons are the same in every report:
#      the sidecar, the security, NOTICE, risk and conformance reports, the
#      summary file and what the web server reads.
#
# Tier 1 (default, no Docker): fixed CycloneDX documents go to
#   docker/lib/assess-completeness.sh and the report generators directly, with
#   Trivy stubbed. It also proves the check can fail: the same matrix is run
#   against a copy of docker/lib whose completeness marking is switched off, and
#   must be rejected.
# Tier 2 (BOMLENS_MATRIX_DOCKER=1, nightly): the CLI scans small synthetic
#   projects and one received empty SBOM in the scanner image, and the same
#   rules are applied to the reports of each run.
#
# Usage: tests/test-journey-matrix.sh
# Env:
#   BOMLENS_MATRIX_DOCKER=1  also run tier 2
#   SBOM_SCANNER_IMAGE       scanner image for tier 2 (default: sbom-scanner:test)
#   BOMLENS_MATRIX_LIB       docker/lib directory to judge in tier 1 (default:
#                            this checkout's). Pointing it at a copy with the
#                            marking switched off must make this test fail.
#   VERBOSE=true             print every judgment that failed
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_REAL="$ROOT_DIR/docker/lib"
LIB="${BOMLENS_MATRIX_LIB:-$LIB_REAL}"
FIX="$ROOT_DIR/tests/fixtures/journey"
VERBOSE="${VERBOSE:-false}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

for t in jq python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t is not installed"; exit 0; }
done

# --- judgment -------------------------------------------------------------
# Every broken rule is one line in $JLOG; a run is good when the log is empty.
JLOG="$WORK/judgments.log"
broke() { echo "$1: $2" >> "$JLOG"; }
has() { grep -qF -- "$2" "$1" 2>/dev/null; }

# judge <id> <dir> <want grade, or any> [reason code that must be listed]: the
# reports are <dir>/<id>_*.
judge() {
    local id="$1" p="$2/$1" want="$3" want_code="${4:-}" f grade label title msg
    if [ ! -f "${p}_completeness.json" ]; then
        broke "$id" "no completeness file was written"
        return 0
    fi
    grade="$(jq -r .grade "${p}_completeness.json")"
    label="$(jq -r .gradeLabel.en "${p}_completeness.json")"
    if [ "$want" != any ] && [ "$grade" != "$want" ]; then
        broke "$id" "grade is $grade, expected $want"
    fi
    if [ -n "$want_code" ] && ! jq -e --arg c "$want_code" 'any(.reasons[]; .code == $c)' "${p}_completeness.json" >/dev/null 2>&1; then
        broke "$id" "the reasons do not include $want_code"
    fi
    title="$(jq -r .labels.title.en "$LIB_REAL/completeness-reasons.json")"
    if [ "$grade" = complete ]; then
        # The clean sentence is for a result with no finding; a complete scan of
        # a project with known vulnerabilities lists them instead.
        if [ "$(jq '[.Results[]?.Vulnerabilities[]?] | length' "${p}_security.json" 2>/dev/null || echo 0)" = 0 ]; then
            has "${p}_security.md" "No known vulnerabilities found" \
                || broke "$id" "a complete result lost the clean sentence in the security report"
        fi
        for f in security.md security.html NOTICE.txt NOTICE.html risk-report.md risk-report.html; do
            has "${p}_$f" "$title" && broke "$id" "$f carries an incompleteness notice on a complete result"
        done
        has "${p}_summary.result" "completeness" \
            && broke "$id" "the summary file names a grade for a complete result"
        return 0
    fi
    for f in security.md security.html risk-report.md risk-report.html; do
        has "${p}_$f" "No known vulnerabilities" \
            && broke "$id" "$f says no known vulnerabilities on a $grade result"
    done
    for f in security.md security.html NOTICE.txt NOTICE.html risk-report.md risk-report.html; do
        if [ ! -f "${p}_$f" ]; then broke "$id" "$f was not written"; continue; fi
        has "${p}_$f" "$title: $label" || broke "$id" "$f does not say $label"
        while IFS= read -r msg; do
            case "$f" in *.html) msg="$(printf '%s' "$msg" | jq -Rr '@html')" ;; esac
            has "${p}_$f" "$msg" || broke "$id" "$f lacks a reason sentence: ${msg:0:50}"
        done < <(jq -r '.reasons[].message.en | gsub("[\r\n]+"; " ")' "${p}_completeness.json")
    done
    for f in conformance.md conformance.html; do
        has "${p}_$f" "$label: $(jq -r '[.reasons[].code] | join(", ")' "${p}_completeness.json")" \
            || broke "$id" "$f does not say $label with the same reasons"
    done
    jq -e --arg l "$label" '.checks[] | select(.id == "result-completeness") | .detail | startswith($l)' \
        "${p}_conformance.json" >/dev/null 2>&1 || broke "$id" "conformance.json has no matching completeness row"
    [ "$(awk -F'\t' '$1 == "completeness" {print $2}' "${p}_summary.result" 2>/dev/null)" = "$grade" ] \
        || broke "$id" "the summary file does not carry grade $grade"
    [ "$(awk -F'\t' '$1 == "completenessReasons" {print $2}' "${p}_summary.result" 2>/dev/null)" \
        = "$(jq -r '[.reasons[].code] | join(",")' "${p}_completeness.json")" ] \
        || broke "$id" "the summary file does not carry the same reasons"
    return 0
}

# What the web server reads must be the same file: grade, label and reasons.
# <out> holds <id>/<id>_completeness.json for each id, as the server's output
# folder does.
judge_web() { # <out> <id>...
    local out="$1" line; shift
    while IFS= read -r line; do
        [ -n "$line" ] && broke "web" "$line"
    done < <(SBOM_OUTPUT_DIR="$out" python3 -I - "$ROOT_DIR" "$out" "$@" 2>&1 <<'PY'
import sys, os, json
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
out = sys.argv[2]
for rid in sys.argv[3:]:
    side = json.load(open(os.path.join(out, rid, rid + "_completeness.json")))
    c = server.completeness_summary(rid)
    if not c or c["grade"] != side["grade"] or c["gradeLabel"]["en"] != side["gradeLabel"]["en"] \
            or [r["code"] for r in c["reasons"]] != [r["code"] for r in side["reasons"]]:
        print(rid + ": the server reads a different completeness than the file")
PY
)
}

# --- tier 1 ----------------------------------------------------------------
FAKEBIN="$WORK/fakebin"; mkdir -p "$FAKEBIN"
# MATRIX_TRIVY_FAIL=1: Trivy stops on its database download, as it does when
# the network cannot resolve the registry.
cat > "$FAKEBIN/trivy" <<'SH'
#!/bin/sh
if [ "${MATRIX_TRIVY_FAIL:-}" = 1 ]; then
    echo "2026-11-21T00:00:00Z	FATAL	Fatal error	init error: DB error: failed to download vulnerability DB: dial tcp: lookup ghcr.io: no such host" >&2
    exit 1
fi
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "--output" ] && { out="$2"; shift; }
    shift
done
echo '{"SchemaVersion":2,"Results":[]}' > "$out"
SH
chmod +x "$FAKEBIN/trivy"

JAVA="$FIX/java-license-exceptions/sbom-exceptions.cdx.json"
EMPTY='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"p","version":"1"}},"components":[]}'
with_props() { jq -c --argjson p "$1" '.metadata.properties = $p' "$JAVA"; }       # resolved, with properties
empty_props() { printf '%s' "$EMPTY" | jq -c --argjson p "$1" '.metadata.properties = $p'; } # no component

# Writes <dir>/<id>/<id>_bom.json for every input and prints "<id> <grade>".
matrix_inputs() {
    local d="$1"
    add() { mkdir -p "$d/$1"; cat > "$d/$1/$1_bom.json"; echo "$1 $2 ${3:-}"; }
    add resolved-java complete < "$JAVA"
    printf '%s' "$EMPTY" | add nothing-declared partial
    empty_props '[{"name":"bomlens:sbom-supplied","value":"true"}]' | add supplier-empty unreliable
    empty_props '[{"name":"bomlens:sbom-empty-with-manifests","value":"pom.xml"}]' | add manifests-unresolved unreliable
    empty_props '[{"name":"bomlens:sbom-empty-all-excluded","value":"pyproject.toml, uv.lock"}]' | add all-excluded partial
    # A package.json with only devDependencies and no lock file: the exclusion
    # is the reason (not no-components), and the grade stays partial.
    empty_props '[{"name":"bomlens:sbom-empty-all-excluded","value":"package.json devDependencies: eslint, jest"},{"name":"bomlens:lockfile-missing","value":"package.json: no package-lock.json"}]' | add node-dev-only partial only-excluded-dependencies
    empty_props '[{"name":"bomlens:sbom-empty-with-manifests","value":"vcpkg.json"}]' | add native-manifest unreliable
    with_props '[{"name":"bomlens:lockfile-missing","value":"package-lock.json"}]' | add lockfile-missing partial
    with_props '[{"name":"bomlens:lockfile-missing","value":"go.mod: no go.sum; Cargo.toml: no Cargo.lock"}]' | add lockfile-missing-go-cargo partial
    with_props '[{"name":"bomlens:lockfile-corrupt","value":"Gemfile.lock"}]' | add lockfile-corrupt partial
    with_props '[{"name":"bomlens:manifest-not-read","value":"vcpkg.json: curl, fmt"}]' | add native-manifest-not-read partial
    with_props '[{"name":"bomlens:sbom-tool-degraded","value":"cdxgen"}]' | add tool-degraded partial
    with_props '[{"name":"bomlens:pipeline-step-failed","value":"gradle-dependencies"}]' | add step-failed partial
    # A failed step with the cause the build tool reported and a hint.
    with_props '[{"name":"bomlens:pipeline-step-failed","value":"maven-dependency-tree"},{"name":"bomlens:pipeline-step-cause","value":"maven-dependency-tree: Non-resolvable parent POM example.mm:parent:1.0.0 (../pom.xml is outside the scanned folder)"},{"name":"bomlens:resolution-hint","value":"maven-parent-outside-scan"}]' | add step-cause-hint partial
    # A resolved project whose vulnerability check failed (Trivy could not
    # download its database), and one more failed check on a result that was
    # already partial: both reasons are stated.
    add security-failed partial vulnerability-check-failed < "$JAVA"
    with_props '[{"name":"bomlens:lockfile-missing","value":"package-lock.json"}]' | add security-failed-lockfile partial vulnerability-check-failed
    empty_props '[{"name":"bomlens:sbom-empty-with-manifests","value":"app/build.gradle"},{"name":"bomlens:pipeline-step-failed","value":"android-release-classpath"},{"name":"bomlens:pipeline-step-cause","value":"android-release-classpath: Execution failed for task '"'"':app:dependencies'"'"'. Configuration `:app:debugRuntimeClasspath` contains AndroidX dependencies, but the `android.useAndroidX` property is not enabled, which may cause runtime issues."},{"name":"bomlens:resolution-hint","value":"android-useandroidx-missing"},{"name":"bomlens:resolution-hint","value":"android-release-classpath-unresolved"}]' | add android-unresolved unreliable
}

# The entrypoint's order: the conformance check, the security scan and the stamp
# of a check that gave no result (mark_vulnerability_check), NOTICE, the
# conformance check again with what came after it (refresh_conformance), the
# risk report.
run_reports() { # <dir> <id>
    local d="$1/$2" n="$2" trivy_fail=""
    case "$n" in security-failed*) trivy_fail=1 ;; esac
    ( cd "$d" || exit 1
      export PATH="$FAKEBIN:$PATH" SECURITY_ENRICH=false DEEP_CVE=false MATRIX_TRIVY_FAIL="$trivy_fail"
      bash "$LIB/assess-completeness.sh" "${n}_bom.json" "$n" >/dev/null 2>&1
      bash "$LIB/validate-sbom.sh" "${n}_bom.json" "$n" proj >/dev/null 2>&1
      bash "$LIB/scan-security.sh" "${n}_bom.json" "$n" proj >/dev/null 2>&1
      # shellcheck disable=SC1091
      ( . "$LIB/pipeline-step.sh" && mark_vulnerability_check "${n}_bom.json" "$n" "" ok ) >/dev/null 2>&1
      bash "$LIB/generate-notice.sh" "${n}_bom.json" "$n" proj >/dev/null 2>&1
      bash "$LIB/validate-sbom.sh" "${n}_bom.json" "$n" proj >/dev/null 2>&1
      bash "$LIB/generate-risk-report.sh" "$n" proj >/dev/null 2>&1 ) || true
}

run_tier1() { # <dir>: the broken rules are left in $JLOG
    local d="$1" id g code ids=""
    mkdir -p "$d"
    : > "$JLOG"
    while read -r id g code; do
        run_reports "$d" "$id"
        judge "$id" "$d/$id" "$g" "$code"
        ids="$ids $id"
    done < <(matrix_inputs "$d")
    # shellcheck disable=SC2086
    judge_web "$d" $ids
}

echo "== tier 1: fixed SBOMs through the report generators (no Docker) =="
run_tier1 "$WORK/t1"
if [ ! -s "$JLOG" ]; then
    pass "every input: grade, reasons and the no-vulnerabilities sentence agree across the reports"
else
    fail "the matrix found disagreements" "$(if [ "$VERBOSE" = true ]; then cat "$JLOG"; else head -5 "$JLOG"; fi)"
fi

echo "== tier 1: the check fails when completeness marking is switched off =="
# A copy of docker/lib whose assessment writes nothing: the reports then have no
# verdict to print. The same matrix must reject it.
STRIP="$WORK/stripped-lib"
cp -R "$LIB_REAL" "$STRIP"
printf '#!/bin/bash\nexit 0\n' > "$STRIP/assess-completeness.sh"
saved_lib="$LIB"; LIB="$STRIP"
run_tier1 "$WORK/t1-stripped"
LIB="$saved_lib"
broken_n="$(wc -l < "$JLOG" | tr -d ' ')"
if [ "$broken_n" -gt 0 ]; then
    pass "a lib without completeness marking is rejected ($broken_n broken rules)"
else
    fail "a lib without completeness marking passed the matrix"
fi

# --- tier 2 ----------------------------------------------------------------
if [ "${BOMLENS_MATRIX_DOCKER:-}" = "1" ]; then
    echo "== tier 2: CLI scans of small synthetic projects (Docker) =="
    IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        fail "tier 2 needs a running Docker daemon"
    elif ! docker image inspect "$IMG" >/dev/null 2>&1 && ! docker pull "$IMG" >/dev/null 2>&1; then
        fail "tier 2 needs the scanner image" "$IMG is neither present nor pullable"
    else
        # Under the repo, not /var/folders: Docker Desktop shares the former.
        T2="$ROOT_DIR/tests/test-workspace/journey-matrix"
        rm -rf "$T2"; mkdir -p "$T2/in" "$T2/out"
        : > "$JLOG"
        ids=""
        # <name> <fixture dir, or "-" for a folder with no manifest> <grade, or any>
        while read -r name src want; do
            [ -z "$name" ] && continue
            mkdir -p "$T2/in/$name"
            if [ "$src" = "-" ]; then
                echo "notes" > "$T2/in/$name/README.txt"
            else
                cp -R "$FIX/$src/." "$T2/in/$name/"
            fi
            ( cd "$T2/out" && SBOM_SCANNER_IMAGE="$IMG" bash "$ROOT_DIR/scripts/scan-sbom.sh" \
                --project "$name" --version 1 --target "$T2/in/$name" --all --generate-only ) \
                > "$T2/$name.log" 2>&1 || true
            # An Android tree stops before any report when its SDK image is not
            # on this machine (the image is built where it is used).
            if grep -q 'ANDROID_SDK_IMAGE_MISSING' "$T2/$name.log"; then
                echo "  SKIP: $name (the Android SDK image is not on this machine)"
                continue
            fi
            judge "${name}_1" "$T2/out/${name}_1" "$want"
            ids="$ids ${name}_1"
        done <<'CASES'
all-excluded python-uv-lock partial
git-dependency npm-git-dep any
optional-gem ruby-optional-group any
go-module go-mod any
go-no-sum go-mod-no-sum partial
rust-no-lock rust-no-lock partial
old-wrapper android-old-wrapper any
both-tools java-both-tools any
CASES
        # A received SBOM with no component, scanned with --analyze.
        mkdir -p "$T2/in/supplier-empty"
        printf '%s' "$EMPTY" > "$T2/in/supplier-empty/sbom.json"
        ( cd "$T2/out" && SBOM_SCANNER_IMAGE="$IMG" bash "$ROOT_DIR/scripts/scan-sbom.sh" \
            --project supplier-empty --version 1 --analyze "$T2/in/supplier-empty/sbom.json" --all --generate-only ) \
            > "$T2/supplier-empty.log" 2>&1 || true
        judge "supplier-empty_1" "$T2/out/supplier-empty_1" unreliable
        ids="$ids supplier-empty_1"
        # shellcheck disable=SC2086
        judge_web "$T2/out" $ids
        if [ ! -s "$JLOG" ]; then
            pass "every scanned input: grade, reasons and the no-vulnerabilities sentence agree across the reports"
        else
            fail "the scanned matrix found disagreements" "$(cat "$JLOG")"
        fi
        rm -rf "$T2"
    fi
fi

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
