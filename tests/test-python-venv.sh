#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-python-venv.sh: No-Docker checks for reading a project's installed Python
# environment (docker/lib/read-python-venv.py and the build-prep.sh section that
# uses it) when the package index cannot be used.
#
# The environments are hand-written *.dist-info folders (no pip, no network):
#   - scope: only what the declared dependencies reach is kept, a test tool
#     installed beside them drops out, and the graph follows Requires-Dist;
#   - markers: Python version and platform from pyvenv.cfg and WHEEL tags,
#     extras, and a marker that cannot be settled is kept and counted;
#   - names are written as PEP 503 names and purls;
#   - the Windows layout (Lib/site-packages);
#   - no environment, an empty one, nothing declared, nothing installed;
#   - pyproject.toml, Poetry groups and BOMLENS_INCLUDE_DEV_DEPENDENCIES;
#   - the merge into cdxgen's SBOM and the bomlens:python-environment* properties;
#   - the build-prep.sh gate: an index that answers leaves today's path, one
#     that does not (or a failed pip install) reads the environment, and
#     BOMLENS_PYTHON_VENV=false turns it off;
#   - the licence evidence pass reads the environment's metadata;
#   - the completeness grade of a result with unsettled parts.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
READER="$LIB/read-python-venv.py"
PREP="$LIB/build-prep.sh"
WORK="$(mktemp -d)"
SRV_PID=""
trap '[ -z "$SRV_PID" ] || kill "$SRV_PID" 2>/dev/null; rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed"; exit 0; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is not installed"; exit 0; }

# dist <site-packages> <Name> <Version> [Requires-Dist ...]
dist() {
    local site="$1" name="$2" version="$3" d
    shift 3
    d="$site/$name-$version.dist-info"
    mkdir -p "$d"
    {
        echo "Metadata-Version: 2.1"
        echo "Name: $name"
        echo "Version: $version"
        for r in "$@"; do echo "Requires-Dist: $r"; done
        echo ""
        echo "Long description: Requires-Dist: not-a-header"
    } > "$d/METADATA"
}
wheel_tag() {  # <site-packages> <Name> <Version> <tag>
    printf 'Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: %s\n' "$4" > "$1/$2-$3.dist-info/WHEEL"
}

# A Linux venv: requests[socks] and flask declared; pytest installed beside.
make_linux() {  # <dir>
    local p="$1" s
    s="$p/.venv/lib/python3.12/site-packages"
    mkdir -p "$s"
    printf 'home = /usr/local/bin\ninclude-system-site-packages = false\nversion = 3.12.4\n' > "$p/.venv/pyvenv.cfg"
    dist "$s" Requests 2.31.0 'charset_normalizer<4,>=2' 'idna<4,>=2.5' 'PySocks!=1.5.7,>=1.5.6; extra == "socks"' \
        'win-inet-pton; sys_platform == "win32"'
    dist "$s" charset_normalizer 3.3.2
    dist "$s" idna 3.6
    dist "$s" PySocks 1.7.1
    dist "$s" win_inet_pton 1.1.0
    dist "$s" Flask 3.0.0 'Werkzeug>=3.0.0' 'importlib-metadata>=3.6; python_version < "3.10"' \
        'asgiref>=3.2; extra == "async"' 'zipp; platform_release >= "5"'
    dist "$s" werkzeug 3.0.1 'MarkupSafe>=2.1.1'
    dist "$s" MarkupSafe 2.1.5
    wheel_tag "$s" MarkupSafe 2.1.5 cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64
    dist "$s" asgiref 3.7.2
    dist "$s" importlib_metadata 7.0.0
    dist "$s" zipp 3.17.0
    dist "$s" pytest 8.0.0 iniconfig 'tomli>=1; python_version < "3.11"'
    dist "$s" iniconfig 2.0.0
    dist "$s" tomli 2.0.1
    dist "$s" pip 24.0
    printf 'requests[socks]==2.31.0\nFlask  # the web framework\n--index-url https://user:secret@index.example.com/simple\n' > "$p/requirements.txt"
}

read_env() {  # <dir> <venv> [VAR=value ...]: runs `read`, output in <dir>.json, status in <dir>.out
    local d="$1" v="$2"
    shift 2
    env "$@" python3 "$READER" read "$d" "$v" "$d.json" > "$d.out" 2> "$d.err"
    echo $?
}
purls() { jq -r '[.components[].purl] | join(" ")' "$1"; }
deps_of() { jq -r --arg r "$2" '[.dependencies[] | select(.ref == $r) | .dependsOn[]] | join(" ")' "$1"; }

echo "== find =="
L="$WORK/linux"; make_linux "$L"
check "find names the folder and its site-packages" "$(python3 "$READER" find "$L" | sed "s|$L/||" | tr '\n' ' ')" \
    ".venv .venv/lib/python3.12/site-packages "
mkdir -p "$WORK/none"; : > "$WORK/none/requirements.txt"
python3 "$READER" find "$WORK/none" >/dev/null; check "no environment: find exits 1" "$?" "1"
mkdir -p "$WORK/empty/.venv/lib/python3.12/site-packages"; printf 'version = 3.12.1\n' > "$WORK/empty/.venv/pyvenv.cfg"
python3 "$READER" find "$WORK/empty" >/dev/null; check "an environment with no package metadata is not used" "$?" "1"
mkdir -p "$WORK/nocfg/.venv/lib/python3.12/site-packages"; dist "$WORK/nocfg/.venv/lib/python3.12/site-packages" idna 3.6
python3 "$READER" find "$WORK/nocfg" >/dev/null; check "a folder without pyvenv.cfg is not an environment" "$?" "1"
mkdir -p "$WORK/other/env1/lib/python3.11/site-packages"; printf 'version = 3.11.2\n' > "$WORK/other/env1/pyvenv.cfg"
dist "$WORK/other/env1/lib/python3.11/site-packages" idna 3.6
check "one other top-level folder with pyvenv.cfg is found" "$(python3 "$READER" find "$WORK/other" | head -n 1)" "env1"
mkdir -p "$WORK/outside/elsewhere/lib/python3.12/site-packages" "$WORK/outside/proj"
printf 'version = 3.12.1\n' > "$WORK/outside/elsewhere/pyvenv.cfg"; dist "$WORK/outside/elsewhere/lib/python3.12/site-packages" idna 3.6
ln -s "$WORK/outside/elsewhere" "$WORK/outside/proj/.venv"
python3 "$READER" find "$WORK/outside/proj" >/dev/null; check "an environment linked from outside the tree is not followed" "$?" "1"

echo "== scope, markers, names =="
check "read exits 0" "$(read_env "$L" .venv)" "0"
check "kept: what requests[socks] and flask reach, nothing else" "$(purls "$L.json")" \
    "pkg:pypi/charset-normalizer@3.3.2 pkg:pypi/flask@3.0.0 pkg:pypi/idna@3.6 pkg:pypi/markupsafe@2.1.5 pkg:pypi/pysocks@1.7.1 pkg:pypi/requests@2.31.0 pkg:pypi/werkzeug@3.0.1 pkg:pypi/zipp@3.17.0"
check "the status line: kept, installed, unsure" "$(cut -f1,2,4 "$L.out")" "$(printf '8\t15\t1 dependency marker(s) could not be evaluated')"
check "the root links the declared dependencies" "$(deps_of "$L.json" bomlens-python-environment-root)" "pkg:pypi/flask@3.0.0 pkg:pypi/requests@2.31.0"
check "requests depends on its requirements and the socks extra" "$(deps_of "$L.json" pkg:pypi/requests@2.31.0)" \
    "pkg:pypi/charset-normalizer@3.3.2 pkg:pypi/idna@3.6 pkg:pypi/pysocks@1.7.1"
check "a transitive link (werkzeug to markupsafe)" "$(deps_of "$L.json" pkg:pypi/werkzeug@3.0.1)" "pkg:pypi/markupsafe@2.1.5"
check "the unsure detail is recorded" "$(jq -r '.metadata.properties[] | select(.name == "bomlens:python-environment-unsure") | .value' "$L.json")" \
    "1 dependency marker(s) could not be evaluated"
check "the METADATA file is the component's location" "$(jq -r '.components[] | select(.name == "idna") | .properties[] | select(.name == "SrcFile") | .value' "$L.json")" \
    ".venv/lib/python3.12/site-packages/idna-3.6.dist-info/METADATA"
check "names are PEP 503 names" "$(jq -r '[.components[].name] | join(" ")' "$L.json")" \
    "charset-normalizer flask idna markupsafe pysocks requests werkzeug zipp"
check "the long description is not read as headers" "$(grep -c not-a-header "$L.json")" "0"

L2="$WORK/noextra"; make_linux "$L2"; printf 'requests\nflask\n' > "$L2/requirements.txt"
read_env "$L2" .venv >/dev/null
case " $(purls "$L2.json") " in *pysocks*) fail "without the extra, PySocks is left out" ;; *) pass "without the extra, PySocks is left out" ;; esac

echo "== the marker evaluator =="
mk_eval() {  # <marker> <json env>: prints True, False or None
    python3 - "$READER" "$1" "$2" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("rv", sys.argv[1])
rv = importlib.util.module_from_spec(spec); spec.loader.exec_module(rv)
print(rv.eval_marker(sys.argv[2], json.loads(sys.argv[3])))
PY
}
E='{"python_version":"3.12","python_full_version":"3.12.4","sys_platform":"linux","extra":""}'
check "python_version < 3.10 is false on 3.12" "$(mk_eval 'python_version < "3.10"' "$E")" "False"
check "an unknown variable is unknown" "$(mk_eval 'platform_machine == "x86_64"' "$E")" "None"
check "false and unknown is false" "$(mk_eval 'python_version < "3" and platform_machine == "x86_64"' "$E")" "False"
check "true or unknown is true" "$(mk_eval '(sys_platform == "linux") or platform_machine == "arm64"' "$E")" "True"
check "the extra name is normalised" "$(mk_eval 'extra == "Socks_Extra"' '{"extra":"socks-extra"}')" "True"
check "a marker that does not parse is unknown" "$(mk_eval 'python_version <<< "3"' "$E")" "None"
check "a reversed comparison" "$(mk_eval '"3.8" <= python_full_version' "$E")" "True"
check "in on strings" "$(mk_eval '"linux" in sys_platform' "$E")" "True"

echo "== Windows layout =="
W="$WORK/win"; S="$W/venv/Lib/site-packages"; mkdir -p "$S" "$W/venv/Scripts"
printf 'home = C:\\Users\\dev\\AppData\\Local\\Programs\\Python\\Python311\nversion = 3.11.7\n' > "$W/venv/pyvenv.cfg"
dist "$S" click 8.1.7 'colorama; platform_system == "Windows"' 'importlib-metadata; python_version < "3.8"'
dist "$S" colorama 0.4.6
dist "$S" importlib-metadata 7.0.0
printf 'click==8.1.7\n' > "$W/requirements.txt"
check "the Windows environment is found" "$(python3 "$READER" find "$W" | head -n 1)" "venv"
read_env "$W" venv >/dev/null
check "a Windows-only requirement is kept there" "$(purls "$W.json")" "pkg:pypi/click@8.1.7 pkg:pypi/colorama@0.4.6"
check "with no marker left unsettled" "$(cut -f4 "$W.out")" ""

echo "== declared but not installed, version pins, nothing usable =="
M="$WORK/missing"; make_linux "$M"; printf 'requests==2.32.0\nflask\nrich\n' > "$M/requirements.txt"
read_env "$M" .venv >/dev/null
case "$(cut -f4 "$M.out")" in
    *"declared but not installed: rich"*"installed version differs from the declared pin: requests (2.31.0, declared 2.32.0)"*)
        pass "a missing and a differently pinned dependency are named as unsure" ;;
    *) fail "a missing and a differently pinned dependency are named as unsure" "$(cat "$M.out")" ;;
esac
N="$WORK/nodecl"; make_linux "$N"; rm -f "$N/requirements.txt"
check "nothing declared: read exits 2" "$(read_env "$N" .venv)" "2"
check "and says so" "$(cat "$N.err")" "no declared dependency could be read"
X="$WORK/noinst"; make_linux "$X"; printf 'rich\n' > "$X/requirements.txt"
check "nothing declared is installed: read exits 3" "$(read_env "$X" .venv)" "3"
T="$WORK/testsdir"; make_linux "$T"; rm -f "$T/requirements.txt"; mkdir -p "$T/tests"; printf 'pytest\n' > "$T/tests/requirements.txt"
check "a requirements file under tests/ is not read when non-shipped trees are left out" \
    "$(read_env "$T" .venv BOMLENS_NON_SHIPPED_DIRS="test tests")" "2"
read_env "$T" .venv BOMLENS_NON_SHIPPED_DIRS="" >/dev/null
check "and is read when they are kept" "$(purls "$T.json")" "pkg:pypi/iniconfig@2.0.0 pkg:pypi/pytest@8.0.0"

echo "== pyproject.toml and Poetry =="
if python3 -c 'import tomllib' 2>/dev/null; then
    P="$WORK/pyproj"; make_linux "$P"; rm -f "$P/requirements.txt"
    cat > "$P/pyproject.toml" <<'TOML'
[project]
name = "My_App"
dependencies = ["idna>=3"]

[tool.poetry.dependencies]
python = "^3.11"
werkzeug = { version = "^3", markers = "python_version >= '3.8'" }
asgiref = { version = "*", optional = true }

[tool.poetry.group.dev.dependencies]
pytest = "^8"
TOML
    dist "$P/.venv/lib/python3.12/site-packages" my_app 1.0.0 'idna'
    read_env "$P" .venv >/dev/null
    check "project and Poetry main dependencies; optional, dev group and the project itself left out" "$(purls "$P.json")" \
        "pkg:pypi/idna@3.6 pkg:pypi/markupsafe@2.1.5 pkg:pypi/werkzeug@3.0.1"
    read_env "$P" .venv BOMLENS_INCLUDE_DEV_DEPENDENCIES=1 >/dev/null
    check "BOMLENS_INCLUDE_DEV_DEPENDENCIES=1 adds the dev group" "$(purls "$P.json")" \
        "pkg:pypi/idna@3.6 pkg:pypi/iniconfig@2.0.0 pkg:pypi/markupsafe@2.1.5 pkg:pypi/pytest@8.0.0 pkg:pypi/werkzeug@3.0.1"
else
    echo "  SKIP: this python3 has no tomllib"
fi

echo "== licences and references =="
LL="$WORK/lic"; make_linux "$LL"; printf 'idna\nwerkzeug\n' > "$LL/requirements.txt"
S="$LL/.venv/lib/python3.12/site-packages"
printf 'Metadata-Version: 2.4\nName: idna\nVersion: 3.6\nLicense-Expression: BSD-3-Clause\nProject-URL: Source, https://github.com/kjd/idna\nHome-page: https://example.org/idna\n' > "$S/idna-3.6.dist-info/METADATA"
printf 'Metadata-Version: 2.1\nName: werkzeug\nVersion: 3.0.1\nRequires-Dist: MarkupSafe>=2.1.1\nClassifier: License :: OSI Approved :: BSD License\n' > "$S/werkzeug-3.0.1.dist-info/METADATA"
printf 'Metadata-Version: 2.1\nName: MarkupSafe\nVersion: 2.1.5\nLicense: MIT OR Apache-2.0\n' > "$S/MarkupSafe-2.1.5.dist-info/METADATA"
read_env "$LL" .venv >/dev/null
check "License-Expression is the licence" "$(jq -c '.components[] | select(.name == "idna") | .licenses' "$LL.json")" '[{"license":{"name":"BSD-3-Clause"}}]'
check "a classifier names the licence when nothing else does" "$(jq -c '.components[] | select(.name == "werkzeug") | .licenses' "$LL.json")" '[{"license":{"name":"BSD License"}}]'
check "a License field with an operator is an expression" "$(jq -c '.components[] | select(.name == "markupsafe") | .licenses' "$LL.json")" '[{"license":{"name":"MIT OR Apache-2.0"}}]'
check "website and vcs references" "$(jq -c '[.components[] | select(.name == "idna") | .externalReferences[] | .type] ' "$LL.json")" '["website","vcs"]'

echo "== merge =="
B="$WORK/bom.json"
cat > "$B" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"app","version":"1.0","bom-ref":"pkg:pypi/app@1.0"},
   "properties":[{"name":"bomlens:python-environment","value":"stale"}]},
 "components":[{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0","bom-ref":"pkg:npm/left-pad@1.3.0"},
   {"type":"library","name":"idna","version":"3.6","purl":"pkg:pypi/idna@3.6","bom-ref":"pkg:pypi/idna@3.6"}],
 "dependencies":[{"ref":"pkg:pypi/app@1.0","dependsOn":["pkg:npm/left-pad@1.3.0"]}]}
JSON
check "merge adds the components not already there" "$(python3 "$READER" merge "$B" "$L.json" .venv index-unreachable)" "7"
check "the components" "$(jq -r '.components | length' "$B")" "9"
check "the root keeps its links and gains the declared ones" "$(jq -r '.dependencies[] | select(.ref == "pkg:pypi/app@1.0") | .dependsOn | join(" ")' "$B")" \
    "pkg:npm/left-pad@1.3.0 pkg:pypi/flask@3.0.0 pkg:pypi/requests@2.31.0"
check "the SBOM records the folder, the reason and the unsure detail" \
    "$(jq -c '[.metadata.properties[] | select(.name | startswith("bomlens:python-environment")) | [.name, .value]]' "$B")" \
    '[["bomlens:python-environment",".venv"],["bomlens:python-environment-reason","index-unreachable"],["bomlens:python-environment-unsure","1 dependency marker(s) could not be evaluated"]]'
check "every dependsOn names a component or the root" \
    "$(jq -r '([.components[]."bom-ref"] + [.metadata.component."bom-ref"]) as $r | [.dependencies[].dependsOn[] | select(. as $x | $r | index($x) | not)] | length' "$B")" "0"
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{},"components":[]}\n' > "$WORK/noroot.json"
PROJECT_NAME=My_App PROJECT_VERSION=1.0 python3 "$READER" merge "$WORK/noroot.json" "$L.json" .venv pip-install-failed >/dev/null
check "no root from cdxgen: one is made and links the declared dependencies" \
    "$(jq -c '[.metadata.component."bom-ref", (.dependencies[] | select(.ref == "pkg:pypi/my-app@1.0") | .dependsOn)]' "$WORK/noroot.json")" \
    '["pkg:pypi/my-app@1.0",["pkg:pypi/flask@3.0.0","pkg:pypi/requests@2.31.0"]]'
check "nothing is written into the environment" "$(find "$L/.venv" -newer "$L/requirements.txt" -type f | wc -l | tr -d ' ')" "0"

echo "== build-prep.sh: when the environment is read =="
_lp_block=$(sed -n '/^# --- licence lookup probe ---$/,/^# --- end licence lookup probe ---$/p' "$PREP")
_pv_block=$(sed -n '/^# --- installed python environment ---$/,/^# --- end installed python environment ---$/p' "$PREP")
if ! command -v node >/dev/null 2>&1; then
    echo "  SKIP: node is not installed"
elif [ -z "$_lp_block" ] || [ -z "$_pv_block" ]; then
    fail "the probe or the installed python environment block could not be extracted from build-prep.sh"
else
    cat > "$WORK/srv.js" <<'JS'
const http = require("http");
const fs = require("fs");
const ok = http.createServer((req, res) => { res.writeHead(404); res.end(); });
const closed = http.createServer();
closed.listen(0, "127.0.0.1", () => { const shut = closed.address().port; closed.close(() =>
  ok.listen(0, "127.0.0.1", () => fs.writeFileSync(process.argv[2], ok.address().port + " " + shut))); });
setTimeout(() => process.exit(0), 120000);
JS
    node "$WORK/srv.js" "$WORK/ports" &
    SRV_PID=$!
    n=0; while [ ! -s "$WORK/ports" ] && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    read -r OK_PORT CLOSED_PORT < "$WORK/ports"
    G="$WORK/gate"; make_linux "$G"; sed -i.bak '/--index-url/d' "$G/requirements.txt"; rm -f "$G/requirements.txt.bak"
    # <dir> <PREP_FAILED> [VAR=value ...]: the two gate functions around a
    # stand-in pip step; prints the outcome.
    gate() {
        local d="$1" pf="$2"
        shift 2
        ( cd "$d" && env -u PIP_INDEX_URL -u PIP_CONFIG_FILE HOME="$WORK/home" BOMLENS_PYTHON_VENV_READER="$READER" "$@" \
            sh -c 'log() { echo "[build-prep] $*"; }
            SRC="$(pwd)"; SPEC=1.6; EXCLUDE_NON_SHIPPED=1; NON_SHIPPED_DIRS="test tests"
            PREP_FAILED=""; PREP_APPLIED=""
            mark_prep_failed() { PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$1"; }
            mark_prep_applied() { PREP_APPLIED="${PREP_APPLIED:+$PREP_APPLIED }$1"; }
            unmark_prep_failed() { PREP_FAILED=$(printf "%s\n" $PREP_FAILED | grep -vx "$1" | tr "\n" " " | sed "s/ $//"); }
            '"$_lp_block"'
            '"$_pv_block"'
            python_venv_before_pip
            [ -n "$PY_VENV_USED" ] || { echo "PIP-STEP"; PREP_FAILED="'"$pf"'"; }
            python_venv_after_pip
            echo "USED=$PY_VENV_USED REASON=$PY_VENV_REASON DIR=$PY_VENV_DIR FAILED=$PREP_FAILED APPLIED=$PREP_APPLIED SITE=${BOMLENS_PYTHON_VENV_SITE:+set}"
            [ -z "$PY_VENV_SBOM" ] || jq -r "[.components[].name] | join(\" \")" "$PY_VENV_SBOM"' ) 2>&1
    }
    out="$(gate "$G" "" PIP_INDEX_URL="http://127.0.0.1:$OK_PORT/simple/")"
    check "an index that answers: pip runs as today and the environment is not read" "$(printf '%s\n' "$out" | grep -E '^(PIP-STEP|USED=)')" \
        "$(printf 'PIP-STEP\nUSED= REASON= DIR=.venv FAILED= APPLIED= SITE=')"
    out="$(gate "$G" "" PIP_INDEX_URL="http://127.0.0.1:$CLOSED_PORT/simple/")"
    check "an index that does not answer: pip is not run and the environment is read" "$(printf '%s\n' "$out" | grep -E '^(PIP-STEP|USED=)')" \
        "USED=1 REASON=index-unreachable DIR=.venv FAILED= APPLIED=python-environment SITE=set"
    case "$out" in
        *"[build-prep] python: reading the installed environment .venv/ (the package index 127.0.0.1:$CLOSED_PORT did not answer, it could not be reached (ECONNREFUSED)): kept 8 of 15 installed package(s), the ones the declared dependencies reach; not settled: 1 dependency marker(s) could not be evaluated"*)
            pass "one log line names the folder, the count kept and why" ;;
        *) fail "one log line names the folder, the count kept and why" "$out" ;;
    esac
    check "the packages read" "$(printf '%s\n' "$out" | tail -n 1)" "charset-normalizer flask idna markupsafe pysocks requests werkzeug zipp"
    out="$(gate "$G" "pip-install" PIP_INDEX_URL="http://127.0.0.1:$OK_PORT/simple/")"
    check "a failed pip install: the environment is read and the failure is taken off" "$(printf '%s\n' "$out" | grep -E '^USED=')" \
        "USED=1 REASON=pip-install-failed DIR=.venv FAILED= APPLIED=python-environment SITE=set"
    out="$(gate "$G" "pip-install" PIP_INDEX_URL="http://127.0.0.1:$CLOSED_PORT/simple/" BOMLENS_PYTHON_VENV=false)"
    check "BOMLENS_PYTHON_VENV=false: nothing read, the failure stays" "$(printf '%s\n' "$out" | grep -E '^(PIP-STEP|USED=)')" \
        "$(printf 'PIP-STEP\nUSED= REASON= DIR= FAILED=pip-install APPLIED= SITE=')"
    case "$out" in *"not read (BOMLENS_PYTHON_VENV=false)"*) pass "the opt-out is logged" ;; *) fail "the opt-out is logged" "$out" ;; esac
    G2="$WORK/gate-nodecl"; make_linux "$G2"; rm -f "$G2/requirements.txt"
    out="$(gate "$G2" "" PIP_INDEX_URL="http://127.0.0.1:$CLOSED_PORT/simple/")"
    check "an environment with nothing declared: today's path" "$(printf '%s\n' "$out" | grep -E '^(PIP-STEP|USED=)')" \
        "$(printf 'PIP-STEP\nUSED= REASON= DIR=.venv FAILED= APPLIED= SITE=')"
    case "$out" in *"is not used: no declared dependency could be read"*) pass "and says why" ;; *) fail "and says why" "$out" ;; esac
    out="$(gate "$WORK/none" "" PIP_INDEX_URL="http://127.0.0.1:$CLOSED_PORT/simple/")"
    check "no environment: today's path, no probe" "$(printf '%s\n' "$out" | grep -vE '^\[build-prep\]' | head -n 2 | tr '\n' '|')" \
        "PIP-STEP|USED= REASON= DIR= FAILED= APPLIED= SITE=|"
    out="$(gate "$G" "" PIP_INDEX_URL="http://127.0.0.1:$CLOSED_PORT/simple/" BOMLENS_PYTHON_VENV_READER=/nonexistent/read-python-venv.py)"
    case "$out" in *"was not handed to this container"*"PIP-STEP"*) pass "without the reader: today's path, and the log says why" ;; *) fail "without the reader" "$out" ;; esac
    # The index URL pip would use.
    idx() { ( cd "$1" && env -u PIP_INDEX_URL -u PIP_CONFIG_FILE HOME="$WORK/home" "${@:2}" sh -c "$_pv_block"'
        python_index_url' ); }
    check "the default index is PyPI" "$(idx "$G")" "https://pypi.org/simple/"
    check "PIP_INDEX_URL, without its login" "$(idx "$G" PIP_INDEX_URL=https://me:tok@pypi.corp.example/simple)" "https://pypi.corp.example/simple"
    check "an --index-url in requirements.txt first" "$(idx "$L" PIP_INDEX_URL=https://other.example/simple)" "https://index.example.com/simple"
    mkdir -p "$WORK/home/.config/pip"; printf '[global]\nindex-url = https://conf.example/simple\n' > "$WORK/home/.config/pip/pip.conf"
    check "index-url in pip.conf" "$(idx "$G")" "https://conf.example/simple"
    rm -rf "$WORK/home/.config"
    kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
fi
grep -q '^    set -- "$@" --exclude-type python$' "$PREP" \
    && grep -q 'python_venv_before_pip$' "$PREP" && grep -q 'python_venv_after_pip$' "$PREP" \
    && grep -q '"\$PY_VENV_READER" merge "\$OUT" "\$PY_VENV_SBOM"' "$PREP" \
    && pass "build-prep.sh leaves cdxgen's python cataloger out and merges the environment" \
    || fail "build-prep.sh: the exclusion, the gate calls or the merge are missing"

echo "== the licence evidence pass reads the environment =="
_pylic=$(sed -n "/^    cat > \"\$_pylic\" <<'PY_LIC'\$/,/^PY_LIC\$/p" "$PREP" | sed '1d;$d')
if [ -z "$_pylic" ]; then
    fail "the licence evidence pass could not be extracted from build-prep.sh"
else
    printf '%s\n' "$_pylic" > "$WORK/pylic.py"
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"idna","version":"3.6","purl":"pkg:pypi/idna@3.6"}]}\n' > "$WORK/lic-bom.json"
    BOMLENS_PYTHON_VENV_SITE="$LL/.venv/lib/python3.12/site-packages" python3 "$WORK/pylic.py" "$WORK/lic-bom.json" 2>/dev/null
    check "the environment's License-Expression settles the licence" \
        "$(jq -c '.components[0] | [.licenses, (.properties[] | select(.name == "bomlens:licenseSource") | .value)]' "$WORK/lic-bom.json")" \
        '[[{"license":{"id":"BSD-3-Clause"}}],"installed license expression"]'
fi

echo "== completeness =="
assess() {  # <name> <properties json array>
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"p","version":"1"},"properties":%s},"components":[{"type":"library","name":"idna","version":"3.6","purl":"pkg:pypi/idna@3.6"}]}\n' "$2" > "$WORK/$1.json"
    bash "$LIB/assess-completeness.sh" "$WORK/$1.json" "$WORK/$1" >/dev/null 2>&1
}
assess unsure '[{"name":"bomlens:python-environment","value":".venv"},{"name":"bomlens:python-environment-unsure","value":"declared but not installed: rich"}]'
check "something unsettled: partial, installed-environment-unsure" "$(jq -r '[.grade, (.reasons[].code)] | join(" ")' "$WORK/unsure_completeness.json")" \
    "partial installed-environment-unsure"
case "$(jq -r '.reasons[0].message.ko' "$WORK/unsure_completeness.json")" in *"declared but not installed: rich"*) pass "the Korean message carries the detail" ;; *) fail "the Korean message carries the detail" ;; esac
assess settled '[{"name":"bomlens:python-environment","value":".venv"},{"name":"bomlens:python-environment-reason","value":"index-unreachable"}]'
check "everything settled: complete" "$(jq -r .grade "$WORK/settled_completeness.json")" "complete"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
