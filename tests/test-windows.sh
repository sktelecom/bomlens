#!/usr/bin/env bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-windows.sh — Windows / no-Docker contract & orchestration tests.
#
# Why this exists: every other test in tests/ needs a running Docker daemon and
# the built scanner image, so a Windows user who just cloned the repo has no way
# to sanity-check it before installing a multi-gigabyte engine. This suite runs
# in Git Bash (or any POSIX shell) with NO Docker daemon: it puts a stub `docker`
# on PATH that records each invocation and fakes success, then drives the REAL
# scripts/scan-sbom.sh. That exercises the host-side orchestration end to end —
# argument parsing, language detection, per-language image selection, target-mode
# routing (source / image / binary / firmware / analyze), zip + git ingestion,
# and the mutual-exclusivity guards — exactly as it runs on a user's machine.
#
# It does NOT validate the container internals (cdxgen/syft/trivy) or Docker
# Desktop path mounting; those need a real daemon and are covered by test-e2e.sh.
#
# Usage:   bash tests/test-windows.sh
# Env:     VERBOSE=true   show the captured scan output for failing cases
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$REPO/scripts/scan-sbom.sh"
VERBOSE="${VERBOSE:-false}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sbom-win.XXXXXX")"
BIN="$WORK/bin"; mkdir -p "$BIN"
cleanup() { cd "$REPO" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
PASS=0; FAIL=0; SKIP=0; FAILED=()
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); [ -n "${2:-}" ] && echo "        ↳ $2"; }
skip() { echo -e "  ${c_yellow}SKIP${c_reset} $1"; SKIP=$((SKIP+1)); }
section() { echo ""; echo "▶ $1"; }

# --------------------------------------------------------
# Stub `docker`: fakes daemon checks and `docker run`, logging every call to
# $DOCKER_STUB_LOG. When the post-process / single-shot stage runs (it is the
# only stage carrying PROJECT_NAME/PROJECT_VERSION env), it writes the SBOM the
# real container would have dropped on the host, so `--generate-only`'s final
# "artifact reached the host" check passes and the script completes cleanly.
# --------------------------------------------------------
cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
log="${DOCKER_STUB_LOG:-/dev/null}"
echo "docker $*" >> "$log"
case "${1:-}" in
  version|info|pull|image|inspect|stop|rm) exit 0 ;;
  run)
    pn=""; pv=""
    for a in "$@"; do
      case "$a" in
        PROJECT_NAME=*)    pn="${a#PROJECT_NAME=}" ;;
        PROJECT_VERSION=*) pv="${a#PROJECT_VERSION=}" ;;
      esac
    done
    if [ -n "$pn" ] && [ -n "$pv" ]; then
      printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"%s","version":"%s"}},"components":[]}\n' \
        "$pn" "$pv" > "${pn}_${pv}_bom.json"
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$BIN/docker"
export PATH="$BIN:$PATH"

# Run scan-sbom.sh in $dir with a fresh docker log. Sets globals OUT, LOG, RC.
N=0
scan_in() {
  local dir="$1"; shift
  N=$((N+1))
  LOG="$WORK/docker.$N.log"; : > "$LOG"
  OUT="$WORK/out.$N"
  ( cd "$dir" && DOCKER_STUB_LOG="$LOG" bash "$SCAN" "$@" ) > "$OUT" 2>&1
  RC=$?
  return 0
}
show() { [ "$VERBOSE" = "true" ] && sed 's/^/        /' "$OUT"; return 0; }
in_out() { grep -qF -- "$1" "$OUT"; }
in_log() { grep -qF -- "$1" "$LOG"; }

new_proj() { local d="$WORK/proj.$N.$1"; mkdir -p "$d"; echo "$d"; }

echo "=================================================="
echo " sbom-tools — Windows / no-Docker tests"
echo " bash: $(bash --version | head -1)"
echo " scan: $SCAN"
echo "=================================================="

# --------------------------------------------------------
section "CLI contract (no docker daemon touched)"
# --------------------------------------------------------
HELP="$(bash "$SCAN" --help 2>&1)"; hrc=$?
[ "$hrc" -eq 0 ] && pass "--help exits 0" || fail "--help exits 0" "rc=$hrc"
for flag in --project --version --target --git --branch --firmware --analyze \
            --generate-only --notice --security --all --no-report --deep-license \
            --byte-stable --sign --ui; do
  if printf '%s' "$HELP" | grep -q -- "$flag"; then pass "help documents $flag"
  else fail "help documents $flag"; fi
done

# Required args are validated BEFORE the docker daemon check, so this needs no stub.
err="$(bash "$SCAN" --generate-only 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q "required"; then
  pass "missing --project/--version exits non-zero with a clear message"
else
  fail "missing --project/--version exits non-zero" "rc=$rc: $err"
fi

err="$(bash "$SCAN" --project p --version 1 --bogus-flag 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q "Unknown option"; then
  pass "unknown option is rejected"
else
  fail "unknown option is rejected" "rc=$rc: $err"
fi

# --------------------------------------------------------
section "Language detection → per-language cdxgen image (source mode)"
# --------------------------------------------------------
# table: label | manifest file | manifest body | expected lang | expected image substring
detect_case() {
  local label="$1" file="$2" body="$3" lang="$4" img="$5"
  local d; d="$(new_proj "$label")"
  printf '%s' "$body" > "$d/$file"
  scan_in "$d" --project "P$label" --version 1.0.0 --generate-only
  local ok=1
  in_out "Mode: SOURCE"                 || ok=0
  in_out "Language: $lang"              || ok=0
  in_log "$img"                         || ok=0
  if [ "$ok" = 1 ]; then pass "$label → $lang ($img)"; else
    fail "$label → $lang ($img)" "rc=$RC; mode/lang/image mismatch"; show; fi
}
detect_case node   package.json     '{"name":"a","dependencies":{"express":"^4"}}' node   cdxgen-node20
detect_case python requirements.txt 'flask==3.0.0'                                  python cdxgen-python312
detect_case java   pom.xml          '<project><modelVersion>4.0.0</modelVersion></project>' java cdxgen-temurin-java21
detect_case go     go.mod           'module x\n\ngo 1.21\n'                          go     cdxgen-debian-golang124
detect_case rust   Cargo.toml       '[package]\nname="x"\nversion="0.1.0"'          rust   cdxgen-debian-rust
detect_case ruby   Gemfile          "source 'https://rubygems.org'\ngem 'rack'"     ruby   cdxgen-debian-ruby34
detect_case php    composer.json    '{"require":{"monolog/monolog":"^3"}}'          php    cdxgen-debian-php84

# .NET needs a *.csproj glob, swift needs Package.swift — handled specially.
d="$(new_proj dotnet)"; printf '<Project></Project>' > "$d/app.csproj"
scan_in "$d" --project Pdotnet --version 1.0.0 --generate-only
{ in_out "Language: dotnet" && in_log "cdxgen-debian-dotnet9"; } \
  && pass "dotnet (*.csproj) → dotnet image" || { fail "dotnet (*.csproj) → dotnet image" "rc=$RC"; show; }

d="$(new_proj swift)"; printf '// swift-tools-version:5.9\n' > "$d/Package.swift"
scan_in "$d" --project Pswift --version 1.0.0 --generate-only
{ in_out "Language: swift" && in_log "cdxgen-debian-swift"; } \
  && pass "swift (Package.swift) → swift image" || { fail "swift (Package.swift) → swift image" "rc=$RC"; show; }

# Unknown (no manifest) and mixed (two manifests) both fall back to all-in-one.
d="$(new_proj unknown)"; printf 'hello\n' > "$d/README"
scan_in "$d" --project Punknown --version 1.0.0 --generate-only
{ in_out "Language: unknown" && in_out "No package manifest" && in_log "cyclonedx/cdxgen:v12"; } \
  && pass "no manifest → unknown → all-in-one image + warning" || { fail "no manifest → all-in-one"; show; }

d="$(new_proj mixed)"; printf '{}' > "$d/package.json"; printf 'module x\ngo 1.21\n' > "$d/go.mod"
scan_in "$d" --project Pmixed --version 1.0.0 --generate-only
{ in_out "Language: mixed" && in_log "cyclonedx/cdxgen:v12"; } \
  && pass "two manifests → mixed → all-in-one image" || { fail "mixed → all-in-one"; show; }

# A completed source scan must print success and leave the SBOM on the host.
d="$(new_proj complete)"; printf '{"name":"a"}' > "$d/package.json"
scan_in "$d" --project Done --version 2.0.0 --generate-only
{ [ "$RC" -eq 0 ] && in_out "Analysis Complete" && [ -f "$d/Done_2.0.0_bom.json" ]; } \
  && pass "source scan completes and writes <proj>_<ver>_bom.json" \
  || { fail "source scan completes and writes SBOM" "rc=$RC"; show; }

# --------------------------------------------------------
section "Target-mode routing"
# --------------------------------------------------------
d="$(new_proj img)"
scan_in "$d" --project Img --version 1 --target nginx:latest --generate-only
{ in_out "Mode: IMAGE" && in_log "TARGET_IMAGE=nginx:latest"; } \
  && pass "--target nginx:latest → IMAGE mode" || { fail "--target image → IMAGE mode" "rc=$RC"; show; }

d="$(new_proj bin)"; printf 'ELFish\n' > "$d/app.out"
scan_in "$d" --project Bin --version 1 --target app.out --generate-only
in_out "Mode: BINARY" && pass "--target regular-file → BINARY mode" || { fail "--target file → BINARY" "rc=$RC"; show; }

d="$(new_proj fw)"; printf 'blob\n' > "$d/dev.bin"
scan_in "$d" --project Fw --version 1 --target dev.bin --generate-only
in_out "Mode: FIRMWARE" && pass "--target *.bin → FIRMWARE mode (extension)" || { fail "--target .bin → FIRMWARE" "rc=$RC"; show; }

d="$(new_proj rootfs)"; mkdir -p "$d/rootfs/usr/bin"; printf 'x' > "$d/rootfs/usr/bin/f"
scan_in "$d" --project Root --version 1 --target rootfs --generate-only
in_out "Mode: ROOTFS" && pass "--target directory → ROOTFS mode" || { fail "--target dir → ROOTFS" "rc=$RC"; show; }

d="$(new_proj analyze)"; printf '{"bomFormat":"CycloneDX"}' > "$d/supplier.json"
scan_in "$d" --project Sup --version 1 --analyze supplier.json --generate-only
in_out "Mode: ANALYZE" && pass "--analyze <sbom> → ANALYZE mode" || { fail "--analyze → ANALYZE" "rc=$RC"; show; }

# --------------------------------------------------------
section "Mutual-exclusivity & input guards"
# --------------------------------------------------------
guard() { # label | expected-substring | args...
  local label="$1" want="$2"; shift 2
  local d; d="$(new_proj guard)"
  scan_in "$d" "$@"
  if [ "$RC" -ne 0 ] && in_out "$want"; then pass "$label"; else
    fail "$label" "rc=$RC; expected '$want'"; show; fi
}
guard "--git + --target rejected"      "mutually exclusive" --project p --version 1 --git https://github.com/x/y --target z
guard "--git + --analyze rejected"     "mutually exclusive" --project p --version 1 --git https://github.com/x/y --analyze s.json
guard "--analyze + --target rejected"  "mutually exclusive" --project p --version 1 --analyze s.json --target z
guard "--firmware without --target"    "--firmware requires" --project p --version 1 --firmware
guard "unsafe git URL (shell metachar)" "unsafe or unsupported" --project p --version 1 --git "https://github.com/x/y;rm -rf /"
guard "unsafe git URL (path traversal)" "unsafe or unsupported" --project p --version 1 --git "https://github.com/../../etc"

# --------------------------------------------------------
section "Archive ingestion (auto-extract → source scan)"
# --------------------------------------------------------
# Exercises ingest_archive end to end. We prefer a .tar.gz fixture because
# `tar` ships with Git Bash whereas `zip` usually does not, so the common
# Windows install can still cover the extract→flatten→source-scan path. A .zip
# case is added on top when a `zip` binary is available.
archive_case() { # label | archive-name | build-cmd... (run inside $d, must create the archive)
  local label="$1" arc="$2"; shift 2
  local d; d="$(new_proj "$label")"; mkdir -p "$d/app"
  printf '{"name":"arcapp","dependencies":{"express":"^4"}}' > "$d/app/package.json"
  ( cd "$d" && "$@" ) >/dev/null 2>&1
  scan_in "$d" --project "P$label" --version 1.0.0 --target "$arc" --generate-only
  { in_out "Extracting archive" && in_out "Mode: SOURCE" && in_out "Language: node" && [ "$RC" -eq 0 ]; } \
    && pass "$label → extracted → SOURCE node scan completes" || { fail "$label ingestion" "rc=$RC"; show; }
  if ls -d "$d"/.sbom-arc.* >/dev/null 2>&1; then
    fail "$label ingestion cleans up temp extraction dir"
  else
    pass "$label ingestion cleans up temp extraction dir"
  fi
}

if command -v tar >/dev/null 2>&1; then
  archive_case "tar.gz" app.tar.gz tar -czf app.tar.gz app
else
  skip "tar.gz ingestion (tar unavailable)"
fi

if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
  archive_case "zip" app.zip zip -qr app.zip app
else
  skip "zip ingestion (zip/unzip unavailable — tar.gz case covers ingest_archive)"
fi

# --------------------------------------------------------
section "Git ingestion (offline file:// clone)"
# --------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
  skip "git ingestion (git unavailable)"
else
  g="$(new_proj git)"; mkdir -p "$g/src"
  printf '{"name":"gitapp","dependencies":{"lodash":"^4"}}' > "$g/src/package.json"
  ( cd "$g/src" && git init -q && git config user.email t@t && git config user.name t \
      && git add -A && git commit -qm init ) >/dev/null 2>&1
  ( cd "$g" && git clone -q --bare src fixture.git ) >/dev/null 2>&1
  run="$(new_proj gitrun)"
  # file:// URL must satisfy the strict is_git_url allowlist on Windows paths too.
  scan_in "$run" --project Git --version 1.0.0 --git "file://$g/fixture.git" --generate-only
  { in_out "Cloning" && in_out "Mode: SOURCE" && in_out "Language: node" && [ "$RC" -eq 0 ]; } \
    && pass "git file:// clone → SOURCE node scan completes" || { fail "git ingestion" "rc=$RC"; show; }
  if ls -d "$run"/.sbom-git.* >/dev/null 2>&1; then
    fail "git ingestion cleans up temp clone dir"
  else
    pass "git ingestion cleans up temp clone dir"
  fi
fi

# --------------------------------------------------------
section "Windows wrappers (static checks)"
# --------------------------------------------------------
UI_BAT="$REPO/scripts/sbom-ui.bat"
SCAN_BAT="$REPO/scripts/scan-sbom.bat"
CHECK_BAT="$REPO/scripts/check-setup.bat"
CHECK_SH="$REPO/scripts/check-setup.sh"
[ -f "$UI_BAT" ]   && pass "scripts/sbom-ui.bat present"   || fail "scripts/sbom-ui.bat present"
[ -f "$SCAN_BAT" ] && pass "scripts/scan-sbom.bat present" || fail "scripts/scan-sbom.bat present"
if [ -f "$UI_BAT" ]; then
  grep -q "MODE=UI" "$UI_BAT"            && pass "sbom-ui.bat sets MODE=UI"               || fail "sbom-ui.bat sets MODE=UI"
  grep -qi "docker version" "$UI_BAT"    && pass "sbom-ui.bat preflight-checks docker"    || fail "sbom-ui.bat preflight-checks docker"
  # New onboarding behaviors: artifacts go to a dedicated home-dir folder, and the
  # image is pre-pulled on first run so the user sees download progress.
  grep -q "sbom-output" "$UI_BAT"        && pass "sbom-ui.bat isolates output to a dedicated sbom-output folder" || fail "sbom-ui.bat isolates output folder"
  grep -qi "docker image inspect" "$UI_BAT"      && pass "sbom-ui.bat checks for the image before run" || fail "sbom-ui.bat checks for image"
  grep -qi "docker pull" "$UI_BAT"               && pass "sbom-ui.bat pre-pulls the image on first run" || fail "sbom-ui.bat pre-pulls image"
fi
if [ -f "$SCAN_BAT" ]; then
  grep -q "scan-sbom.sh" "$SCAN_BAT"     && pass "scan-sbom.bat delegates to scan-sbom.sh" || fail "scan-sbom.bat delegates to scan-sbom.sh"
  grep -qi "where bash" "$SCAN_BAT"      && pass "scan-sbom.bat checks for Git Bash"        || fail "scan-sbom.bat checks for Git Bash"
fi
# check-setup helper exists on both platforms and inspects the same prerequisites.
[ -f "$CHECK_BAT" ] && pass "scripts/check-setup.bat present" || fail "scripts/check-setup.bat present"
[ -f "$CHECK_SH" ]  && pass "scripts/check-setup.sh present"  || fail "scripts/check-setup.sh present"
if [ -f "$CHECK_SH" ]; then
  grep -qi "docker image inspect" "$CHECK_SH" && pass "check-setup.sh inspects the scanner image" || fail "check-setup.sh inspects image"
fi

# --------------------------------------------------------
echo ""
echo "=================================================="
echo -e " ${c_green}PASS=$PASS${c_reset}  ${c_red}FAIL=$FAIL${c_reset}  ${c_yellow}SKIP=$SKIP${c_reset}"
if [ "$FAIL" -gt 0 ]; then echo " Failed:"; for t in "${FAILED[@]}"; do echo "   - $t"; done; fi
echo "=================================================="
[ "$FAIL" -eq 0 ]
