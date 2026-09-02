#!/usr/bin/env bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
    # Drop the SBOM where the real container would: the host dir bind-mounted to
    # /host-output (post-process / single-shot) or /out (source stage 1) — i.e.
    # the per-run subfolder scan-sbom.sh now creates. Falls back to cwd so the
    # legacy flat layout (SBOM_OUTPUT_FLAT) still works.
    pn=""; pv=""; hostout=""; prev=""
    for a in "$@"; do
      case "$prev" in
        -v)
          case "$a" in
            *:/host-output) hostout="${a%:/host-output}" ;;
            *:/out)         [ -z "$hostout" ] && hostout="${a%:/out}" ;;
          esac ;;
      esac
      case "$a" in
        PROJECT_NAME=*)    pn="${a#PROJECT_NAME=}" ;;
        PROJECT_VERSION=*) pv="${a#PROJECT_VERSION=}" ;;
      esac
      prev="$a"
    done
    # DOCKER_STUB_NOWRITE=1 models a container that ran and reported success but
    # whose /host-output mount never reached the host (folder outside Docker
    # Desktop file sharing / Colima's home-only mount) — nothing lands on disk.
    if [ -n "$pn" ] && [ -n "$pv" ] && [ "${DOCKER_STUB_NOWRITE:-0}" != "1" ]; then
      dest="${hostout:-.}"; mkdir -p "$dest" 2>/dev/null
      printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"%s","version":"%s"}},"components":[]}\n' \
        "$pn" "$pv" > "$dest/${pn}_${pv}_bom.json"
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
echo " BomLens — Windows / no-Docker tests"
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
            --byte-stable --sign --output-dir --timestamp --ui \
            --license --sbom-author --model --model-file --usage --merge --merge-root \
            --trusca --upload-target --deep-cve --identify-vendored --spdx --lang; do
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

# A completed source scan must print success and leave the SBOM on the host,
# isolated in the per-run <proj>_<ver>/ subfolder (not flat in the source tree).
d="$(new_proj complete)"; printf '{"name":"a"}' > "$d/package.json"
scan_in "$d" --project Done --version 2.0.0 --generate-only
{ [ "$RC" -eq 0 ] && in_out "Analysis Complete" \
    && [ -f "$d/Done_2.0.0/Done_2.0.0_bom.json" ] && [ ! -f "$d/Done_2.0.0_bom.json" ]; } \
  && pass "source scan completes and writes <proj>_<ver>/<proj>_<ver>_bom.json" \
  || { fail "source scan completes and writes SBOM" "rc=$RC"; show; }

# Fail-closed on an empty host mount, in the DEFAULT (non --generate-only) path.
# Regression: the "did the artifact reach the host?" guard used to run ONLY under
# --generate-only, so a full scan whose /host-output mount silently landed nothing
# on the host still printed "Analysis Complete!" over an empty folder. The stub's
# DOCKER_STUB_NOWRITE=1 models exactly that (container succeeds, writes nothing);
# the script must now exit non-zero with a "not found on host" diagnostic.
d="$(new_proj nowrite)"; printf '{"name":"a"}' > "$d/package.json"
export DOCKER_STUB_NOWRITE=1
scan_in "$d" --project Empty --version 3.0.0
unset DOCKER_STUB_NOWRITE
{ [ "$RC" -ne 0 ] && in_out "not found on host" && ! in_out "Analysis Complete"; } \
  && pass "empty host mount (no --generate-only) fails closed with 'not found on host'" \
  || { fail "empty host mount not caught in the default path" "rc=$RC"; show; }

# The completion summary must describe what is ON DISK, not what was requested.
# Regression: it printed a line per request flag, so a scanner image that predates
# a feature (or a step that degraded) still produced "SPDX: <proj>_<ver>_bom.spdx.json"
# for a file the user did not have — the exact symptom of running --spdx/--all on a
# pre-v1.8.0 image. The stub writes only _bom.json, so every other requested
# artifact is missing and must be reported as such instead of announced.
d="$(new_proj summary)"; printf '{"name":"a"}' > "$d/package.json"
scan_in "$d" --project Sum --version 4.0.0 --all --generate-only
{ [ "$RC" -eq 0 ] && in_out "Analysis Complete" \
    && ! in_out "_bom.spdx.json" \
    && in_out "requested but not produced" \
    && in_out "SPDX export" && in_out "notice" && in_out "security report"; } \
  && pass "summary reports only artifacts on disk and names the missing ones" \
  || { fail "summary announced artifacts that were never produced" "rc=$RC"; show; }

# The mirror case: artifacts that DID land are listed, with no false warning.
d="$(new_proj summary_ok)"; printf '{"name":"a"}' > "$d/package.json"
scan_in "$d" --project SumOk --version 4.1.0 --generate-only --no-report
{ [ "$RC" -eq 0 ] && in_out "SBOM: SumOk_4.1.0_bom.json" \
    && ! in_out "requested but not produced"; } \
  && pass "summary lists the delivered SBOM without a spurious missing-artifact warning" \
  || { fail "summary warned about artifacts that were not requested" "rc=$RC"; show; }

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
guard "--merge + --target rejected"     "mutually exclusive" --project p --version 1 --merge a.json b.json --target z
guard "--merge needs >=2 files"         "needs at least 2" --project p --version 1 --merge one.json
guard "--merge-root without --merge"    "only applies with --merge" --project p --version 1 --merge-root x.json
guard "--merge-root not in --merge list" "must be one of the --merge input files" \
  --project p --version 1 --merge a.json b.json --merge-root c.json
guard "--usage without --model/--model-file" "AI model and dataset scans only" --project p --version 1 --target x --usage internal

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
section "AI model modes (--model, --model-file, auto-detect)"
# --------------------------------------------------------
d="$(new_proj model)"
scan_in "$d" --project M --version 1 --model owner/repo --generate-only
in_out "Mode: AIBOM" && pass "--model <owner/name> -> AIBOM mode" || { fail "--model -> AIBOM"; show; }

d="$(new_proj modelfile)"; printf 'not-a-real-gguf' > "$d/weights.gguf"
scan_in "$d" --project MF --version 1 --model-file weights.gguf --generate-only
in_out "Mode: MODELFILE" && pass "--model-file <path> -> MODELFILE mode" || { fail "--model-file -> MODELFILE"; show; }

d="$(new_proj modelfile_missing)"
scan_in "$d" --project MF --version 1 --model-file nope.gguf --generate-only
{ [ "$RC" -ne 0 ] && in_out "not found"; } \
  && pass "--model-file <missing path> fails with 'not found'" || { fail "--model-file missing"; show; }

d="$(new_proj modelfile_autodetect)"; printf 'not-a-real-safetensor' > "$d/weights.safetensors"
scan_in "$d" --project MFA --version 1 --target weights.safetensors --generate-only
{ in_out "AI model file; reading its header" && in_out "Mode: MODELFILE"; } \
  && pass "--target *.safetensors auto-routes to MODELFILE" || { fail "--target *.safetensors -> MODELFILE"; show; }

d="$(new_proj usage_bad)"; printf 'x' > "$d/w.gguf"
scan_in "$d" --project MU --version 1 --model-file w.gguf --usage bogus --generate-only
{ [ "$RC" -ne 0 ] && in_out "internal, product, redistribute, outputs-only"; } \
  && pass "--usage rejects an unknown scenario" || { fail "--usage rejects unknown scenario"; show; }

# --------------------------------------------------------
section "Merge mode (--merge)"
# --------------------------------------------------------
CDX='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"a","version":"1"}},"components":[]}'
d="$(new_proj merge)"
printf '%s' "$CDX" > "$d/a.json"
printf '%s' "$CDX" > "$d/b.json"
scan_in "$d" --project Merged --version 1.0.0 --merge a.json b.json --generate-only
{ in_out "Mode: MERGE" && [ "$RC" -eq 0 ] && in_out "Analysis Complete"; } \
  && pass "--merge a.json b.json -> MERGE mode completes" || { fail "--merge -> MERGE mode"; show; }

d="$(new_proj merge_root)"
printf '%s' "$CDX" > "$d/a.json"
printf '%s' "$CDX" > "$d/b.json"
scan_in "$d" --project MergedR --version 1.0.0 --merge a.json b.json --merge-root a.json --generate-only
{ in_out "Mode: MERGE" && [ "$RC" -eq 0 ]; } \
  && pass "--merge-root naming one of the --merge inputs succeeds" || { fail "--merge-root valid input"; show; }

# --------------------------------------------------------
section "Yocto build directory detection"
# --------------------------------------------------------
d="$(new_proj yocto)"; mkdir -p "$d/conf" "$d/tmp/deploy/images/qemux86-64"
: > "$d/conf/bblayers.conf"
printf '{"spdxVersion":"SPDX-3.0","creationInfo":{"createdBy":["bitbake"]}}' \
  > "$d/tmp/deploy/images/qemux86-64/core-image-minimal.rootfs.spdx.json"
scan_in "$d" --project Yocto --version 1.0.0 --target "$d" --generate-only
{ in_out "Yocto build directory" && in_out "Mode: ANALYZE" \
    && in_out "Image SBOM:" && [ "$RC" -eq 0 ]; } \
  && pass "Yocto build dir (bblayers.conf + image SPDX) -> ANALYZE mode" \
  || { fail "Yocto build dir -> ANALYZE mode"; show; }

d="$(new_proj yocto_empty)"; mkdir -p "$d/conf"
: > "$d/conf/bblayers.conf"
scan_in "$d" --project YoctoEmpty --version 1 --target "$d" --generate-only
{ [ "$RC" -ne 0 ] && in_out "neither an SPDX SBOM" && in_out "image package manifest to read"; } \
  && pass "Yocto build dir with no SPDX/manifest fails with guidance" \
  || { fail "Yocto build dir with no SPDX/manifest"; show; }

# --------------------------------------------------------
section "Formats that need unpacking (installer / app package)"
# --------------------------------------------------------
if command -v zip >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then
  d="$(new_proj apk)"; printf 'x' > "$d/classes.dex"
  ( cd "$d" && zip -q app.apk classes.dex ) >/dev/null 2>&1
  scan_in "$d" --project Apk --version 1 --target app.apk --generate-only
  { in_out "app package" && in_out "unpacking it to read what is inside" \
      && in_out "Mode: FIRMWARE" && in_log "bomlens-firmware"; } \
    && pass "--target *.apk (zip w/ firmware image available) -> FIRMWARE mode (unpacked)" \
    || { fail "--target *.apk -> FIRMWARE (unpacking)"; show; }
else
  skip "unpacking-required format detection (zip/file unavailable)"
fi

# --------------------------------------------------------
section "Container image archive (docker save tar)"
# --------------------------------------------------------
if command -v tar >/dev/null 2>&1; then
  d="$(new_proj cimg)"; mkdir -p "$d/blobs/sha256"
  printf '[{"Config":"cfg"}]' > "$d/manifest.json"
  printf 'layer' > "$d/blobs/sha256/abc123"
  ( cd "$d" && tar -cf image.tar manifest.json blobs ) >/dev/null 2>&1
  scan_in "$d" --project Cimg --version 1 --target image.tar --generate-only
  { in_out "Container image archive detected" && in_out "Mode: BINARY"; } \
    && pass "--target <docker save tar> is recognized and not auto-extracted as source" \
    || { fail "docker-save tar container-archive detection"; show; }
else
  skip "container image archive detection (tar unavailable)"
fi

# --------------------------------------------------------
section "Pass-through flags reach the container"
# --------------------------------------------------------
d="$(new_proj passthrough)"; printf 'ELFish\n' > "$d/app.out"
scan_in "$d" --project PT --version 1 --target app.out --generate-only \
  --license Apache-2.0 --sbom-author "ACME Corp" --identify-vendored --deep-cve \
  --trusca proj-123
{ in_log "PROJECT_LICENSE=Apache-2.0" && in_log "SBOM_AUTHOR=ACME Corp" \
    && in_log "IDENTIFY_VENDORED=true" && in_log "UPLOAD_TARGET=trusca" \
    && in_log "TRUSCA_PROJECT_ID=proj-123" && in_log "bomlens-deep-cve"; } \
  && pass "--license/--sbom-author/--identify-vendored/--trusca/--deep-cve reach the container" \
  || { fail "pass-through flags reach the container"; show; }

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
