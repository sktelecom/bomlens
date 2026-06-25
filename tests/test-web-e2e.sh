#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-web-e2e.sh — full-path e2e for the BomLens web UI.
#
# Unlike tests/test-web-ui.sh (No-Docker, API contract only), this boots the UI
# CONTAINER (MODE=UI -> server.py), and drives the real /scan-stream SSE endpoint
# for each source type the browser offers. It parses the final `done` event and
# asserts ok, the component count, the scan mode, and — the regression that let two
# bugs through — that `results` lists ONLY this scan's artifacts (its prefix),
# never the whole output directory. This is the path a user actually takes
# (web -> upload -> container scan -> done) that no other suite covered.
#
# Two regressions are guarded explicitly:
#   #1  SCANOSS skipped dot-prefixed paths. Web uploads/clones extract under
#       OUTPUT_DIR/.uploads/<token>/extracted/... (a hidden dir), so scanoss-py
#       fingerprinted ZERO files and vendored identification was always empty.
#       Fix: --all-hidden in identify-vendored.sh. Verified network-free, at the
#       "files found to fingerprint" stage (no OSSKB match needed).
#   #2  The `done` event called list_results() WITHOUT the scan prefix, returning
#       every artifact in OUTPUT_DIR (e.g. 43 files from past scans). Fix:
#       list_results(prefix). Verified by pre-seeding an unrelated past scan and
#       asserting it never appears in this scan's results.
#
# IMPORTANT — why the current source server.py is mounted over the image's copy:
# the baked bomlens-full:local can lag the working tree. Mounting docker/web/
# server.py guarantees we test the code under review, not a stale layer (the very
# place regression #2 hides). The entrypoint/lib scripts come from the image.
#
# Deterministic, network-free source types run every time: sbom-upload, current-
# dir, zip-upload, rootfs-dir (the last two fall back to syft/manifest-only, which
# is enough to prove the path reaches a valid `done`). docker-image runs when
# alpine can be pulled. The rest are gated and self-skip (logged, never silent):
# firmware-upload only when unblob is in the image (SBOM_FIRMWARE=true build),
# git-url only with WEB_GIT_E2E=1 (network clone), and ai-model / real OSSKB
# matching / the 15GB cdxgen language image are out of scope here.
#
# Requirements: docker, curl, python3. A scanner image with server.py + run-scan +
# syft (+ scanoss-py for the #1 regression). Override with SBOM_E2E_IMAGE.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$ROOT_DIR/docker/web/server.py"
IMAGE="${SBOM_E2E_IMAGE:-bomlens-full:local}"
PORT="${WEB_E2E_TEST_PORT:-18091}"
BASE="http://127.0.0.1:${PORT}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
skip() { echo "  SKIP: $1"; }

command -v docker >/dev/null 2>&1 || { echo "[ERROR] docker required"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "[ERROR] curl required";   exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 required"; exit 1; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[SKIP] scanner image '$IMAGE' not present locally."
    echo "       Build it or set SBOM_E2E_IMAGE to a published image, then re-run."
    echo "       (e.g. docker build -t bomlens-full:local ./docker)"
    exit 0
fi

# The web src/output dirs are bind-mounted INTO the container. On macOS, Docker
# Desktop does not share $TMPDIR (/var/folders/...), so a mktemp dir would appear
# empty inside the container and current-dir/zip scans would see no source. Put
# the work tree under $HOME, which Docker Desktop shares by default; on Linux/CI
# /tmp is shared, but $HOME works there too, so we use it unconditionally.
WORK="$(mktemp -d "${HOME}/.bomlens-e2e.XXXXXX")"
SRC="$WORK/src"; OUT="$WORK/out"
mkdir -p "$SRC" "$OUT"
CID=""
cleanup() {
    [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# A tiny CycloneDX SBOM for the ANALYZE path (no network, fully deterministic).
cat > "$SRC/sample_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
 "metadata":{"component":{"type":"application","name":"demo","version":"1.0"}},
 "components":[
   {"type":"library","name":"flask","version":"2.0.0","purl":"pkg:pypi/flask@2.0.0"},
   {"type":"library","name":"requests","version":"2.28.0","purl":"pkg:pypi/requests@2.28.0"}
 ]}
JSON
# A tiny source tree (a package manifest) for the current-dir / zip SOURCE path.
cat > "$SRC/package.json" <<'JSON'
{"name":"demo-app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}
JSON

# A subfolder under /src for the rootfs-dir (MODE=ROOTFS) path.
mkdir -p "$SRC/subapp"
cat > "$SRC/subapp/package.json" <<'JSON'
{"name":"sub-app","version":"2.0.0","dependencies":{"left-pad":"1.3.0"}}
JSON

# Pre-seed an UNRELATED past scan in OUTPUT_DIR. Regression #2: it must never
# appear in any new scan's `done` results (which are prefix-scoped).
cat > "$OUT/oldscan_9.9_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"name":"stale","version":"1","type":"library"}]}
JSON
cat > "$OUT/oldscan_9.9_NOTICE.txt" <<'TXT'
stale 1
TXT

echo "== booting UI container ($IMAGE, port $PORT) =="
CID="$(docker run -d --rm -p "${PORT}:8080" \
    -v "$SRC":/src -v "$OUT":/host-output \
    -v "$SERVER":/usr/local/lib/sbom-web/server.py:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e MODE=UI -e UI_PORT=8080 -e SBOM_UI_HOST_DIR="$SRC" "$IMAGE" 2>/dev/null)"
if [ -z "$CID" ]; then
    fail "could not start the UI container"
    echo ""; echo "Results: ${PASS} passed, ${FAIL} failed"; exit 1
fi

ready=0
for _ in $(seq 1 60); do
    if curl -fsS "$BASE/capabilities" >/dev/null 2>&1; then ready=1; break; fi
    docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null | grep -q true || break
    sleep 0.5
done
if [ "$ready" = 1 ]; then
    pass "UI container is up and answering the API"
else
    fail "UI container did not become ready" "$(docker logs "$CID" 2>&1 | tail -8)"
    echo ""; echo "Results: ${PASS} passed, ${FAIL} failed"; exit 1
fi

# Confirm the mounted server.py is the FIXED one (prefix-scoped done results).
# A guard so a future refactor that drops the mount/fix doesn't silently pass.
if docker exec "$CID" grep -q 'results.*list_results(prefix)' \
        /usr/local/lib/sbom-web/server.py 2>/dev/null; then
    pass "server.py under test scopes done.results by prefix (regression #2 fix present)"
else
    fail "server.py under test still calls list_results() without a prefix"
fi

# upload <kind> <file> -> echoes the upload token (empty on failure).
upload() {
    curl -fsS -F "kind=$1" -F "file=@$2" "$BASE/upload?kind=$1" 2>/dev/null \
        | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null
}

# stream <querystring> -> writes the raw `done` data payload to $WORK/done.json.
# Returns non-zero if no done event arrived.
stream() {
    local qs="$1"
    curl -fsS -N --max-time 240 "$BASE/scan-stream?$qs" 2>/dev/null \
        | awk '/^event: done/{getline; sub(/^data: /,""); print; exit}' > "$WORK/done.json"
    [ -s "$WORK/done.json" ]
}

# assert_done <case> <expected_mode> <prefix> <min_components>
# Parses $WORK/done.json and checks ok=true, mode, prefix-only results
# (regression #2), no leaked oldscan, and a minimum component count.
# strict=False on json.loads: vuln descriptions carry raw newlines in the payload.
assert_done() {
    local label="$1" want_mode="$2" prefix="$3" min="$4"
    PREFIX="$prefix" WANT_MODE="$want_mode" MIN="$min" LABEL="$label" \
    python3 - "$WORK/done.json" <<'PY'
import sys, os, json
label = os.environ["LABEL"]; want_mode = os.environ["WANT_MODE"]
prefix = os.environ["PREFIX"]; min_c = int(os.environ["MIN"])
try:
    d = json.loads(open(sys.argv[1]).read(), strict=False)
except Exception as exc:
    print("PARSE_FAIL %s" % exc); sys.exit(1)
errs = []
if d.get("ok") is not True:
    errs.append("ok=%r (expected True)" % d.get("ok"))
if d.get("mode") != want_mode:
    errs.append("mode=%r (expected %s)" % (d.get("mode"), want_mode))
names = [r.get("name", "") for r in (d.get("results") or [])]
leaked = [n for n in names if not n.startswith(prefix + "_")]
if leaked:
    errs.append("results NOT prefix-scoped (regression #2): %s" % leaked[:5])
if any(n.startswith("oldscan_9.9_") for n in names):
    errs.append("a pre-existing scan's artifact leaked into results (regression #2)")
comps = (d.get("sbom") or {}).get("components")
if comps is None or comps < min_c:
    errs.append("components=%r (expected >= %d)" % (comps, min_c))
if errs:
    print("CHECK_FAIL " + " | ".join(errs)); sys.exit(1)
print("OK mode=%s components=%s results=%d" % (d["mode"], comps, len(names)))
PY
}

echo "== [1/3] sbom-upload (MODE=ANALYZE) — no network, most stable =="
tok="$(upload sbom "$SRC/sample_bom.json")"
if [ -z "$tok" ]; then
    fail "SBOM upload returned no token"
elif stream "project=analyzeproj&version=3.1&source=sbom-upload&token=$tok&security=true"; then
    out="$(assert_done "sbom-upload" ANALYZE analyzeproj_3.1 2)"
    case "$out" in
        OK*) pass "sbom-upload -> done.ok, ANALYZE, 2 components, prefix-scoped results ($out)" ;;
        *)   fail "sbom-upload done event wrong" "$out" ;;
    esac
else
    fail "sbom-upload produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
fi

echo "== [2/3] docker-image (MODE=IMAGE) — small alpine image =="
if docker pull alpine:latest >/dev/null 2>&1; then
    if stream "project=alpimg&version=latest&source=docker-image&target=alpine:latest&security=false"; then
        out="$(assert_done "docker-image" IMAGE alpimg_latest 1)"
        case "$out" in
            OK*) pass "docker-image (alpine) -> done.ok, IMAGE, components, prefix-scoped ($out)" ;;
            *)   fail "docker-image done event wrong" "$out" ;;
        esac
    else
        fail "docker-image produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
    fi
else
    skip "docker-image: could not pull alpine:latest (no network)"
fi

echo "== [3/3] current-dir (MODE=SOURCE, syft fallback) — tiny package.json =="
if stream "project=srcproj&version=1.0&source=current-dir&security=false"; then
    out="$(assert_done "current-dir" SOURCE srcproj_1.0 1)"
    case "$out" in
        OK*) pass "current-dir -> done.ok, SOURCE, >=1 component, prefix-scoped ($out)" ;;
        *)   fail "current-dir done event wrong (syft may have found no manifest)" "$out" ;;
    esac
else
    fail "current-dir produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
fi

echo "== zip-upload (MODE=SOURCE, syft fallback) — uploaded archive =="
# Zip the manifest (python3 is already required by assert_done, so no zip CLI
# dependency). The server extracts it under .uploads/<token>/ and scans as SOURCE.
# Component discovery off the extracted tree is syft-path-dependent (min 0); what
# this proves is that upload -> extract -> SOURCE reaches a valid, scoped done.
( cd "$SRC" && python3 -m zipfile -c "$WORK/app.zip" package.json ) 2>/dev/null
ztok="$(upload zip "$WORK/app.zip")"
if [ -z "$ztok" ]; then
    fail "zip upload returned no token"
elif stream "project=zipproj&version=1.0&source=zip-upload&token=$ztok&security=false"; then
    out="$(assert_done "zip-upload" SOURCE zipproj_1.0 0)"
    case "$out" in
        OK*) pass "zip-upload -> done.ok, SOURCE, prefix-scoped ($out)" ;;
        *)   fail "zip-upload done event wrong" "$out" ;;
    esac
else
    fail "zip-upload produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
fi

echo "== rootfs-dir (MODE=ROOTFS) — a subfolder of /src =="
# A directory target relative to /src routes to ROOTFS (syft dir). Component
# discovery from a bare manifest is syft-dependent, so the check is min 0 — what
# this proves is that the rootfs path reaches a valid, prefix-scoped done.
if stream "project=rootfsproj&version=1.0&source=rootfs-dir&target=subapp&security=false"; then
    out="$(assert_done "rootfs-dir" ROOTFS rootfsproj_1.0 0)"
    case "$out" in
        OK*) pass "rootfs-dir -> done.ok, ROOTFS, prefix-scoped ($out)" ;;
        *)   fail "rootfs-dir done event wrong" "$out" ;;
    esac
else
    fail "rootfs-dir produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
fi

echo "== firmware-upload (MODE=FIRMWARE) — only when unblob is in this image =="
# The base/scanoss image has no unblob, so this self-skips there; it exercises the
# web firmware path only on a SBOM_FIRMWARE=true image. Network-independent: a
# tiny non-firmware blob still drives upload -> FIRMWARE mode -> best-effort done.
if docker exec "$CID" sh -c 'command -v unblob >/dev/null 2>&1'; then
    printf 'not real firmware, just exercises the path\n' > "$WORK/fw.bin"
    ftok="$(upload firmware "$WORK/fw.bin")"
    if [ -z "$ftok" ]; then
        fail "firmware upload returned no token"
    elif stream "project=fwproj&version=1.0&source=firmware-upload&token=$ftok&security=false"; then
        out="$(assert_done "firmware-upload" FIRMWARE fwproj_1.0 0)"
        case "$out" in
            OK*) pass "firmware-upload -> done.ok, FIRMWARE, prefix-scoped ($out)" ;;
            *)   fail "firmware-upload done event wrong" "$out" ;;
        esac
    else
        fail "firmware-upload produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
    fi
else
    skip "firmware-upload: unblob not in this image (use a SBOM_FIRMWARE=true build)"
fi

echo "== git-url (MODE=SOURCE via clone) — opt-in, needs network =="
# A real clone is network-dependent and slower, so it is opt-in (WEB_GIT_E2E=1)
# and skipped by default — logged, never silent.
if [ "${WEB_GIT_E2E:-0}" = "1" ]; then
    if stream "project=gitproj&version=1.0&source=git-url&target=https://github.com/octocat/Hello-World&security=false"; then
        out="$(assert_done "git-url" SOURCE gitproj_1.0 0)"
        case "$out" in
            OK*) pass "git-url -> done.ok, SOURCE, prefix-scoped ($out)" ;;
            *)   fail "git-url done event wrong" "$out" ;;
        esac
    else
        fail "git-url produced no done event" "$(docker logs "$CID" 2>&1 | tail -5)"
    fi
else
    skip "git-url: set WEB_GIT_E2E=1 to clone over the network"
fi

echo "== regression #1: SCANOSS must fingerprint dot-prefixed (.uploads) paths =="
# Web uploads/clones land under OUTPUT_DIR/.uploads/<token>/extracted/... — a
# hidden path. scanoss-py skips dot-prefixed paths by DEFAULT, so without
# --all-hidden it finds zero files and vendored identification is always empty.
# We assert the flag's effect at the "files found to fingerprint" stage only:
# WITHOUT the flag scanoss prints "No files found to scan"; WITH it, it does not.
# This needs no OSSKB match, so it is network-independent and CI-stable.
if docker exec "$CID" sh -c 'command -v scanoss-py >/dev/null 2>&1'; then
    sig="$(docker exec "$CID" sh -c '
        HID=/host-output/.uploads/e2etok/extracted/proj
        mkdir -p "$HID"
        printf "%s\n" \
          "/* vendored AES-like source, >256 bytes so scanoss fingerprints it */" \
          "#include <stdint.h>" \
          "static const uint8_t SBOX[8]={0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5};" \
          "void enc(uint8_t*b){for(int i=0;i<8;i++)b[i]=SBOX[b[i]&7];}" \
          "int main(void){uint8_t x[8]={1,2,3,4,5,6,7,8};enc(x);return x[0];}" \
          "/* padding padding padding padding padding padding padding pad */" > "$HID/aes.c"
        no=$(scanoss-py scan "$HID" --skip-snippets --output /tmp/n.json 2>&1 \
               | grep -c "No files found to scan")
        yes=$(scanoss-py scan "$HID" --all-hidden --skip-snippets --output /tmp/y.json 2>&1 \
               | grep -c "No files found to scan")
        echo "${no}:${yes}"
    ' 2>/dev/null)"
    no_flag="${sig%%:*}"; with_flag="${sig##*:}"
    if [ "${no_flag:-0}" -ge 1 ] && [ "${with_flag:-9}" = "0" ]; then
        pass "scanoss skips dot path WITHOUT --all-hidden, fingerprints it WITH (regression #1)"
    else
        fail "scanoss hidden-path behaviour unexpected (no_flag=$no_flag with_flag=$with_flag)" \
             "expected no_flag>=1 (bug reproduces) and with_flag=0 (fix works)"
    fi
    # Belt-and-braces: the production script must actually pass the flag.
    if grep -q -- '--all-hidden' "$ROOT_DIR/docker/lib/identify-vendored.sh"; then
        pass "identify-vendored.sh passes --all-hidden to scanoss-py"
    else
        fail "identify-vendored.sh no longer passes --all-hidden (regression #1 would return)"
    fi
else
    skip "regression #1: scanoss-py not in this image (use a SBOM_SCANOSS=true build)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
