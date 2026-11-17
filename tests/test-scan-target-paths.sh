#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-scan-target-paths.sh - No-Docker unit tests for how the web server decides
# what a folder scan covers and how it shows it.
#
# The defect these guard: a folder added in the app (mounted read-only under
# /scan-targets/<name>) with a sub-folder chosen as the scan target was scanned
# whole. The sibling projects' manifests joined the SBOM, their build failures
# counted against the scan, the language came out "unknown", and the result page
# showed the container path (non-ASCII names replaced by dashes) as the scanned
# folder. Also covered: the scan stops at once, with a code an app can read, when
# the folder is empty inside the container (a folder the Docker engine's VM does
# not share is mounted empty).
#
# The functions are the server's own (docker/web/server.py is imported), not copies.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 required"; exit 1; }

WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT

# An added folder with a Korean name and a space, holding sibling projects, the
# way the app mounts it: the container path has the non-ASCII name as dashes and
# the host path is what the user picked.
ADDED="$WORK/scan-targets/-----"
HOST_LABEL="/Users/홍 길동/샘플 폴더"
mkdir -p "$ADDED/proj-a" "$ADDED/proj b/inner" "$ADDED/proj-c" "$ADDED/empty" "$WORK/outside" "$WORK/out"
echo '<project/>' > "$ADDED/proj-a/pom.xml"
echo '<project/>' > "$ADDED/proj b/pom.xml"
echo '<project/>' > "$ADDED/proj-c/pom.xml"
echo 'x' > "$ADDED/proj b/inner/Main.java"
ln -s "$WORK/outside" "$ADDED/escape"

echo "== a sub-folder picked inside an added folder is the scan root, not its parent =="
if SBOM_OUTPUT_DIR="$WORK/out" SBOM_UI_SCAN_ROOTS="$ADDED|$HOST_LABEL" \
   python3 -I - "$ROOT_DIR" "$ADDED" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
added, work = sys.argv[2], sys.argv[3]
HOST_LABEL = "/Users/홍 길동/샘플 폴더"

# The picked sub-folder resolves to itself and belongs to the added folder.
d = server.safe_scan_dir(added + "/proj-a")
assert d == os.path.realpath(added + "/proj-a"), d
assert server.picked_scan_root(d)["path"] == added, server.picked_scan_root(d)

# The copy source the handler builds from the listing: the sub-folder only.
base = os.path.realpath(added)
rel = os.path.relpath(d, base)
src = server.find_scan_entry(base, rel)
assert src == d, (src, d)
dest = os.path.join(work, "copy")
server.copy_scan_target_tree(src, dest)
assert os.listdir(dest) == ["pom.xml"], os.listdir(dest)     # no proj b, no proj-c

# A name with a space, and a deeper sub-folder, resolve the same way.
d2 = server.safe_scan_dir(added + "/proj b/inner")
rel2 = os.path.relpath(d2, base)
assert rel2 == "proj b/inner", rel2
assert server.find_scan_entry(base, rel2) == d2

# Choosing the added folder itself still means the whole folder.
whole = server.safe_scan_dir(added)
assert os.path.relpath(whole, base) == ".", whole

# What the result page shows is the user's own path, not the container path.
lab = server.scan_source_label("scan-target-src", added + "/proj b/inner")
assert lab == HOST_LABEL + "/proj b/inner", lab
assert server.scan_source_label("rootfs-dir", added) == HOST_LABEL
assert "-----" not in server.scan_source_label("scan-target-src", added + "/proj-a")
assert server.scan_source_label("git-url", added) == ""
assert server.scan_source_label("scan-target-src", "") == ""
PY
then
    pass "sub-folder copy holds only the chosen folder; the shown path is the host path (Korean + space intact)"
else
    fail "sub-folder scan root or label check failed (see assertion above)"
fi

echo "== path validation is as strict as before =="
if SBOM_OUTPUT_DIR="$WORK/out" SBOM_UI_SCAN_ROOTS="$ADDED|$HOST_LABEL" \
   python3 -I - "$ROOT_DIR" "$ADDED" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
added, work = sys.argv[2], sys.argv[3]
for bad in (added + "/../outside", added + "/escape", added + "/proj-a/../../outside",
            added + "/proj-a\x00", added + "/nope", "/etc", "../../etc", ""):
    assert server.safe_scan_dir(bad) is None, bad
    assert server.scan_source_label("scan-target-src", bad) == "", bad
# A link in the middle of a relative path is not followed when the copy source is looked up.
base = os.path.realpath(added)
assert server.find_scan_entry(base, "escape/x") is None
assert server.find_scan_entry(base, "../outside") is None
# The sink re-checks containment on its own.
try:
    server.copy_scan_target_tree(os.path.join(work, "outside"), os.path.join(work, "copy2"))
except ValueError:
    pass
else:
    raise AssertionError("copy_scan_target_tree accepted a path outside the scan roots")
PY
then
    pass "traversal, link escape, NUL and empty paths are still refused; the copy sink still checks containment"
else
    fail "path validation regressed (see assertion above)"
fi

echo "== a folder that is empty inside the container stops the scan with a code =="
if SBOM_OUTPUT_DIR="$WORK/out" SBOM_UI_SCAN_ROOTS="$ADDED|$HOST_LABEL" \
   python3 -I - "$ROOT_DIR" "$ADDED" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
added = sys.argv[2]

assert server.scan_target_not_visible(server.safe_scan_dir(added + "/proj-a")) is None
msg = server.scan_target_not_visible(server.safe_scan_dir(added + "/empty"))
assert msg and msg.startswith("SCAN_TARGET_NOT_VISIBLE:"), msg
assert "Colima" in msg and "File sharing" in msg and "홈 폴더" in msg, msg   # English and Korean
assert "/Users/홍 길동/샘플 폴더/empty" in msg, msg                          # the user's path
assert "-----" not in msg, msg                                              # not the container path

# The code reaches the done event: the tracker reads it from the scanner's [ERROR] line,
# and only a known code is passed on.
t = server._ScanErrorTracker()
t.feed("[ERROR] ANDROID_SDK_IMAGE_MISSING: Android SDK image not found: bomlens-android-sdk34:latest")
t.feed("        Build it once ...")
assert t.code == "ANDROID_SDK_IMAGE_MISSING", t.code
t2 = server._ScanErrorTracker()
t2.feed("[ERROR] SOMETHING_ELSE: not a known code")
assert t2.code is None
t3 = server._ScanErrorTracker()
t3.feed("[ERROR] plain failure")
assert t3.code is None
PY
then
    pass "an empty-in-container folder gives SCAN_TARGET_NOT_VISIBLE (English + Korean, host path); only known error codes are passed on"
else
    fail "not-visible message or error code handling failed (see assertion above)"
fi

echo "== the scanner's own Android stop carries the same code =="
out="$(CDXGEN_IMAGE_PREFIX=ghcr.io/cdxgen/ bash -c ". '$ROOT_DIR/docker/lib/source-detect.sh'; android_sdk_image_missing bomlens-android-sdk34:latest 34 ''" 2>&1)"
if printf '%s\n' "$out" | grep -q '^\[ERROR\] ANDROID_SDK_IMAGE_MISSING: Android SDK image not found: bomlens-android-sdk34:latest' \
   && printf '%s\n' "$out" | grep -q '^\[ERROR\] ANDROID_SDK_IMAGE_MISSING: 안드로이드 SDK 이미지가 없어' \
   && printf '%s\n' "$out" | grep -q 'docker build --build-arg ANDROID_API=34 -t bomlens-android-sdk34:latest https://github.com/'; then
    pass "android_sdk_image_missing: code on both blocks, and a build command that needs no local folder"
else
    fail "android_sdk_image_missing output" "$out"
fi
if grep -q 'android_sdk_image_missing "\$img" "\$api" ""' "$ROOT_DIR/docker/entrypoint.sh" \
   && grep -q '\[ "${CDXGEN_FAIL_REASON:-}" != "android-sdk-image" \] || exit 1' "$ROOT_DIR/docker/entrypoint.sh"; then
    pass "entrypoint.sh stops on a missing Android SDK image instead of falling back to a manifest-only scan"
else
    fail "entrypoint.sh no longer stops on a missing Android SDK image"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
