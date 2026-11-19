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

# A sub-folder of the launch folder (/src) is a deep-scan target too. The launch
# folder stands in at $WORK/launch; the server's SRC_DIR is pointed there.
LAUNCH="$WORK/launch"
mkdir -p "$LAUNCH/proj-a" "$LAUNCH/proj b/inner" "$LAUNCH/proj-c" "$LAUNCH/plain/sub" "$WORK/elsewhere/proj-z" "$WORK/out2"
echo '<project><groupId>g</groupId><version>2.4.1</version><parent><version>9.9.9</version></parent></project>' > "$LAUNCH/proj-a/pom.xml"
echo '<project/>' > "$LAUNCH/proj b/pom.xml"
echo '<project/>' > "$WORK/elsewhere/proj-z/pom.xml"
echo '{"name":"c","version":"0.3.0-rc.1"}' > "$LAUNCH/proj-c/package.json"
mkdir -p "$LAUNCH/proj-d"; printf '[package]\nname = "d"\nversion = "1.2.3"\n[dependencies]\nversion = "9"\n' > "$LAUNCH/proj-d/Cargo.toml"
mkdir -p "$LAUNCH/proj-e"; printf 'group = "x"\nversion = "3.1.0"\n' > "$LAUNCH/proj-e/build.gradle"
ln -s "$WORK/elsewhere" "$LAUNCH/out-link"
ln -s "$WORK/elsewhere/proj-z" "$LAUNCH/out-proj-link"
ln -s "$LAUNCH/proj-a" "$LAUNCH/in-link"

echo "== a sub-folder of the launch folder is a deep-scan target =="
if SBOM_OUTPUT_DIR="$WORK/out2" python3 -I - "$ROOT_DIR" "$LAUNCH" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
launch, work = sys.argv[2], sys.argv[3]
server.SRC_DIR = launch
server.ALLOWED_SCAN_ROOTS = [launch]
server.EXTRA_SCAN_ROOTS = []

# The sub-folder, by relative or absolute-looking path, resolves to itself.
for given in ("proj-a", "/proj-a", "proj b/inner"):
    d = server.safe_scan_dir(given)
    assert d == os.path.realpath(os.path.join(launch, given.lstrip("/"))), (given, d)
    src, rel = server.deep_copy_source(d)
    assert src == d and rel == given.lstrip("/"), (given, src, rel)

# Only that folder is copied: no sibling project comes along.
d = server.safe_scan_dir("proj-a")
dest = os.path.join(work, "copy-a")
server.copy_scan_target_tree(server.deep_copy_source(d)[0], dest)
assert os.listdir(dest) == ["pom.xml"], os.listdir(dest)

# The launch folder itself is the current-dir input, not this one.
assert server.deep_copy_source(server.safe_scan_dir("")) is None if server.safe_scan_dir("") else True
assert server.deep_copy_source(os.path.realpath(launch)) is None
assert server.launch_scan_subdir(os.path.realpath(launch)) is None

# A link to a place outside the launch folder, or a path through one, is refused.
for bad in ("out-link", "out-link/proj-z", "out-proj-link", "../elsewhere", "proj-a/../../elsewhere",
            "/../elsewhere", "proj-a\x00", "nope", "%s/elsewhere/proj-z" % work):
    assert server.safe_scan_dir(bad) is None, bad
# Another root that is not registered is refused even by absolute path.
assert server.safe_scan_dir(os.path.join(work, "elsewhere", "proj-z")) is None
# A link that stays inside the launch folder resolves to its real place, so the
# copy source is that real folder and not a link.
d = server.safe_scan_dir("in-link")
assert d == os.path.realpath(os.path.join(launch, "proj-a")), d
assert server.deep_copy_source(d)[1] == "proj-a"
# The listing lookup does not follow a link in the middle of a path.
base = os.path.realpath(launch)
assert server.find_scan_entry(base, "out-link/proj-z") is None
assert server.find_scan_entry(base, "in-link/x") is None
assert server.find_scan_entry(base, "../elsewhere") is None
# A directory that is not a registered root and not under the launch folder.
assert server.deep_copy_source(os.path.join(work, "elsewhere")) is None
# The label is the host path the user knows, never a bare container path of another root.
assert server.scan_source_label("scan-target-src", "proj-a") != ""
assert server.scan_source_label("scan-target-src", "out-link") == ""
PY
then
    pass "launch sub-folder: resolves, copies only itself; .., links out, other roots and the folder itself are refused"
else
    fail "launch sub-folder checks failed (see assertion above)"
fi

echo "== a sub-folder of an added folder and of the launch folder do not mix =="
if SBOM_OUTPUT_DIR="$WORK/out2" SBOM_UI_SCAN_ROOTS="$WORK/elsewhere|/host/elsewhere" python3 -I - "$ROOT_DIR" "$LAUNCH" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
launch, work = sys.argv[2], sys.argv[3]
server.SRC_DIR = launch
server.ALLOWED_SCAN_ROOTS = [launch] + [r["path"] for r in server.EXTRA_SCAN_ROOTS]
d = server.safe_scan_dir(os.path.join(work, "elsewhere", "proj-z"))
assert d, "registered root path must resolve"
src, rel = server.deep_copy_source(d)
assert rel == "proj-z" and src == d, (src, rel)
assert server.picked_scan_root(d) is not None
# The launch folder's link into the registered root resolves, and is then a
# sub-folder of that root (its own root), not of the launch folder.
d2 = server.safe_scan_dir("out-proj-link")
assert d2 == d, (d2, d)
assert server.scan_source_label("scan-target-src", "out-proj-link") == "/host/elsewhere/proj-z"
PY
then
    pass "added-folder sub-folders keep their own root; a link into one resolves to it"
else
    fail "added-folder versus launch-folder resolution failed (see assertion above)"
fi

echo "== project_info: version from the manifest, sub-projects of a folder with none =="
if SBOM_OUTPUT_DIR="$WORK/out2" python3 -I - "$ROOT_DIR" "$LAUNCH" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
launch, work = sys.argv[2], sys.argv[3]
server.SRC_DIR = launch
server.ALLOWED_SCAN_ROOTS = [launch]
def info(rel):
    return server.project_info(server.safe_scan_dir(rel))
a = info("proj-a")
assert a["version"] == "2.4.1" and a["versionFrom"] == "pom.xml" and a["hasManifest"], a   # not the parent's
assert info("proj-c")["version"] == "0.3.0-rc.1"
assert info("proj-d")["version"] == "1.2.3", info("proj-d")                                 # [package], not [dependencies]
assert info("proj-e")["version"] == "3.1.0"
assert info("proj b")["version"] == "" and info("proj b")["hasManifest"] is True
# The launch folder has no manifest of its own and holds projects: they are listed.
top = server.project_info(os.path.realpath(launch))
assert top["hasManifest"] is False, top
assert top["subProjects"] == ["proj b", "proj-a", "proj-c", "proj-d", "proj-e"], top["subProjects"]  # links and plain/ left out
# A folder with its own manifest is one project, however many manifests are below it.
assert info("proj-a")["subProjects"] == []
# A manifest that is a link, too large, malformed or carries an odd version gives no version.
os.makedirs(os.path.join(launch, "odd"), exist_ok=True)
os.symlink(os.path.join(launch, "proj-a", "pom.xml"), os.path.join(launch, "odd", "pom.xml"))
assert info("odd")["version"] == "", info("odd")
open(os.path.join(launch, "odd", "package.json"), "w").write('{"version": "1.0; rm -rf /"}')
os.remove(os.path.join(launch, "odd", "pom.xml"))
assert info("odd")["version"] == ""
open(os.path.join(launch, "odd", "package.json"), "w").write('{"version": ')
assert info("odd")["version"] == ""
open(os.path.join(launch, "odd", "package.json"), "w").write("x" * (server._PROJECT_INFO_MAX_BYTES + 1))
assert info("odd")["version"] == ""
open(os.path.join(launch, "odd", "pom.xml"), "w").write('<!DOCTYPE p [<!ENTITY a "b">]><project><version>1.0</version></project>')
assert info("odd")["version"] == ""
PY
then
    pass "project_info reads the version from pom.xml/package.json/build.gradle/Cargo.toml and lists sibling projects; links, big, broken and odd files give nothing"
else
    fail "project_info checks failed (see assertion above)"
fi

echo "== results folder differs from the launch folder =="
if SBOM_OUTPUT_DIR="$WORK/out2" SBOM_UI_HOST_DIR="/home/u/proj" SBOM_UI_OUTPUT_HOST_DIR="/home/u/sbom-output" \
   python3 -I - "$ROOT_DIR" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
work = sys.argv[2]
assert server.output_host_dir() == "/home/u/sbom-output"
assert server.launch_is_output() is False
assert server.host_path_of(server.OUTPUT_DIR + "/run1") == "/home/u/sbom-output/run1"
assert server.host_path_of(server.SRC_DIR + "/a/b") == "/home/u/proj/a/b"
PY
then
    pass "output and launch folders map to their own host paths"
else
    fail "output host path mapping failed (see assertion above)"
fi
if SBOM_OUTPUT_DIR="$WORK/out2" SBOM_UI_HOST_DIR="/home/u/sbom-output" python3 -I - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
assert server.output_host_dir() == "/home/u/sbom-output"
assert server.launch_is_output() is True
PY
then
    pass "a launcher that mounts one folder as both is reported as launch folder = results folder"
else
    fail "launch_is_output for a single mount failed"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
