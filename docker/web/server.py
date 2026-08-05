#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# server.py — local web UI backend for BomLens (Python stdlib only).
# Runs inside the scanner image and drives /usr/local/bin/run-scan.
#   GET  /                -> index.html (React SPA)
#   GET  /capabilities    -> {firmware, docker}: which input types are usable here
#   GET  /results         -> JSON list of generated artifacts
#   GET  /download-all    -> zip of every generated artifact
#   GET  /file?name=...   -> serve one artifact (path-traversal guarded)
#   POST /upload?kind=... -> store an uploaded file, return a {token}
#   GET  /scan-stream?... -> Server-Sent Events: live scan log + final summary
#
# Input types (the `source` query param on /scan-stream):
#   current-dir   -> MODE=SOURCE  (syft dir scan of /src)
#   rootfs-dir    -> MODE=ROOTFS  (syft dir scan of <target>, a subfolder of /src)
#   git-url       -> clone <target> then MODE=SOURCE
#   zip-upload    -> extract uploaded zip then MODE=SOURCE
#   package-upload-> MODE=BINARY on a jar/deb/rpm, or extract a wheel then ROOTFS
#   sbom-upload   -> MODE=ANALYZE on the uploaded SBOM
#   firmware-upload -> MODE=FIRMWARE (only when unblob is present in this image)
#   ai-model      -> MODE=AIBOM on <model id> (only in the bomlens-aibom image)
#   docker-image  -> MODE=IMAGE on <target>
import glob
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.parse
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(WEB_DIR, "dist")  # built React SPA (Vite output)
# /host-output inside the container; overridable so the server can run standalone
# (e.g. the No-Docker UI contract test points it at a temp dir).
OUTPUT_DIR = os.environ.get("SBOM_OUTPUT_DIR", "/host-output")
SRC_DIR = "/src"
UPLOAD_DIR = os.path.join(OUTPUT_DIR, ".uploads")  # uploaded files + extracted/cloned trees
PORT = int(os.environ.get("UI_PORT", "8080"))
FIRMWARE_IMAGE = os.environ.get(
    "SBOM_FIRMWARE_IMAGE", "ghcr.io/sktelecom/bomlens-firmware:latest"
)
DEEP_CVE_IMAGE = os.environ.get(
    "SBOM_DEEP_CVE_IMAGE", "ghcr.io/sktelecom/bomlens-deep-cve:latest"
)
AIBOM_IMAGE = os.environ.get(
    "SBOM_AIBOM_IMAGE", "ghcr.io/sktelecom/bomlens-aibom:latest"
)
# In-process scan runner. Inside the image this is always the baked-in
# /usr/local/bin/run-scan; the No-Docker contract tests (tests/test-web-ui.sh)
# substitute a stub scanner here so the /scan-stream SSE protocol is testable
# without Docker. Server-env only — never derived from request input.
RUN_SCAN = os.environ.get("SBOM_RUN_SCAN", "/usr/local/bin/run-scan")
# The scanner image, used ONLY to convert a finished BOM to SPDX in a sibling
# container when this image has no syft of its own (the desktop app's base UI
# image). Same default+override as scan-sbom.sh's POSTPROCESS_IMAGE.
SCANNER_IMAGE = os.environ.get(
    "SBOM_SCANNER_IMAGE", "ghcr.io/sktelecom/bomlens:latest"
)
# Pipeline shell helpers. Baked in at /usr/local/lib/sbom (Dockerfile), but the
# server also runs straight from the source tree in the contract tests, where
# they sit next to docker/web/ — resolve both, server-env only.
LIB_DIR = os.environ.get("SBOM_LIB_DIR") or next(
    (d for d in ("/usr/local/lib/sbom", os.path.join(os.path.dirname(WEB_DIR), "lib"))
     if os.path.isdir(d)), "/usr/local/lib/sbom"
)

# Per-kind upload size caps (bytes).
#
# The SBOM cap is set from measurement, not preference. Build-system SBOMs are far
# larger than hand-written ones: a Yocto core-image-minimal SPDX 3.0 document is
# 15.8 MB, and a product image with more packages scales from there. Parsing peaks
# at ~4.8x the file size (15.8 MB in, 75.7 MB resident, 0.23 s), so 100 MB keeps the
# worst case near 500 MB of transient memory — affordable for a local single-run
# tool, while still refusing inputs large enough to threaten the container.
MAX_BYTES = {
    "sbom": 100 * 1024 * 1024,       # 100 MB
    "zip": 500 * 1024 * 1024,        # 500 MB
    "package": 500 * 1024 * 1024,    # 500 MB
    "firmware": 500 * 1024 * 1024,   # 500 MB
}
# Accepted extensions per upload kind (lowercased).
UPLOAD_EXTS = {
    # .spdx.tar.zst is what a Yocto SPDX 2.2 build deploys, and the only SBOM
    # such a build produces — there is no .spdx.json beside it to send instead.
    # Named in full rather than as .tar.zst, which would admit any zstd tarball.
    "sbom": (".json", ".xml", ".spdx", ".cdx.json", ".spdx.json", ".spdx.tar.zst"),
    "zip": (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar"),
    # Build artifacts a supplier ships instead of source. The list is measured,
    # not aspirational: syft's file scan reads java archives (an executable jar
    # yields its bundled dependencies) and OS packages (one component, the
    # package itself), while a python wheel yields nothing until it is unpacked
    # — see the routing in the package-upload branch. Formats that stayed at
    # zero either way (ruby gems, double-compressed) are deliberately absent, as
    # is .apk, which names both an Android and an Alpine package.
    # .exe/.msi/.dmg are installers: the components are inside, not in the outer
    # file, so they are unpacked through the firmware path rather than read as a
    # file (see the package-upload branch). Measured on a desktop media player's
    # own downloads — the Windows installer yields 1 component read as a file and
    # 39 unpacked, the macOS disk image 0 and 25.
    "package": (".jar", ".war", ".ear", ".deb", ".rpm", ".whl",
                ".exe", ".msi", ".dmg"),
    "firmware": (".bin", ".img", ".squashfs", ".sqsh", ".ubi", ".ubifs",
                 ".trx", ".chk", ".fw", ".rom", ".dlf",
                 # Compressed firmware images (unblob unpacks these), e.g. the
                 # OpenWRT *.img.gz releases. .zip belongs here because that is
                 # how most vendors ship a firmware download — D-Link, NETGEAR,
                 # TP-Link, Tenda and Zyxel images all arrive as one. The CLI has
                 # always taken them; leaving the extension out here meant the
                 # same file the CLI scans was refused by the upload form.
                 ".gz", ".tgz", ".tar", ".xz", ".bz2", ".lzma", ".zst", ".zip"),
}

# Content types for the static SPA bundle.
STATIC_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".map": "application/json",
    ".webmanifest": "application/manifest+json",
    # third-party-licenses.txt, generated into the bundle at build time. Without
    # this it would be served as octet-stream and download instead of opening.
    ".txt": "text/plain; charset=utf-8",
}

ARTIFACT_SUFFIXES = (
    "_bom.json", "_NOTICE.txt", "_NOTICE.html", "_NOTICE.pdf",
    "_security.json", "_security.md", "_security.html",
    "_conformance.json", "_conformance.md", "_conformance.html",
    "_risk-report.md", "_risk-report.html",
    "_bom.json.sig", "_scancode.json",
    # SPDX 2.3 export: converted from the final CycloneDX BOM, either by the CLI's
    # --spdx during the scan or on demand from the UI (GET /spdx-export), plus its
    # cosign signature when the CLI signed it.
    "_bom.spdx.json", "_bom.spdx.json.sig",
    # Source file tree (ScanCode-shaped, structure-only). Emitted by the scanner
    # for source-having modes so the UI's source-tree view works without the
    # opt-in ScanCode deep-license scan; the frontend prefers _scancode (which
    # carries licenses) when both exist.
    "_files.json",
    # Source snapshot (source-snapshot.py): the text content behind that tree,
    # captured during the scan because the scanned tree itself (a container's
    # /src, a firmware unpacker's temp dir) does not outlive it. Backs the file
    # viewer, and is served like any other artifact.
    "_source.json",
    # Supplier-SBOM header summary (describe-input-sbom.py, ANALYZE only): the
    # format, spec version, producing tool and authorship of the document as it
    # arrived, read before the conversion to CycloneDX rewrites all of it.
    "_input.json",
    # EPSS/KEV priority sidecar (scan-security.sh) and the SCANOSS vendored-OSS
    # SBOM (identify-vendored). Both back result views, so include them in the
    # download bundle and the per-scan results listing.
    "_security_epss.json", "_vendored.cdx.json",
    # AI compliance profile (generate-ai-profile.sh, AI SBOMs only): a governance
    # page that re-aggregates the G7 status, regulatory crosswalk and flagged
    # licenses. User-facing report in three formats, so list/download it.
    "_ai-profile.json", "_ai-profile.md",
)

# Recent-scans sidebar shows the newest N; older scans stay on disk but are not
# listed (the user deletes via the UI or the output folder).
RECENT_SCANS_CAP = 20

# Per-run scan-configuration sidecar (the inputs + toggles a scan was launched
# with), saved in the run folder so the UI can offer "re-scan with the same
# settings". The dot prefix keeps it out of list_results()/downloads and out of
# the /scans listing (list_scans skips dotfiles), and it NEVER records tokens or
# credentials — only the non-secret source/target and the on/off feature flags.
SCANMETA_NAME = ".scanmeta.json"


def safe_name(s):
    """Mirror entrypoint.sh filename normalization."""
    s = re.sub(r"[^a-zA-Z0-9.-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def output_prefix(project, version):
    """The {project}_{version} filename prefix every artifact of a scan shares."""
    return "%s_%s" % (safe_name(project), safe_name(version))


def safe_output_path(name):
    """Resolve a filename strictly inside OUTPUT_DIR (block path traversal)."""
    base = os.path.basename(name)
    if base != name or not base:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, base))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


def safe_prefix_path(prefix, suffix):
    """Resolve OUTPUT_DIR/<prefix><suffix> strictly inside OUTPUT_DIR. The prefix
    is normally already sanitized (output_prefix / scan_id_ok), but the summary
    helpers take it as a parameter, so re-check here: reject separators/traversal
    and confirm the realpath stays in OUTPUT_DIR. Returns None on a bad prefix."""
    if not isinstance(prefix, str) or not prefix or "/" in prefix or "\\" in prefix or ".." in prefix:
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, prefix + suffix))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


def run_dir(run_id):
    """Resolve a scan's run folder OUTPUT_DIR/<run_id> strictly inside OUTPUT_DIR.

    A scan's artifacts live in a per-run subfolder (run_id = the folder name,
    e.g. {prefix} or {prefix}_{timestamp}). The run_id must pass scan_id_ok (no
    separators / traversal); then confirm the realpath stays inside OUTPUT_DIR
    (blocks symlink escape). Returns the real path, or None on a bad id/escape.
    Same path-injection barrier as safe_output_path / safe_prefix_path."""
    if not scan_id_ok(run_id):
        return None
    path = os.path.realpath(os.path.join(OUTPUT_DIR, run_id))
    if not path.startswith(os.path.realpath(OUTPUT_DIR) + os.sep):
        return None
    return path


def run_file(run_id, suffix):
    """Resolve a scan's artifact ending in `suffix`, traversal-safe.

    Prefers the run subfolder: OUTPUT_DIR/<run_id>/*<suffix>. entrypoint.sh names
    files by the {prefix} (PROJECT/VERSION), which can differ from the folder name
    on a timestamped run, so we glob by suffix — one scan per folder means the
    suffix is unique. Each candidate's basename is re-joined and realpath-checked
    against the run folder boundary before it is returned (keeps the resolver
    visible to static analysis). Falls back to the legacy flat layout
    OUTPUT_DIR/<run_id><suffix> so pre-upgrade scans keep opening. Returns a path
    inside OUTPUT_DIR, or None."""
    d = run_dir(run_id)
    if d and os.path.isdir(d):
        droot = os.path.realpath(d)
        for hit in sorted(glob.glob(os.path.join(d, "*" + suffix))):
            base = os.path.basename(hit)
            cand = os.path.realpath(os.path.join(d, base))
            if cand.startswith(droot + os.sep) and os.path.isfile(cand):
                return cand
    return safe_prefix_path(run_id, suffix)


def run_artifact_path(run_id, name):
    """Resolve a single artifact by run id + basename, traversal-safe.

    Used by /file and /download-all. The name must be a bare basename (no
    separators). Prefers OUTPUT_DIR/<run_id>/<name>, realpath-checked against the
    run-folder boundary; falls back to the legacy flat OUTPUT_DIR/<name> (also
    when run_id is empty, for pre-upgrade scans). Returns None on a bad name."""
    base = os.path.basename(name or "")
    if not base or base != name:
        return None
    d = run_dir(run_id) if run_id else None
    if d and os.path.isdir(d):
        droot = os.path.realpath(d)
        cand = os.path.realpath(os.path.join(d, base))
        if cand.startswith(droot + os.sep) and os.path.isfile(cand):
            return cand
    return safe_output_path(base)


# Extra read-only scan-target mounts from `scan-sbom.sh --ui --mount <dir>`
# (or the Windows launcher's SBOM_UI_MOUNT_DIR). One "<container>|<host>" pair
# per line: the container path joins the rootfs-dir allow-list below, the host
# path is the label the UI shows the user. Server-env only — never derived
# from request input. Entries whose container path does not exist are dropped
# with a warning (a typo'd launcher mount, or a stale env).
def _parse_scan_roots(raw):
    roots = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        cpath, _, hpath = line.partition("|")
        cpath = os.path.normpath(cpath)
        if not os.path.isabs(cpath) or not os.path.isdir(cpath):
            print(f"[WARN] SBOM_UI_SCAN_ROOTS entry ignored (not a directory): "
                  f"{cpath}", file=sys.stderr)
            continue
        roots.append({"path": cpath, "hostPath": hpath})
    return roots


EXTRA_SCAN_ROOTS = _parse_scan_roots(os.environ.get("SBOM_UI_SCAN_ROOTS", ""))

# Directories the UI is allowed to scan as a ROOTFS target: the /src mount the
# UI was launched from, plus any extra `--mount` scan targets. The boundary
# check below applies to every root alike.
ALLOWED_SCAN_ROOTS = [SRC_DIR] + [r["path"] for r in EXTRA_SCAN_ROOTS]


def safe_scan_dir(rel):
    """Resolve a user-supplied directory path strictly inside an allowed scan
    root (block path traversal and symlink escape). Returns the real path on
    success, or None. Used by the rootfs-dir input — a relative path under /src,
    or an absolute container path inside an extra `--mount` scan root.
    """
    if not rel or any(c in rel for c in ("\x00", "\n", "\r")):
        return None
    if any(rel == r["path"] or rel.startswith(r["path"] + os.sep)
           for r in EXTRA_SCAN_ROOTS):
        real = os.path.realpath(rel)
    else:
        # Treat input as relative to /src: stripping any leading '/' folds an
        # absolute path like /etc back under /src, so it can't escape the boundary.
        real = os.path.realpath(os.path.join(SRC_DIR, rel.lstrip("/")))
    for root in ALLOWED_SCAN_ROOTS:
        r = os.path.realpath(root)
        if (real == r or real.startswith(r + os.sep)) and os.path.isdir(real):
            return real
    return None


# ---------------------------------------------------------------------------
# Yocto build directory
#
# A folder the user points at can be a Yocto build directory, and then the thing
# worth reading is not the tree — sysroots, native build tools, per-recipe work
# directories, none of which ships in the image — but the SBOM the build itself
# published under tmp/deploy/images/<machine>/. Recognize it and analyze that.
#
# This mirrors is_yocto_build_dir / yocto_spdx_candidates / yocto_pick_spdx in
# scripts/scan-sbom.sh; the two must agree, or the same folder would be read one
# way from the CLI and another from the UI. Rules, in the order they matter:
#   - conf/bblayers.conf and tmp*/deploy/images are bitbake's own and stand
#     alone, so a build that never emitted an SBOM is still recognized (and can
#     be told which setting to add) rather than scanned as a directory.
#   - deploy/images and *.manifest are ordinary names any project can carry, so
#     they count only alongside a document bitbake actually wrote.
#   - TMPDIR carries the C library suffix outside poky (tmp-glibc), hence tmp*.
# ---------------------------------------------------------------------------
_YOCTO_DOC_RE = re.compile(rb"bitbake|openembedded", re.IGNORECASE)
_SPDX2_RE = re.compile(rb'"spdxVersion"\s*:\s*"SPDX-2')


def _file_matches(path, pattern):
    """True when the file's bytes match `pattern` anywhere. Streamed with a small
    overlap so a marker straddling a chunk boundary is still found — an image
    SBOM runs to tens of megabytes and is not worth holding in memory."""
    try:
        with open(path, "rb") as fh:
            tail = b""
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    return False
                if pattern.search(tail + chunk):
                    return True
                tail = chunk[-64:]
    except OSError:
        return False


def is_yocto_spdx_doc(path):
    """True for an SPDX document bitbake produced. Both SPDX 2.x and 3.x name it
    as the creating tool; the container does the authoritative check
    (parse-yocto-spdx.py), this only decides whether a directory is Yocto's."""
    return os.path.isfile(path) and _file_matches(path, _YOCTO_DOC_RE)


def is_spdx2_doc(path):
    """True for an SPDX 2.x document. For a Yocto build that form is only an
    index: the packages live in per-recipe documents inside the sibling
    <image>.spdx.tar.zst, so it converts to an almost empty SBOM."""
    return _file_matches(path, _SPDX2_RE)


def containing_scan_root(path):
    """The allowed scan root `path` sits in, or None. /src and every extra
    `--mount` root, resolved, so a symlinked or relative spelling still matches
    the mount it belongs to."""
    real = os.path.normpath(os.path.realpath(path))
    for root in ALLOWED_SCAN_ROOTS:
        base = os.path.normpath(os.path.realpath(root))
        if real == base or real.startswith(base + os.sep):
            return base
    return None


def scan_root_dir(d):
    """The directory `d` names, rebuilt from the scan root that contains it.

    The request path is resolved by safe_scan_dir before it gets here, but the
    functions below walk the filesystem on their own, and a containment check
    they inherit from a caller is a guarantee they cannot see. So the path is
    rebuilt here instead: start at the allowed root, and take each component
    from what the directory actually contains rather than from the request. The
    value that reaches the filesystem calls is then made of our own root plus
    names read off the disk — a request naming something outside a root, or
    something that does not exist, produces None and no walk at all.
    """
    real = os.path.normpath(os.path.realpath(d))
    base = containing_scan_root(real)
    if base is None:
        return None
    rel = os.path.relpath(real, base)
    if rel in (".", os.curdir):
        return base if os.path.isdir(base) else None
    resolved = base
    for wanted in rel.split(os.sep):
        # os.pardir cannot appear (both sides are resolved), but a walk that
        # accepted one would climb out of the root, so refuse it outright.
        if wanted in ("", os.curdir, os.pardir):
            return None
        step = None
        try:
            with os.scandir(resolved) as entries:
                for entry in entries:
                    if entry.name == wanted:
                        step = os.path.join(resolved, entry.name)
                        break
        except OSError:
            return None
        if step is None:
            return None
        resolved = step
    return resolved if os.path.isdir(resolved) else None


def is_yocto_build_dir(d):
    """True when `d` is a Yocto build directory, a deploy tree, or the
    per-machine image folder inside one. Anything outside an allowed scan root
    is not one, by definition — the containment check is repeated here rather
    than taken on trust, because this is where the filesystem walk happens."""
    safe = scan_root_dir(d)
    if safe is None:
        return False
    if os.path.isfile(os.path.join(safe, "conf", "bblayers.conf")):
        return True
    esc = glob.escape(safe)
    if any(os.path.isdir(p) for p in glob.glob(os.path.join(esc, "tmp*", "deploy", "images"))):
        return True
    for pat in ("deploy/images/*/*.spdx.json", "images/*/*.spdx.json"):
        if any(is_yocto_spdx_doc(p) for p in glob.glob(os.path.join(esc, pat))):
            return True
    # An SPDX 2.x archive is compressed, so nothing in it can be searched for —
    # the name is the signal, and only bitbake writes it.
    for pat in ("deploy/images/*/*.spdx.tar.zst", "images/*/*.spdx.tar.zst", "*.spdx.tar.zst"):
        if any(os.path.isfile(p) for p in glob.glob(os.path.join(esc, pat))):
            return True
    if glob.glob(os.path.join(esc, "*.manifest")):
        if any(is_yocto_spdx_doc(p) for p in glob.glob(os.path.join(esc, "*.spdx.json"))):
            return True
    return False


def yocto_spdx_candidates(d):
    """Every image SPDX document in `d`, resolved, most specific location first. The looser
    `*.spdx.json` tier is consulted only when `<image>.rootfs.spdx.json` finds
    nothing, so an image document is never listed twice. bitbake publishes each
    artifact as a timestamped file plus an IMAGE_LINK_NAME symlink to it, so
    entries resolving to one file are collapsed — otherwise a single-image build
    would present a choice between two names for the same document."""
    safe = scan_root_dir(d)
    if safe is None:
        return []
    esc = glob.escape(safe)
    # The archive tiers are last because they are the SPDX 2.x form: a 3.0 build
    # leaves a .spdx.json and no archive, and a 2.2 build leaves the archive and
    # nothing else — its image document is packed inside, not written beside it.
    for tier in (".rootfs.spdx.json", ".spdx.json", ".rootfs.spdx.tar.zst", ".spdx.tar.zst"):
        hits, seen = [], set()
        for pat in ("tmp*/deploy/images/*/*", "deploy/images/*/*", "images/*/*", "*"):
            for p in sorted(glob.glob(os.path.join(esc, pat + tier))):
                if not os.path.isfile(p):
                    continue
                real = os.path.realpath(p)
                if real in seen:
                    continue
                seen.add(real)
                hits.append(p)
        if hits:
            return hits
    return []


# Files that end in .manifest but are not the image package manifest.
_NOT_IMAGE_MANIFEST = ("image_license.manifest",)


def yocto_manifest_in(d):
    """The image package manifest in `d`, when the build wrote one.

    A build with no SPDX still records what it shipped: <image>.manifest lists
    every installed package. image_license.manifest sits beside it and describes
    the image recipe rather than its contents, so it does not count. Only the
    presence is decided here — parse-yocto-manifests.py reads the contents.
    """
    safe = scan_root_dir(d)
    if safe is None:
        return None
    esc = glob.escape(safe)
    for pattern in ("tmp*/deploy/images/*/*.manifest", "deploy/images/*/*.manifest",
                    "images/*/*.manifest", "*.manifest"):
        for path in sorted(glob.glob(os.path.join(esc, pattern))):
            if os.path.isfile(path) and os.path.basename(path) not in _NOT_IMAGE_MANIFEST:
                return path
    return None


def yocto_pick_spdx(candidates):
    """The one document to analyze: SPDX 3.x over 2.x (only 3.x carries the
    installed set and the build's CVE verdicts), then most recently written.
    None when there is nothing to pick."""
    best3 = best2 = None
    for p in candidates:
        try:
            mtime = os.path.getmtime(p)
        except OSError:
            continue
        if is_spdx2_doc(p):
            if best2 is None or mtime > best2[1]:
                best2 = (p, mtime)
        elif best3 is None or mtime > best3[1]:
            best3 = (p, mtime)
    chosen = best3 or best2
    return chosen[0] if chosen else None


# Directories a build-based source scan re-resolves from manifests, so copying
# them wastes time and disk (and, for a 1.8 GB tree, dominates the copy). Skipped
# when cloning a read-only picked folder into a writable tree for a deep scan;
# cdxgen/build-prep reinstalls dependencies from the manifests it keeps.
_DEEP_COPY_SKIP = {
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "build", "dist", "out", "target", ".gradle", ".next", ".nuxt",
    "coverage", ".coverage", ".idea", ".vscode",
}


def copy_scan_target_tree(src, dest):
    """Copy a read-only picked folder into a writable tree for a deep (build)
    source scan, skipping heavy re-resolvable dirs (_DEEP_COPY_SKIP).

    The desktop app mounts a chosen folder read-only at /scan-targets/<name>, but
    cdxgen's build-prep must WRITE into the source tree (install deps, drop the
    bom). So the tree is cloned into a writable dir under OUTPUT_DIR — which maps
    to a host mount (host_path_of), letting the sibling cdxgen container see it via
    --volumes-from, exactly like the current-dir path. The user's folder is never
    touched. Returns the destination root."""
    # Barrier at the filesystem sink: re-resolve and confirm the source stays
    # inside an allowed scan root. safe_scan_dir already did this on the caller's
    # side, but keeping realpath + containment local to the copy stops any future
    # caller from feeding an unchecked path here — and it is the sanitizer the
    # py/path-injection analysis recognizes, so the taint is provably cleared.
    real_src = os.path.realpath(src)
    if not any(real_src == os.path.realpath(r) or real_src.startswith(os.path.realpath(r) + os.sep)
               for r in ALLOWED_SCAN_ROOTS):
        raise ValueError("scan source resolves outside the allowed scan roots")

    def _ignore(_dir, names):
        return [n for n in names if n in _DEEP_COPY_SKIP]
    shutil.copytree(real_src, dest, ignore=_ignore, symlinks=True,
                    ignore_dangling_symlinks=True, dirs_exist_ok=True)
    return dest


def firmware_capable():
    """The firmware tools (unblob) are only built into the firmware image."""
    return shutil.which("unblob") is not None


def scanoss_capable():
    """Vendored-OSS identification (scanoss-py) is only built in with SBOM_SCANOSS."""
    return shutil.which("scanoss-py") is not None


def aibom_capable():
    """AI-model SBOM generation (OWASP AIBOM Generator) lives only in the opt-in
    bomlens-aibom image — mirror scan-aibom.sh's detection."""
    aibom_dir = os.environ.get("AIBOM_DIR", "/opt/aibom-generator")
    return os.path.isfile(os.path.join(aibom_dir, "src", "cli.py")) or shutil.which("aibom") is not None


def docker_capable():
    # Socket path is env-overridable for the No-Docker contract tests only
    # (tests/test-web-ui.sh points it at a nonexistent path to exercise the
    # "socket not mounted" error branch even on hosts that DO have Docker).
    # Inside the image the mount path is fixed; server-env only.
    return os.path.exists(os.environ.get("SBOM_DOCKER_SOCK", "/var/run/docker.sock"))


def docker_cli_present():
    """A docker CLI in THIS image lets the base UI container launch a sibling
    firmware/aibom container via the mounted host socket (same pattern as the
    cdxgen language images in entrypoint.sh)."""
    return shutil.which("docker") is not None


def firmware_usable():
    """Firmware analysis is offered when either the tools are built into THIS
    image (run in-process) OR we can launch the firmware image as a sibling
    container (docker CLI + host socket). The sibling path is how the desktop
    app's permissive-only base UI image reaches the GPL-isolated firmware image."""
    return firmware_capable() or (docker_cli_present() and docker_capable())


def aibom_usable():
    """AI-model SBOMs are offered when the generator is in THIS image OR we can
    launch the aibom image as a sibling container (docker CLI + host socket)."""
    return aibom_capable() or (docker_cli_present() and docker_capable())


def deep_cve_capable():
    """Deep CVE matching (grype + a bundled NVD DB for maven CPE matching) is
    only built into the bomlens-deep-cve image."""
    return shutil.which("grype") is not None


def deep_cve_usable():
    """Deep CVE matching is offered on an uploaded SBOM when grype is in THIS
    image (run in-process) OR we can launch the deep-cve image as a sibling
    container (docker CLI + host socket). Mirrors aibom_usable()."""
    return deep_cve_capable() or (docker_cli_present() and docker_capable())


def spdx_convert_capable():
    """True when this image can convert a BOM to SPDX in-process: syft (the
    converter) plus jq (the validator) on PATH, and the pipeline helper present.
    The scanner image ships all three, so the normal deployment converts here."""
    return (shutil.which("syft") is not None and shutil.which("jq") is not None
            and os.path.isfile(os.path.join(LIB_DIR, "convert-to-spdx.sh")))


def spdx_convert_usable():
    """SPDX export is offered when this image can convert in-process OR we can
    launch the scanner image as a sibling to do it (docker CLI + host socket).
    Mirrors firmware_usable()/aibom_usable()."""
    return spdx_convert_capable() or (docker_cli_present() and docker_capable())


def list_results(run_id=None):
    """Generated artifacts for a scan. With a run_id, the artifacts in that scan's
    run folder OUTPUT_DIR/<run_id>/ (ARTIFACT_SUFFIXES only); when no run folder
    exists, the legacy flat {run_id}_* files in OUTPUT_DIR (pre-upgrade scans).
    With no run_id, the artifacts directly in OUTPUT_DIR (legacy flat layout)."""
    out = []
    if run_id is not None:
        d = run_dir(run_id)
        if d and os.path.isdir(d):
            for name in sorted(os.listdir(d)):
                p = os.path.join(d, name)
                if os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES):
                    out.append({"name": name, "size": os.path.getsize(p)})
            return out
        # Legacy flat layout: {run_id}_* artifacts in OUTPUT_DIR root.
        if os.path.isdir(OUTPUT_DIR):
            for name in sorted(os.listdir(OUTPUT_DIR)):
                p = os.path.join(OUTPUT_DIR, name)
                if not (os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES)):
                    continue
                if not name.startswith(run_id + "_"):
                    continue
                out.append({"name": name, "size": os.path.getsize(p)})
        return out
    # No run_id: legacy flat listing of every artifact in OUTPUT_DIR root.
    if os.path.isdir(OUTPUT_DIR):
        for name in sorted(os.listdir(OUTPUT_DIR)):
            p = os.path.join(OUTPUT_DIR, name)
            if os.path.isfile(p) and name.endswith(ARTIFACT_SUFFIXES):
                out.append({"name": name, "size": os.path.getsize(p)})
    return out


def scan_id_ok(sid):
    """A scan id is a filename prefix; allow only the safe_name charset (no
    path separators / traversal)."""
    return bool(sid) and re.fullmatch(r"[A-Za-z0-9._-]+", sid) is not None


def write_scanmeta(run_out, config):
    """Persist the scan-configuration sidecar inside an already-resolved run
    folder. run_out comes from run_dir (realpath confirmed inside OUTPUT_DIR) and
    SCANMETA_NAME is a fixed dot-prefixed basename, so the write stays inside the
    run folder and out of list_results(). Best-effort: a write failure must not
    abort the scan. The caller must never put secrets in `config`."""
    try:
        with open(os.path.join(run_out, SCANMETA_NAME), "w") as f:
            json.dump(config, f)
    except OSError:
        pass


def scanmeta(run_id):
    """Read the scan-configuration sidecar (SCANMETA_NAME) for a past run.

    Traversal-safe: run_dir re-applies the scan_id_ok allowlist + realpath
    boundary before the fixed dot-prefixed basename is joined, so the read can
    never escape OUTPUT_DIR. Returns the stored dict (source + non-secret feature
    toggles the scan was launched with), or None when the sidecar is absent (a
    pre-feature scan) or unreadable."""
    d = run_dir(run_id)
    if not d or not os.path.isdir(d):
        return None
    p = os.path.join(d, SCANMETA_NAME)
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


# Row caps so a huge SBOM/scan can't bloat the SSE 'done' payload. The counts
# (sbom.components, severity totals) stay exact; only the detail lists are capped.
MAX_COMPONENT_ROWS = 2000
MAX_VULN_ROWS = 2000
MAX_VULN_REFS = 12  # reference links per CVE in the detail view
MAX_VULN_DESC = 600  # description chars per CVE (keeps the SSE payload bounded)
MAX_CONFORMANCE_MISSING = 50  # missing items per conformance check
MAX_CHECK_REGULATIONS = 12  # regulation refs mapped to one conformance check
MAX_GUIDANCE_SNIPPET = 2000  # chars of the CycloneDX fill-in fragment per check
MAX_CROSSWALK_FRAMEWORKS = 20  # frameworks in the regulatory crosswalk view
MAX_CROSSWALK_ELEMENTS = 200  # mapped elements listed per framework
MAX_CROSSWALK_REFS = 12  # regulation refs per crosswalk element
MAX_ASSESS_MODELS = 50  # assessed model entries in the AI profile card
MAX_ASSESS_REASONS = 20  # reason strings per assessed model
MAX_ASSESS_CONDITIONS = 20  # license conditions listed per assessed model
MAX_ASSESS_URLS = 8  # license source links per assessed model

# Severity ranking for picking a component's worst vulnerability.
_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}


def _as_list(v):
    """Return v when it is a list, else an empty list. CycloneDX does not force
    array fields (components, properties, licenses, externalReferences, hashes)
    to actually be arrays, and an ANALYZE scan copies an untrusted uploaded SBOM
    verbatim — so a scalar/null where a list is expected must degrade to empty
    instead of crashing the summary. No copy, no cost on the common (list) path."""
    return v if isinstance(v, list) else []


def _as_dict(v):
    """Return v when it is a dict, else an empty dict (same rationale as
    _as_list): an untrusted SBOM object field may arrive as a scalar/null."""
    return v if isinstance(v, dict) else {}


def _dicts(v):
    """The dict elements of a list-shaped field, skipping any non-dict entries
    (an untrusted `components`/`properties` array may hold scalars). Used before
    any `.get()` loop so a malformed element is ignored, not crashed on."""
    return [x for x in _as_list(v) if isinstance(x, dict)]


def _component_licenses(c):
    """SPDX ids / names / expressions for one CycloneDX component (notice parity)."""
    out = []
    for lic in _dicts(c.get("licenses")):
        node = _as_dict(lic.get("license"))
        val = node.get("id") or node.get("name") or lic.get("expression")
        if val:
            out.append(val)
    return out


def _cvss_best(v):
    """Highest CVSS score and its vector across Trivy's sources (V3, fallback V2).

    Mirrors scan-security.sh so the web detail view and the rendered report agree.
    Returns (score, vector) with score None when no source carries a score.
    """
    best_score = None
    best_vector = ""
    for src in (v.get("CVSS") or {}).values():
        if not isinstance(src, dict):
            continue
        score = src.get("V3Score")
        vector = src.get("V3Vector") or ""
        if score is None:
            score = src.get("V2Score")
            vector = src.get("V2Vector") or ""
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = vector
    return best_score, best_vector


def _epss_kev_map(run_id):
    """Per-CVE EPSS probability + CISA KEV flag, written by scan-security.sh as a
    sidecar (Trivy's _security.json carries neither). Empty when absent/offline."""
    p = run_file(run_id, "_security_epss.json")
    if not p or not os.path.isfile(p):
        return {}
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# Names the kernel arrives under: `linux_kernel` from a signature checker,
# `kernel` from an opkg or rpm database, and `linux-kernel` or `linux` from an
# advisory feed. Kept in step with the same list in docker/lib/scan-security.sh.
_KERNEL_PKG_NAMES = ("linux_kernel", "linux-kernel", "kernel", "linux")


def security_summary(run_id):
    p = run_file(run_id, "_security.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    priority = _epss_kev_map(run_id)
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    kernel = 0
    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            s = (v.get("Severity") or "UNKNOWN").upper()
            if s not in sev:
                s = "UNKNOWN"
            # Kernel advisories are counted on their own, matching the generated
            # report. A rootfs carries one kernel and an old one carries thousands
            # of advisories (measured: 5,262 and 5,032 on two consumer routers),
            # nearly all for subsystems the image never compiled in. Mixed into
            # the totals they make a device with two real criticals read like one
            # with two thousand. The same closed name list as scan-security.sh —
            # the kernel arrives under different names depending on which pass
            # found it.
            if (v.get("PkgName") or "").lower() in _KERNEL_PKG_NAMES:
                kernel += 1
                continue
            sev[s] += 1
            if len(vulns) < MAX_VULN_ROWS:
                score, vector = _cvss_best(v)
                desc = (v.get("Description") or "")[:MAX_VULN_DESC]
                cid = v.get("VulnerabilityID") or ""
                pr = priority.get(cid) or {}
                row = {
                    "id": cid,
                    "severity": s,
                    "pkg": v.get("PkgName") or "",
                    "installed": v.get("InstalledVersion") or "",
                    "fixed": v.get("FixedVersion") or "",
                    "title": v.get("Title") or "",
                    "cvss": score,
                    "cvssVector": vector,
                    "description": desc,
                    "url": v.get("PrimaryURL") or "",
                    "refs": (v.get("References") or [])[:MAX_VULN_REFS],
                }
                # EPSS (exploit probability, 0..1) + CISA KEV (actively exploited).
                epss = pr.get("epss")
                if isinstance(epss, (int, float)):
                    row["epss"] = epss
                if pr.get("kev"):
                    row["kev"] = True
                vulns.append(row)
    sev["TOTAL"] = sum(sev.values())
    sev["vulnerabilities"] = vulns
    # Reported, but on its own line: a number the reader should see without it
    # moving the severity figures the screen is built around.
    if kernel:
        sev["kernelCount"] = kernel
    # scan-security.sh records a failed engine run as ScanError; surface it so
    # consumers can tell "scan failed" from a genuine zero-findings result.
    err = data.get("ScanError")
    if isinstance(err, dict) and err.get("Message"):
        sev["scanError"] = str(err["Message"])[:400]
    return sev


def _norm_purl(purl):
    """purl without qualifiers/subpath, lowercased — a stable join key across the
    SBOM (cdxgen) and the security report (Trivy), which may differ in qualifiers."""
    if not purl:
        return ""
    return purl.split("?", 1)[0].split("#", 1)[0].strip().lower()


def _component_risk_index(run_id):
    """Join the Trivy security report to packages: worst severity + count per
    package, keyed by normalized purl and by (name, version). Uncapped (unlike
    the detail list) so a component's Risk reflects every finding against it.
    Returns (by_purl, by_nv); both empty when there is no security report."""
    p = run_file(run_id, "_security.json")
    by_purl, by_nv = {}, {}
    if not p or not os.path.isfile(p):
        return by_purl, by_nv
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return by_purl, by_nv

    def bump(index, key, sev):
        cur = index.get(key)
        if cur is None:
            index[key] = {"sev": sev, "count": 1}
        else:
            cur["count"] += 1
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(cur["sev"], 0):
                cur["sev"] = sev

    for r in (data.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev not in _SEV_RANK:
                sev = "UNKNOWN"
            ident = v.get("PkgIdentifier")
            purl = ident.get("PURL") if isinstance(ident, dict) else None
            if purl:
                bump(by_purl, _norm_purl(purl), sev)
            name = (v.get("PkgName") or "").lower()
            if name:
                bump(by_nv, (name, v.get("InstalledVersion") or ""), sev)
    return by_purl, by_nv


def _scope_index(data):
    """Per-ref dependency scope from CycloneDX dependencies[]: 'direct' (the root
    component depends on it) vs 'transitive'. Mirrors the client sbomGraph: roots
    are the metadata component's dependsOn, or refs nothing depends on when the
    root has no entry. Returns (scope_by_ref, has_dependencies)."""
    deps = _as_list(data.get("dependencies"))
    adjacency, depended_on = {}, set()
    for d in deps:
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            continue
        targets = [t for t in _as_list(d.get("dependsOn")) if isinstance(t, str)]
        adjacency[d["ref"]] = targets
        depended_on.update(targets)
    if not any(adjacency.values()):
        return {}, False

    meta_comp = _as_dict(_as_dict(data.get("metadata")).get("component"))
    meta_ref = meta_comp.get("bom-ref") or meta_comp.get("purl")
    # The root's direct deps are the metadata component's dependsOn. cdxgen
    # sometimes emits the root entry with an EMPTY dependsOn and floats the real
    # direct deps as nodes nothing depends on — so require a non-empty list
    # before trusting it, otherwise fall back to those orphan roots (matches the
    # client's tree). `adjacency.get` is empty/falsey for both the missing and
    # the empty-dependsOn case.
    if meta_ref and adjacency.get(meta_ref):
        roots = adjacency[meta_ref]
    else:
        roots = [r for r in adjacency if r not in depended_on]
    direct = set(roots)

    refs = set(adjacency)
    for targets in adjacency.values():
        refs.update(targets)
    return {ref: ("direct" if ref in direct else "transitive") for ref in refs}, True


def sbom_summary(run_id):
    p = run_file(run_id, "_bom.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    comps = _as_list(data.get("components"))
    risk_by_purl, risk_by_nv = _component_risk_index(run_id)
    scope_by_ref, has_deps = _scope_index(data)
    rows = []
    for c in comps[:MAX_COMPONENT_ROWS]:
        # An untrusted (ANALYZE) SBOM may hold a scalar where a component object
        # is expected — skip it rather than crash the whole summary.
        if not isinstance(c, dict):
            continue
        props = _dicts(c.get("properties"))
        vendored = any(
            p.get("name") == "bomlens:layer" and p.get("value") == "vendored"
            for p in props
        )
        # SCANOSS match confidence, surfaced read-only so a reviewer can eyeball it
        # (no accept/reject workflow — match triage belongs to TRUSCA).
        match = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:scanoss:match"),
            "",
        )
        # AI-relevant restrictive license class (behavioral-use / non-commercial),
        # set by normalize-sbom.sh via the shared license-flags.jq classifier.
        review = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:licenseReview"),
            "",
        )
        refs = _dicts(c.get("externalReferences"))
        source = next(
            (
                r.get("url")
                for r in refs
                if isinstance(r.get("url"), str)
                and r.get("type") in ("vcs", "distribution", "website")
            ),
            "",
        )
        # Proved present by ELF structure with no version recovered. It carries no
        # purl and no CPE, so no vulnerability database can be asked about it — a
        # clean vulnerability result does not cover it, and the row has to say so
        # rather than look like an ordinary component that happens to lack a
        # version field.
        presence_only = any(
            p.get("name") == "bomlens:evidenceGrade" and p.get("value") == "presence-only"
            for p in props
        )
        row = {
            "name": c.get("name") or "",
            "version": c.get("version") or "",
            "group": c.get("group") or "",
            "purl": c.get("purl") or "",
            "type": c.get("type") or "",
            "licenses": _component_licenses(c),
            "vendored": vendored,
            "presenceOnly": presence_only,
            "matchConfidence": match,
            "source": source,
            "copyright": c.get("copyright") or "",
        }

        # Scope: direct/transitive from the dependency graph (a component may be
        # addressed by bom-ref or purl). Omitted when the SBOM has no graph.
        if has_deps:
            scope = scope_by_ref.get(c.get("bom-ref")) or scope_by_ref.get(c.get("purl"))
            if scope:
                row["scope"] = scope

        # Risk: worst severity + count of vulnerabilities hitting this component.
        # Prefer the purl join; fall back to (name, version). Use one index only
        # so the count is not doubled.
        npurl = _norm_purl(c.get("purl"))
        risk = risk_by_purl.get(npurl) if npurl else None
        if risk is None:
            risk = risk_by_nv.get(((c.get("name") or "").lower(), c.get("version") or ""))
        if risk:
            row["maxSeverity"] = risk["sev"]
            row["vulnCount"] = risk["count"]

        if review:
            row["licenseReview"] = review

        # Outbound-license conflict, set by normalize-sbom.sh only when the SBOM's
        # root component declares a license (--license / PROJECT_LICENSE). Absent
        # means "not assessed" — the UI says so rather than implying an all-clear.
        conflict = next(
            (
                p.get("value")
                for p in props
                if p.get("name") == "bomlens:licenseConflict"
            ),
            "",
        )
        # Known-malicious package (enrich-malicious.sh, bundled OSV snapshot).
        # Deliberately not folded into maxSeverity/vulnCount: this is not a flaw
        # to patch but a package to remove, so the UI must be able to show it
        # apart from the severity counts.
        malicious = any(
            p.get("name") == "bomlens:malicious" and p.get("value") == "true"
            for p in props
        )
        if malicious:
            row["malicious"] = True
            mal_id = next(
                (p.get("value") for p in props if p.get("name") == "bomlens:malicious:id"),
                "",
            )
            if mal_id:
                row["maliciousId"] = mal_id
            mal_src = next(
                (p.get("value") for p in props if p.get("name") == "bomlens:malicious:source"),
                "",
            )
            if mal_src:
                row["maliciousSource"] = mal_src

        if conflict:
            row["licenseConflict"] = conflict
            why = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:licenseConflict:why"
                ),
                "",
            )
            if why:
                row["licenseConflictWhy"] = why

        # End-of-life: set by enrich-eol.sh from a bundled endoflife.date snapshot.
        # "true"/"false"/"unknown" for a mapped component; absent for unmapped ones
        # (implicitly unknown). Surfaced read-only so a reviewer sees which runtimes
        # /frameworks are past upstream support (a risk distinct from CVEs).
        eol = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:eol"), None
        )
        if eol:
            row["eol"] = eol
            eol_date = next(
                (p.get("value") for p in props if p.get("name") == "bomlens:eol:date"),
                None,
            )
            if eol_date:
                row["eolDate"] = eol_date

        # Version currency. bomlens:currency:* is offline (behind the latest patch
        # in the same cycle, from the endoflife snapshot). bomlens:staleness:* is
        # the opt-in deps.dev signal (absolute newest version, releases behind,
        # last-release date). Surfaced read-only.
        outdated = next(
            (
                p.get("value")
                for p in props
                if p.get("name") == "bomlens:currency:outdated"
            ),
            None,
        )
        if outdated:
            row["outdated"] = outdated
        latest_version = next(
            (p.get("value") for p in props if p.get("name") == "bomlens:staleness:latest"),
            None,
        ) or next(
            (
                p.get("value")
                for p in props
                if p.get("name") == "bomlens:currency:latestPatch"
            ),
            None,
        )
        if latest_version:
            row["latestVersion"] = latest_version
        releases_behind = next(
            (
                p.get("value")
                for p in props
                if p.get("name") == "bomlens:staleness:releasesBehind"
            ),
            None,
        )
        if releases_behind is not None:
            try:
                row["releasesBehind"] = int(releases_behind)
            except (TypeError, ValueError):
                pass
        last_released = next(
            (
                p.get("value")
                for p in props
                if p.get("name") == "bomlens:staleness:lastReleased"
            ),
            None,
        )
        if last_released:
            row["lastReleased"] = last_released

        # AI model/dataset risk verdict, stamped by assess-ai-risk.sh on
        # machine-learning-model and data components (license-terms registry +
        # HuggingFace file-scan / weight-format signals for models). Guidance,
        # not legal advice. Surfaced read-only and only for the AI component
        # types; an absent property means an absent field (the UI hides it).
        if c.get("type") in ("machine-learning-model", "data"):
            assessment = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:assessment:overall"
                ),
                None,
            )
            if assessment:
                row["assessment"] = assessment
            axes = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:assessment:axes"
                ),
                None,
            )
            if axes:
                row["assessmentAxes"] = axes
            reasons = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:assessment:reasons"
                ),
                None,
            )
            if reasons:
                row["assessmentReasons"] = reasons
            hf_status = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:hf:scan:status"
                ),
                None,
            )
            if hf_status:
                row["hfScanStatus"] = hf_status
            weight_formats = next(
                (
                    p.get("value")
                    for p in props
                    if p.get("name") == "bomlens:weights:formats"
                ),
                None,
            )
            if weight_formats:
                row["weightFormats"] = weight_formats

        rows.append(row)
    # suggest-identify-vendored: set by suggest-vendored.sh when the scan looks like
    # C/C++ embedded source with no package manager. Drives the result banner.
    meta_props = _dicts(_as_dict(data.get("metadata")).get("properties"))
    suggest = any(
        p.get("name") == "bomlens:suggest-identify-vendored" and p.get("value") == "true"
        for p in meta_props
    )
    # sbom-tool-degraded: set by entrypoint.sh when cdxgen couldn't run and the
    # scan fell back to syft (direct deps only) — e.g. "disk-space". Drives a
    # result banner so the thin dependency graph has a visible reason.
    degraded = next(
        (
            p.get("value")
            for p in meta_props
            if p.get("name") == "bomlens:sbom-tool-degraded"
        ),
        None,
    )
    # Direct/transitive split across ALL components (not just the capped rows),
    # so the Overview dependency tile is accurate on large SBOMs too. Zero when
    # the SBOM has no dependency graph (flat firmware/image SBOMs).
    direct_count = transitive_count = 0
    if has_deps:
        for c in comps:
            if not isinstance(c, dict):
                continue
            sc = scope_by_ref.get(c.get("bom-ref")) or scope_by_ref.get(c.get("purl"))
            if sc == "direct":
                direct_count += 1
            elif sc == "transitive":
                transitive_count += 1
    # End-of-life counts across ALL components (not just the capped rows), so the
    # KPI is accurate on large SBOMs. eolCount = components flagged past upstream
    # support; atRiskCount = those that ALSO carry a vulnerability — the actionable
    # set, since an EOL component has no upstream patch coming for its CVEs.
    eol_count = at_risk_count = outdated_count = 0
    # Model risk verdict KPI across ALL model components (not just the capped
    # rows): how many machine-learning-model components carry each
    # bomlens:assessment:overall verdict. Datasets are excluded — the tile
    # answers "can I use these models". Omitted entirely when no model carries
    # a verdict, so non-AI scans see no AI tile.
    assess_counts = {"ok": 0, "conditional": 0, "caution": 0, "review": 0}
    assessed_models = 0
    for c in comps:
        if not isinstance(c, dict):
            continue
        cprops = _dicts(c.get("properties"))
        if c.get("type") == "machine-learning-model":
            overall = next(
                (
                    p.get("value")
                    for p in cprops
                    if p.get("name") == "bomlens:assessment:overall"
                ),
                None,
            )
            if overall in assess_counts:
                assess_counts[overall] += 1
                assessed_models += 1
        if any(
            p.get("name") == "bomlens:currency:outdated" and p.get("value") == "true"
            for p in cprops
        ):
            outdated_count += 1
        if not any(
            p.get("name") == "bomlens:eol" and p.get("value") == "true" for p in cprops
        ):
            continue
        eol_count += 1
        npurl = _norm_purl(c.get("purl"))
        risk = risk_by_purl.get(npurl) if npurl else None
        if risk is None:
            risk = risk_by_nv.get(((c.get("name") or "").lower(), c.get("version") or ""))
        if risk and risk.get("count", 0) > 0:
            at_risk_count += 1
    meta_comp = _as_dict(_as_dict(data.get("metadata")).get("component"))
    summary = {
        "components": len(comps),
        "componentList": rows,
        "truncated": len(comps) > MAX_COMPONENT_ROWS,
        "suggestIdentifyVendored": suggest,
        "sbomToolDegraded": degraded,
        # CycloneDX root component type — drives the honest scan-kind subtitle and
        # works on re-open too, where the scan MODE isn't stored.
        "componentType": meta_comp.get("type"),
        "directCount": direct_count,
        "transitiveCount": transitive_count,
        "eolCount": eol_count,
        "atRiskCount": at_risk_count,
        "outdatedCount": outdated_count,
        # Counted over ALL components, not just the capped rows, so the figure is
        # right on a large SBOM. These have no version and so no advisory can be
        # looked up for them; the vulnerability panel says "0" about the rest of
        # the SBOM, not about these.
        "presenceOnlyCount": sum(
            1
            for c in comps
            if isinstance(c, dict)
            and any(
                p.get("name") == "bomlens:evidenceGrade" and p.get("value") == "presence-only"
                for p in _dicts(c.get("properties"))
            )
        ),
    }
    # Outbound license the project declares, and the conflict tally across ALL
    # components. Both omitted when nothing declared it — the UI then explains
    # how to turn the check on instead of showing an empty, all-clear table.
    outbound = next(
        (
            lic
            for lic in _component_licenses(meta_comp)
            if lic
        ),
        "",
    )
    if outbound:
        summary["outboundLicense"] = outbound
        conflict_counts = {"incompatible": 0, "conditional": 0, "unknown": 0, "compatible": 0}
        for c in comps:
            if not isinstance(c, dict):
                continue
            v = next(
                (
                    p.get("value")
                    for p in _dicts(c.get("properties"))
                    if p.get("name") == "bomlens:licenseConflict"
                ),
                None,
            )
            if v in conflict_counts:
                conflict_counts[v] += 1
        summary["conflictCounts"] = conflict_counts
    # Malicious-package count across ALL components, so the KPI is right on a
    # large SBOM too. Omitted when zero: the tile appears only when there is
    # something to act on, and its absence never claims the scan was clean —
    # the snapshot may simply not have been bundled.
    malicious_count = 0
    for c in comps:
        if not isinstance(c, dict):
            continue
        if any(
            p.get("name") == "bomlens:malicious" and p.get("value") == "true"
            for p in _dicts(c.get("properties"))
        ):
            malicious_count += 1
    if malicious_count:
        summary["maliciousCount"] = malicious_count
    if assessed_models:
        summary["assessCounts"] = assess_counts
    return summary


def scanoss_status(run_id):
    """SCANOSS vendored-ID outcome for the UI, read from the vendored SBOM's
    metadata: 'unavailable' (search failed — rate limit / no network / no token),
    'no-match' (ran clean but found nothing vendored), or 'matched'. None when
    vendored identification wasn't run (no vendored artifact)."""
    p = run_file(run_id, "_vendored.cdx.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    props = _dicts(_as_dict(data.get("metadata")).get("properties"))
    status = next(
        (x.get("value") for x in props if x.get("name") == "bomlens:scanoss:status"),
        None,
    )
    return {"status": status, "count": len(_as_list(data.get("components")))}


def yocto_vex_summary(run_id):
    """Build-time vulnerability judgements from a Yocto SPDX SBOM (ANALYZE only).

    Written by parse-yocto-spdx.py. The security report lists only what is still
    unresolved, so without these counts the UI cannot tell "this build patched
    12255 CVEs" from "we found nothing" — two very different statements. Absent
    (None) for every non-Yocto scan.
    """
    p = run_file(run_id, "_yocto_vex.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    def _count(value):
        return value if isinstance(value, int) and value >= 0 else 0

    j = data.get("judgements") if isinstance(data.get("judgements"), dict) else {}
    return {
        "fixed": _count(j.get("fixed")),
        "notAffected": _count(j.get("notAffected")),
        "affected": _count(j.get("affected")),
        "unresolved": _count(data.get("unresolved")),
    }


def conformance_summary(run_id):
    """Supplier-SBOM conformance verdict (ANALYZE mode only)."""
    p = run_file(run_id, "_conformance.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    # Per-check results drive the conformance / G7 section. The report is ours
    # (validate-sbom.sh), so it is trusted and already bounded, but normalize
    # defensively to a known shape and cap the missing lists.
    checks = []
    for c in (data.get("checks") or []):
        if not isinstance(c, dict):
            continue
        row = {
            "id": str(c.get("id") or ""),
            "label": str(c.get("label") or ""),
            "required": bool(c.get("required")),
            "status": str(c.get("status") or "warn"),
            "detail": str(c.get("detail") or ""),
            "missing": [str(m) for m in (c.get("missing") or [])][:MAX_CONFORMANCE_MISSING],
            "evidence": [str(e) for e in (c.get("evidence") or [])][:MAX_CONFORMANCE_MISSING],
            # G7 checks carry a cluster (metadata/slp/models/dp/infrastructure/sp/
            # kpi) and a data source (auto/inferred/declared/na); base format checks
            # leave these empty. Passed through so the UI can group by cluster and
            # badge how each element was satisfied. Dropped here => dropped from UI.
            "cluster": str(c.get("cluster") or ""),
            "source": str(c.get("source") or ""),
        }
        # Any check can carry a regulatory-crosswalk mapping (validate-sbom.sh
        # joins docker/lib/regulation-crosswalk.json by check id): the named
        # documentation obligations a gap in this check touches. G7 elements map to
        # the AI frameworks; the plain SBOM-format checks map to the CRA/NTIA SBOM
        # baselines. Informational only — it never changes a status. Preserved per
        # check so the UI can show "which regulation does this map to"; omitted when
        # absent.
        regs = [
            {
                "framework": str(r.get("framework") or ""),
                "ref": str(r.get("ref") or ""),
                "basis": str(r.get("basis") or ""),
                # Short display names (validate-sbom.sh joins them from the
                # crosswalk frameworks) so the UI can badge a check row with
                # "BSI TR-03183-2 Section 5.2.2" instead of the framework id.
                "short": str(r.get("short") or r.get("framework") or ""),
                "short_ko": str(r.get("short_ko") or r.get("short") or r.get("framework") or ""),
            }
            for r in (c.get("regulations") or [])
            if isinstance(r, dict)
        ][:MAX_CHECK_REGULATIONS]
        if regs:
            row["regulations"] = regs
        # Fill-in guidance for this element (validate-sbom.sh joins
        # docker/lib/g7-guidance.json by element id): the CycloneDX fragment that
        # would satisfy it, plus a reference link. Runs produced before the
        # guidance registry existed simply carry none, so treat it as optional.
        g = c.get("guidance")
        if isinstance(g, dict):
            snippet = str(g.get("snippet") or "")[:MAX_GUIDANCE_SNIPPET]
            doc_url = str(g.get("docUrl") or "")
            # The URL is rendered into an href; only accept an absolute https one
            # so a malformed report cannot turn it into a javascript: link.
            if not doc_url.startswith("https://"):
                doc_url = ""
            if snippet or doc_url:
                row["guidance"] = {"snippet": snippet, "docUrl": doc_url}
        checks.append(row)
    out = {
        "result": data.get("result", "unknown"),
        "format": data.get("format", ""),
        "checks": checks,
    }
    # Top-level regulatory crosswalk rollup (AI SBOMs only; validate-sbom.sh omits
    # the key entirely for non-AI SBOMs or when the crosswalk registry is absent).
    # Documentation-preparation view, not a compliance verdict. Surfaced as-is,
    # normalized defensively and capped.
    xwalk = _crosswalk_view(data.get("regulatoryCrosswalk"))
    if xwalk is not None:
        out["regulatoryCrosswalk"] = xwalk
    return out


def _crosswalk_view(xwalk):
    """Normalize a regulatoryCrosswalk object (top-level in _conformance.json and
    _ai-profile.json) to a bounded, known shape, or None when absent/empty.

    Shape: {disclaimer, frameworks:[{id,title,source,total,present,gap,review,
    elements:[{label,status,source,refs:[...]}]}]}. Trusted (our own generator)
    but capped so the SSE/scan payload stays light."""
    if not isinstance(xwalk, dict):
        return None
    frameworks = []
    for fw in (xwalk.get("frameworks") or []):
        if not isinstance(fw, dict):
            continue
        elements = []
        for e in (fw.get("elements") or [])[:MAX_CROSSWALK_ELEMENTS]:
            if not isinstance(e, dict):
                continue
            elements.append({
                "label": str(e.get("label") or ""),
                "status": str(e.get("status") or ""),
                "source": str(e.get("source") or ""),
                "refs": [str(x) for x in (e.get("refs") or [])][:MAX_CROSSWALK_REFS],
            })
        frameworks.append({
            "id": str(fw.get("id") or ""),
            "title": str(fw.get("title") or ""),
            "source": str(fw.get("source") or ""),
            "total": int(fw.get("total") or 0),
            "present": int(fw.get("present") or 0),
            "gap": int(fw.get("gap") or 0),
            "review": int(fw.get("review") or 0),
            "elements": elements,
        })
        if len(frameworks) >= MAX_CROSSWALK_FRAMEWORKS:
            break
    if not frameworks:
        return None
    return {
        "disclaimer": str(xwalk.get("disclaimer") or ""),
        "frameworks": frameworks,
    }


def ai_profile_summary(run_id):
    """AI compliance profile card summary (AI SBOMs only), read from the run's
    _ai-profile.json (generate-ai-profile.sh re-aggregates the conformance + SBOM
    artifacts; no new scan). Returns a light, card-sized rollup — the big arrays
    (g7.reviewItems, licenseReview.items, crosswalk elements) are dropped here to
    keep the SSE/scan payload small; the full detail lives in the artifact files
    the UI can download. None when no profile exists (i.e. not an AI SBOM)."""
    p = run_file(run_id, "_ai-profile.json")
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    g7 = data.get("g7") or {}
    clusters = []
    for cl in (g7.get("clusters") or []):
        if not isinstance(cl, dict):
            continue
        clusters.append({
            "cluster": str(cl.get("cluster") or ""),
            "total": int(cl.get("total") or 0),
            "present": int(cl.get("present") or 0),
            "gap": int(cl.get("gap") or 0),
            "review": int(cl.get("review") or 0),
        })
    lic = data.get("licenseReview") or {}
    xwalk = data.get("regulatoryCrosswalk") or {}
    frameworks = []
    for fw in (xwalk.get("frameworks") or [])[:MAX_CROSSWALK_FRAMEWORKS]:
        if not isinstance(fw, dict):
            continue
        frameworks.append({
            "id": str(fw.get("id") or ""),
            "title": str(fw.get("title") or ""),
            "total": int(fw.get("total") or 0),
            "present": int(fw.get("present") or 0),
            "gap": int(fw.get("gap") or 0),
            "review": int(fw.get("review") or 0),
        })
    out = {
        "conformanceResult": str(data.get("conformanceResult") or "unknown"),
        "g7": {
            "total": int(g7.get("total") or 0),
            "auto": int(g7.get("auto") or 0),
            "present": int(g7.get("present") or 0),
            "gap": int(g7.get("gap") or 0),
            "review": int(g7.get("review") or 0),
            "clusters": clusters,
        },
        "licenseReview": {
            "total": int(lic.get("total") or 0),
            "behavioral": int(lic.get("behavioral") or 0),
            "nonCommercial": int(lic.get("nonCommercial") or 0),
        },
        "regulatoryCrosswalk": {
            "disclaimer": str(xwalk.get("disclaimer") or ""),
            "frameworks": frameworks,
        },
    }
    # Model risk assessment (assess-ai-risk.sh verdicts re-aggregated by
    # generate-ai-profile.sh with the registry's summaries/conditions).
    # Guidance, not legal advice — the disclaimer travels with the data.
    # Normalized defensively and capped; omitted on pre-feature profiles.
    assess = data.get("riskAssessment")
    if isinstance(assess, dict):
        raw_counts = assess.get("counts") if isinstance(assess.get("counts"), dict) else {}
        models = []
        for m in (assess.get("models") or [])[:MAX_ASSESS_MODELS]:
            if not isinstance(m, dict):
                continue
            raw_axes = m.get("axes") if isinstance(m.get("axes"), dict) else {}
            models.append({
                "name": str(m.get("name") or ""),
                "version": str(m.get("version") or ""),
                "license": str(m.get("license") or ""),
                "overall": str(m.get("overall") or ""),
                "usageContext": str(m.get("usageContext") or ""),
                # Only the axes actually evaluated for this model (empty-string
                # placeholders in the artifact are dropped).
                "axes": {
                    k: str(raw_axes.get(k))
                    for k in ("license", "security", "datasets")
                    if raw_axes.get(k)
                },
                "reasons": [str(r) for r in (m.get("reasons") or [])][:MAX_ASSESS_REASONS],
                "summary": str(m.get("summary") or ""),
                "summary_ko": str(m.get("summary_ko") or ""),
                "conditions": [
                    {
                        "id": str(cond.get("id") or ""),
                        "label": str(cond.get("label") or ""),
                        "label_ko": str(cond.get("label_ko") or ""),
                    }
                    for cond in (m.get("conditions") or [])
                    if isinstance(cond, dict)
                ][:MAX_ASSESS_CONDITIONS],
                "sourceUrls": [str(u) for u in (m.get("sourceUrls") or [])][:MAX_ASSESS_URLS],
            })
        out["riskAssessment"] = {
            "usageContext": str(assess.get("usageContext") or ""),
            "disclaimer": str(assess.get("disclaimer") or ""),
            "disclaimer_ko": str(assess.get("disclaimer_ko") or ""),
            "counts": {
                k: int(raw_counts.get(k) or 0)
                for k in ("ok", "conditional", "caution", "review")
            },
            "models": models,
        }
    return out


def _max_severity(security):
    """Highest severity with a non-zero count in a security summary, else None."""
    if not security:
        return None
    for s in SEVERITY_ORDER:
        if security.get(s, 0) > 0:
            return s
    return None


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def list_scans():
    """Past scans in OUTPUT_DIR, newest first. Each scan is a run folder
    OUTPUT_DIR/<run_id>/ holding one *_bom.json (the id is the folder name); the
    legacy flat OUTPUT_DIR/{prefix}_bom.json layout is still listed too (id is the
    prefix), so pre-upgrade scans don't disappear. The real project/version come
    from the SBOM's metadata.component. Local files only; no account, no db."""
    scans = []
    if not os.path.isdir(OUTPUT_DIR):
        return scans

    def add_scan(run_id, bom_path):
        try:
            mtime = int(os.path.getmtime(bom_path))
            with open(bom_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        # An untrusted (ANALYZE) SBOM can hold scalars in components[]; iterate the
        # dict entries only so one poisoned scan folder can't crash the whole
        # Recent list (list_scans walks every scan in OUTPUT_DIR). The count still
        # reflects the full array length, to match sbom_summary's `components`.
        comp_count = len(_as_list(data.get("components")))
        comps = _dicts(data.get("components"))
        meta = _as_dict(_as_dict(data.get("metadata")).get("component"))
        # The OWASP AIBOM generator names the root metadata.component after its
        # job id (job-<timestamp>), which is meaningless in the Recent list. For
        # AI scans, label by the model component instead.
        model = next(
            (c for c in comps if c.get("type") == "machine-learning-model"), None
        )
        if model:
            project = model.get("name") or run_id
            version = model.get("version") or ""
        else:
            project = meta.get("name") or run_id
            version = meta.get("version") or ""
        scans.append({
            "id": run_id,
            "project": project,
            "version": version,
            "components": comp_count,
            "maxSeverity": _max_severity(security_summary(run_id)),
            "isAiScan": any(c.get("type") == "machine-learning-model" for c in comps),
            # CycloneDX root component type — lets the Recent list label the scan
            # honestly (application/firmware/container/operating-system/data),
            # straight from what the SBOM declares.
            "componentType": meta.get("type"),
            # What the scan was actually pointed at, from the run-folder sidecar.
            # The root component type alone cannot tell an analyzed supplier SBOM
            # from a source scan: both end up as "application", so a submitted
            # SBOM was labelled Source. None for a pre-sidecar scan, where the
            # type falls back to the component type as before.
            "inputSource": (scanmeta(run_id) or {}).get("source"),
            "generatedAt": mtime,
        })

    for entry in os.listdir(OUTPUT_DIR):
        if entry.startswith("."):  # .uploads and other dotfiles are not scans
            continue
        full = os.path.join(OUTPUT_DIR, entry)
        if os.path.isdir(full):
            # New layout: a per-run subfolder; find its (unique) *_bom.json.
            d = run_dir(entry)
            if not d or not os.path.isdir(d):
                continue
            boms = sorted(glob.glob(os.path.join(d, "*_bom.json")))
            if boms:
                add_scan(entry, boms[0])
        elif os.path.isfile(full) and entry.endswith("_bom.json"):
            # Legacy flat layout: id is the {prefix}.
            add_scan(entry[: -len("_bom.json")], full)

    scans.sort(key=lambda s: s["generatedAt"], reverse=True)
    return scans[:RECENT_SCANS_CAP]


def scan_detail(run_id):
    """A past scan as a done-event payload (its own artifacts only)."""
    sbom = sbom_summary(run_id)
    if sbom is None:
        return None
    return {
        "ok": True,
        "mode": None,
        "id": run_id,
        "results": list_results(run_id),
        "sbom": sbom,
        "security": security_summary(run_id),
        "conformance": conformance_summary(run_id),
        # Yocto build-time VEX counts (Yocto SPDX input only); None otherwise.
        "yoctoVex": yocto_vex_summary(run_id),
        # AI compliance profile card (AI SBOMs only); None otherwise. Paired with
        # the done-event payload below — keep both in sync.
        "aiProfile": ai_profile_summary(run_id),
        "scanoss": scanoss_status(run_id),
        # How the scan was launched (source + toggles), saved as a sidecar so the
        # UI can offer "re-scan with the same settings". None for pre-feature
        # scans that have no sidecar.
        "scanConfig": scanmeta(run_id),
    }


# --------------------------------------------------------------------------
# Upload handling
# --------------------------------------------------------------------------
def upload_token_dir(token):
    """Resolve UPLOAD_DIR/<token> for a well-formed token only, traversal-safe."""
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        return None
    base = os.path.realpath(os.path.join(UPLOAD_DIR, token))
    if not base.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        return None
    return base


def resolve_upload(token):
    """Return the single uploaded file inside UPLOAD_DIR/<token>, traversal-safe."""
    base = upload_token_dir(token)
    if base is None:
        return None
    if not os.path.isdir(base):
        return None
    for name in os.listdir(base):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return p
    return None


def _parse_boundary(content_type):
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return None
    b = m.group(1).strip().strip('"')
    return b.encode("latin-1") if b else None


def extract_file_part(rfile, length, boundary, dest_path):
    """Stream the single `file` part of a multipart body to dest_path.

    One pass, bounded memory (the pending window never exceeds ~64 KB + the
    boundary length). Returns the original client filename. Raises ValueError on
    a malformed body."""
    delim = b"--" + boundary
    remaining = length

    def read_chunk(n):
        nonlocal remaining
        n = min(n, remaining)
        if n <= 0:
            return b""
        d = rfile.read(n)
        remaining -= len(d)
        return d

    # Accumulate until we have the FILE part's header terminator. Other parts
    # (e.g. a text "kind" field) may precede it, so locate `filename=` first,
    # then the \r\n\r\n that closes that part's headers.
    buf = b""
    header_blob = rest = None
    while True:
        fpos = buf.find(b"filename=")
        if fpos != -1:
            term = buf.find(b"\r\n\r\n", fpos)
            if term != -1:
                header_blob = buf[:term]
                rest = buf[term + 4:]
                break
        chunk = read_chunk(8192)
        if not chunk:
            raise ValueError("no file part found")
        buf += chunk
        if len(buf) > (1 << 20):  # 1 MB of headers = abuse
            raise ValueError("multipart headers too large")

    fm = re.search(rb'filename="([^"]*)"', header_blob)
    filename = (fm.group(1).decode("utf-8", "replace") if fm else "upload.bin")

    closing = b"\r\n" + delim
    pending = rest
    with open(dest_path, "wb") as f:
        while True:
            idx = pending.find(closing)
            if idx != -1:
                f.write(pending[:idx])
                return filename
            # Flush all but a tail that might hold a partial boundary.
            if len(pending) > len(closing):
                safe = len(pending) - len(closing)
                f.write(pending[:safe])
                pending = pending[safe:]
            chunk = read_chunk(65536)
            if not chunk:
                f.write(pending)  # malformed; flush what we have
                return filename
            pending += chunk


def safe_extract_zip(zip_path, dest_dir):
    """Extract a zip, rejecting absolute/traversal members (zip-slip)."""
    dest_real = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise ValueError("unsafe path in archive: %s" % member)
        zf.extractall(dest_dir)


def scan_root_of(extract_dir):
    """If the extracted tree is a single wrapping dir, descend into it."""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


def host_path_of(container_path):
    """Map a path inside THIS container to the equivalent host path.

    The UI launches with `-v $(pwd):/src -v $(pwd):/host-output`, so both mount
    points resolve to the same host dir (SBOM_UI_HOST_DIR). The entrypoint needs
    the host path to bind-mount the scanned tree into the sibling cdxgen
    container. Returns "" when SBOM_UI_HOST_DIR is unset or the path falls
    outside the known mounts (the entrypoint then falls back to syft).
    """
    hostdir = os.environ.get("SBOM_UI_HOST_DIR", "")
    if not hostdir:
        return ""
    # Normalize backslashes so the posixpath math below joins cleanly on Windows.
    # Only the SOURCE path still calls this — to signal to the entrypoint that the
    # scanned tree is under a mount we own (the sibling then inherits it via
    # --volumes-from; the returned value itself is no longer used as a mount source,
    # so its drive form no longer matters). No-op for POSIX host dirs.
    hostdir = hostdir.replace("\\", "/")
    p = os.path.normpath(container_path)
    for base in (OUTPUT_DIR, SRC_DIR):
        b = os.path.normpath(base)
        if p == b:
            return hostdir
        if p.startswith(b + os.sep):
            return os.path.join(hostdir, os.path.relpath(p, b))
    return ""


def display_path_of(container_path):
    """The path to show a user for something inside this container.

    A folder the user picked is theirs, not ours: they know it as the host path
    they mounted (`--mount <dir>`, or the desktop app's Add folder), so print
    that. Extra scan roots carry their own host path; anything under /src maps
    through the launch folder. Falls back to the container path, which is at
    least true.
    """
    # Matched on the resolved path: a scan dir arrives realpath'd (safe_scan_dir)
    # while a mount is recorded as given, and on macOS those differ by /private.
    p = os.path.realpath(container_path)
    for root in EXTRA_SCAN_ROOTS:
        base = os.path.realpath(root["path"])
        host = root.get("hostPath") or ""
        if not host:
            continue
        if p == base:
            return host
        if p.startswith(base + os.sep):
            return os.path.join(host, os.path.relpath(p, base))
    return host_path_of(p) or os.path.normpath(container_path)


# Allowlist charsets for the image ref / model id / container name interpolated into
# the sibling docker-run command line. Each is enforced as an inline
# `re.fullmatch(<const>, value)` barrier in run_sibling_scan, in the same scope as the
# flow it gates: string substitution (re.sub) does NOT break command-injection taint, but
# a full-match guard the value must pass to reach the sink does. (Container paths — the
# output dir and the upload — are no longer bind-mounted by host path; they ride
# --volumes-from and are guarded by containment, see _path_under.)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*")          # image ref
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?")
_CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}")  # docker --name

# scan-firmware.sh emits `[firmware-cvedb-progress] NN%` on stdout while the
# (large, one-time) firmware CVE database downloads. The server turns each such
# marker into an SSE `progress` event instead of a plain log line.
_CVEDB_PROGRESS_RE = re.compile(r"^\[firmware-cvedb-progress\]\s+(\d+)%\s*$")


def _emit_or_log(line, on_log, on_progress=None):
    """Route a captured child-process line to the right SSE channel.

    If the line is a firmware CVE-DB progress marker and a progress handler is
    given, emit the clamped (0..100) percent via on_progress; otherwise pass the
    line through to on_log unchanged (preserving the existing log behaviour)."""
    m = _CVEDB_PROGRESS_RE.match(line) if on_progress is not None else None
    if m is not None:
        percent = max(0, min(100, int(m.group(1))))
        on_progress(percent)
    else:
        on_log(line)


# Modes this dispatcher may launch as a sibling. A fixed allowlist (not the raw
# caller string) is interpolated into the docker-run command line, so the MODE
# argument can only ever be one of these literals.
_SIBLING_MODES = ("FIRMWARE", "AIBOM", "ANALYZE")

# AI usage scenarios (the CLI's --usage) the model risk assessment may be scoped
# to; forwarded to assess-ai-risk.sh as AI_USAGE_CONTEXT. A closed allowlist:
# only one of these exact literals — never the request string — reaches the scan
# environment or a docker-run argv.
_USAGE_CONTEXTS = ("internal", "product", "redistribute", "outputs-only")


def _valid_image_ref(ref):
    """True for a plain image reference (registry/name[:tag][@digest]).

    The image comes from server env (SBOM_FIRMWARE_IMAGE / SBOM_AIBOM_IMAGE),
    not user input, but we still allowlist the charset so a misconfigured env
    can't smuggle a docker-run flag (no leading '-', no whitespace/separators).
    run_sibling_scan re-applies the same _REF_RE inline as the taint barrier."""
    return bool(ref) and _REF_RE.fullmatch(ref) is not None


def _valid_model_id(mid):
    """True for a HuggingFace model id (owner/name; owner optional).

    Shares _MODEL_RE with the inline barrier in run_sibling_scan, so the value
    that reaches the command line is charset-constrained (no leading '-', no
    whitespace, no path traversal) regardless of call site."""
    return bool(mid) and _MODEL_RE.fullmatch(mid) is not None


def _env_flag_value(value):
    """Sanitize a free-text value (project name/version) for a docker-run
    `-e KEY=<value>` argument.

    It is already a single argv element (subprocess is invoked with a list and
    shell=False, so it can never split into a new flag), but we additionally
    strip control characters and the few shell-significant bytes so the value
    that reaches the command line is a plain, bounded token."""
    return re.sub(r"[^\w.+:/ @=-]", "", (value or ""))[:256]


def _self_container_id():
    """This container's own id, for `docker run --volumes-from` (mirrors
    entrypoint.sh's self_container_id). Docker bind-mounts /etc/hostname et al. from
    /var/lib/docker/containers/<id>/, so the full id is in /proc/self/mountinfo
    regardless of cgroup version; fall back to $HOSTNAME (the short id by default)."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                m = re.search(r"/containers/([0-9a-f]{64})/", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return os.environ.get("HOSTNAME", "")


def _path_under(path, base):
    """True when `path` resolves inside `base` (both realpath'd) — the containment
    guard for a container path handed to a sibling via --volumes-from."""
    try:
        rp = os.path.realpath(path)
        rb = os.path.realpath(base)
    except OSError:
        return False
    return rp == rb or rp.startswith(rb + os.sep)


def run_sibling_scan(image, mode, out_dir, on_log, *, upload_file=None, model_id=None,
                     extra_env=None, on_progress=None, cancel=None, container_name=None):
    """Run a firmware/aibom SBOM scan in a SIBLING container.

    The desktop app's base UI image is permissive-only (no GPL firmware tools,
    no heavy aibom deps), so when the user picks firmware/AI we hand the job to
    the dedicated firmware/aibom image launched via the mounted host Docker
    socket — the same sibling pattern entrypoint.sh uses for cdxgen language
    images. The sibling runs the FULL run-scan pipeline (generate + normalize +
    notice + security + sign) with MODE set, writing finished artifacts straight
    into the run's output dir, which is under THIS container's OUTPUT_DIR. So the
    base container just streams the sibling's log and then summarizes the
    artifacts exactly as it does for an in-process scan.

    Sharing is by --volumes-from THIS container, NOT by host-path bind mounts: a
    host path (e.g. a Windows drive path C:/…) cannot be consumed by the
    in-container Linux docker CLI (the ':' splits the -v spec), which silently
    broke firmware/AI on Windows. --volumes-from replays the daemon's already
    resolved OUTPUT_DIR mount, so both `out_dir` and `upload_file` (both container
    paths under OUTPUT_DIR) are visible at the same paths on every host OS.
      out_dir      the run's output dir (HOST_OUTPUT_DIR / -w; == run_out)
      upload_file  the firmware upload, read in place as TARGET_FILE  [firmware only]
    The host socket is mounted so the firmware image can, in turn, do its own
    work; AIBOM needs only outbound network (HuggingFace).

    Returns the sibling's exit code, or -1 if docker could not be invoked.
    Streams every line (docker pull progress + scan log) through on_log so the
    SSE UX is identical to an in-process scan.
    """
    # Gate every user-influenced value with an inline full-match allowlist right
    # before it reaches the command line, and REBIND each name to the match's
    # group(0). The value that flows into the docker-run argv is then the freshly
    # extracted match, not the original (taint-carrying) string — a guard that
    # merely returns on a failed re.fullmatch but reuses the original variable
    # does NOT break command-injection taint, whereas `m.group(0)` does. The
    # charsets admit no leading '-', whitespace, ':' (which would split a -v
    # mount) or shell metacharacter.
    _m = _REF_RE.fullmatch(image) if image else None
    if _m is None:
        on_log("[ui] refusing to launch sibling: invalid image reference")
        return -1
    image = _m.group(0)
    if mode not in _SIBLING_MODES:
        on_log("[ui] refusing to launch sibling: unsupported mode")
        return -1
    # Pin MODE to the exact matched literal (drops the caller's string identity).
    mode = _SIBLING_MODES[_SIBLING_MODES.index(mode)]
    # Share via --volumes-from THIS container; we need its id.
    self_cid = _self_container_id()
    if not self_cid:
        on_log("[ui] cannot launch sibling: could not determine this container's id "
               "for --volumes-from")
        return -1
    # out_dir and upload_file are container paths passed into the sibling's -w /
    # HOST_OUTPUT_DIR / TARGET_FILE (never a -v spec, so no ':' split concern; the
    # subprocess list carries them as single argv values, so no shell parsing). Guard
    # each by CONTAINMENT — it must resolve inside OUTPUT_DIR / UPLOAD_DIR — which also
    # keeps a traversal-crafted path from escaping the shared tree.
    if not out_dir or not _path_under(out_dir, OUTPUT_DIR):
        on_log("[ui] cannot launch sibling: output dir is outside OUTPUT_DIR")
        return -1
    # The file to analyze is normally an upload, but a Yocto build directory
    # supplies one the scanner found inside an allowed scan root instead. Both
    # ride --volumes-from at the same path in the sibling, so the guard admits
    # either tree and nothing else.
    if upload_file is not None and not (
            _path_under(upload_file, UPLOAD_DIR)
            or any(_path_under(upload_file, r) for r in ALLOWED_SCAN_ROOTS)):
        on_log("[ui] refusing to launch sibling: input is outside the uploads dir "
               "and every scan root")
        return -1
    if model_id is not None:
        _m = _MODEL_RE.fullmatch(model_id)
        if _m is None:
            on_log("[ui] refusing to launch sibling: invalid model id")
            return -1
        model_id = _m.group(0)

    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)

    # Normalize the boolean-ish flags to exactly "true"/"false".
    def _bool_env(key):
        return "true" if env.get(key, "true") == "true" else "false"

    # A deterministic --name lets us stop this exact sibling on cancel. Rebind to
    # the allowlist match so only a safe name reaches the argv (never the caller's
    # string). An invalid/absent name just means no --name (cancel can't reach it).
    safe_name = None
    if container_name:
        _nm = _CONTAINER_RE.fullmatch(container_name)
        safe_name = _nm.group(0) if _nm else None

    args = [
        "docker", "run", "--rm",
        *(["--name", safe_name] if safe_name else []),
        # Inherit THIS container's mounts (incl. OUTPUT_DIR) instead of bind-mounting a
        # host path — a Windows drive path cannot be consumed by the in-container CLI.
        "--volumes-from", self_cid,
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", "MODE=%s" % mode,  # mode ∈ _SIBLING_MODES (checked above)
        "-e", "PROJECT_NAME=%s" % _env_flag_value(env.get("PROJECT_NAME", "")),
        "-e", "PROJECT_VERSION=%s" % _env_flag_value(env.get("PROJECT_VERSION", "")),
        # Outbound license (SPDX id) for the license-conflict check. Sanitized the
        # same way as the project name; empty means the check stays off.
        "-e", "PROJECT_LICENSE=%s" % _env_flag_value(env.get("PROJECT_LICENSE", "")),
        "-e", "HOST_OUTPUT_DIR=%s" % out_dir,  # container path, contained in OUTPUT_DIR
        "-e", "GENERATE_NOTICE=%s" % _bool_env("GENERATE_NOTICE"),
        "-e", "GENERATE_SECURITY=%s" % _bool_env("GENERATE_SECURITY"),
        # No GENERATE_SPDX: SPDX is exported on demand after the scan
        # (convert_bom_to_spdx), so the sibling never produces it.
        "-e", "GENERATE_REPORT=%s" % _bool_env("GENERATE_REPORT"),
    ]
    # Opt-in OSV advisories for firmware: forward only the two fixed control
    # values the UI may have set on the firmware path. We re-derive each from a
    # closed allowlist (never the env string itself) so no user-influenced text
    # can reach the docker-run argv. Absent/any-other value -> not forwarded,
    # so scan-firmware.sh keeps its offline-bundle default.
    if mode == "FIRMWARE":
        if env.get("CVE_BIN_TOOL_DISABLE_SOURCES") == "GAD":
            args += ["-e", "CVE_BIN_TOOL_DISABLE_SOURCES=GAD"]
        if env.get("CVE_BIN_TOOL_MODE") == "online":
            args += ["-e", "CVE_BIN_TOOL_MODE=online"]
    # Optional AI usage scenario for the model risk assessment: forwarded only on
    # the AIBOM path, and only as one of the fixed _USAGE_CONTEXTS literals (the
    # env string is compared, the allowlist literal is interpolated), so no
    # user-influenced text can reach the docker-run argv. Any other value is
    # simply not forwarded — assess-ai-risk.sh then runs without a scenario.
    if mode == "AIBOM":
        for _uc in _USAGE_CONTEXTS:
            if env.get("AI_USAGE_CONTEXT") == _uc:
                args += ["-e", "AI_USAGE_CONTEXT=%s" % _uc]
                break
    if upload_file is not None:
        # The upload lives under UPLOAD_DIR (inside OUTPUT_DIR), so --volumes-from
        # already exposes it at this same container path — read it in place, no extra
        # mount. Contained in UPLOAD_DIR (checked above) and passed as a single argv
        # value, so an odd upload filename cannot inject a flag or split a mount.
        # FIRMWARE reads it as TARGET_FILE; ANALYZE (deep-cve on an uploaded SBOM)
        # reads it as ANALYZE_SBOM.
        if mode == "ANALYZE":
            args += ["-e", "ANALYZE_SBOM=%s" % upload_file]
        else:
            args += ["-e", "TARGET_FILE=%s" % upload_file]
    # Deep CVE matching: forward the opt-in flag on the ANALYZE path only, from a
    # fixed literal (never the env string), so the deep-cve image's scan-security.sh
    # runs the grype maven NVD-CPE sidecar. The image swap itself is the caller's.
    if mode == "ANALYZE" and env.get("DEEP_CVE") == "true":
        args += ["-e", "DEEP_CVE=true"]
    if model_id is not None:
        # model_id passed _MODEL_RE above.
        args += ["-e", "MODEL_ID=%s" % model_id]
    # A HuggingFace credential, when this container was launched with one, is
    # forwarded by NAME ONLY so the value stays out of the argv (and out of `ps`).
    # The UI never accepts a token over HTTP: there is no credential store here,
    # and a posted secret would linger in request logs and run state.
    if mode == "AIBOM" and os.environ.get("HF_TOKEN"):
        args += ["-e", "HF_TOKEN"]
    # Upload gate: the sibling runs the same entrypoint, which defaults
    # UPLOAD_ENABLED to true and then exits 1 without credentials — so a web-UI
    # firmware/AIBOM/ANALYZE scan (all sibling modes) would report failure even
    # though every artifact was generated. Forward the flag so the sibling is
    # generate-only by default (the UI reads results from run_out, it does not
    # upload from the sibling), matching the in-process path. When the user DID
    # configure an upload, forward the destination too, with the API key by NAME
    # ONLY — its value rides the subprocess env below, never the argv/`ps`.
    # Default OFF for the sibling (generate-only) unless the caller explicitly
    # enabled upload — _bool_env defaults a missing flag to "true", which is the
    # wrong direction here and would re-introduce the failing upload gate.
    args += ["-e", "UPLOAD_ENABLED=%s" % ("true" if env.get("UPLOAD_ENABLED") == "true" else "false")]
    if env.get("UPLOAD_ENABLED") == "true":
        if env.get("UPLOAD_TARGET") in ("dependency-track", "trusca"):
            args += ["-e", "UPLOAD_TARGET=%s" % env["UPLOAD_TARGET"]]
        if env.get("API_URL"):
            args += ["-e", "API_URL=%s" % _env_flag_value(env["API_URL"])]
        if env.get("API_KEY"):
            args += ["-e", "API_KEY"]  # name only; value in the subprocess env
        for _k in ("TRUSCA_PROJECT_ID", "TRUSCA_REF", "TRUSCA_RELEASE"):
            if env.get(_k):
                args += ["-e", "%s=%s" % (_k, _env_flag_value(env[_k]))]
    # The sibling writes into the run's output dir; run-scan also cds there via cwd.
    args += ["-w", out_dir, "--entrypoint", "/usr/local/bin/run-scan", image]

    # Pull progress first so the (heavy, one-time) firmware/aibom image download
    # shows up in the live log rather than as a silent stall.
    if not _sibling_image_present(image):
        on_log("[ui] pulling %s (first run is large; one-time download)..." % image)
        # Through the same reader the pre-pull endpoint uses, so this path also
        # reports layer counts instead of stalling with only raw pull lines.
        _pull_image(image, on_log,
                    on_progress=(lambda snap: on_progress({"phase": "pull", **snap}))
                    if on_progress is not None else None,
                    cancel=cancel)

    on_log("[ui] launching %s in a sibling container (%s)..." % (mode.lower(), image))
    # Pass the assembled env (os.environ + extra_env) to the docker-run process so
    # a NAME-ONLY `-e API_KEY` / `-e HF_TOKEN` resolves the value from here instead
    # of the argv — keeping the upload token and HF token out of `ps`.
    return _stream_cmd(args, on_log, on_progress=on_progress, cancel=cancel,
                       container=safe_name, env=env)


def convert_bom_to_spdx(bom_path, spdx_path, stable, on_log):
    """Convert a finished CycloneDX BOM to SPDX 2.3 JSON, on demand.

    The UI does not decide SPDX before a scan (the pipeline always writes
    CycloneDX); the user asks for the conversion from the results screen, so this
    runs against an already-produced BOM. lib/convert-to-spdx.sh is pure
    post-processing on one input file — the same helper entrypoint.sh runs for the
    CLI's --spdx, so both paths produce an identical file.

    Runs in-process when this image has syft (the scanner image does). Otherwise
    the work goes to a SIBLING scanner container, the same --volumes-from pattern
    run_sibling_scan uses: both paths are container paths under OUTPUT_DIR, so
    they resolve identically in the sibling without a host bind mount (which a
    Windows drive path would break). Returns the exit code, -1 if unavailable.

    Signing is deliberately not offered here: the UI has no signing toggle at all,
    so an on-demand SPDX is unsigned like every other UI-produced artifact. Use the
    CLI's `--spdx --sign` when a signature is required.
    """
    # Both paths are server-derived (run_file / a fixed suffix on its basename),
    # never request text — but they cross into an argv, so confirm containment.
    if not _path_under(bom_path, OUTPUT_DIR) or not _path_under(os.path.dirname(spdx_path), OUTPUT_DIR):
        on_log("[ui] refusing to convert: path outside the output dir")
        return -1
    args = [bom_path, spdx_path] + (["--stable"] if stable else [])

    if spdx_convert_capable():
        return _stream_cmd(["bash", os.path.join(LIB_DIR, "convert-to-spdx.sh")] + args, on_log)

    if not (docker_cli_present() and docker_capable()):
        on_log("[ui] cannot export SPDX: no syft in this image and no docker socket")
        return -1
    # Same taint barrier as run_sibling_scan: rebind to the allowlist match so the
    # value reaching the argv is the freshly extracted one.
    _m = _REF_RE.fullmatch(SCANNER_IMAGE) if SCANNER_IMAGE else None
    if _m is None:
        on_log("[ui] refusing to launch sibling: invalid image reference")
        return -1
    image = _m.group(0)
    self_cid = _self_container_id()
    if not self_cid:
        on_log("[ui] cannot launch sibling: could not determine this container's id")
        return -1
    if not _sibling_image_present(image):
        on_log("[ui] pulling %s (one-time download)..." % image)
        _pull_image(image, on_log)
    return _stream_cmd([
        "docker", "run", "--rm",
        "--volumes-from", self_cid,
        "-w", os.path.dirname(bom_path),
        "--entrypoint", "bash", image,
        "/usr/local/lib/sbom/convert-to-spdx.sh",
    ] + args, on_log)


# --------------------------------------------------------------------------
# Pulling a per-feature image, with progress
#
# Firmware analysis, AI-model SBOMs and deep CVE matching each live in their own
# image rather than in this one: the firmware tools are GPL-family, and the AI
# dependencies are heavy. Those images are pulled on the feature's first use,
# which used to mean a multi-minute stall in the middle of a scan with only raw
# `docker pull` lines to show for it. The endpoints below let the UI pull one
# ahead of time and show how far it has got, and the same progress reading is
# applied to the first-use pull so that path is no longer a silent wait either.
#
# The keys are a closed set. A request names a feature, never an image reference:
# the reference comes from this server's own environment, so no request can make
# the daemon pull something else.
# --------------------------------------------------------------------------
def _pullable_images():
    """Feature key -> image reference, from server env only.

    `scanner` is deliberately absent. SPDX conversion falls back to the scanner
    image, but every published image is built from the one Dockerfile and carries
    syft, so spdx_convert_capable() is true in every shipped arrangement and the
    fallback never runs. A key with no arrangement that reaches it would be UI
    that cannot be tested; the set is closed, so it can be added if one appears.
    """
    return {"firmware": FIRMWARE_IMAGE, "aibom": AIBOM_IMAGE, "deep-cve": DEEP_CVE_IMAGE}


# A layer status line from `docker pull`. Ported from electron/lib/pullprogress.mjs
# (the desktop app's start screen), which the frontend cannot import: the SPA and
# the Electron app are separate packages, and the line arrives here as a child
# process line anyway. The two must agree, so both are tested against the same
# captured transcript (tests/fixtures/docker-pull-nontty.txt).
#
# Only layer counts are reported. A non-TTY `docker pull` prints no byte totals
# and no percentage — those belong to the TTY progress bar — so a percentage here
# would be invented. Total layers are counted from every layer id that appears,
# not from "Pulling fs layer" lines, because docker omits that line for layers it
# already has. Completion is decided by the pull's exit code, not by the count.
_PULL_LAYER_RE = re.compile(r"^([0-9a-f]{6,}):\s+(.+?)\s*$")
_PULL_DONE_STATUSES = ("Pull complete", "Already exists")


class PullProgress:
    """Accumulates layer statuses. feed() returns a snapshot only when the count
    changed, so a caller can emit one event per real change."""

    def __init__(self):
        self._layers = {}
        self._last = ""

    def snapshot(self):
        complete = sum(1 for st in self._layers.values() if st in _PULL_DONE_STATUSES)
        return {"complete": complete, "total": len(self._layers)}

    def feed(self, line):
        m = _PULL_LAYER_RE.match(str(line))
        if m is None:
            return None
        # A TTY progress bar can reach us when someone pipes a console log in;
        # drop the "[===>   ] 12MB/120MB" tail and keep the status name.
        status = re.sub(r"\s*\[.*$", "", m.group(2)).strip()
        self._layers[m.group(1)] = status
        snap = self.snapshot()
        key = "%d/%d" % (snap["complete"], snap["total"])
        if key == self._last:
            return None
        self._last = key
        return snap


# Why a pull failed, as a key the UI translates. Ported from the same module.
# Order matters: the specific signals (disk, name resolution) are checked before
# the general ones, because a proxy performing TLS interception shows up as x509
# and a corporate proxy refusing the connection as 403 or proxyconnect.
def classify_pull_failure(log_tail="", reason="exit"):
    if reason == "timeout":
        return "timeout"
    s = str(log_tail)
    if re.search(r"no space left on device|disk quota exceeded", s, re.I):
        return "disk"
    if re.search(r"no such host|dial tcp: lookup|name resolution"
                 r"|Temporary failure in name resolution", s, re.I):
        return "dns"
    if re.search(r"proxyconnect|x509|certificate signed by unknown authority"
                 r"|certificate is not trusted|\b403\b|Forbidden|tls: (?:bad|failed)", s, re.I):
        return "proxy"
    if re.search(r"unauthorized|authentication required|pull access denied|denied:", s, re.I):
        return "auth"
    return "unknown"


# How much of the pull log to keep for classify_pull_failure. A full pull log can
# run to megabytes.
_PULL_LOG_TAIL = 4096

# One pull per image at a time. ThreadingHTTPServer serves each request on its own
# thread, so without this two clicks would run two pulls of the same image. The
# daemon de-duplicates the layer downloads, so nothing breaks either way — there
# is simply no reason to run it twice.
_pull_lock = threading.Lock()
_pull_active = set()


def _pull_image(image, on_log, on_progress=None, cancel=None):
    """Pull an image, reporting layer progress. Returns (exit code, failure key).

    The failure key is None on success. Log lines that are not layer status lines
    pass through to on_log, so the existing live-log behaviour is unchanged for
    anything the progress reader does not recognise.
    """
    if not _valid_image_ref(image):
        on_log("[ui] refusing to pull: invalid image reference")
        return -1, "unknown"
    prog = PullProgress()
    tail = []

    def line(text):
        tail.append(text)
        if sum(len(x) for x in tail) > _PULL_LOG_TAIL:
            del tail[0]
        snap = prog.feed(text) if on_progress is not None else None
        if snap is not None:
            on_progress(snap)
        else:
            on_log(text)

    code = _stream_cmd(["docker", "pull", image], line, cancel=cancel)
    if code == 0:
        return 0, None
    return code, classify_pull_failure("\n".join(tail), "exit")


# Compressed download size for an image, read from the registry manifest, or None.
#
# This is the number of bytes the user waits for, which is what they need before
# deciding to start. It is NOT the installed size: the manifest carries compressed
# layer sizes only, and the on-disk size after extraction is not derivable from
# them. Measured on the published images: firmware downloads 0.42 GB and installs
# 1.81 GB, the AI image downloads 3.76 GB and installs 10.8 GB. So the UI says
# what the download is and does not guess at the rest.
#
# Cached because it is a network round trip; the value for a tag changes only when
# the tag is republished, and a stale value costs a wrong size estimate, not a
# wrong action.
_download_size_cache = {}


def _image_download_bytes(image):
    if image in _download_size_cache:
        return _download_size_cache[image]
    size = None
    if _valid_image_ref(image) and shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "manifest", "inspect", "--verbose", image],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=30)
            if r.returncode == 0:
                data = json.loads(r.stdout.decode("utf-8", "replace"))
                entries = data if isinstance(data, list) else [data]
                for e in entries:
                    desc = (e.get("Descriptor") or {})
                    plat = (desc.get("platform") or {})
                    # A multi-arch tag lists every platform; the one that matters is
                    # the one this daemon would pull. amd64/linux is the published
                    # platform (the registry publishes amd64 only).
                    if plat and plat.get("architecture") not in (None, "amd64"):
                        continue
                    layers = ((e.get("SchemaV2Manifest") or {}).get("layers") or [])
                    total = sum(int(l.get("size") or 0) for l in layers)
                    if total > 0:
                        size = total
                        break
        except (OSError, ValueError, subprocess.SubprocessError):
            size = None
    _download_size_cache[image] = size
    return size


def _sibling_image_present(image):
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except OSError:
        return False


def _stream_cmd(args, on_log, on_progress=None, cancel=None, container=None, env=None):
    """Run a command, streaming combined stdout/stderr line-by-line to on_log.
    Returns the exit code, or -1 if the binary could not be launched.

    rich (used by the firmware tools) rewrites the same terminal line via '\\r',
    so a single read can carry several logical lines; split on '\\r' and route
    each non-empty piece through _emit_or_log so progress markers are caught.

    When `cancel()` turns true mid-stream (the client closed the SSE), stop the
    named sibling container with `docker kill` and terminate the local docker-run
    process, so a cancelled firmware/AI scan doesn't keep running detached."""
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env,
        )
    except OSError as exc:
        on_log("[ui] failed to launch: %s" % exc)
        return -1
    for raw in proc.stdout:
        for piece in raw.rstrip("\n").split("\r"):
            if piece:
                _emit_or_log(piece, on_log, on_progress)
        if cancel and cancel():
            if container:
                try:
                    subprocess.run(["docker", "kill", container],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except OSError:
                    pass
            proc.terminate()
            break
    proc.wait()
    return proc.returncode


# Single-use private-repo tokens, stashed via POST /git-cred so the secret
# never travels in the scan-stream querystring (which could be logged/cached).
_GIT_CREDS = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # close-terminated; fine for one SSE per scan

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- GET ----
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/results":
            qs = urllib.parse.parse_qs(parsed.query)
            self._send(200, json.dumps(list_results((qs.get("id") or [""])[0] or None)))
        elif path == "/download-all":
            self._download_all(urllib.parse.parse_qs(parsed.query))
        elif path == "/capabilities":
            self._send(200, json.dumps({
                # `firmware`/`aibom` are the input-gating flags the frontend reads:
                # true when the input type is offerable here, whether the tools are
                # built into THIS image (run in-process) or reachable by launching
                # the firmware/aibom image as a SIBLING container (docker socket).
                "firmware": firmware_usable(),
                "scanoss": scanoss_capable(),
                "docker": docker_capable(),
                "aibom": aibom_usable(),
                # Deep CVE matching (maven NVD-CPE via grype) offered on uploaded
                # SBOMs: grype in THIS image, or reachable via the deep-cve sibling.
                "deepCve": deep_cve_usable(),
                # Whether the offer is satisfied by a sibling container (the desktop
                # app's permissive-only base UI image) — the frontend shows a
                # one-time "pulling the image" notice for the first sibling run.
                "firmwareSibling": not firmware_capable() and docker_cli_present() and docker_capable(),
                "aibomSibling": not aibom_capable() and docker_cli_present() and docker_capable(),
                "deepCveSibling": not deep_cve_capable() and docker_cli_present() and docker_capable(),
                # SPDX is exported on demand from the results screen (GET
                # /spdx-export), not chosen before a scan, so the frontend gates
                # the export button on this rather than on a scan-form toggle.
                "spdxExport": spdx_convert_usable(),
                "spdxSibling": not spdx_convert_capable() and docker_cli_present() and docker_capable(),
                # Whether a HuggingFace credential was handed to this container, so
                # the UI can say that private/gated models resolve. A boolean only —
                # the token itself is never exposed over the API.
                "hfAuth": bool(os.environ.get("HF_TOKEN")),
                "firmwareImage": FIRMWARE_IMAGE,
                "aibomImage": AIBOM_IMAGE,
                "deepCveImage": DEEP_CVE_IMAGE,
                "hostDir": os.environ.get("SBOM_UI_HOST_DIR", ""),
                # Extra --mount scan targets the rootfs-dir input can pick
                # from: container path (what the scan request sends) + host
                # path (what the user recognizes).
                "scanRoots": EXTRA_SCAN_ROOTS,
            }))
        elif path == "/spdx-export":
            self._spdx_export(urllib.parse.parse_qs(parsed.query))
        elif path == "/file":
            self._serve_file(urllib.parse.parse_qs(parsed.query))
        elif path == "/scans":
            self._send(200, json.dumps(list_scans()))
        elif path == "/scan":
            self._serve_scan(urllib.parse.parse_qs(parsed.query))
        elif path == "/scan-stream":
            self._scan_stream(urllib.parse.parse_qs(parsed.query))
        elif path == "/image-status":
            self._image_status(urllib.parse.parse_qs(parsed.query))
        elif path == "/pull-stream":
            self._pull_stream(urllib.parse.parse_qs(parsed.query))
        else:
            self._serve_static(path)

    # ---- POST ----
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/upload":
            self._upload(urllib.parse.parse_qs(parsed.query))
        elif parsed.path == "/git-cred":
            self._git_cred()
        elif parsed.path == "/scan-delete":
            self._scan_delete(urllib.parse.parse_qs(parsed.query))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def _scan_delete(self, qs):
        """Delete one past scan. New layout: remove the whole run folder
        OUTPUT_DIR/<id>/. Legacy flat layout: remove every {id}_* artifact.
        Local-only housekeeping (no account/db); the id is a validated run id."""
        sid = (qs.get("id") or [""])[0]
        if not scan_id_ok(sid):
            self._send(400, json.dumps({"error": "bad scan id"}))
            return
        removed = 0
        d = run_dir(sid)
        if d and os.path.isdir(d):
            # run_dir re-resolved {sid} with realpath and confirmed it stays
            # strictly inside OUTPUT_DIR (never OUTPUT_DIR itself), so the
            # recursive delete cannot escape the boundary.
            removed = sum(
                1 for n in os.listdir(d)
                if os.path.isfile(os.path.join(d, n)) and n.endswith(ARTIFACT_SUFFIXES)
            )
            shutil.rmtree(d, ignore_errors=True)
        else:
            for suf in ARTIFACT_SUFFIXES:
                # safe_prefix_path re-resolves {sid}{suf} with realpath and
                # confirms it stays inside OUTPUT_DIR, so the delete cannot escape
                # even though scan_id_ok already allowlisted the id. It also makes
                # the boundary explicit to static analysis.
                p = safe_prefix_path(sid, suf)
                if p and os.path.isfile(p):
                    try:
                        os.remove(p)
                        removed += 1
                    except OSError:
                        pass
        self._send(200, json.dumps({"deleted": sid, "removed": removed}))

    def _git_cred(self):
        """Stash a private-repo token; return a single-use credId."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 8192:
            self._send(400, json.dumps({"error": "bad credential request"}))
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            token = (data.get("token") or "").strip()
        except (ValueError, OSError):
            self._send(400, json.dumps({"error": "invalid JSON"}))
            return
        if not token:
            self._send(400, json.dumps({"error": "token required"}))
            return
        cid = secrets.token_hex(16)
        _GIT_CREDS[cid] = token
        self._send(200, json.dumps({"credId": cid}))

    def _upload(self, qs):
        kind = (qs.get("kind") or [""])[0]
        if kind not in MAX_BYTES:
            self._send(400, json.dumps({"error": "unknown upload kind"}))
            return
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            self._send(400, json.dumps({"error": "expected multipart/form-data"}))
            return
        boundary = _parse_boundary(ctype)
        if not boundary:
            self._send(400, json.dumps({"error": "missing multipart boundary"}))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._send(411, json.dumps({"error": "Content-Length required"}))
            return
        if length > MAX_BYTES[kind]:
            # Name the limit and the actual size: "too large" alone leaves the user
            # guessing whether trimming helps or the file is simply unsupported.
            self._send(413, json.dumps({
                "error": "file too large for %s: %.1f MB (limit %d MB)" % (
                    kind, length / (1024.0 * 1024.0), MAX_BYTES[kind] // (1024 * 1024)
                )
            }))
            return

        token = secrets.token_hex(16)
        dest_dir = os.path.join(UPLOAD_DIR, token)
        os.makedirs(dest_dir, exist_ok=True)
        tmp_path = os.path.join(dest_dir, "_incoming")
        try:
            filename = extract_file_part(self.rfile, length, boundary, tmp_path)
        except (ValueError, OSError) as exc:
            shutil.rmtree(dest_dir, ignore_errors=True)
            self._send(400, json.dumps({"error": "upload parse failed: %s" % exc}))
            return

        safe_fn = os.path.basename(filename) or "upload.bin"
        safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", safe_fn)
        lower = safe_fn.lower()
        if not lower.endswith(UPLOAD_EXTS[kind]):
            shutil.rmtree(dest_dir, ignore_errors=True)
            self._send(415, json.dumps({
                "error": "unsupported file type for %s (got %s)" % (kind, safe_fn)
            }))
            return
        final_path = os.path.join(dest_dir, safe_fn)
        os.replace(tmp_path, final_path)
        self._send(200, json.dumps({"token": token, "filename": safe_fn, "kind": kind}))

    def _serve_static(self, path):
        rel = path.lstrip("/") or "index.html"
        distroot = os.path.realpath(DIST_DIR)
        target = os.path.realpath(os.path.join(DIST_DIR, rel))
        inside = target == distroot or target.startswith(distroot + os.sep)
        if not inside or not os.path.isfile(target):
            target = os.path.join(DIST_DIR, "index.html")  # SPA fallback
        if not os.path.isfile(target):
            self._send(503, json.dumps({"error": "UI bundle not built"}))
            return
        ctype = STATIC_CTYPES.get(
            os.path.splitext(target)[1], "application/octet-stream"
        )
        with open(target, "rb") as f:
            self._send(200, f.read(), ctype)

    def _spdx_export(self, qs):
        """Convert a finished scan's CycloneDX BOM to SPDX 2.3 JSON on demand.

        SPDX is a format conversion of an artifact the scan already produced, so
        asking for it up front (as a scan option) only forced users to re-run a
        whole scan when they decided later. The converted file lands in the run
        folder under the name the pipeline would have used, which is already in
        ARTIFACT_SUFFIXES — so it joins the results listing and the download
        bundle with no further wiring.

        Idempotent: an existing SPDX file is returned as-is rather than rebuilt.
        Responds with the new artifact's name plus the refreshed results listing.
        """
        rid = (qs.get("id") or [""])[0]
        if not scan_id_ok(rid):
            self._send(400, json.dumps({"error": "invalid scan id"}))
            return
        bom = run_file(rid, "_bom.json")
        if not bom or not os.path.isfile(bom):
            self._send(404, json.dumps({"error": "no CycloneDX SBOM for this scan"}))
            return
        spdx = bom[: -len("_bom.json")] + "_bom.spdx.json"

        if not os.path.isfile(spdx):
            if not spdx_convert_usable():
                self._send(503, json.dumps({"error": "SPDX export is not available here"}))
                return
            # Match the original scan's reproducibility setting so the converted
            # file is what a --byte-stable run would have written.
            stable = bool((scanmeta(rid) or {}).get("byteStable"))
            log = []
            rc = convert_bom_to_spdx(bom, spdx, stable, log.append)
            if rc != 0 or not os.path.isfile(spdx):
                sys.stderr.write("[ui] SPDX export failed for %s:\n%s\n" % (rid, "\n".join(log)))
                self._send(500, json.dumps({"error": "SPDX conversion failed"}))
                return

        self._send(200, json.dumps({
            "name": os.path.basename(spdx),
            "results": list_results(rid),
        }))

    def _serve_file(self, qs):
        rid = (qs.get("id") or [""])[0]
        name = (qs.get("name") or [""])[0]
        # run_artifact_path joins the run folder (OUTPUT_DIR/<id>/<name>) and
        # realpath-checks the boundary, with a flat OUTPUT_DIR/<name> fallback for
        # pre-upgrade scans (and when no id is supplied by an older frontend).
        path = run_artifact_path(rid, name)
        if not path or not os.path.isfile(path):
            self._send(404, json.dumps({"error": "not found"}))
            return
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif name.endswith(".json") or name.endswith(".sig"):
            ctype = "application/json"
        else:
            ctype = "text/plain; charset=utf-8"
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)

    def _serve_scan(self, qs):
        """Re-open a past scan by id (its {prefix}). Traversal-safe."""
        sid = (qs.get("id") or [""])[0]
        if not scan_id_ok(sid):
            self._send(400, json.dumps({"error": "invalid scan id"}))
            return
        detail = scan_detail(sid)
        if detail is None:
            self._send(404, json.dumps({"error": "not found"}))
            return
        self._send(200, json.dumps(detail))

    def _download_all(self, qs=None):
        """Bundle one scan's generated artifacts into one in-memory zip.

        Artifacts are reports/JSON and stay small, so building the zip in a
        BytesIO and sending it with a fixed Content-Length fits the server's
        close-terminated model (no chunked transfer). With ?id=<run_id> only that
        scan's run folder is bundled; without an id (or for a pre-upgrade scan)
        the legacy flat layout is used. Only files already whitelisted by
        list_results() are added — no new path is exposed.
        """
        rid = ((qs or {}).get("id") or [""])[0]
        files = list_results(rid or None)
        if not files:
            self._send(404, json.dumps({"error": "no artifacts to download"}))
            return

        # Zip name from the shared "{project}_{version}" prefix; fall back to a
        # generic name if the artifacts don't share one.
        first = files[0]["name"]
        prefix = first
        for suf in ARTIFACT_SUFFIXES:
            if first.endswith(suf):
                prefix = first[: -len(suf)]
                break
        prefix = prefix.strip("._")
        zip_name = (prefix + "_sbom-artifacts.zip") if prefix else "sbom-artifacts.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                path = run_artifact_path(rid, f["name"])
                if path and os.path.isfile(path):
                    zf.write(path, arcname=f["name"])
        body = buf.getvalue()

        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header(
            "Content-Disposition", 'attachment; filename="%s"' % zip_name
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- per-feature image: status and pull (SSE) ----
    #
    # Kept out of /capabilities on purpose. That response is fetched on every app
    # load and adds no subprocess calls today; and its value would go stale the
    # moment a pull finished, since nothing re-fetches it.
    def _image_status(self, qs):
        key = ((qs.get("image") or [""])[0]).strip()
        images = _pullable_images()
        if key not in images:
            self._send(400, json.dumps({"error": "unknown image"}))
            return
        image = images[key]
        out = {"image": image, "present": _sibling_image_present(image)}
        size = _image_download_bytes(image) if not out["present"] else None
        if size:
            out["downloadBytes"] = size
        self._send(200, json.dumps(out))

    def _pull_stream(self, qs):
        key = ((qs.get("image") or [""])[0]).strip()
        images = _pullable_images()
        if key not in images:
            self._send(400, json.dumps({"error": "unknown image"}))
            return
        # The reference is this server's own env value for the requested feature,
        # never the request string.
        image = images[key]

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        disconnected = [False]

        def sse(event, payload):
            try:
                self.wfile.write(("event: %s\ndata: %s\n\n" % (event, payload)).encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                disconnected[0] = True

        if _sibling_image_present(image):
            sse("done", json.dumps({"ok": True, "image": image, "alreadyPresent": True}))
            return

        with _pull_lock:
            if image in _pull_active:
                sse("busy", json.dumps({"image": image}))
                sse("done", json.dumps({"ok": False, "image": image, "reason": "busy"}))
                return
            _pull_active.add(image)
        try:
            sse("log", json.dumps("[ui] pulling %s ..." % image))
            # Closing the stream stops the pull. Layers already fetched stay in the
            # daemon's cache, so pressing the button again resumes rather than
            # starting over.
            code, reason = _pull_image(
                image,
                lambda ln: sse("log", json.dumps(ln)),
                on_progress=lambda snap: sse("progress", json.dumps({"phase": "pull", **snap})),
                cancel=lambda: disconnected[0],
            )
        finally:
            with _pull_lock:
                _pull_active.discard(image)
        if code == 0:
            sse("done", json.dumps({"ok": True, "image": image}))
        else:
            sse("done", json.dumps({"ok": False, "image": image, "reason": reason}))

    # ---- scan stream (SSE) ----
    def _scan_stream(self, qs):
        def g(k, d=""):
            return (qs.get(k) or [d])[0]

        project = g("project").strip()
        version = g("version").strip()
        if not project or not version:
            self._send(400, json.dumps({"error": "project and version required"}))
            return

        source = g("source", "current-dir").strip() or "current-dir"
        # Not an input the form offers: it is what a folder scan turned out to be,
        # recorded in the scan config. A re-scan of one replays the folder, so
        # take it back to the directory input it came from and let the detection
        # below decide again — the folder may have been rebuilt, or cleaned.
        if source == "yocto-build-dir":
            source = "rootfs-dir"
        target = g("target").strip()
        token = g("token").strip()
        # Optional outbound license (--license on the CLI) enabling the
        # license-conflict check. Free text by nature (any SPDX id), so it is
        # bounded here and sanitized again at the docker-run boundary; an empty
        # value simply leaves the check off.
        outbound_license = g("license").strip()[:64]

        # Optional AI usage scenario (--usage on the CLI) scoping the model risk
        # assessment. Closed allowlist: an out-of-list value is refused before
        # the stream starts, and the literal REBOUND from _USAGE_CONTEXTS (never
        # the request string) is what reaches the scan environment.
        usage = g("usage").strip()
        if usage:
            if usage not in _USAGE_CONTEXTS:
                self._send(400, json.dumps(
                    {"error": "invalid usage (expected internal|product|"
                              "redistribute|outputs-only)"}))
                return
            usage = _USAGE_CONTEXTS[_USAGE_CONTEXTS.index(usage)]

        # Per-run output folder OUTPUT_DIR/<run_id>/ (matches scan-sbom.sh). The
        # default run_id is the {prefix}; with ?timestamp=true the folder name
        # gets a _{YYYYMMDD-HHMMSS} suffix so repeat scans don't overwrite each
        # other. Files inside stay named by the {prefix} (entrypoint.sh uses
        # PROJECT/VERSION), so the folder name and the file prefix can differ.
        prefix = output_prefix(project, version)
        run_id = prefix
        if g("timestamp") == "true":
            run_id = "%s_%s" % (prefix, datetime.now().strftime("%Y%m%d-%H%M%S"))
        # Route through run_dir so the same path-injection barrier the read side
        # uses (scan_id_ok allowlist + realpath boundary) gates makedirs. run_id
        # already derives from the sanitized project/version, but resolving it
        # here keeps the write path traversal-safe and analyzer-visible.
        run_out = run_dir(run_id)
        if run_out is None:
            self._send(400, json.dumps({"error": "invalid run id"}))
            return
        os.makedirs(run_out, exist_ok=True)

        # What to show as this scan's provenance when `target` cannot say it.
        # An upload arrives as an opaque token, so the name the user picked is
        # only knowable here; a folder scan has no target at all, so name the
        # host folder it was launched from (or the mount it selected). Falls
        # back to empty, which the UI reads as "nothing honest to show".
        source_label = ""
        if token:
            uploaded = resolve_upload(token)
            if uploaded:
                source_label = os.path.basename(uploaded)
        elif source == "current-dir":
            source_label = os.environ.get("SBOM_UI_HOST_DIR", "")
        elif source in ("rootfs-dir", "scan-target-src"):
            source_label = next(
                (r["hostPath"] for r in EXTRA_SCAN_ROOTS if r["path"] == target),
                "",
            )

        # Record how this scan was launched (source + non-secret feature toggles)
        # so the UI can offer "re-scan with the same settings". Saved into the run
        # folder as a dot-prefixed sidecar that stays out of the artifact listing
        # and downloads. Tokens/credentials (token, cred, scanoss_cred, gitToken)
        # are deliberately omitted — never persist secrets here.
        scan_config = {
            "source": source,
            "target": target,
            # What the user actually picked, when `target` cannot say it: the
            # uploaded file's name, or the folder a mounted scan ran against.
            # The Overview prints this as the scan's provenance. Kept out of
            # `target` because "re-scan" refills the form from `target`, and an
            # upload has to be chosen again rather than retyped.
            "sourceLabel": source_label,
            "project": project,
            "version": version,
            "notice": g("notice", "true") == "true",
            "security": g("security", "true") == "true",
            "deepLicense": g("deep_license") == "true",
            "identifyVendored": g("identify_vendored") == "true",
            "includeOsv": g("includeOsv") == "true",
            "byteStable": g("byte_stable") == "true",
            "deepCve": g("deep_cve") == "true",
        }
        write_scanmeta(run_out, scan_config)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        # Set when the client closes the stream (e.g. the UI's Cancel button), so
        # the scan loop can stop the subprocess instead of running it to the end.
        disconnected = [False]

        def sse(event, payload):
            try:
                self.wfile.write(("event: %s\ndata: %s\n\n" % (event, payload)).encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                disconnected[0] = True

        def fail(msg):
            sse("error", json.dumps(msg))
            sse("done", json.dumps({"ok": False, "id": run_id, "results": list_results(run_id),
                                    "sbom": None, "security": None, "conformance": None}))

        # Build the run-scan environment + working dir for the chosen source.
        env = os.environ.copy()
        env.update({
            "PROJECT_NAME": project,
            "PROJECT_VERSION": version,
            "PROJECT_LICENSE": outbound_license,
            "UPLOAD_ENABLED": "false",
            "HOST_OUTPUT_DIR": run_out,
            "GENERATE_NOTICE": "true" if g("notice", "true") == "true" else "false",
            "GENERATE_SECURITY": "true" if g("security", "true") == "true" else "false",
            # No GENERATE_SPDX: the UI exports SPDX on demand from the results
            # screen (GET /spdx-export) instead of deciding before the scan.
            "GENERATE_REPORT": "true",  # 오픈소스위험분석보고서: default-on (mirrors CLI)
            "DEEP_LICENSE": "true" if g("deep_license") == "true" else "false",
            # Vendored-OSS identification (SCANOSS). SCANOSS_API_URL/KEY, if set in
            # the server's environment, pass through via env.copy() above.
            "IDENTIFY_VENDORED": "true" if g("identify_vendored") == "true" else "false",
            "BYTE_STABLE": "true" if g("byte_stable") == "true" else "false",
            # Opt-in deep CVE matching (maven NVD-CPE via grype). Consumed by
            # scan-security.sh in the deep-cve image; a plain boolean from a fixed
            # literal, no user text. SECURITY_NVD_VERIFY stays off (network/NVD key).
            "DEEP_CVE": "true" if g("deep_cve") == "true" else "false",
        })
        # Allowlisted above (and rebound to the _USAGE_CONTEXTS literal). Set
        # only when given: assess-ai-risk.sh treats the absent var as "no
        # scenario" and reports every binding condition instead.
        if usage:
            env["AI_USAGE_CONTEXT"] = usage
        # Optional SCANOSS token (single-use, stashed via POST /git-cred). Lets a
        # web-UI user supply their own OSSKB key, since the free anonymous endpoint
        # is heavily rate-limited. Overrides any key from the server environment.
        scanoss_cred = g("scanoss_cred").strip()
        if scanoss_cred:
            tok = _GIT_CREDS.pop(scanoss_cred, None)
            if tok:
                env["SCANOSS_API_KEY"] = tok
        # Optional upload: push the generated SBOM to Dependency-Track or TRUSCA.
        # The API token is a secret, so it arrives as a single-use credId (stashed
        # via POST /git-cred), never in the scan-stream query string — same as
        # scanoss_cred. The non-secret fields (target, url, project id) are plain
        # params. Upload turns on only when fully specified; a partially-filled
        # form leaves the scan generate-only rather than failing the run. The
        # server URL and token are used for this run only and never persisted.
        upload_target = g("upload_target").strip()
        if upload_target in ("dependency-track", "trusca"):
            upload_url = g("upload_url").strip()
            upload_cred = g("upload_cred").strip()
            api_key = _GIT_CREDS.pop(upload_cred, None) if upload_cred else None
            trusca_pid = g("trusca_project_id").strip()
            if upload_url and api_key and (upload_target != "trusca" or trusca_pid):
                env["UPLOAD_ENABLED"] = "true"
                env["UPLOAD_TARGET"] = upload_target
                env["API_URL"] = upload_url
                env["API_KEY"] = api_key
                if upload_target == "trusca":
                    env["TRUSCA_PROJECT_ID"] = trusca_pid
        cwd = run_out
        cleanup_dir = None
        mode = None
        # When set, run the scan in a SIBLING container (firmware/aibom image)
        # instead of in-process run-scan. dict: {image, upload_file?, model_id?}.
        sibling = None

        # A folder the user pointed at can be a Yocto build directory. Asked here
        # rather than inside each branch so both folder inputs — a directory
        # target and a picked scan-target folder — answer it the same way, and so
        # the answer is known before the per-source dispatch below.
        yocto_dir = None
        if source in ("rootfs-dir", "scan-target-src"):
            _picked = safe_scan_dir(target)
            if _picked and is_yocto_build_dir(_picked):
                yocto_dir = _picked

        try:
            if yocto_dir is not None:
                # Analyze what the build published, not the tree it published
                # from: a directory scan of a build directory reports sysroots
                # and native build tools that never ship in the image. Joins the
                # ANALYZE path, so conformance, notice, security and the risk
                # report behave exactly as they do for an uploaded SBOM.
                shown = display_path_of(yocto_dir)
                sse("log", json.dumps("▶ Yocto build directory: %s" % shown))
                candidates = yocto_spdx_candidates(yocto_dir)
                doc = yocto_pick_spdx(candidates)
                if not doc and yocto_manifest_in(yocto_dir):
                    # No SPDX, but a build records what it shipped anyway: the
                    # image package manifest, license.manifest and cve-check's
                    # report. Read those rather than refuse — scanning the build
                    # tree as a directory would report sysroots and native build
                    # tools that never ship in the image.
                    sse("log", json.dumps(
                        "▶ No SPDX in this build; reading the manifests it wrote instead. "
                        "Components and licenses come from the image and license manifests, "
                        "and vulnerabilities from cve-check when the build ran it. For "
                        'CPE-accurate matching, rebuild with INHERIT += "create-spdx-3.0".'))
                    mode = "ANALYZE"
                    env["MODE"] = "ANALYZE"
                    env["YOCTO_BUILD_DIR"] = yocto_dir
                    env["GENERATE_NOTICE"] = "true"
                    env["GENERATE_SECURITY"] = "true"
                    scan_config["source"] = "yocto-build-dir"
                    scan_config["sourceLabel"] = shown
                    write_scanmeta(run_out, scan_config)
                elif not doc:
                    fail("This is a Yocto build directory, but it holds neither an SPDX "
                         "SBOM nor an image package manifest to read. "
                         'Add INHERIT += "create-spdx-3.0" and INHERIT += "vex" to '
                         "conf/local.conf and build the image again — the SBOM then "
                         "appears as tmp/deploy/images/<machine>/<image>.rootfs.spdx.json "
                         "and this folder can be scanned as it is. If the build writes "
                         "its images somewhere else, upload that document with the SBOM "
                         "input instead. Scanning the build tree as a directory is not "
                         "offered as a fallback: it reports sysroots and native build "
                         "tools that never ship in the image.")
                    return
                if doc:
                    if len(candidates) > 1:
                        sse("log", json.dumps(
                            "▶ Several image SBOMs in this build directory — analyzing by SPDX "
                            "version first (3.x carries the installed set and the build's CVE "
                            "verdicts), then by which was written last:"))
                        for cand in candidates:
                            sse("log", json.dumps(
                                "    %s%s" % (os.path.relpath(cand, yocto_dir),
                                              "  <- analyzing this one" if cand == doc else "")))
                    if doc.endswith(".spdx.tar.zst"):
                        sse("log", json.dumps(
                            "▶ SPDX 2.x build: the packages come from inside this archive. "
                            "Vulnerabilities are matched from the CPEs, since only SPDX 3.0 "
                            "records which CVEs a recipe patched — "
                            'INHERIT += "create-spdx-3.0" adds that on 5.0 Scarthgap and later.'))
                    elif is_spdx2_doc(doc):
                        # An SPDX 2.x image document is only an index; its packages are
                        # in the archive beside it, which the parser reads when present.
                        archive = doc[: -len(".spdx.json")] + ".spdx.tar.zst"
                        if os.path.isfile(archive):
                            sse("log", json.dumps(
                                "▶ SPDX 2.x build: the packages come from %s beside the image "
                                "document. Vulnerabilities are matched from the CPEs, since only "
                                "SPDX 3.0 records which CVEs a recipe patched — "
                                'INHERIT += "create-spdx-3.0" adds that.'
                                % os.path.basename(archive)))
                        else:
                            sse("log", json.dumps(
                                "▶ %s is an SPDX 2.x document and the archive holding its packages "
                                "(%s) is not beside it, so expect an almost empty result. Keep the "
                                'two together, or rebuild with INHERIT += "create-spdx-3.0".'
                                % (os.path.basename(doc), os.path.basename(archive))))
                    sse("log", json.dumps("▶ Image SBOM: %s" % os.path.relpath(doc, yocto_dir)))
                    mode = "ANALYZE"
                    env["MODE"] = "ANALYZE"
                    env["ANALYZE_SBOM"] = doc
                    # ANALYZE needs license + vulnerability data for the risk report.
                    env["GENERATE_NOTICE"] = "true"
                    env["GENERATE_SECURITY"] = "true"
                    # Record what this turned out to be, so the result page names a
                    # Yocto build rather than a directory scan. `target` keeps the
                    # folder the user picked, which is what "re-scan" replays — the
                    # detection then runs again on the same folder.
                    scan_config["source"] = "yocto-build-dir"
                    scan_config["sourceLabel"] = shown
                    write_scanmeta(run_out, scan_config)
                    # Same opt-in as an uploaded SBOM: the base UI image has no
                    # grype, so deep CVE matching runs in the deep-cve image as a
                    # sibling. Only for a document — the manifest path has no
                    # single file to hand over, and runs in process or not at all.
                    if g("deep_cve") == "true" and not deep_cve_capable():
                        if docker_cli_present() and docker_capable():
                            sibling = {"image": DEEP_CVE_IMAGE, "upload_file": doc}
                        else:
                            fail("Deep CVE matching requires Docker (to run the deep-cve "
                                 "image) or relaunching the UI from the deep-cve image."); return

            elif source == "docker-image":
                if not target:
                    fail("Docker image name required"); return
                # Validate the image reference like every other source validates
                # its target (git URL / model id / rootfs path). TARGET_IMAGE
                # reaches `syft "$TARGET_IMAGE"` in the entrypoint; _REF_RE starts
                # with an alphanumeric, so a leading "-" cannot inject a syft flag.
                if not _valid_image_ref(target):
                    fail("Unsafe or unsupported image reference"); return
                if not docker_capable():
                    fail("Docker socket not mounted (-v /var/run/docker.sock:...)"); return
                mode = "IMAGE"
                env["MODE"] = "IMAGE"
                env["TARGET_IMAGE"] = target

            elif source == "current-dir":
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = SRC_DIR
                # The launch folder is scanned as source on request, so this one
                # is not switched under the user — but a Yocto build directory
                # scanned as source reads the build tree rather than the image,
                # and saying so beats handing back an inventory of sysroots.
                if is_yocto_build_dir(SRC_DIR):
                    sse("log", json.dumps(
                        "▶ Note: this folder looks like a Yocto build directory. Scanned as "
                        "source it reports the build tree, not what the image ships. To read "
                        "the image SBOM the build published, pick this folder with the "
                        "Directory / rootfs input instead."))

            elif source == "rootfs-dir":
                # Scan an OS rootfs (or any subfolder) under /src — or under an
                # extra --mount scan target — as a directory. The path is
                # validated to stay inside an allowed mount so it can't reach
                # /host-output uploads or container system paths.
                scan_dir = safe_scan_dir(target)
                if not scan_dir:
                    fail("Invalid or out-of-bounds directory path (must be a "
                         "folder inside the current folder or a mounted scan "
                         "target)"); return
                mode = "ROOTFS"
                env["MODE"] = "ROOTFS"
                env["TARGET_DIR"] = scan_dir

            elif source == "scan-target-src":
                # Deep source scan of a picked folder (desktop "Add folder…"): the
                # transitive-resolution path — same cdxgen build as current-dir —
                # for a read-only scan-target mount. The folder is validated to a
                # picked scan root, then cloned into a writable tree under
                # OUTPUT_DIR so build-prep can install/write; SOURCE_ROOT_HOST is
                # filled below (the copy is under a mount we own), which is the
                # signal the entrypoint needs to run cdxgen instead of shallow syft.
                scan_dir = safe_scan_dir(target)
                if not scan_dir:
                    fail("Invalid or out-of-bounds directory path (must be a "
                         "picked scan-target folder)"); return
                # The request only selects WHICH registered scan root to build.
                # Copy from that root's own recorded path (from EXTRA_SCAN_ROOTS,
                # set by the desktop app / --mount), never from the request-derived
                # path — a deep scan always builds the whole picked folder, and
                # sourcing the server's own record keeps request input out of the
                # copytree sink.
                picked = next((r for r in EXTRA_SCAN_ROOTS
                               if scan_dir == r["path"] or scan_dir.startswith(r["path"] + os.sep)),
                              None)
                if picked is None:
                    fail("Deep source scan is only available for an added folder "
                         "(the current folder already scans deep)."); return
                cleanup_dir = os.path.join(OUTPUT_DIR, ".srccopy-" + secrets.token_hex(8))
                sse("log", json.dumps("▶ Preparing a writable copy of %s ..."
                                      % os.path.basename(picked["path"].rstrip("/"))))
                try:
                    copy_scan_target_tree(picked["path"], cleanup_dir)
                except (OSError, shutil.Error) as exc:
                    fail("could not prepare the folder for a deep scan: %s" % exc)
                    return
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = scan_root_of(cleanup_dir)

            elif source == "git-url":
                if not target:
                    fail("Git URL required"); return
                if not re.match(r"^(https?://|git@|ssh://git@|file://)[A-Za-z0-9._~:@/+-]+$", target) \
                        or ".." in target or " " in target:
                    fail("Unsafe or unsupported git URL"); return
                if not shutil.which("git"):
                    fail("git not available in this image"); return
                # Optional private-repo token (single-use, via POST /git-cred).
                # Injected into the clone URL only; the log shows the bare URL.
                clone_url = target
                cred = g("cred").strip()
                if cred:
                    tok = _GIT_CREDS.pop(cred, None)
                    if tok and target.startswith("https://"):
                        clone_url = "https://x-access-token:%s@%s" % (tok, target[len("https://"):])
                cleanup_dir = os.path.join(UPLOAD_DIR, "git-" + secrets.token_hex(8))
                os.makedirs(cleanup_dir, exist_ok=True)
                clone_dest = os.path.join(cleanup_dir, "repo")
                sse("log", json.dumps("▶ Cloning %s ..." % target))
                cp = subprocess.run(
                    ["git", "clone", "--depth", "1", "--single-branch", "--", clone_url, clone_dest],
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                if cp.returncode != 0:
                    out = re.sub(r"x-access-token:[^@]*@", "x-access-token:***@", (cp.stdout or "").strip()[-500:])
                    fail("git clone failed: %s" % out); return
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = scan_root_of(clone_dest)

            elif source == "zip-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded archive not found (re-upload)"); return
                cleanup_dir = os.path.join(os.path.dirname(up), "extracted")
                os.makedirs(cleanup_dir, exist_ok=True)
                sse("log", json.dumps("▶ Extracting %s ..." % os.path.basename(up)))
                try:
                    if up.lower().endswith((".zip",)):
                        safe_extract_zip(up, cleanup_dir)
                    else:
                        # tarballs: shell out to tar (present in the image), traversal-guarded
                        listing = subprocess.run(["tar", "-tf", up], stdout=subprocess.PIPE, text=True)
                        if re.search(r"(^|\n)(/|.*\.\.(/|$))", listing.stdout or ""):
                            fail("unsafe path in archive"); return
                        # Reject a symlink/hardlink member whose target escapes the
                        # extraction dir (a link "evil -> /etc" followed by "evil/x"
                        # writes through the link). The name guard above misses these
                        # because the member names themselves are benign; the verbose
                        # listing exposes the "name -> target" link line.
                        vlist = subprocess.run(["tar", "-tvf", up], stdout=subprocess.PIPE, text=True)
                        for _ln in (vlist.stdout or "").splitlines():
                            if " -> " in _ln:
                                _tgt = _ln.split(" -> ", 1)[1].strip()
                                if _tgt.startswith("/") or ".." in _tgt.split("/"):
                                    fail("unsafe link in archive"); return
                        subprocess.run(["tar", "-C", cleanup_dir, "--no-same-owner", "-xf", up], check=True)
                except (ValueError, OSError, subprocess.CalledProcessError) as exc:
                    fail("archive extraction failed: %s" % exc); return
                mode = "SOURCE"
                env["MODE"] = "SOURCE"
                env["SOURCE_ROOT"] = scan_root_of(cleanup_dir)

            elif source == "package-upload":
                # A build artifact rather than source: the case where a supplier
                # ships a jar or a package instead of the tree it was built from.
                up = resolve_upload(token)
                if not up:
                    fail("uploaded package not found (re-upload)"); return
                if up.lower().endswith(".whl"):
                    # A wheel carries no manifest syft can read from the file
                    # itself; unpacked, its dist-info is an ordinary directory
                    # scan. It is a zip, so the existing traversal-guarded
                    # extractor applies unchanged.
                    cleanup_dir = os.path.join(os.path.dirname(up), "extracted")
                    os.makedirs(cleanup_dir, exist_ok=True)
                    sse("log", json.dumps("▶ Extracting %s ..." % os.path.basename(up)))
                    try:
                        safe_extract_zip(up, cleanup_dir)
                    except (ValueError, OSError) as exc:
                        fail("archive extraction failed: %s" % exc); return
                    mode = "ROOTFS"
                    env["MODE"] = "ROOTFS"
                    env["TARGET_DIR"] = cleanup_dir
                elif up.lower().endswith((".exe", ".msi", ".dmg")):
                    # An installer read as a single file yields almost nothing:
                    # what it carries is inside. Unpacking is the firmware path,
                    # so route it there — in this image when the tools are built
                    # in, otherwise as a sibling container. When neither is
                    # available, fall back to reading the file and say so, rather
                    # than returning a near-empty result as if it were the answer.
                    if firmware_usable():
                        mode = "FIRMWARE"
                        env["MODE"] = "FIRMWARE"
                        env["TARGET_FILE"] = up
                    else:
                        mode = "BINARY"
                        env["MODE"] = "BINARY"
                        env["TARGET_FILE"] = up
                        sse("log", json.dumps(
                            "▶ %s is a packaged installer. It was read as a single file "
                            "without unpacking, so only components with a version string in "
                            "the outer file can be found. Unpacking needs Docker and the "
                            "firmware image." % os.path.basename(up)))
                else:
                    mode = "BINARY"
                    env["MODE"] = "BINARY"
                    env["TARGET_FILE"] = up

            elif source == "sbom-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded SBOM not found (re-upload)"); return
                mode = "ANALYZE"
                env["MODE"] = "ANALYZE"
                env["ANALYZE_SBOM"] = up
                # ANALYZE needs license + vulnerability data for the risk report.
                env["GENERATE_NOTICE"] = "true"
                env["GENERATE_SECURITY"] = "true"
                # Opt-in deep CVE matching: the base UI image has no grype, so run
                # the analysis in the deep-cve image (in-process only if this image
                # already has grype). DEEP_CVE is forwarded via env (set above).
                if g("deep_cve") == "true":
                    if deep_cve_capable():
                        pass  # in-process (UI launched from the deep-cve image)
                    elif docker_cli_present() and docker_capable():
                        sibling = {"image": DEEP_CVE_IMAGE, "upload_file": up}
                    else:
                        fail("Deep CVE matching requires Docker (to run the deep-cve "
                             "image) or relaunching the UI from the deep-cve image."); return

            elif source == "firmware-upload":
                up = resolve_upload(token)
                if not up:
                    fail("uploaded firmware not found (re-upload)"); return
                mode = "FIRMWARE"
                env["MODE"] = "FIRMWARE"
                env["TARGET_FILE"] = up
                # Opt-in: also pull OSV advisories from osv.dev for this scan.
                # Default (off) keeps scan-firmware.sh's offline bundle matching
                # (CVE_BIN_TOOL_DISABLE_SOURCES=GAD,OSV, auto/offline). When the
                # user enables it we re-enable only OSV (leave GAD disabled) and
                # force the online updater. The wire field is a plain boolean,
                # and only these two fixed literals are injected (no user text).
                if g("includeOsv") == "true":
                    env["CVE_BIN_TOOL_DISABLE_SOURCES"] = "GAD"
                    env["CVE_BIN_TOOL_MODE"] = "online"
                if firmware_capable():
                    # Tools are in THIS image (UI launched from the firmware image):
                    # run in-process exactly as before.
                    pass
                elif docker_cli_present() and docker_capable():
                    # Permissive-only base UI image: hand the GPL-isolated firmware
                    # image the job as a sibling container. It reads the upload in place
                    # via --volumes-from (up is a container path under UPLOAD_DIR), so no
                    # host path is needed.
                    sibling = {"image": FIRMWARE_IMAGE, "upload_file": up}
                else:
                    fail("Firmware analysis requires Docker (to run the firmware image) "
                         "or relaunching the UI from the firmware image."); return

            elif source == "ai-model":
                # Generate an AI SBOM (CycloneDX 1.7 ML-BOM) for a HuggingFace
                # model via the OWASP AIBOM Generator (opt-in bomlens-aibom image).
                if not target:
                    fail("HuggingFace model id required (owner/name)"); return
                # owner/name (optional owner), HuggingFace charset only; no traversal.
                if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$", target):
                    fail("Unsupported model id (expected owner/name)"); return
                mode = "AIBOM"
                env["MODE"] = "AIBOM"
                env["MODEL_ID"] = target
                if aibom_capable():
                    pass  # in-process (UI launched from the aibom image)
                elif docker_cli_present() and docker_capable():
                    # Heavy aibom image runs as a sibling; needs only outbound net.
                    sibling = {"image": AIBOM_IMAGE, "model_id": target}
                else:
                    fail("AI-model SBOM generation requires Docker (to run the AIBOM image) "
                         "or relaunching the UI from the AIBOM image."); return

            else:
                fail("unknown input type: %s" % source); return

            # For a source scan, hand the entrypoint the HOST path of the scanned
            # tree so it can run a cdxgen language image as a sibling container
            # (transitive resolution). Empty -> entrypoint falls back to syft.
            if env.get("MODE") == "SOURCE" and env.get("SOURCE_ROOT"):
                host_root = host_path_of(env["SOURCE_ROOT"])
                if host_root:
                    env["SOURCE_ROOT_HOST"] = host_root

            sse("log", json.dumps("▶ Starting %s scan: %s %s" % (mode.lower(), project, version)))
            ok = False
            if sibling is not None:
                # Firmware / AI on the permissive-only base image: run the
                # dedicated image as a sibling container (host socket). It does
                # the full pipeline and writes artifacts into our run_out folder
                # (shared via --volumes-from) — so the summary below reads them
                # just like an in-process scan.
                rc = run_sibling_scan(
                    sibling["image"], env["MODE"], run_out,
                    lambda ln: sse("log", json.dumps(ln)),
                    upload_file=sibling.get("upload_file"),
                    model_id=sibling.get("model_id"),
                    extra_env=env,
                    on_progress=lambda p: sse("progress", json.dumps({"phase": "cvedb", "percent": p})),
                    # Cancel: if the client closes the stream, stop this sibling.
                    cancel=lambda: disconnected[0],
                    container_name="bomlens-sib-%s" % run_id,
                )
                ok = rc == 0
                if rc == -1:
                    sse("error", json.dumps("Failed to launch the %s sibling container." % mode.lower()))
            else:
                try:
                    proc = subprocess.Popen(
                        [RUN_SCAN], env=env, cwd=cwd,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1,
                    )
                    for raw in proc.stdout:
                        for piece in raw.rstrip("\n").split("\r"):
                            if piece:
                                _emit_or_log(
                                    piece,
                                    lambda ln: sse("log", json.dumps(ln)),
                                    lambda p: sse("progress", json.dumps({"phase": "cvedb", "percent": p})),
                                )
                        # Client cancelled (the SSE write broke): stop the scan
                        # instead of running it to completion on a dead stream.
                        if disconnected[0]:
                            proc.terminate()
                            break
                    proc.wait()
                    ok = proc.returncode == 0
                except Exception as exc:  # noqa: BLE001
                    sse("error", json.dumps("Failed to launch scan: %s" % exc))

            # Artifacts landed in run_out (the run folder named run_id); the
            # summary helpers glob it by suffix. The done event carries id=run_id
            # so the frontend's later /file, /download-all and /scan requests
            # address this scan's folder.
            done = {
                "ok": ok,
                "mode": mode,
                "id": run_id,
                "results": list_results(run_id),
                "sbom": sbom_summary(run_id),
                "security": security_summary(run_id) if env["GENERATE_SECURITY"] == "true" else None,
                "conformance": conformance_summary(run_id),
                # Yocto build-time VEX counts (Yocto SPDX input only); None otherwise.
                "yoctoVex": yocto_vex_summary(run_id),
                # AI compliance profile card (AI SBOMs only); None otherwise.
                # Paired with scan_detail() so a re-opened scan carries it too.
                "aiProfile": ai_profile_summary(run_id),
                "scanoss": scanoss_status(run_id),
                # The inputs + toggles this scan ran with (no secrets); also saved
                # as the run-folder sidecar so a re-opened scan carries it too.
                "scanConfig": scan_config,
            }
            sse("done", json.dumps(done))
        except Exception as exc:  # noqa: BLE001
            # The summary helpers are defended against malformed artifacts, so a
            # reaching this is unexpected — but the client is blocked waiting for a
            # terminal event, so never let an exception leave the SSE stream open.
            # Emit an error + a fail-shaped done so the UI stops waiting instead of
            # hanging on "scan in progress" forever.
            sse("error", json.dumps("Scan finished but the summary could not be built: %s" % exc))
            sse("done", json.dumps({"ok": False, "id": run_id,
                                    "results": list_results(run_id),
                                    "sbom": None, "security": None,
                                    "conformance": None}))
        finally:
            # Remove uploaded/cloned/extracted trees; keep generated artifacts
            # (entrypoint wrote them into the run folder run_out).
            token_dir = upload_token_dir(token)
            if token_dir:
                shutil.rmtree(token_dir, ignore_errors=True)
            if cleanup_dir and source in ("git-url", "scan-target-src"):
                shutil.rmtree(cleanup_dir, ignore_errors=True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    print("[ui] BomLens Web UI listening on 0.0.0.0:%d" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
