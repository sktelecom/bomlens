#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read the running kernel's own version signature from wherever in the image it sits.

Usage: identify-kernel-version.py <extract_root> [rootfs_hint] > components.json

Every other identification pass in this pipeline (cve-bin-tool's checkers,
identify-elf-presence.py, identify-version-strings.py) reads only inside the one
directory scan-firmware.sh picked as the rootfs (the parent of the shallowest
`etc`). That choice is right for the filesystem the device boots into, and
deliberately narrow: the rootfs picker exists because a wider search once picked
a bundled sub-package over the real root (see scan-firmware.sh's
`pick_shallowest`).

The kernel does not live inside that filesystem, though. Some images boot the
kernel from a completely separate top-level structure beside the installed
rootfs (an ISO's boot catalog and its install payload are siblings, not parent
and child). Others carry it as an intermediate decompression stage on the way
down to the rootfs — the kernel image itself is what unblob unpacks *through*
before it reaches the layer that has `etc` in it, so it sits one or more levels
above the rootfs, not inside it. Either way, a rootfs-scoped search never reads
the one file every image ships exactly once.

So this pass reads the whole extraction (`extract_root`), not the rootfs — but
only for the kernel's own two signatures, nothing else. Widening a search's
directory scope is safe here in a way it would not be for identify-version-strings.py's
open-ended table: there is exactly one kernel question to ask, not an open set of
product names, so there is no equivalent of the XMP-namespace/HTTP-header false
positives a wider *pattern* search invites. What still has to be guarded is
picking among candidates when the image carries more than one.

Two signatures, ranked by how directly each names the kernel it belongs to:

  vermagic=<version>   A loadable module's own record of the exact kernel it
                        was built against. Strongest: a module cannot lie about
                        this and still load.
  Linux version <version> ... #<n> <weekday>
                        The kernel's own boot banner, embedded in the kernel
                        image itself.

Both patterns are cve-bin-tool's (cve_bin_tool/checkers/linux_kernel.py), kept
identical on purpose so a hit here means the same thing a hit there would have.
One difference: cve-bin-tool applies its banner pattern to a string-extraction
pass that has already joined printable runs with newlines, so its `\\r?\\n`
anchor is doing that pass's job, not describing the raw file. Applied to raw
bytes the anchor before "Linux version" is whatever byte actually precedes it
there — usually a NUL, never a newline — so the anchor here is "not a printable
character, or the start of the file" instead. The vermagic pattern has no such
anchor and needs no change.

The banner's `(?:Linux version |)` alternation makes the prefix optional in
cve-bin-tool, because it runs only inside a directory the caller already knows
is a kernel tree. Run over an entire firmware image, an unprefixed
`<digit>.<digit>.<digit> ... #<n> <letter>` is not rare enough to trust, so the
prefix is required here.

When the image carries more than one candidate (an A/B partition pair, a
rescue kernel beside the main one), depth is not a valid tiebreaker the way it
is for the rootfs: how many compression layers unblob had to peel to reach a
file describes the archive format, not which kernel boots. So candidates are
ranked by evidence grade first (a vermagic hit beats a banner hit), then by
how many distinct files support each version, then by version, and the answer
is deterministic regardless of filesystem walk order — `choose()` is kept
importable and unit-tested against shuffled input for exactly that property.
"""
import json
import os
import re
import sys

# cve-bin-tool: cve_bin_tool/checkers/linux_kernel.py, VERSION_PATTERNS[0].
# No anchor needed: "vermagic=" itself is specific enough, and it appears
# verbatim in a module's raw bytes (it is a linked-in string, not something an
# extraction pass reformats).
_VERMAGIC_RE = re.compile(rb"vermagic=(\d+\.\d+\.\d+)")

# cve-bin-tool: same file, VERSION_PATTERNS[1], with the leading anchor
# reinterpreted for raw bytes (see module docstring) and the "Linux version "
# prefix made mandatory (see module docstring).
_BANNER_RE = re.compile(
    rb"(?:\A|[^\x20-\x7e])Linux version (\d+\.\d+\.\d+)"
    rb"[A-Za-z0-9 ,+@\-.()]* #\d+ [A-Za-z]"
)

# Cheap substring prefilter before the regex runs, so a chunk with neither
# marker anywhere in it costs one `bytes.__contains__` scan (memchr-backed)
# per chunk instead of a regex pass.
_PREFILTER = (b"vermagic=", b"Linux version ")

_CTRL_RE = re.compile(r"^[\x00-\x1f\x7f]+")

_CHUNK = 8 << 20  # 8 MiB
# A match can straddle a chunk boundary; keep enough of the tail of one chunk
# to re-present it at the head of the next. Longer than either pattern's max
# possible span.
_OVERLAP = 512


# Same contract as identify-version-strings.py's cap(): the caller always
# forwards `-e NAME=`, set or not, so an unset cap arrives as "" and must fall
# back rather than raise or be read as zero.
def cap(name, default):
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_FILES = cap("FW_KERNEL_MAX_FILES", 200000)
MAX_BYTES = cap("FW_KERNEL_MAX_BYTES", 8 * 1024 * 1024 * 1024)
MAX_VERSIONS = cap("FW_KERNEL_MAX_VERSIONS", 2)

_GRADE_RANK = {"vermagic": 0, "banner": 1}  # lower sorts first (stronger)


def scan_file(path):
    """Yield (grade, version, evidence) for every kernel signature in one file.

    Reads in fixed-size chunks with a small overlap so a match straddling a
    chunk boundary is not missed and a multi-hundred-MB kernel image is never
    held in memory whole.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size == 0:
        return
    try:
        with open(path, "rb") as fh:
            tail = b""
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                buf = tail + chunk
                if any(marker in buf for marker in _PREFILTER):
                    for m in _VERMAGIC_RE.finditer(buf):
                        yield "vermagic", m.group(1).decode("ascii"), \
                            buf[m.start():m.end()].decode("ascii", "replace")
                    for m in _BANNER_RE.finditer(buf):
                        # The match includes the anchor byte before "Linux
                        # version" (a control byte, or nothing at \A) so the
                        # regex can require it; strip it back off for display.
                        text = buf[m.start():m.end()].decode("ascii", "replace")
                        yield "banner", m.group(1).decode("ascii"), _CTRL_RE.sub("", text)
                tail = buf[-_OVERLAP:] if len(buf) > _OVERLAP else buf
    except OSError:
        return


def choose(candidates, rootfs_hint=None):
    """candidates: iterable of (grade, version, file, evidence).

    Returns up to MAX_VERSIONS (version, grade, file, evidence, support_count)
    tuples, deterministic regardless of the order candidates arrive in.

    Only the strongest grade present is considered: a vermagic hit anywhere
    outranks every banner hit, because a module's vermagic cannot be present
    without a real kernel build behind it, while a banner-shaped string in an
    arbitrary file (a saved boot log, a vendor changelog) is weaker evidence
    for what is *installed* even though the pattern already requires the
    "Linux version " prefix.
    """
    by_version = {}
    for grade, version, file, evidence in candidates:
        d = by_version.setdefault(version, {"grade": grade, "files": set(), "evidence": evidence})
        if _GRADE_RANK[grade] < _GRADE_RANK[d["grade"]]:
            d["grade"], d["evidence"] = grade, evidence
        d["files"].add(file)

    if not by_version:
        return []

    best_rank = min(_GRADE_RANK[d["grade"]] for d in by_version.values())
    pool = {v: d for v, d in by_version.items() if _GRADE_RANK[d["grade"]] == best_rank}

    def modules_dir_hint(version):
        if not rootfs_hint:
            return 0
        return 1 if os.path.isdir(os.path.join(rootfs_hint, "lib", "modules", version)) else 0

    def version_key(v):
        # Numeric-tuple comparison, not lexicographic ("4.9.0" must sort below
        # "4.10.0"). A component that fails to parse as dotted digits sorts
        # lowest rather than raising -- version is already regex-guaranteed
        # to be \d+\.\d+\.\d+ here, but stay defensive.
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (-1,)

    # Strongest first: most supporting files, then a modules/<version> dir on
    # disk, then the numerically newest version. All three wanted descending,
    # so sort ascending on the negated/inverted form of each.
    ranked = sorted(
        pool.items(),
        key=lambda kv: (len(kv[1]["files"]), modules_dir_hint(kv[0]), version_key(kv[0])),
        reverse=True,
    )

    out = []
    for version, d in ranked[:MAX_VERSIONS]:
        out.append((version, d["grade"], sorted(d["files"])[0], d["evidence"], len(d["files"])))
    if len(ranked) > MAX_VERSIONS:
        dropped = [v for v, _ in ranked[MAX_VERSIONS:]]
        print(f"[kernel-version] {len(dropped)} additional kernel version candidate(s) "
              f"not reported (raise FW_KERNEL_MAX_VERSIONS to include them): "
              f"{', '.join(dropped)}", file=sys.stderr)
    return out


def strip_extract_marker(path, root):
    """Path as it exists inside the firmware, for display only -- never used
    as a dedupe key (see identify-version-strings.py's MARKER for why a path
    stripped this way collides across unrelated branches of the tree)."""
    rel = os.path.relpath(path, root)
    parts = re.split(r"_extract/|[.]extracted/", rel)
    return parts[-1] if len(parts) > 1 and parts[-1] else rel


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = sys.argv[1]
    rootfs_hint = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isdir(root):
        print("[]")
        return 0

    candidates = []
    scanned, total_bytes, capped = 0, 0, False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if capped:
                break
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if scanned >= MAX_FILES or total_bytes + size > MAX_BYTES:
                capped = True
                break
            scanned += 1
            total_bytes += size
            rel = strip_extract_marker(p, root)
            for grade, version, evidence in scan_file(p):
                candidates.append((grade, version, rel, evidence))
        if capped:
            break

    if capped:
        print(f"[kernel-version] WARN: stopped after {scanned} file(s)/{total_bytes} byte(s); "
              f"raise FW_KERNEL_MAX_FILES/FW_KERNEL_MAX_BYTES to cover the rest.", file=sys.stderr)

    picked = choose(candidates, rootfs_hint)

    components = []
    for version, grade, file, evidence, support in picked:
        components.append({
            "bom-ref": f"kernel-signature:linux_kernel@{version}",
            "type": "library",
            "name": "linux_kernel",
            "version": version,
            # cve-bin-tool's own CPE 2.2 URI form (confirmed against its actual
            # scan output and the Dockerfile's kernel smoke test) -- not 2.3,
            # and not part `o`: firmware-cpe-match.py's parse_cpe() only reads
            # part `a` out of either CPE form, and a part-`o` CPE here would be
            # parsed as None and the component silently dropped before it ever
            # reaches the index PR #616 already taught to accept linux_kernel.
            "cpe": f"cpe:/a:linux:linux_kernel:{version}",
            "properties": [
                {"name": "bomlens:identifiedBy", "value": "kernel-signature"},
                {"name": "bomlens:versionEvidence", "value": evidence},
            ],
            "evidence": {"occurrences": [{"location": file}]},
        })

    print(json.dumps(components, ensure_ascii=False))
    print(f"[kernel-version] {scanned} file(s) read; "
          f"{len(components)} kernel version(s) identified.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
