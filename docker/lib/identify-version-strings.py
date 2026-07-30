#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
"""Pull versions out of binaries whose spelling cve-bin-tool's checkers do not match.

Usage: identify-version-strings.py <rootfs> [version-string-map.json] > components.json

cve-bin-tool requires a fixed string and regex per component. A three-digit
requirement drops `FFmpeg version 4.1`; a CLI-only marker drops a library build.
This adds those forms and nothing else — the merge keeps whichever judgement
already exists, so this never overrides identification, it only fills gaps.

The name set is closed, and that is the whole safety argument. Running an open
`<name> <version>` pattern over the corpus first returned, in order of frequency:
XMP namespace URLs, `HTTP/1.1`, PDF versions, netmasks, IP addresses and
cross-toolchain paths. Nothing about a version-shaped string says it belongs to a
component. So each entry in the table carries its own anchored pattern, and a
component not in the table is not looked for.

Two provenance rules follow from the same measurement:

  A match inside a cross-toolchain path is a build marker, not a shipped
  component. A D-Link image records `crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26`
  in binaries that run against uClibc, not glibc; a NETGEAR one records
  `hndtools-arm-linux-2.6.36-uclibc-4.5.3`. Reading those as components repeats
  the mistake of reporting a compiler as shipped software.

  A CPE is attached only where the table gives one. No version guessing and no
  identifier guessing: `net-tools` has no product in the NVD index at all, and
  five unrelated products are called `hydra`.

Every judgement records the string it came from and the file it was in, so the
claim can be checked.
"""
import json
import os
import re
import sys

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

# Marks a cross-toolchain or build-sysroot path. A version-shaped token inside one
# describes how the firmware was built, not what it ships.
TOOLCHAIN = re.compile(
    r"crosstools|/toolchains?/|buildroot-\d|/staging_dir/|hndtools|"
    r"/lib/gcc/|toolchain_build|-linux-gnueabi/|/usr/src/",
    re.I,
)

# unblob names each nesting level `<something>_extract/`, and the carve pass adds
# `<image>.extracted/`. The same rootfs lands under both, so one file is seen twice.
MARKER = re.compile(r".*(?:_extract/|\.extracted/)")

# A firmware rootfs is attacker-supplied. Bound both the file count and the size of
# any single file, and say when a bound was hit — a silent cap reads as full coverage.
MAX_FILES = int(os.environ.get("FW_VERSTR_MAX_FILES", "20000"))
MAX_BYTES = int(os.environ.get("FW_VERSTR_MAX_BYTES", str(64 * 1024 * 1024)))


def load_entries(path):
    try:
        raw = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"[version-string] WARN: cannot read {path} ({exc}); skipping", file=sys.stderr)
        return None
    out = []
    for e in raw.get("entries") or []:
        try:
            out.append({
                "name": e["name"],
                "re": re.compile(e["pattern"]),
                "cpe": e.get("cpe"),
            })
        except (KeyError, re.error) as exc:
            print(f"[version-string] WARN: skipping bad entry {e.get('name')!r} ({exc})",
                  file=sys.stderr)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = sys.argv[1]
    map_path = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "version-string-map.json")

    entries = load_entries(map_path)
    if not entries or not os.path.isdir(root):
        print("[]")
        return 0

    # (name, version) -> {"file": str, "evidence": str, "cpe": str|None}
    found = {}
    toolchain_skipped = 0
    seen, scanned, capped = set(), 0, False

    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = MARKER.sub("", os.path.relpath(p, root), count=1)
            if rel in seen:
                continue
            seen.add(rel)
            if scanned >= MAX_FILES:
                capped = True
                break
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
                blob = open(p, "rb").read()
            except OSError:
                continue
            scanned += 1
            for run in PRINTABLE.findall(blob):
                text = run.decode("ascii", "replace")
                for e in entries:
                    for m in e["re"].finditer(text):
                        if TOOLCHAIN.search(text):
                            toolchain_skipped += 1
                            continue
                        key = (e["name"], m.group(1))
                        if key in found:
                            continue
                        found[key] = {
                            "file": rel,
                            # The matched span, not the whole run: a run can be
                            # kilobytes of a symbol table and is unreadable in a report.
                            "evidence": m.group(0).strip(),
                            "cpe": e["cpe"],
                        }
        if capped:
            break

    if capped:
        print(f"[version-string] WARN: stopped at {MAX_FILES} files; "
              f"raise FW_VERSTR_MAX_FILES to cover the rest.", file=sys.stderr)

    components = []
    for (name, version) in sorted(found):
        d = found[(name, version)]
        props = [
            {"name": "bomlens:identifiedBy", "value": "version-string"},
            {"name": "bomlens:versionEvidence", "value": d["evidence"]},
        ]
        comp = {
            "bom-ref": f"version-string:{name}@{version}",
            "type": "library",
            "name": name,
            "version": version,
            "properties": props,
            "evidence": {"occurrences": [{"location": d["file"]}]},
        }
        if d["cpe"]:
            comp["cpe"] = d["cpe"].replace("{version}", version)
        else:
            # Said out loud in the artifact: the version is known but nothing can be
            # asked of a vulnerability database, because no identifier is safe here.
            props.append({"name": "bomlens:cpeUnmapped", "value": "true"})
        components.append(comp)

    print(json.dumps(components, ensure_ascii=False))
    print(f"[version-string] {scanned} file(s) read; {len(components)} component(s) "
          f"identified by a version string.", file=sys.stderr)
    if toolchain_skipped:
        print(f"[version-string] {toolchain_skipped} match(es) ignored inside "
              f"cross-toolchain paths (build markers, not shipped components).",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
