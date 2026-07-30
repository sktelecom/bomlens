#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
"""Report the components a firmware's ELF files prove are present.

Usage: identify-elf-presence.py <rootfs> [soname-map.json] > components.json

Signature identification only reports a component once it can read a version out
of a binary. Plenty of firmware carries a component with no version string left
anywhere — and for a licence obligation the version is not the question. A
Zyxel switch ships libnetsnmp.so.30.0.1 and twelve executables that list it as
NEEDED; net-snmp is in there whether or not anything says which release.

So this reads structure, not text:

  - a shared library file, by its SONAME if it declares one, else its filename
  - an executable under bin/ or sbin/, by the name it is installed under
  - NEEDED entries in other ELFs, counted as corroboration

The name a program is installed under is often not its component: brctl ships in
bridge-utils, chat and pppd in ppp, hostapd_cli in hostapd, ip and tc in
iproute2. Both mappings are written out by hand (elf-soname-map.json and
elf-program-map.json) rather than derived.

The library file has to be in the image. A NEEDED entry alone is a link-time name
a vendor is free to reuse, and it leaves nothing for a reader to check: MikroTik
RouterOS lists `libubox.so` beside its own libumsg, liburadius, libucrypto and
libuc++ — its own `libu*` family, not OpenWrt's libubox.

Both come out of the ELF dynamic section, which is why a plain string search is
not used instead. "readline" appearing in busybox's help text is not evidence
that readline is linked in, and a grep would report it as such.

What this deliberately does NOT do:

  Derive a version from a filename. The digits in a SONAME are an ABI number.
  libcrypto.so.1.0.0 is not OpenSSL 1.0.0 and libcurl.so.4.3.0 is not curl 4.3.0.
  A wrong version is worse than none: it draws another component's CVEs.

  Guess a name. An unmapped library is counted and named in the run log so the
  map can be extended, and no component is emitted for it.

Every component it emits is marked `bomlens:evidenceGrade = presence-only` and
carries no version, no purl and no CPE, so nothing downstream can match it to an
advisory. The occurrences list holds the file that proves it.
"""
import json
import os
import re
import subprocess
import sys

ELF_MAGIC = b"\x7fELF"

# readelf is given many files per call; one call per file over a large rootfs is
# thousands of processes. The output separates files with a `File: <path>` line.
BATCH = 200

# A firmware rootfs is attacker-supplied and can hold an arbitrary number of
# files. Stop rather than run unbounded, and say so — a silent cap reads as
# "everything was looked at".
MAX_FILES = int(os.environ.get("FW_ELF_MAX_FILES", "20000"))

NEEDED_RE = re.compile(r"\(NEEDED\).*\[([^\]]+)\]")
SONAME_RE = re.compile(r"\(SONAME\).*\[([^\]]+)\]")
FILE_RE = re.compile(r"^File: (.*)$")

# unblob names each nesting level `<something>_extract/`, and the carve pass adds
# `<image>.extracted/`. The same rootfs routinely lands under both, so one file
# appears twice. Cutting at the last marker gives the path as it exists inside the
# firmware — the same rule scan-firmware.sh uses on component names. Without it
# every evidence path is listed twice and every NEEDED count is doubled.
MARKER_RE = re.compile(r".*(?:_extract/|\.extracted/)")


def in_firmware_path(rel):
    return MARKER_RE.sub("", rel, count=1) or rel


def stem(soname):
    """libnetsnmp.so.30.0.1 -> libnetsnmp. Everything from `.so` on is ABI, not name."""
    base = os.path.basename(soname or "").strip()
    cut = base.find(".so")
    if cut > 0:
        base = base[:cut]
    return base.lower()


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def find_elf_files(root):
    out = []
    capped = False
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            # A symlink to a library is the same file counted twice, and a
            # dangling one is not readable at all.
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if len(out) >= MAX_FILES:
                capped = True
                return out, capped
            if is_elf(p):
                out.append(p)
    return out, capped


def read_dynamic(paths):
    """path -> {"soname": str|None, "needed": [str]} for every ELF that has a dynamic section."""
    info = {}
    for i in range(0, len(paths), BATCH):
        chunk = paths[i:i + BATCH]
        try:
            proc = subprocess.run(["readelf", "-d", "--"] + chunk,
                                  capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.SubprocessError):
            continue
        # With one file readelf prints no `File:` header, so seed it.
        current = chunk[0] if len(chunk) == 1 else None
        for line in proc.stdout.splitlines():
            m = FILE_RE.match(line)
            if m:
                current = m.group(1)
                continue
            if current is None:
                continue
            m = NEEDED_RE.search(line)
            if m:
                info.setdefault(current, {"soname": None, "needed": []})["needed"].append(m.group(1))
                continue
            m = SONAME_RE.search(line)
            if m:
                info.setdefault(current, {"soname": None, "needed": []})["soname"] = m.group(1)
    return info


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    map_path = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(here, "elf-soname-map.json")
    prog_path = sys.argv[3] if len(sys.argv) > 3 else \
        os.path.join(here, "elf-program-map.json")

    def load_map(path, required):
        try:
            raw = json.load(open(path))
        except (OSError, ValueError) as exc:
            level = "WARN" if required else "note"
            print(f"[elf-presence] {level}: cannot read {path} ({exc})", file=sys.stderr)
            return None
        return {k: v for k, v in raw.items() if not k.startswith("_")}

    name_of = load_map(map_path, True)
    if name_of is None:
        print("[]")
        return 0
    prog_of = load_map(prog_path, False) or {}

    if not os.path.isdir(root):
        print("[]")
        return 0

    paths, capped = find_elf_files(root)
    if capped:
        print(f"[elf-presence] WARN: stopped at {MAX_FILES} ELF files; "
              f"raise FW_ELF_MAX_FILES to cover the rest.", file=sys.stderr)
    if not paths:
        print("[]")
        return 0

    dynamic = read_dynamic(paths)

    # component name -> {"files": set, "needed_by": int, "sonames": set}
    found = {}
    unmapped = {}

    def note(key, evidence_path, as_needed, soname):
        comp = name_of.get(key)
        if not comp:
            if key:
                unmapped[key] = unmapped.get(key, 0) + 1
            return
        e = found.setdefault(comp, {"files": set(), "needed_by": 0, "sonames": set()})
        if soname:
            e["sonames"].add(soname)
        if as_needed:
            e["needed_by"] += 1
        elif evidence_path:
            e["files"].add(evidence_path)

    busybox_applets = 0

    def is_busybox(path):
        """An image can install `/bin/telnetd` as a copy of busybox. That image is
        carrying busybox, which is already identified with a version, not telnetd."""
        try:
            with open(path, "rb") as f:
                return b"BusyBox v" in f.read(4 * 1024 * 1024)
        except OSError:
            return False

    seen_paths = set()
    for path in paths:
        d = dynamic.get(path)
        rel = in_firmware_path(os.path.relpath(path, root))
        if rel in seen_paths:
            continue
        seen_paths.add(rel)

        # An installed program name is the other half of the evidence. `/bin/dhcpcd`
        # says dhcpcd is here as plainly as libnetsnmp.so.30 says net-snmp is, and
        # the name a program is installed under is often not its component:
        # brctl ships in bridge-utils, chat and pppd in ppp, ip and tc in iproute2.
        # Only under bin/ or sbin/, so a data file that happens to share a name
        # cannot stand in for the program.
        parts = rel.split("/")
        if len(parts) >= 2 and parts[-2] in ("bin", "sbin"):
            comp = prog_of.get(parts[-1].lower())
            if comp:
                if is_busybox(path):
                    busybox_applets += 1
                else:
                    e = found.setdefault(comp, {"files": set(), "needed_by": 0,
                                                "sonames": set()})
                    e["files"].add(rel)

        if d and d.get("soname"):
            note(stem(d["soname"]), rel, False, d["soname"])
        elif os.path.basename(path).find(".so") > 0:
            # A shared library that declares no SONAME still names itself.
            note(stem(os.path.basename(path)), rel, False, os.path.basename(path))
        for lib in (d or {}).get("needed", []):
            note(stem(lib), None, True, lib)

    components = []
    needed_only = []
    for comp in sorted(found):
        e = found[comp]
        # A NEEDED entry on its own is not enough. It is a link-time name a vendor
        # is free to reuse, and there is no file to point a reader at: MikroTik
        # RouterOS has one binary listing `libubox.so`, beside its own libumsg,
        # liburadius, libucrypto and libuc++ — its own `libu*` family, not
        # OpenWrt's libubox. Reported as a component that would have been a wrong
        # name backed by no evidence. The library file has to be in the image.
        if not e["files"]:
            needed_only.append(comp)
            continue
        occ = [{"location": p} for p in sorted(e["files"])]
        props = [{"name": "bomlens:evidenceGrade", "value": "presence-only"},
                 {"name": "bomlens:identifiedBy", "value": "elf-presence"}]
        if e["sonames"]:
            props.append({"name": "bomlens:elfSoname", "value": ", ".join(sorted(e["sonames"]))})
        if e["needed_by"]:
            props.append({"name": "bomlens:elfNeededBy", "value": str(e["needed_by"])})
        components.append({
            "bom-ref": f"elf-presence:{comp}",
            "type": "library",
            "name": comp,
            "properties": props,
            **({"evidence": {"occurrences": occ}} if occ else {}),
        })

    print(json.dumps(components, ensure_ascii=False))
    print(f"[elf-presence] {len(seen_paths)} distinct ELF file(s) of {len(paths)} found; "
          f"{len(components)} component(s) proved present by structure.", file=sys.stderr)
    if busybox_applets:
        print(f"[elf-presence] {busybox_applets} program name(s) skipped because the "
              f"file is a copy of busybox, which is identified separately.",
              file=sys.stderr)
    if needed_only:
        print(f"[elf-presence] {len(needed_only)} mapped name(s) appeared only as a NEEDED "
              f"entry with no library file present, so they were not reported: "
              + ", ".join(sorted(needed_only)), file=sys.stderr)
    if unmapped:
        top = sorted(unmapped.items(), key=lambda kv: -kv[1])[:15]
        print(f"[elf-presence] {len(unmapped)} library name(s) have no mapping and were "
              f"not reported: " + ", ".join(f"{k}({n})" for k, n in top), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
