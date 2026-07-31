#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
  - the symbols an ELF exports, for a component linked into someone else's binary
  - for a SONAME that names a slot rather than a project, the marker the occupant
    writes about itself
  - NEEDED entries in other ELFs, counted as corroboration

The name a program is installed under is often not its component: brctl ships in
bridge-utils, chat and pppd in ppp, hostapd_cli in hostapd, ip and tc in
iproute2. All three mappings are written out by hand (elf-soname-map.json,
elf-program-map.json and elf-symbol-map.json) rather than derived.

The slot pass exists because some SONAMEs name a role, not a project. `libc`
says something is the C library, not which one, and the corpus has three
different answers across seven images with three different licences. The library
settles it inside its own file: musl writes `musl libc` into its loader banner,
glibc writes `GNU C Library`. This is not the string search rejected below —
structure has already picked the file, and the string only chooses among a closed
list of candidates for that one slot.

The symbol pass exists because the first two only work while a component is
still its own file. The Zyxel GS1900-8 notice declares ncurses, readline and
quagga, and all three sit inside one 400 KB executable with no version string
left for any of them — but it exports 1259 dynamic symbols, among them 46
ncurses internals, 145 readline internals and 18 vtysh entry points, because its
plugin libraries resolve back into it. Where the symbols did not survive there is
still nothing to read: MikroTik's sshfs has FUSE linked in and exports none.

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

# How much of a slot library to read looking for its self-identifying marker. The
# banner sits in the loader's string table, well inside this, and only the handful
# of files whose SONAME is a listed slot are read at all.
SLOT_READ_BYTES = 4 * 1024 * 1024

NEEDED_RE = re.compile(r"\(NEEDED\).*\[([^\]]+)\]")
SONAME_RE = re.compile(r"\(SONAME\).*\[([^\]]+)\]")
FILE_RE = re.compile(r"^File: (.*)$")
# A .dynsym row: "   446: 10006388     4 OBJECT  GLOBAL DEFAULT   23 rl_char_is_quoted_p".
# -W is passed so the name is never abbreviated to `rl_completion_qu[...]`, which
# would silently miss every symbol long enough to be worth matching on.
SYMROW_RE = re.compile(r"^\s*\d+:\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$")

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


def read_dynamic(paths, watched=frozenset()):
    """path -> {"soname": str|None, "needed": [str], "syms": set} for every ELF read.

    The dynamic section and the dynamic symbol table come out of one readelf call
    per batch: asking twice would double the process count over a tree that
    already runs to thousands of files.

    Only symbols in `watched` are kept. A rootfs of a few hundred ELFs holds
    hundreds of thousands of symbols, and all but the handful the maps name are
    of no interest — holding them would be the one place this could grow without
    bound. For the same reason the output is streamed rather than captured whole.
    """
    info = {}

    def entry(path):
        return info.setdefault(path, {"soname": None, "needed": [], "syms": set()})

    for i in range(0, len(paths), BATCH):
        chunk = paths[i:i + BATCH]
        args = ["readelf", "-W", "-d"] + (["--dyn-syms"] if watched else []) + ["--"] + chunk
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
        except (OSError, subprocess.SubprocessError):
            continue
        # With one file readelf prints no `File:` header, so seed it.
        current = chunk[0] if len(chunk) == 1 else None
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                m = FILE_RE.match(line)
                if m:
                    current = m.group(1)
                    continue
                if current is None:
                    continue
                m = NEEDED_RE.search(line)
                if m:
                    entry(current)["needed"].append(m.group(1))
                    continue
                m = SONAME_RE.search(line)
                if m:
                    entry(current)["soname"] = m.group(1)
                    continue
                if watched:
                    m = SYMROW_RE.match(line)
                    if m and m.group(1) in watched:
                        entry(current)["syms"].add(m.group(1))
        finally:
            proc.stdout.close()
            try:
                proc.wait(timeout=300)
            except subprocess.SubprocessError:
                proc.kill()
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
    sym_map = load_map(os.path.join(here, "elf-symbol-map.json"), False) or {}

    # component -> (set of its symbols, how many have to be present). One name
    # shared with another project is a coincidence; the threshold is what makes a
    # match mean something, and what lets a vendor-patched build still be read.
    sym_rules = {}
    watched = set()
    # family name -> [(member, marker bytes)]. A fork can keep its parent's symbol
    # names, so the symbols say the family and the file says which member.
    sym_variants = {}
    for comp, rule in sym_map.items():
        syms = set(rule.get("symbols") or [])
        if not syms:
            continue
        need = int(rule.get("min", len(syms)))
        sym_rules[comp] = (syms, max(1, min(need, len(syms))))
        watched |= syms
        var = rule.get("variants") or {}
        cands = []
        for c in var.get("candidates") or []:
            marks = [m.encode("utf-8", "ignore") for m in (c.get("markers") or [])]
            if c.get("name") and marks:
                cands.append((c["name"], marks))
        if cands:
            sym_variants[comp] = (cands, var.get("default") or comp)

    # soname stem -> [(component, marker bytes)]. Only a stem listed here is ever
    # read for content, and only the library file itself.
    slot_map = load_map(os.path.join(here, "elf-ambiguous-soname-map.json"), False) or {}
    slot_rules = {}
    for stem_name, rule in slot_map.items():
        cands = [(c.get("name"), (c.get("marker") or "").encode("utf-8", "ignore"))
                 for c in (rule.get("candidates") or [])]
        cands = [(n, m) for n, m in cands if n and m]
        if cands:
            slot_rules[stem_name.lower()] = cands

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

    dynamic = read_dynamic(paths, watched)

    # component name -> {"files": set, "needed_by": int, "sonames": set, "symbols": dict}
    found = {}
    unmapped = {}

    def blank():
        return {"files": set(), "needed_by": 0, "sonames": set(), "symbols": {},
                "markers": {}}

    # A slot SONAME whose file named nobody, or named two. Counted so the run log
    # can say the slot was looked at and left open, rather than saying nothing.
    slot_open = {}

    def fills_slot(path, key):
        """For a SONAME that names a slot, ask the file which project fills it.

        Exactly one candidate has to match. Two markers mean the file is not what
        the SONAME said it was, none means the slot holds something not listed,
        and neither is a basis for naming a component."""
        cands = slot_rules.get(key)
        if not cands:
            return None, None
        try:
            with open(path, "rb") as f:
                blob = f.read(SLOT_READ_BYTES)
        except OSError:
            return None, None
        hit = [(n, m) for n, m in cands if m in blob]
        if len(hit) == 1:
            return hit[0][0], hit[0][1].decode("utf-8", "replace")
        slot_open[key] = slot_open.get(key, 0) + 1
        return None, None

    def note(key, evidence_path, as_needed, soname):
        comp = name_of.get(key)
        if not comp:
            if key:
                unmapped[key] = unmapped.get(key, 0) + 1
            return
        e = found.setdefault(comp, blank())
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

    # A fork that kept its parent's symbol names, reported under the family name
    # because the file said nothing either way. Counted so the log can say so.
    variant_undecided = {}

    def which_variant(path, family):
        """Which member of a symbol family this file is, and the marker that said so.

        A fork can inherit every symbol name it was forked from — FRRouting kept
        quagga's, down to writing /var/tmp/quagga — so the symbol table names the
        family and only the file's own wording separates the members. Exactly one
        candidate may match: a file matching two is not something these markers
        settle, and one matching none is a build whose wording is unknown. Both
        fall back to the family name rather than guess."""
        rule = sym_variants.get(family)
        if not rule:
            return family, None
        cands, default = rule
        try:
            with open(path, "rb") as f:
                blob = f.read(SLOT_READ_BYTES)
        except OSError:
            return default, None
        hit = [(n, m) for n, marks in cands for m in marks if m in blob]
        names = {n for n, _ in hit}
        if len(names) == 1:
            n, m = hit[0]
            return n, m.decode("utf-8", "replace")
        variant_undecided[family] = variant_undecided.get(family, 0) + 1
        return default, None

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
                    found.setdefault(comp, blank())["files"].add(rel)

        # A SONAME that names a slot rather than a project (`libc`) is settled by
        # the file, which writes its own name inside. Everything else goes to the
        # name map as before.
        selfname = None
        if d and d.get("soname"):
            selfname = d["soname"]
        elif os.path.basename(path).find(".so") > 0:
            # A shared library that declares no SONAME still names itself.
            selfname = os.path.basename(path)
        if selfname:
            key = stem(selfname)
            comp, marker = fills_slot(path, key)
            if comp:
                e = found.setdefault(comp, blank())
                e["files"].add(rel)
                e["sonames"].add(selfname)
                e["markers"][rel] = marker
            else:
                note(key, rel, False, selfname)
        for lib in (d or {}).get("needed", []):
            # Nothing to read for a NEEDED entry, so a slot name stays unresolved
            # here and is counted as unmapped, which is what it is.
            note(stem(lib), None, True, lib)

        # A component linked into someone else's binary has no file and no
        # SONAME left to read, but its symbols can still be exported. Which ones
        # matched is recorded so a reader can check the call rather than take it.
        seen_syms = (d or {}).get("syms") or set()
        if seen_syms:
            for comp, (want, need) in sym_rules.items():
                hit = seen_syms & want
                if len(hit) < need:
                    continue
                name, marker = which_variant(path, comp)
                e = found.setdefault(name, blank())
                e["files"].add(rel)
                e["symbols"].setdefault(rel, set()).update(hit)
                if marker:
                    e["markers"][rel] = marker

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
        if e["markers"]:
            # Name the marker and the file it was in. A reader who doubts the
            # call can open that file and look for that string.
            props.append({"name": "bomlens:elfSlotMarker",
                          "value": "; ".join(f"{p}: {m}"
                                             for p, m in sorted(e["markers"].items()))})
        if e["symbols"]:
            # Name the symbols, not just the count. "matched 6 symbols" cannot be
            # checked by anyone; "_nc_setupterm in bin/cli" can, and this whole
            # pass is only worth having if its judgements are checkable.
            shown = ["%s: %s" % (p, ", ".join(sorted(s)))
                     for p, s in sorted(e["symbols"].items())]
            props.append({"name": "bomlens:elfSymbols", "value": "; ".join(shown)})
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
    by_slot = sorted(c for c in found if found[c]["markers"])
    if by_slot:
        print(f"[elf-presence] {len(by_slot)} of them fill a SONAME that names a slot "
              f"rather than a project, and were read from the marker the library "
              f"writes about itself: " + ", ".join(by_slot), file=sys.stderr)
    if slot_open:
        detail = ", ".join(f"{k}({n})" for k, n in sorted(slot_open.items()))
        print(f"[elf-presence] {sum(slot_open.values())} slot librar(y/ies) matched no "
              f"candidate marker, or more than one, so the slot was left unnamed: "
              f"{detail}", file=sys.stderr)
    if variant_undecided:
        detail = ", ".join(f"{k}({n})" for k, n in sorted(variant_undecided.items()))
        print(f"[elf-presence] {sum(variant_undecided.values())} file(s) matched a symbol "
              f"family whose members share those names, and carried no marker that "
              f"tells them apart, so the family name was kept: {detail}", file=sys.stderr)
    by_symbol = sorted(c for c in found if found[c]["symbols"])
    if by_symbol:
        print(f"[elf-presence] {len(by_symbol)} of them were linked into another "
              f"binary and read from its exported symbols: " + ", ".join(by_symbol),
              file=sys.stderr)
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
