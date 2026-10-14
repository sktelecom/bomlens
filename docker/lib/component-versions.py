#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# component-versions.py - fill in the versions a firmware, root filesystem or
# binary scan could not read, from a two-column file the supplier writes, and
# list the components still missing one.
#
# Usage: component-versions.py [--no-template] <sbom.json> <out_prefix> [versions.csv]
#   edits <sbom.json> in place when a file is given, and writes
#   <out_prefix>_component-versions.template.csv listing every component that
#   still has no version and whose name the file can hold (removed when there
#   is none). --no-template only
#   lists them: the entrypoint passes it when the file given is that template,
#   so the supplier's filled-in copy is not overwritten.
#
# The file (--component-versions on the CLI) is CSV with two columns, name and
# version. A first row reading "name,version" is a header; blank lines and
# lines starting with '#' are skipped; a row with an empty version is read as
# "not known" and skipped before anything else in the row is checked, so the
# template this script writes can be passed back with only some rows filled.
#
# A version normalize-sbom.sh removes counts as no version here: the
# placeholder UNKNOWN (a kernel module with no version in its metadata), and an
# operating-system epoch:version-release string on a component whose purl is
# not an OS package. This step runs before normalize, so such a component is
# listed in the template, and a version the file gives replaces the
# placeholder instead of being dropped with it. A name the file format cannot
# hold (outside the character set below) is listed on the console, not in the
# template, so the template passed back is always accepted.
#
# What a row does, matched on the component name (case is ignored):
#   - a package component with no version takes the version from the file. A
#     presence-only judgement (bomlens:evidenceGrade) is dropped, since the
#     component now has a version, and bomlens:versionSource=supplier-declared
#     records where that version came from. The evidence is kept;
#   - a component whose version the scan read keeps it. When the file says
#     something different, a warning names both: a version read from the
#     binary is what is installed, and a source tree can hold several;
#   - a name the scan did not find is added as a library component marked
#     bomlens:identifiedBy=supplier-declared.
#
# The file is external input. It is refused as a whole, with the line and the
# reason, when it is larger than MAX_BYTES, holds more than MAX_ROWS rows, is not
# UTF-8 text, has a row that is not exactly two fields, has a name or version
# outside a conservative character set (no path separators, no '..', no spaces
# or control characters), or gives one name two different versions. Exit code 3
# means the file was refused and the SBOM was not changed.
import csv
import io
import json
import os
import re
import sys

MAX_BYTES = 256 * 1024
MAX_ROWS = 5000
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$")
PACKAGE_TYPES = {"library", "application", "framework", "firmware", "operating-system"}
TEMPLATE_SUFFIX = "_component-versions.template.csv"
DECLARED = "supplier-declared"
# What normalize-sbom.sh removes from .version (UNKNOWN_VERSION_FIX and
# VERSION_EVR_CONTAMINATION_FIX); keep the two in step.
PLACEHOLDER_VERSIONS = {"unknown"}
_EVR_PREFIX = re.compile(r"^[0-9]+:")
_OS_PURL = re.compile(r"^pkg:(rpm|deb|apk|alpm)/")


class Refused(Exception):
    pass


def valid_name(name):
    return bool(NAME_RE.match(name)) and ".." not in name


def read_versions(path):
    """{lower-cased name: (name as written, version)} from the file, or Refused."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise Refused(f"the file cannot be read ({exc.strerror})")
    if size > MAX_BYTES:
        raise Refused(f"the file is {size} bytes; the limit is {MAX_BYTES}")
    with open(path, "rb") as f:
        raw = f.read(MAX_BYTES + 1)
    if b"\x00" in raw:
        raise Refused("the file holds a NUL byte, so it is not a text file")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise Refused(f"the file is not UTF-8 text (byte {exc.start})")
    out = {}
    rows = 0
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        for fields in reader:
            line = reader.line_num
            if not fields or all(not f.strip() for f in fields):
                continue
            if fields[0].lstrip().startswith("#"):
                continue
            rows += 1
            if rows > MAX_ROWS:
                raise Refused(f"the file has more than {MAX_ROWS} rows")
            if len(fields) != 2:
                raise Refused(f"line {line}: expected two fields (name,version), found {len(fields)}")
            name, version = fields[0].strip(), fields[1].strip()
            if rows == 1 and name.lower() == "name" and version.lower() == "version":
                continue
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in name + version):
                raise Refused(f"line {line}: a control character is not allowed")
            if version == "":
                continue
            if not valid_name(name):
                raise Refused(f"line {line}: '{name[:60]}' is not a component name "
                              "(letters, digits and . _ + - only, up to 128 characters)")
            if not VERSION_RE.match(version) or ".." in version:
                raise Refused(f"line {line}: '{version[:60]}' is not a version "
                              "(letters, digits and . _ + ~ - only, up to 64 characters)")
            key = name.lower()
            if key in out and out[key][1] != version:
                raise Refused(f"line {line}: {name} is given two versions, "
                              f"{out[key][1]} and {version}")
            out[key] = (name, version)
    except csv.Error as exc:
        raise Refused(f"line {reader.line_num}: {exc}")
    return out


def prop(c, name):
    for p in c.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == name:
            return p.get("value")
    return None


def is_package(c):
    return isinstance(c, dict) and c.get("type", "library") in PACKAGE_TYPES


def placeholder_version(c):
    """True when .version holds a value normalize-sbom.sh removes."""
    v = c.get("version")
    if not isinstance(v, str):
        return False
    if v.strip().lower() in PLACEHOLDER_VERSIONS:
        return True
    purl = c.get("purl") or ""
    return bool(_EVR_PREFIX.match(v)) and purl != "" and not _OS_PURL.match(purl)


def has_version(c):
    v = c.get("version")
    return isinstance(v, str) and v.strip() != "" and not placeholder_version(c)


def apply(doc, versions):
    comps = doc.setdefault("components", [])
    if not isinstance(comps, list):
        comps = doc["components"] = []
    seen = set()
    filled, kept, added = [], [], []
    for c in comps:
        if not is_package(c):
            continue
        key = (c.get("name") or "").strip().lower()
        if key not in versions:
            continue
        seen.add(key)
        _, version = versions[key]
        if has_version(c):
            if c["version"] != version:
                kept.append((c.get("name"), c["version"], version))
            continue
        replaced = c.get("version") if placeholder_version(c) and _EVR_PREFIX.match(c["version"]) else None
        c["version"] = version
        props = [p for p in (c.get("properties") or [])
                 if not (isinstance(p, dict)
                         and ((p.get("name") == "bomlens:evidenceGrade" and p.get("value") == "presence-only")
                              or p.get("name") == "bomlens:versionSource"
                              or (replaced and p.get("name") == "bomlens:versionContaminated")))]
        if replaced:
            # What normalize would have kept: the misattributed string, for audit.
            props.append({"name": "bomlens:versionContaminated", "value": replaced})
        props.append({"name": "bomlens:versionSource", "value": DECLARED})
        c["properties"] = props
        filled.append((c.get("name"), version))
    refs = {c.get("bom-ref") for c in comps if isinstance(c, dict)}
    for key in sorted(versions):
        if key in seen:
            continue
        name, version = versions[key]
        ref = f"{DECLARED}:{name}@{version}"
        if ref in refs:
            continue
        comps.append({
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "properties": [{"name": "bomlens:identifiedBy", "value": DECLARED}],
        })
        refs.add(ref)
        added.append((name, version))
    return filled, kept, added


def versionless(doc):
    names = set()
    for c in doc.get("components") or []:
        if is_package(c) and not has_version(c) and (c.get("name") or "").strip():
            names.add(c["name"].strip())
    return sorted(names, key=str.lower)


def write_template(path, names):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("# Components this scan found but could not read a version for.\n")
        f.write("# Write the version shipped in the product after each name, then pass\n")
        f.write("# this file back with --component-versions. Rows left empty are skipped.\n")
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["name", "version"])
        for n in names:
            w.writerow([n, ""])


def main(argv):
    keep_template = len(argv) > 1 and argv[1] == "--no-template"
    if keep_template:
        argv = argv[:1] + argv[2:]
    if len(argv) not in (3, 4):
        print("usage: component-versions.py [--no-template] <sbom.json> <out_prefix> [versions.csv]", file=sys.stderr)
        return 2
    sbom_path, prefix = argv[1], argv[2]
    try:
        with open(sbom_path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[component-versions] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return 1
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        return 0
    rc = 0
    if len(argv) == 4:
        try:
            versions = read_versions(argv[3])
        except Refused as why:
            print(f"[component-versions] ERROR: the --component-versions file was refused: {why}.", file=sys.stderr)
            print("[component-versions]   Fix it and run the scan again. The format is CSV, two columns:"
                  " name,version (one component per line).", file=sys.stderr)
            versions = None
            rc = 3
        if versions:
            filled, kept, added = apply(doc, versions)
            tmp = sbom_path + ".versions.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False)
            os.replace(tmp, sbom_path)
            print(f"[component-versions] filled the version of {len(filled)} component(s) from the file"
                  f" and added {len(added)} the scan did not find (marked supplier-declared).")
            for name, read, declared in kept:
                print(f"[component-versions] WARN: {name}: the scan read {read}; the file says {declared}."
                      f" Keeping {read}, the version found in the delivered files.", file=sys.stderr)
    template = prefix + TEMPLATE_SUFFIX
    missing_all = versionless(doc)
    missing = [n for n in missing_all if valid_name(n)]
    unwritable = [n for n in missing_all if not valid_name(n)]
    if unwritable:
        shown = ", ".join(repr(n[:60]) for n in unwritable[:10]) + (
            f" (and {len(unwritable) - 10} more)" if len(unwritable) > 10 else "")
        print(f"[component-versions] {len(unwritable)} component(s) with no version have a name the"
              f" --component-versions file cannot hold, so they are not in the template: {shown}")
        print("[component-versions]   A name may hold only letters, digits and . _ + -"
              " (up to 128 characters).")
    if missing:
        shown = ", ".join(missing[:30]) + (f" (and {len(missing) - 30} more)" if len(missing) > 30 else "")
        print(f"[component-versions] {len(missing)} component(s) still have no version: {shown}")
        if keep_template:
            print("[component-versions]   Add them to the file passed with --component-versions.")
        else:
            write_template(template, missing)
            print(f"[component-versions]   Fill in {os.path.basename(template)} and pass it with"
                  " --component-versions to add them.")
    elif os.path.exists(template) and not keep_template:
        os.remove(template)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
