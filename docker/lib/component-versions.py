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
# The file (--component-versions on the CLI) is CSV with the columns name,
# version and an optional third, reason. A first row reading "name,version" or
# "name,version,reason" is a header; blank lines and lines starting with '#'
# are skipped; a row with neither a version nor a reason is read as "not
# known" and skipped before anything else in the row is checked, so the
# template this script writes can be passed back with only some rows filled.
# Two-column files are read as before.
#
# The reason says why a component has no version to give, one of REASONS:
# own-code (the manufacturer's own code), not-open-source (only the name
# matches an open source project) or version-unknown. It is recorded on the
# component as bomlens:versionReason, so the reviewer sees the explanation in
# the SBOM, and the submission conformance profile lists the component as
# explained instead of failing on it. A row that gives a version and a reason
# applies the version and ignores the reason, with a warning.
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
#     bomlens:identifiedBy=supplier-declared;
#   - a reason (no version) is recorded on a component the scan found without
#     a version. Given for a component that has a version, or for a name the
#     scan did not find, it is ignored with a warning: there is nothing to
#     explain, and a component the scan did not find cannot be added without
#     a version.
#
# The file is external input. It is refused as a whole, with the line and the
# reason, when it is larger than MAX_BYTES, holds more than MAX_ROWS rows, is not
# UTF-8 text, has a row that is not two or three fields, has a name or version
# outside a conservative character set (no path separators, no '..', no spaces
# or control characters), has a reason that is not one of REASONS, or gives one
# name two different versions or two different reasons. Exit code 3
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
REASON_PROP = "bomlens:versionReason"
REASONS = ("own-code", "not-open-source", "version-unknown")
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
    """{lower-cased name: (name as written, version, reason)} from the file, or Refused.

    One of version and reason is empty: a row that gives both keeps the version
    and drops the reason (main() warns about each one dropped, from the list
    returned beside the dict). A reason is read case-insensitively.
    """
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
    ignored = []
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
            if len(fields) not in (2, 3):
                raise Refused(f"line {line}: expected two or three fields (name,version[,reason]),"
                              f" found {len(fields)}")
            name, version = fields[0].strip(), fields[1].strip()
            reason = fields[2].strip().lower() if len(fields) == 3 else ""
            if rows == 1 and name.lower() == "name" and version.lower() == "version" \
                    and reason.lower() in ("", "reason"):
                continue
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in name + version + reason):
                raise Refused(f"line {line}: a control character is not allowed")
            if version == "" and reason == "":
                continue
            if reason and reason not in REASONS:
                raise Refused(f"line {line}: '{reason[:60]}' is not a reason"
                              f" (one of {', '.join(REASONS)})")
            if not valid_name(name):
                raise Refused(f"line {line}: '{name[:60]}' is not a component name "
                              "(letters, digits and . _ + - only, up to 128 characters)")
            if version and (not VERSION_RE.match(version) or ".." in version):
                raise Refused(f"line {line}: '{version[:60]}' is not a version "
                              "(letters, digits and . _ + ~ - only, up to 64 characters)")
            key = name.lower()
            if version and reason:
                ignored.append((name, reason))
                reason = ""
            if key in out:
                _, had_version, had_reason = out[key]
                if had_version and version and had_version != version:
                    raise Refused(f"line {line}: {name} is given two versions, "
                                  f"{had_version} and {version}")
                if had_reason and reason and had_reason != reason:
                    raise Refused(f"line {line}: {name} is given two reasons, "
                                  f"{had_reason} and {reason}")
                # A version on one row and a reason on another: the version wins.
                if had_version or version:
                    if reason or had_reason:
                        ignored.append((name, reason or had_reason))
                    out[key] = (name, had_version or version, "")
                    continue
            out[key] = (name, version, reason)
    except csv.Error as exc:
        raise Refused(f"line {reader.line_num}: {exc}")
    return out, ignored


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
    filled, kept, added, explained, unexplainable = [], [], [], [], []
    for c in comps:
        if not is_package(c):
            continue
        key = (c.get("name") or "").strip().lower()
        if key not in versions:
            continue
        seen.add(key)
        _, version, reason = versions[key]
        if not version:
            if has_version(c):
                unexplainable.append((c.get("name"), reason, f"the scan read version {c['version']}"))
                continue
            props = [p for p in (c.get("properties") or [])
                     if not (isinstance(p, dict) and p.get("name") == REASON_PROP)]
            props.append({"name": REASON_PROP, "value": reason})
            c["properties"] = props
            explained.append((c.get("name"), reason))
            continue
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
                              or p.get("name") == REASON_PROP
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
        name, version, reason = versions[key]
        if not version:
            unexplainable.append((name, reason, "the scan did not find it"))
            continue
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
    return filled, kept, added, explained, unexplainable


def versionless(doc):
    """Names of package components with no version and no recorded reason."""
    names = set()
    for c in doc.get("components") or []:
        if is_package(c) and not has_version(c) and (c.get("name") or "").strip() \
                and prop(c, REASON_PROP) not in REASONS:
            names.add(c["name"].strip())
    return sorted(names, key=str.lower)


def write_template(path, names):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("# Components this scan found but could not read a version for.\n")
        f.write("# Write the version shipped in the product after each name, then pass\n")
        f.write("# this file back with --component-versions. Rows left empty are skipped.\n")
        f.write("# When there is no version to give, leave version empty and write a reason:\n")
        f.write("#   own-code         the manufacturer's own code, not open source\n")
        f.write("#   not-open-source  only the name matches an open source project\n")
        f.write("#   version-unknown  open source, but the shipped version cannot be confirmed\n")
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["name", "version", "reason"])
        for n in names:
            w.writerow([n, "", ""])


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
            versions, ignored = read_versions(argv[3])
        except Refused as why:
            print(f"[component-versions] ERROR: the --component-versions file was refused: {why}.", file=sys.stderr)
            print("[component-versions]   Fix it and run the scan again. The format is CSV:"
                  " name,version[,reason] (one component per line; reason is one of "
                  + ", ".join(REASONS) + ").", file=sys.stderr)
            versions, ignored = None, []
            rc = 3
        for name, reason in ignored:
            print(f"[component-versions] WARN: {name}: the file gives a version, so the reason"
                  f" {reason} is ignored.", file=sys.stderr)
        if versions:
            filled, kept, added, explained, unexplainable = apply(doc, versions)
            tmp = sbom_path + ".versions.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False)
            os.replace(tmp, sbom_path)
            print(f"[component-versions] filled the version of {len(filled)} component(s) from the file"
                  f" and added {len(added)} the scan did not find (marked supplier-declared).")
            for name, read, declared in kept:
                print(f"[component-versions] WARN: {name}: the scan read {read}; the file says {declared}."
                      f" Keeping {read}, the version found in the delivered files.", file=sys.stderr)
            if explained:
                shown = ", ".join(f"{n} ({r})" for n, r in explained[:30]) + (
                    f" (and {len(explained) - 30} more)" if len(explained) > 30 else "")
                print(f"[component-versions] recorded the reason {len(explained)} component(s) have no"
                      f" version ({REASON_PROP}): {shown}")
            for name, reason, why in unexplainable:
                print(f"[component-versions] WARN: {name}: the reason {reason} is ignored, because"
                      f" {why}.", file=sys.stderr)
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
