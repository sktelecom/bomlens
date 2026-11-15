#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Identify open-source components in the binaries of a root filesystem from a binary knowledge base.

Usage: identify-binary-kb.py <rootfs> [kb.sqlite3 | kb-directory] > components.json

The knowledge base is built from the sources of each release (see binarykb.py), so this finds
components that left no version string and no package record behind: a library linked into a
program, a daemon whose banner was compiled out. It never overrides another judgement; the merge
in scan-firmware.sh keeps whichever record already carries a version.

What a result says, and how far to trust it:

  version        Written only when exactly one release of the component fits the strings found.
                 When several fit (mbed TLS builds that leave the version out, for one), the
                 component is reported without a version and `bomlens:versionCandidates` lists them,
                 so nothing is matched against a release nobody could pick.
  newer          When the one release that fits is the newest the database has, the shipped version
                 can be newer, and a version that is not in the database comes back as its nearest
                 neighbour (a measured failure: zlib 1.2.13 read as 1.2.11 and matched against four
                 vulnerabilities it does not have). The component is then reported without a version,
                 with `bomlens:versionMayBeNewer` and the release as `bomlens:versionCandidates`, and
                 lands in the component-versions template for the supplier to fill. Set
                 FW_BINKB_TRUST_NEWEST=true to write the version anyway, with the same marker.
  presence only  A component found by constant tables alone has no version.

A review file (FW_BINARY_KB_DECISIONS, a JSON list) records what a person decided about a result:
  {"component": "busybox", "decision": "exclude" | "confirm" | "version",
   "version": "1.36.1", "reason": "...", "reviewer": "...", "evidence_sha256": "..."}
`exclude` drops the component, `version` replaces the version, `confirm` marks the result reviewed.
A decision without a reason is ignored. With `evidence_sha256` it applies only while the file the
result was found in still has that hash, so a changed file goes back to review.
"""
import hashlib
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import binarykb  # noqa: E402

# unblob names each nesting level `<something>_extract/`, and the carve pass adds
# `<image>.extracted/`. The same rootfs lands under both, so one file is seen twice.
MARKER = re.compile(r".*(?:_extract/|\.extracted/)")
MAX_EVIDENCE_FILES = 10
WEAK_FACTOR = 2.5   # a score under this multiple of the stored threshold is reported as low confidence


def cap(name, default):
    """A positive integer from the environment, or the default.

    The caller forwards these as `-e NAME=` whether or not the user set one, so an unset cap
    arrives as an empty string and `int("")` raises. Anything that is not a positive integer
    falls back to the default: a cap is a safety limit, and a malformed one must not stop the
    pass or be read as zero and silently examine nothing.
    """
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_FILES = cap("FW_BINKB_MAX_FILES", 20000)
MAX_BYTES = cap("FW_BINKB_MAX_BYTES", 64 * 1024 * 1024)


# Files that are a component's own although the name does not carry the component's name.
OWN_NAMES = {
    "zlib": ("libz",), "openssl": ("libcrypto", "libssl", "openssl"), "mbedtls": ("libmbedcrypto", "libmbedtls", "libmbedx509"),
    "iproute2": ("ip", "tc", "ss", "bridge"), "hostapd": ("hostapd", "wpad"), "wpa_supplicant": ("wpa_supplicant", "wpad"),
    "libpng": ("libpng",), "expat": ("libexpat",), "libcurl": ("libcurl",), "curl": ("curl", "libcurl"),
}


def is_own_file(component, rel):
    """True when a file is the component itself (libz.so.1 for zlib, bin/busybox for busybox).

    A hit in any other file means the component's code is inside a program that was built
    from it or linked it statically, which is the case a package record never shows.
    The name must start with the component's name or a known own name, followed by the end of the
    name, a dot, a dash or a digit; a name that only contains it (libzstd for zlib) is another file.
    """
    base = os.path.basename(rel).lower()
    comp = component.lower()
    names = {re.sub(r"[^a-z0-9_]", "", comp), re.sub(r"[^a-z0-9]", "", comp)}
    names.update(OWN_NAMES.get(comp, ()))
    for key in names:
        for stem in (key, "lib" + key):
            if re.match(re.escape(stem) + r"(?:$|[.\-_0-9])", base):
                return True
    return False


def locate(arg):
    """The database file named by a path or a directory holding kb.sqlite3, or None."""
    if not arg:
        return None
    if os.path.isdir(arg):
        arg = os.path.join(arg, "kb.sqlite3")
    return arg if os.path.isfile(arg) else None


def load_decisions(path):
    if not path or not os.path.isfile(path):
        return []
    try:
        raw = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"[binary-kb] WARN: cannot read the review file {path} ({exc}); ignoring it", file=sys.stderr)
        return []
    out = []
    for d in raw if isinstance(raw, list) else []:
        if not isinstance(d, dict) or d.get("decision") not in ("exclude", "confirm", "version") or not d.get("component"):
            print(f"[binary-kb] WARN: skipping a malformed review entry: {str(d)[:80]}", file=sys.stderr); continue
        if not str(d.get("reason", "")).strip():
            print(f"[binary-kb] WARN: skipping the review entry for {d['component']}: it gives no reason", file=sys.stderr); continue
        if d["decision"] == "version" and not str(d.get("version", "")).strip():
            print(f"[binary-kb] WARN: skipping the review entry for {d['component']}: no version given", file=sys.stderr); continue
        out.append(d)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = sys.argv[1]
    db_path = locate(sys.argv[2] if len(sys.argv) > 2 else os.environ.get("FW_BINARY_KB", ""))
    if not db_path or not os.path.isdir(root):
        print("[]")
        print("[binary-kb] no knowledge base given; skipping.", file=sys.stderr)
        return 0
    try:
        kb = binarykb.KnowledgeBase(db_path)
    except Exception as exc:   # a damaged or newer database must not stop the scan
        print(f"[binary-kb] WARN: cannot open {db_path} ({exc}); skipping", file=sys.stderr)
        print("[]")
        return 0
    h256 = hashlib.sha256()
    with open(db_path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h256.update(blk)
    kb_sha = h256.hexdigest()
    include_other = os.environ.get("FW_BINKB_NONELF", "") == "true"
    trust_newest = os.environ.get("FW_BINKB_TRUST_NEWEST", "") == "true"
    decisions = load_decisions(os.environ.get("FW_BINARY_KB_DECISIONS", ""))

    # component -> best result and the files it was found in
    found = {}
    seen, scanned, capped, unreadable, damaged = set(), 0, False, 0, False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()   # the order decides which files fall under the cap and which copy of a file is kept
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = MARKER.sub("", os.path.relpath(p, root), count=1)
            if rel in seen:
                continue
            seen.add(rel)
            try:
                if os.path.getsize(p) > MAX_BYTES or os.path.getsize(p) < 64:
                    continue
                with open(p, "rb") as fh:
                    head = fh.read(4)
                    if head != b"\x7fELF" and not include_other:
                        continue
                    data = head + fh.read()
            except OSError:
                continue
            if scanned >= MAX_FILES:
                capped = True
                break
            scanned += 1
            try:
                hits, tables = kb.scan_bytes(data, rel)
            except sqlite3.DatabaseError as exc:   # the base itself is damaged: every later file would fail the same way
                print(f"[binary-kb] WARN: the knowledge base cannot be read ({exc}); the result is incomplete", file=sys.stderr)
                damaged = True
                break
            except (ValueError, IndexError, OverflowError, MemoryError) as exc:
                unreadable += 1
                print(f"[binary-kb] WARN: cannot read {rel} ({exc})", file=sys.stderr)
                continue
            for name in kb.detected(hits, tables, rel):
                h = hits.get(name)
                by_strings = bool(h) and h["unique"] >= kb.rule["unique"] and h["score"] >= kb.rule["score"]
                e = found.setdefault(name, {"per": []})
                sha = hashlib.sha256(data).hexdigest()
                cands = h["versions"] if by_strings else []
                resolved = cands[0] if len(cands) == 1 and (trust_newest or not h["latest"]) else None
                e["per"].append({"file": rel, "sha256": sha, "rank": (h["score"] if by_strings else 0, tables.get(name, [0, 0])[1]),
                                 "hit": h if by_strings else None, "tables": tables.get(name), "resolved": resolved, "cands": cands})
        if capped or damaged:
            break
    if capped:
        print(f"[binary-kb] WARN: stopped at {MAX_FILES} files; raise FW_BINKB_MAX_FILES to cover the rest.", file=sys.stderr)

    def group(per):
        files = [(x["file"], x["sha256"]) for x in per]
        best = max(per, key=lambda x: x["rank"])
        return {"files": files, "best": {"hit": best["hit"], "tables": best["tables"], "file": best["file"], "sha256": best["sha256"]}}

    # One result per name, unless the files disagree on the version: a library of one release next to a
    # program that carries another release is two components, and one of them must not hide the other.
    # A file that could not name a single version joins the groups whose version it still allows.
    entries = []
    for name in sorted(found):
        per = found[name]["per"]
        versions = sorted({x["resolved"] for x in per if x["resolved"]})
        if len(versions) < 2:
            entries.append((name, group(per)))
            continue
        for v in versions:
            entries.append((name, group([x for x in per if x["resolved"] == v or (not x["resolved"] and v in x["cands"])])))

    components, dropped = [], 0
    for name, e in entries:
        b = e["best"]; hit = b["hit"]
        props = [{"name": "bomlens:identifiedBy", "value": "binary-kb"},
                 {"name": "bomlens:kbRelease", "value": kb.release},
                 {"name": "bomlens:kbSha256", "value": kb_sha}]
        if damaged or unreadable:
            props.append({"name": "bomlens:kbResultIncomplete", "value": "true"})
        version = None
        if hit:
            props.append({"name": "bomlens:kbScore", "value": str(hit["score"])})
            props.append({"name": "bomlens:kbUniqueStrings", "value": str(hit["unique"])})
            # A score only a little above the base's threshold is where neighbouring packages that
            # share source strings show up, so such a result is marked for a person to look at.
            props.append({"name": "bomlens:kbConfidence", "value": "high" if hit["score"] >= WEAK_FACTOR * kb.rule["score"] else "low"})
            cands = hit["versions"]
            if len(cands) == 1 and (trust_newest or not hit["latest"]):
                version = cands[0]
                props.append({"name": "bomlens:versionBasis", "value": "kb-release-strings"})
                if hit["latest"]:
                    props.append({"name": "bomlens:versionMayBeNewer", "value": "true"})
            elif cands:
                # Several releases fit, or the one that fits is the newest the base has. In the second
                # case the shipped version can be newer, and a version nobody read would be matched
                # against vulnerabilities that a newer release has already fixed.
                props.append({"name": "bomlens:versionCandidates", "value": ",".join(cands[:50])})
                props.append({"name": "bomlens:versionRange", "value": f"{cands[0]}..{cands[-1]}" if len(cands) > 1 else f"{cands[0]} or later"})
                if hit["latest"]:
                    props.append({"name": "bomlens:versionMayBeNewer", "value": "true"})
        props.append({"name": "bomlens:kbEvidenceFile", "value": b["file"]})
        props.append({"name": "bomlens:kbEvidenceSha256", "value": b["sha256"]})
        if hit and hit.get("sample"):
            props.append({"name": "bomlens:kbEvidenceStrings", "value": json.dumps(hit["sample"], ensure_ascii=False)})
        if b["tables"]:
            props.append({"name": "bomlens:kbTables", "value": f"{b['tables'][0]} tables, {b['tables'][1]} bytes"})
        if version is None:
            # A component with no single version is a presence finding, and the merge drops it
            # when another pass already gave the same component a version.
            props.append({"name": "bomlens:evidenceGrade", "value": "presence-only"})

        verdict = None
        for d in decisions:
            if d["component"] != name:
                continue
            if d.get("evidence_sha256") and d["evidence_sha256"] != b["sha256"]:
                continue
            verdict = d
        if verdict:
            if verdict["decision"] == "exclude":
                dropped += 1
                print(f"[binary-kb] {name}: excluded by review ({verdict.get('reviewer', 'unknown')}): {verdict['reason']}", file=sys.stderr)
                continue
            if verdict["decision"] == "version":
                version = str(verdict["version"]).strip()
                props = [p for p in props if p["name"] not in ("bomlens:versionCandidates", "bomlens:versionRange", "bomlens:versionMayBeNewer",
                                                              "bomlens:evidenceGrade", "bomlens:versionBasis")]
                props.append({"name": "bomlens:versionBasis", "value": "review"})
            props.append({"name": "bomlens:review", "value": f"{verdict['decision']}: {verdict['reason']}"})
            if verdict.get("reviewer"):
                props.append({"name": "bomlens:reviewer", "value": str(verdict["reviewer"])})

        hosts = sorted({f for f, _ in e["files"] if not is_own_file(name, f)})
        if hosts:
            # The component's code was found inside other files: a static link or a copied source file.
            props.append({"name": "bomlens:linkage", "value": "embedded" if len(hosts) == len(e["files"]) else "own-file-and-embedded"})
            props.append({"name": "bomlens:embeddedIn", "value": ",".join(hosts[:MAX_EVIDENCE_FILES])})
        occurrences = [{"location": f} for f, _ in e["files"][:MAX_EVIDENCE_FILES]]
        comp = {"bom-ref": f"binary-kb:{name}@{version or 'unversioned'}", "type": "library", "name": name,
                "properties": props, "evidence": {"occurrences": occurrences}}
        if version:
            comp["version"] = version
        components.append(comp)

    print(json.dumps(components, ensure_ascii=False))
    print(f"[binary-kb] {scanned} file(s) read against release {kb.release}; {len(components)} component(s) identified"
          f"{f', {dropped} excluded by review' if dropped else ''}"
          f"{f', {unreadable} file(s) unreadable' if unreadable else ''}{', INCOMPLETE: knowledge base damaged' if damaged else ''}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
