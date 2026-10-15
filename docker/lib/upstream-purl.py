#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# upstream-purl.py - give a component identified in a firmware, root filesystem
# or binary scan, or read from a Yocto build's records, the purl of its upstream
# source repository.
#
# Usage: upstream-purl.py <sbom.json>                 (CycloneDX JSON, edited in place)
#        upstream-purl.py --resolve <name> <version>  (print the purl, or nothing)
#
# Why: what these scans identify is read out of binaries and package databases
# that belong to no language ecosystem. A component arrives with no purl, with
# pkg:generic, or with a package-manager type such as pkg:opkg that no
# vulnerability or license database resolves, so a tool that looks components
# up by purl cannot identify it even when the name and version are right. The
# upstream repository is something those tools do know: pkg:github/<owner>/<repo>
# at the release tag, or pkg:sourceforge / pkg:gnu for projects published there.
#
# How: docker/lib/upstream-purl-map.json is a closed table of projects, each with
# the names and CPE vendor:product pairs that mean it, its repository purl, the
# version shapes it covers, and how that repository spells a release tag. A
# component is changed only when all of these hold:
#   - its type is a package (library, application, framework, firmware,
#     operating-system), not a file or data;
#   - it has no purl, or one of a type listed in replaceablePurlTypes;
#   - it has a version, and that version, after removing the suffixes the entry
#     allows (a package rebuild count, a kernel build hash), matches the entry's
#     version expression in full (a kernel or glibc X.Y.0 is read as X.Y,
#     the form its repository tags);
#   - one of its names is in the entry's names, or its CPE vendor:product is in
#     the entry's cpe list, and the two do not point at different projects. Its
#     names are the component name and, when the scan recorded one, the name of
#     the source it was built from: the Yocto recipe (bomlens:yocto:recipe), the
#     OpenWrt source package (the last part of syft:metadata:source, so
#     libmbedtls12 is read as mbedtls), and the product of a CPE whose vendor is
#     '*' (Yocto writes its CVE_PRODUCT that way);
#   - for an operating-system component, no package or binary component in
#     the SBOM carries the same purl (busybox is reported as both; the purl
#     goes to the binary only).
# A component the table does not cover gets a purl from its source download
# address (bomlens:sourceUrl, written by the Yocto reader) only when that address
# states the repository and the release outright: a GitHub release asset or tag
# archive (github.com/<owner>/<repo>/releases/download/<tag>/,
# .../archive/refs/tags/<tag>.tar.gz) gives pkg:github/<owner>/<repo>@<tag>, and
# a GNU release (ftp.gnu.org or ftpmirror.gnu.org /gnu/<name>/<name>-<version>.tar.*)
# gives pkg:gnu/<name>@<version>. A plain tarball elsewhere, or a git commit, is
# not read as a release.
# Anything else is left exactly as it is. A name the table does not hold is
# never turned into a repository by pattern: a wrong owner or tag identifies a
# different project or a different version, which is worse than no purl.
#
# The component's version, CPE and evidence are not touched: the CVE matching
# that already ran on them (cve-bin-tool, the bundled CPE index) keeps its
# result, and the CPE stays for the tools that read it. The purl it replaces is
# kept in bomlens:originalPurl, and bomlens:purlSource=upstream-map records
# where the new one came from.
import json
import os
import re
import sys

MAP_FILE = os.environ.get(
    "UPSTREAM_PURL_MAP",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "upstream-purl-map.json"),
)
PURL_SOURCE = "upstream-map"
PACKAGE_TYPES = {"library", "application", "framework", "firmware", "operating-system"}
# What a tag may contain once built. Every rule in the table produces only these
# characters, so a purl version needs no percent-encoding; anything else means
# the table and the version disagree, and the component is left alone.
_TAG_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# A package rebuild count: OpenWrt and Buildroot write 1.36.1-1, Alpine 1.36.1-r2.
# At most three digits, so a dated snapshot suffix (6.4-20230520) is kept and the
# version then fails the entry's expression instead of losing its patch level.
_RELEASE = re.compile(r"-r?[0-9]{1,3}$")
# A build hash the kernel package carries after its version
# (5.15.167-1-040d391394b36f9ba6b7b1889d15738a).
_BUILD_HASH = re.compile(r"-[0-9a-f]{20,}$")
# A base release written with a zero third part (5.4.0) where the repository
# tags it with two (v5.4): the kernel and glibc never tag an X.Y.0.
_ZERO_SUBLEVEL = re.compile(r"^([0-9]+\.[0-9]+)\.0$")
_CPE23 = re.compile(r"^cpe:2\.3:[aho*]:([^:]+):([^:]+):")
_CPE22 = re.compile(r"^cpe:/[aho]:([^:]+):([^:]+)")
# Source addresses that state the release (see the header).
_GH_RELEASE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/"
    r"(?:releases/+download/([^/]+)/[^/]+|archive/refs/tags/([^/]+?)\.(?:tar\.gz|tar\.bz2|tar\.xz|zip))$")
_GNU_RELEASE = re.compile(
    r"^https?://(?:ftp|ftpmirror)\.gnu\.org/gnu/([a-z0-9][a-z0-9+_-]*)/"
    r"([a-z0-9][a-z0-9+_-]*)-([0-9][0-9A-Za-z.]*)\.tar\.(?:gz|bz2|xz|lz|zst)$")


def load_table(path=MAP_FILE):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    entries = []
    for e in doc.get("entries", []):
        if not isinstance(e, dict) or str(e.get("id", "")).startswith("_"):
            continue
        entries.append(dict(e, _re=re.compile(e["version"])))
    # A name or CPE can mean more than one entry when a project's tag spelling
    # changed between release series (OpenSSL 1.x and 3.x); the version picks.
    by_name, by_cpe = {}, {}
    for e in entries:
        for n in e.get("names", []):
            by_name.setdefault(n.lower(), []).append(e)
        for c in e.get("cpe", []):
            by_cpe.setdefault(c.lower(), []).append(e)
    types = {t.lower() for t in doc.get("replaceablePurlTypes", [])}
    return by_name, by_cpe, types


def cpe_vendor_product(cpe):
    if not isinstance(cpe, str):
        return None
    m = _CPE23.match(cpe) or _CPE22.match(cpe)
    if not m:
        return None
    return (m.group(1) + ":" + m.group(2)).lower()


def normalize_version(entry, version):
    v = version.strip()
    steps = entry.get("normalize", [])
    if "build-hash" in steps:
        v = _BUILD_HASH.sub("", v)
    if "release" in steps:
        v = _RELEASE.sub("", v)
    if "zero-sublevel" in steps:
        v = _ZERO_SUBLEVEL.sub(r"\1", v)
    return v


def build_tag(entry, version):
    """The release tag for this version, or None when the version is not of a
    shape the entry covers."""
    v = normalize_version(entry, version)
    m = entry["_re"].fullmatch(v)
    if not m:
        return None
    if "tags" in entry:
        tag = entry["tags"].get(v)
        return tag if tag and _TAG_SAFE.match(tag) else None
    tag = entry["tag"].replace("{v_}", v.replace(".", "_")).replace("{v}", v)
    for i, g in enumerate(m.groups(), start=1):
        tag = tag.replace("{%d}" % i, g or "")
    if re.search(r"\{[^}]*\}", tag) or not _TAG_SAFE.match(tag):
        return None
    return tag


def _project(e):
    return e["purl"]


def pick_entries(by_name, by_cpe, names, cpe):
    """The entries the component's names or CPE point at, or [] when they point
    at different projects."""
    by_n = []
    for n in names:
        for e in by_name.get((n or "").strip().lower(), []):
            if e not in by_n:
                by_n.append(e)
    vp = cpe_vendor_product(cpe)
    by_c = by_cpe.get(vp, []) if vp and not vp.startswith("*:") else []
    projects_n = {_project(e) for e in by_n}
    projects_c = {_project(e) for e in by_c}
    if len(projects_n) > 1:
        return []  # the component's own names mean two different projects
    if projects_n and projects_c and projects_n != projects_c:
        return []  # the name and the CPE name two different projects
    return by_n or by_c


def known(by_name, by_cpe, names, cpe):
    """True when any of the names or the CPE is in the table, whether or not the
    entries agree: such a component is the table's to decide, never an address's."""
    if any(by_name.get((n or "").strip().lower()) for n in names):
        return True
    vp = cpe_vendor_product(cpe)
    return bool(vp and not vp.startswith("*:") and by_cpe.get(vp))


def resolve(by_name, by_cpe, name, version, cpe=None, extra_names=()):
    if not version:
        return None
    names = [name] + [n for n in extra_names if n]
    for entry in pick_entries(by_name, by_cpe, names, cpe):
        tag = build_tag(entry, version)
        if tag is not None:
            return entry["purl"] + "@" + tag
    return None


def source_names(c):
    """The names of what the component was built from, as the scan recorded them."""
    out = []
    for p in c.get("properties") or []:
        if not isinstance(p, dict) or not isinstance(p.get("value"), str):
            continue
        if p.get("name") == "bomlens:yocto:recipe":
            out.append(p["value"])
        elif p.get("name") == "syft:metadata:source":
            last = p["value"].rstrip("/").rsplit("/", 1)[-1]
            # The toolchain path builds libc and libgcc, which it does not name;
            # the kernel path builds every kmod-* package, which are the kernel
            # already listed once, not a project each.
            if last and last not in ("toolchain", "linux"):
                out.append(last)
    vp = cpe_vendor_product(c.get("cpe"))
    if vp and vp.startswith("*:"):
        out.append(vp[2:])
    return out


def _tag_names_version(tag, version):
    """True when a release tag spells this version: v1.2, V_1_2, name-1.2 or 1.2."""
    core = re.sub(r"^(?:[A-Za-z][A-Za-z0-9+.]*?[-_])?[vV]_?", "", tag)
    core = re.sub(r"^[A-Za-z][A-Za-z0-9+.]*?-(?=[0-9])", "", core)
    return core.replace("_", ".") == version


def from_source_url(c, version):
    """pkg:github or pkg:gnu from a source address that states the release.

    Only for a component the table does not cover at all (resolve() decides
    that), and only when the release the address names is the component's
    version: an address can point at a helper fetched beside the project, or at
    a release other than the one packaged."""
    url = next((p.get("value") for p in c.get("properties") or []
                if isinstance(p, dict) and p.get("name") == "bomlens:sourceUrl"), None)
    if not isinstance(url, str):
        return None
    v = normalize_version({"normalize": ["release"]}, version or "")
    if not v:
        return None
    m = _GH_RELEASE.match(url.strip())
    if m:
        tag = m.group(3) or m.group(4)
        if tag and _TAG_SAFE.match(tag) and _tag_names_version(tag, v):
            return f"pkg:github/{m.group(1).lower()}/{m.group(2).lower()}@{tag}"
        return None
    m = _GNU_RELEASE.match(url.strip())
    if m and m.group(1) == m.group(2) and _TAG_SAFE.match(m.group(3)) and m.group(3) == v:
        return f"pkg:gnu/{m.group(1)}@{m.group(3)}"
    return None


def purl_type(purl):
    m = re.match(r"^pkg:([A-Za-z0-9.+-]+)/", purl or "")
    return m.group(1).lower() if m else ""


def apply(doc, table):
    by_name, by_cpe, replaceable = table
    comps = doc.get("components")
    if not isinstance(comps, list):
        return 0, 0
    refs = set()
    for d in doc.get("dependencies") or []:
        if isinstance(d, dict):
            refs.add(d.get("ref"))
            refs.update(d.get("dependsOn") or [])
    plans = []
    for c in comps:
        if not isinstance(c, dict) or c.get("type", "library") not in PACKAGE_TYPES:
            continue
        old = c.get("purl") or ""
        if old and purl_type(old) not in replaceable:
            plans.append((c, old, None))
            continue
        version = c.get("version")
        if not isinstance(version, str) or not version.strip():
            continue
        extra = source_names(c)
        new = resolve(by_name, by_cpe, c.get("name"), version, c.get("cpe"), extra)
        if not new and not known(by_name, by_cpe, [c.get("name")] + extra, c.get("cpe")):
            new = from_source_url(c, version)
        plans.append((c, old, new or ""))
    # The purl each package or binary component carries once this step is done.
    # syft reports a firmware's busybox both as its distribution
    # (operating-system, os:busybox@<v>) and as the binary it classified
    # (application); both resolve to the same repository purl, and one purl on
    # two components reads as the project listed twice. The package keeps it;
    # the operating-system component stays, without it.
    package_purls = {(new if new else old) for c, old, new in plans
                     if c.get("type", "library") != "operating-system"}
    changed = unmapped = 0
    for c, old, new in plans:
        if new is None:
            continue
        if not new:
            unmapped += 1
            continue
        if new == old:
            continue
        if c.get("type") == "operating-system" and new in package_purls:
            continue
        props = [p for p in (c.get("properties") or [])
                 if not (isinstance(p, dict)
                         and p.get("name") in ("bomlens:purlSource", "bomlens:originalPurl"))]
        if old:
            props.append({"name": "bomlens:originalPurl", "value": old})
            # A dependency edge can point at a component by the purl it had,
            # when it carries no bom-ref of its own. Keep that edge resolving.
            if not c.get("bom-ref") and old in refs:
                c["bom-ref"] = old
        props.append({"name": "bomlens:purlSource", "value": PURL_SOURCE})
        c["properties"] = props
        c["purl"] = new
        changed += 1
    return changed, unmapped


def main(argv):
    if len(argv) == 4 and argv[1] == "--resolve":
        by_name, by_cpe, _ = load_table()
        out = resolve(by_name, by_cpe, argv[2], argv[3])
        if out:
            print(out)
        return 0
    if len(argv) != 2:
        print("usage: upstream-purl.py <sbom.json> | --resolve <name> <version>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        table = load_table()
    except (OSError, ValueError, KeyError, re.error) as exc:
        print(f"[upstream-purl] WARN: could not read the mapping table ({exc}); skipping", file=sys.stderr)
        return 1
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[upstream-purl] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return 1
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        return 0
    changed, unmapped = apply(doc, table)
    if changed:
        tmp = path + ".upstream.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        os.replace(tmp, path)
    print(f"[upstream-purl] set the upstream repository purl on {changed} component(s); "
          f"{unmapped} versioned component(s) with no usable purl were left as they are "
          f"(not in the table, or a version form it does not cover).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
