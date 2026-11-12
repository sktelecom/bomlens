#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# scan-go-vulndb.py: match the Go modules of a CycloneDX SBOM against the Go
# vulnerability database (vuln.go.dev, OSV records with GO- ids) and write the
# findings no other engine reported as a Trivy-shaped sidecar for
# scan-security.sh to merge.
#
# Usage: scan-go-vulndb.py <sbom.json> <out_prefix> <vulndb> [report.json ...]
#   <vulndb>       the database export: vulndb.zip from https://vuln.go.dev, or
#                  a folder holding its index/db.json and ID/GO-*.json
#   report.json    results already in hand (Trivy's _security.json, another
#                  engine's sidecar), in the .Results[].Vulnerabilities[] shape
#   writes <out_prefix>_security_govulndb.json
#
# Exit codes: 0 the sidecar was written (it may list no finding, and
# GoVulnDB.Components is 0 when no Go version could be read), 11 the SBOM has
# no pkg:golang purl with a version (no sidecar), 3 the database could not be
# read (no sidecar), 2 usage or an unreadable SBOM.
#
# Matching:
#   - a component is a Go module when its purl is pkg:golang/<module path>@<v>;
#     the path is compared with affected[].package.name, ignoring case
#   - a component whose path is one of affected[].ecosystem_specific.imports[]
#     .path is a package of that module and is matched against the module's
#     ranges; a record that lists the component's own path as a module is
#     judged on that entry only
#   - versions are compared as semantic versions, without the leading "v":
#     build metadata such as +incompatible is ignored, as semver orders it,
#     and a pseudo-version is an ordinary pre-release; the standard library
#     (stdlib) takes Go release names (go1.21.3, go1.22rc1) too
#   - affected[].ranges are evaluated as OSV specifies (introduced, fixed,
#     last_affected); a withdrawn record is skipped
#
# Merging: a finding's id is the record's CVE alias, else its GHSA alias, else
# its GO id, the same choice assess-reachability.py makes, so a --reachability
# judgement applies to it. A record any of whose ids (GO, CVE, GHSA) a report
# already lists for the same component is not written again, and two records
# that share an id for one component are written once. Go records carry no
# severity: one that another finding in the reports rates under a shared id
# takes that rating, otherwise it is UNKNOWN.
#
# The database is read in place (a zip member or a file under the folder is
# opened by its own name, nothing is extracted) and no network is used.
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from urllib.parse import unquote

GO_VULN_URL = "https://pkg.go.dev/vuln/"
DATA_SOURCE = {"ID": "go-vulndb", "Name": "The Go Vulnerability Database", "URL": GO_VULN_URL}
RECORD_NAME = re.compile(r"^ID/GO-[0-9]{4}-[0-9]+\.json$")
# A record is a few KB; the whole export is about 7 MB unpacked (2026-11).
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
SEMVER = re.compile(r"^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?"
                    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
GO_RELEASE = re.compile(r"^go([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:(alpha|beta|rc)([0-9]+))?$")


class DatabaseError(Exception):
    pass


# ---- versions ----------------------------------------------------------------

def parse_semver(v):
    """(major, minor, patch, prerelease identifiers or None), or None."""
    m = SEMVER.match(v or "")
    if not m:
        return None
    pre = None
    if m.group(4) is not None:
        pre = []
        for ident in m.group(4).split("."):
            if ident == "":
                return None
            pre.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
        pre = tuple(pre)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), pre)


def compare(a, b):
    """semver precedence of two parsed versions: -1, 0, 1."""
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    pa, pb = a[3], b[3]
    if pa == pb:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


def stdlib_version(v):
    """A Go release name (go1.21.3, go1.22rc1) as the semver the database uses."""
    m = GO_RELEASE.match(v or "")
    if not m:
        return v
    out = "%s.%s.%s" % (m.group(1), m.group(2) or "0", m.group(3) or "0")
    if m.group(4):
        out += "-%s.%s" % (m.group(4), m.group(5))
    return out


def in_ranges(ver, affected):
    """(affected?, [fixed versions above ver]) for one affected[] entry."""
    hit = False
    fixes = []
    for r in affected.get("ranges") or []:
        if not isinstance(r, dict) or r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = []
        for e in r.get("events") or []:
            if not isinstance(e, dict) or len(e) != 1:
                continue
            kind, val = next(iter(e.items()))
            if kind not in ("introduced", "fixed", "last_affected") or not isinstance(val, str):
                continue
            pv = (0, 0, 0, ((0, -1, ""),)) if (kind == "introduced" and val == "0") else parse_semver(val)
            if pv is None:
                continue
            events.append((pv, kind, val))
        # OSV evaluation: walk the events in version order.
        events.sort(key=_event_key)
        vulnerable = False
        for pv, kind, _ in events:
            if kind == "introduced" and compare(ver, pv) >= 0:
                vulnerable = True
            elif kind == "fixed" and compare(ver, pv) >= 0:
                vulnerable = False
            elif kind == "last_affected" and compare(ver, pv) > 0:
                vulnerable = False
        if vulnerable:
            hit = True
            fixes += [val for pv, kind, val in events if kind == "fixed" and compare(pv, ver) > 0]
    if not hit and not affected.get("ranges"):
        versions = affected.get("versions") or []
        hit = any(parse_semver(x) is not None and compare(parse_semver(x), ver) == 0
                  for x in versions if isinstance(x, str))
    return hit, fixes


class _Key:
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return compare(self.v, other.v) < 0


def _event_key(e):
    return _Key(e[0])


# ---- the database --------------------------------------------------------------

def open_database(path):
    """(modified, [records]) from a vulndb.zip or an unpacked folder."""
    records = []
    total = 0
    if os.path.isdir(path):
        root = os.path.realpath(path)
        meta = _read_file(root, "index/db.json")
        id_dir = os.path.join(root, "ID")
        if not os.path.isdir(id_dir):
            raise DatabaseError("no ID folder in %s" % path)
        for name in sorted(os.listdir(id_dir)):
            rel = "ID/" + name
            if not RECORD_NAME.match(rel):
                continue
            blob = _read_file(root, rel)
            total += len(blob)
            if total > MAX_TOTAL_BYTES:
                raise DatabaseError("the database is larger than %d bytes" % MAX_TOTAL_BYTES)
            records.append(_parse(blob, rel))
    elif zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                infos = {i.filename: i for i in z.infolist()}
                meta = _read_member(z, infos, "index/db.json")
                for name in sorted(infos):
                    if not RECORD_NAME.match(name):
                        continue
                    total += infos[name].file_size
                    if total > MAX_TOTAL_BYTES:
                        raise DatabaseError("the database is larger than %d bytes" % MAX_TOTAL_BYTES)
                    records.append(_parse(_read_member(z, infos, name), name))
        except (zipfile.BadZipFile, OSError) as exc:
            raise DatabaseError("cannot read %s: %s" % (path, exc))
    else:
        raise DatabaseError("%s is neither a zip file nor a folder" % path)
    records = [r for r in records if r is not None]
    if not records:
        raise DatabaseError("no GO- record in %s" % path)
    modified = ""
    try:
        modified = json.loads(meta).get("modified") or ""
    except (ValueError, AttributeError):
        modified = ""
    if not isinstance(modified, str) or not modified:
        modified = max((r.get("modified") or "" for r in records), default="")
    return modified, records


def _read_file(root, rel):
    full = os.path.realpath(os.path.join(root, rel))
    if not full.startswith(root + os.sep) or not os.path.isfile(full):
        raise DatabaseError("missing or outside the database folder: %s" % rel)
    if os.path.getsize(full) > MAX_RECORD_BYTES:
        raise DatabaseError("%s is larger than %d bytes" % (rel, MAX_RECORD_BYTES))
    with open(full, "rb") as f:
        return f.read()


def _read_member(z, infos, name):
    info = infos.get(name)
    if info is None:
        raise DatabaseError("%s is not in the archive" % name)
    if info.file_size > MAX_RECORD_BYTES:
        raise DatabaseError("%s is larger than %d bytes" % (name, MAX_RECORD_BYTES))
    with z.open(info) as f:
        blob = f.read(MAX_RECORD_BYTES + 1)
    if len(blob) > MAX_RECORD_BYTES:
        raise DatabaseError("%s is larger than %d bytes" % (name, MAX_RECORD_BYTES))
    return blob


def _parse(blob, name):
    try:
        rec = json.loads(blob)
    except ValueError:
        print("[go-vulndb] WARN: %s is not valid JSON; skipped" % name, file=sys.stderr)
        return None
    if not isinstance(rec, dict) or not str(rec.get("id", "")).startswith("GO-"):
        return None
    if rec.get("withdrawn"):
        return None
    return rec


def age_days(modified):
    try:
        t = datetime.strptime(re.sub(r"\.[0-9]+", "", modified), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None
    return max(0, int((datetime.now(timezone.utc) - t.replace(tzinfo=timezone.utc)).total_seconds() // 86400))


def build_index(records):
    """lower-cased path -> [(record, affected entry, "module" | "package")]."""
    index = {}
    for rec in records:
        for aff in rec.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            if pkg.get("ecosystem") != "Go" or not isinstance(pkg.get("name"), str):
                continue
            index.setdefault(pkg["name"].lower(), []).append((rec, aff, "module"))
            imports = (aff.get("ecosystem_specific") or {}).get("imports") or []
            for path in {i.get("path") for i in imports if isinstance(i, dict) and isinstance(i.get("path"), str)}:
                if path.lower() != pkg["name"].lower():
                    index.setdefault(path.lower(), []).append((rec, aff, "package"))
    return index


def vuln_ids(rec):
    """(primary id, every id): the CVE when there is one, then GHSA, then GO."""
    go_id = rec.get("id") or ""
    aliases = sorted(a for a in (rec.get("aliases") or []) if isinstance(a, str))
    cves = [a for a in aliases if a.startswith("CVE-")]
    ghsas = [a for a in aliases if a.startswith("GHSA-")]
    primary = (cves or ghsas or [go_id])[0]
    return primary, [go_id] + aliases


# ---- the SBOM and the reports -------------------------------------------------

def walk(components):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


GO_PURL = re.compile(r"^pkg:golang/[^@]+@.", re.IGNORECASE)


def has_go_purl(comp):
    """A pkg:golang purl with a version; entrypoint.sh makes the same test."""
    return isinstance(comp.get("purl"), str) and bool(GO_PURL.match(comp["purl"]))


def go_component(comp):
    """(module path, version string, parsed version, purl) or None."""
    purl = comp.get("purl")
    if not isinstance(purl, str) or not purl.lower().startswith("pkg:golang/"):
        return None
    body = purl[len("pkg:golang/"):].split("#", 1)[0].split("?", 1)[0]
    if "@" not in body:
        return None
    path, version = body.rsplit("@", 1)
    path = "/".join(unquote(seg) for seg in path.split("/") if seg)
    version = unquote(version)
    if not path or not version:
        return None
    parsed = parse_semver(stdlib_version(version) if path == "stdlib" else version)
    if parsed is None:
        return None
    return path, version, parsed, purl


def component_key(path, version):
    v = version[1:] if version[:1] == "v" else version
    return (path.lower() + "@" + v).lower()


def finding_keys(f):
    keys = set()
    p = ((f.get("PkgIdentifier") or {}).get("PURL") or "")
    if p.lower().startswith("pkg:golang/"):
        body = p[len("pkg:golang/"):].split("#", 1)[0].split("?", 1)[0]
        if "@" in body:
            path, version = body.rsplit("@", 1)
            keys.add(component_key("/".join(unquote(s) for s in path.split("/") if s), unquote(version)))
    if f.get("PkgName") and f.get("InstalledVersion"):
        keys.add(component_key(str(f["PkgName"]), str(f["InstalledVersion"])))
    return keys


def load_reports(paths):
    """{component key: set of ids} and {id: finding with a severity}."""
    seen, rated = {}, {}
    for path in paths:
        try:
            with open(path) as f:
                doc = json.load(f)
        except (OSError, ValueError):
            continue
        for res in (doc.get("Results") or []) if isinstance(doc, dict) else []:
            for v in (res.get("Vulnerabilities") or []) if isinstance(res, dict) else []:
                if not isinstance(v, dict) or not v.get("VulnerabilityID"):
                    continue
                ids = {v["VulnerabilityID"]} | {x for x in (v.get("VendorIDs") or []) if isinstance(x, str)}
                for k in finding_keys(v):
                    seen.setdefault(k, set()).update(ids)
                if (v.get("Severity") or "UNKNOWN") != "UNKNOWN":
                    for i in ids:
                        rated.setdefault(i, v)
    return seen, rated


# ---- matching -------------------------------------------------------------------

def record_for(rec, aff, how, comp, fixes, rated, comp_ref):
    path, version, _, purl = comp
    primary, ids = vuln_ids(rec)
    out = {
        "VulnerabilityID": primary,
        "VendorIDs": [i for i in ids if i != primary],
        "PkgID": "%s@%s" % (path, version),
        "PkgName": path,
        "PkgIdentifier": {"PURL": purl, **({"BOMRef": comp_ref} if comp_ref else {})},
        "InstalledVersion": version,
        "Status": "fixed" if fixes else "affected",
        "Severity": "UNKNOWN",
        "PrimaryURL": GO_VULN_URL + rec["id"],
        "DataSource": dict(DATA_SOURCE),
        "Title": (rec.get("summary") or "")[:300],
        "Description": rec.get("details") or "",
        "References": [r["url"] for r in (rec.get("references") or [])
                       if isinstance(r, dict) and isinstance(r.get("url"), str)],
        "source": "go-vulndb",
        "bomlens:goVulnDB": {
            "id": rec["id"],
            "module": (aff.get("package") or {}).get("name", ""),
            "match": how,
            "packages": sorted({i.get("path") for i in ((aff.get("ecosystem_specific") or {}).get("imports") or [])
                                if isinstance(i, dict) and isinstance(i.get("path"), str)}),
        },
    }
    if fixes:
        uniq = sorted(set(fixes), key=lambda x: _Key(parse_semver(x)))
        out["FixedVersion"] = ", ".join(uniq)
    if rec.get("published"):
        out["PublishedDate"] = rec["published"]
    if rec.get("modified"):
        out["LastModifiedDate"] = rec["modified"]
    for i in [primary] + ids:
        src = rated.get(i)
        if src:
            out["Severity"] = src.get("Severity")
            for key in ("SeveritySource", "VendorSeverity", "CVSS", "CweIDs"):
                if src.get(key):
                    out[key] = src[key]
            break
    return out


def scan(sbom, records, reports):
    index = build_index(records)
    seen, rated = load_reports(reports)
    comps, kept = [], []
    already = 0
    done = set()
    for c in walk(sbom.get("components")):
        gc = go_component(c)
        if gc is None:
            continue
        path, version, ver, _ = gc
        key = component_key(path, version)
        if key in done:
            continue
        done.add(key)
        comps.append(gc)
        reported = set(seen.get(key, set()))
        # A record that names this path as a module is judged on that entry;
        # one that only lists it as a package of another module, on that one.
        by_record = {}
        for rec, aff, how in index.get(path.lower(), []):
            by_record.setdefault(rec["id"], []).append((rec, aff, how))
        for rid in sorted(by_record):
            entries = by_record[rid]
            if any(h == "module" for _, _, h in entries):
                entries = [e for e in entries if e[2] == "module"]
            for rec, aff, how in entries:
                hit, fixes = in_ranges(ver, aff)
                if not hit:
                    continue
                _, ids = vuln_ids(rec)
                if reported & set(ids):
                    already += 1
                    break
                kept.append(record_for(rec, aff, how, gc, fixes, rated, c.get("bom-ref")))
                reported |= set(ids)
                break
    return comps, kept, already


def main(argv):
    if len(argv) < 4:
        print("usage: scan-go-vulndb.py <sbom.json> <out_prefix> <vulndb.zip|folder> [report.json ...]",
              file=sys.stderr)
        return 2
    sbom_path, out_prefix, db_path, reports = argv[1], argv[2], argv[3], argv[4:]
    try:
        with open(sbom_path) as f:
            sbom = json.load(f)
    except (OSError, ValueError) as exc:
        print("[go-vulndb] cannot read the SBOM %s: %s" % (sbom_path, exc), file=sys.stderr)
        return 2
    if not isinstance(sbom, dict) or not any(has_go_purl(c) for c in walk(sbom.get("components"))):
        print("[go-vulndb] no Go module (pkg:golang) in the SBOM; nothing to match.")
        return 11
    try:
        modified, records = open_database(db_path)
    except DatabaseError as exc:
        print("[go-vulndb] cannot read the Go vulnerability database: %s" % exc, file=sys.stderr)
        return 3
    comps, kept, already = scan(sbom, records, reports)
    sidecar = {
        "Results": [{
            "Target": "Go modules (Go vulnerability database)",
            "Class": "lang-pkgs",
            "Type": "gomod",
            "Vulnerabilities": kept,
        }],
        "GoVulnDB": {
            "Modified": modified,
            "AgeDays": age_days(modified),
            "Records": len(records),
            "Components": len(comps),
            "New": len(kept),
            "AlreadyReported": already,
        },
    }
    out = "%s_security_govulndb.json" % out_prefix
    tmp = out + ".tmp.%d" % os.getpid()
    with open(tmp, "w") as f:
        json.dump(sidecar, f, ensure_ascii=False)
    os.replace(tmp, out)
    print("[go-vulndb] %d Go module(s) checked against %d record(s) (database of %s): %d new finding(s), "
          "%d already reported by another engine -> %s"
          % (len(comps), len(records), modified or "unknown date", len(kept), already, os.path.basename(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
