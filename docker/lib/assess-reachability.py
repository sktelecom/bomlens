#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Turn govulncheck's findings into a CycloneDX VEX document (--reachability).

Usage: assess-reachability.py <bom.json> <govulncheck.json> <rc | runs> <stderr.txt> <mode> <output.cdx.json>

<govulncheck.json> is govulncheck's `-format json` stream (one JSON object
after another), <rc> its exit status and <stderr.txt> what it printed on
standard error; <mode> is `source` (call graph from the source tree, run in
the Go image of stage 1) or `binary` (`-mode=binary`, the symbols in a Go
executable).

In source mode stage 1 runs govulncheck once per Go module in the tree and
per GOOS (linux, darwin, windows; GOARCH amd64), and the third argument is
then the path of its run list instead of one exit status: one line
`run <n> <rc> <goos> <how> <module dir>` per run, beside `nonce` and `goarch`
lines. Each run's part of the stream starts with a `{"bomlens_run": <n>}`
line, and its part of standard error with a `== bomlens run <n> ==` line.
Every run must succeed: one that failed leaves nothing written (a run that
did not finish is not read as one that found nothing).

govulncheck reports each advisory at the deepest level it could confirm:

    module    the module is required at an affected version
    package   an affected package is in the build (source) or linked (binary)
    symbol    an affected function is called (source) or present (binary)

Across runs the deepest level any run confirmed is kept: an advisory called
on one GOOS or in one module is called. An advisory confirmed only at module
or package level is written with `analysis.state = not_affected`. At module
level no affected package is in the build (source) or linked (binary), so
the justification is `code_not_present`; at package level the package is
there but no affected function is called or linked, so it is
`code_not_reachable`. `detail` says which, and in source mode what was
covered: GOOS linux, darwin and windows with the default build tags. Code
that only a custom build tag (or another GOOS or GOARCH) compiles in is not
seen. One confirmed at symbol level is `exploitable`: CycloneDX defines it
as "may be directly or indirectly exploitable", which is what a call path
(or the symbol in the binary) shows; `in_triage` is a person's open
question, not a tool's answer. `detail` gives the call path or the symbol.

A statement is written only for a module and version that are a component of
the SBOM (pkg:golang purl, module path compared as is, since Go module paths
are case-sensitive, version without its `v`/`go` prefix), so a stdlib that
govulncheck read from a different Go toolchain than the one the SBOM names is
left without one. The SBOM is never modified. The vulnerability `id` is the
advisory's CVE when it has one (what a Trivy finding carries), and its Go and
other ids are listed in `references`.

Standard output is one JSON line. Exit 0 with {"status": "ok", "exploitable":
N, "not_affected": M, "components": K}; exit 3 with {"status": "unavailable",
"detail": ...} when govulncheck could not read the Go vulnerability database;
exit 2 with {"status": "failed", "detail": ...} otherwise (nothing written),
a module that could not be downloaded included.
"""
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote

CDX_SPEC_VERSION = "1.6"
MAX_STREAM_BYTES = 256 * 1024 * 1024
GO_VULN_URL = "https://pkg.go.dev/vuln/"
LEVELS = {"module": 1, "package": 2, "symbol": 3}
# not_affected: the affected package is absent (module level), or present with
# no affected function called or linked (package level).
JUSTIFICATIONS = {"module": "code_not_present", "package": "code_not_reachable"}

# govulncheck reports a database it could not read as "fetching
# vulnerabilities: <the Go http error>", the only case that is the database's
# (skipped, unavailable). A module it could not download while loading the
# packages ("loading packages: ... proxy.golang.org ...: dial tcp ...") names
# the network too, but is a failure of the scan: the tree was not read.
DATABASE_RE = re.compile(r"fetching vulnerabilities", re.IGNORECASE)
NETWORK_RE = re.compile(
    r"dial tcp|no such host|network is unreachable|i/o timeout|connection refused"
    r"|TLS handshake timeout|Client\.Timeout|proxy\.golang\.org|unexpected EOF",
    re.IGNORECASE)
LOADING_RE = re.compile(r"loading packages", re.IGNORECASE)
GOOS_LIST = ("linux", "darwin", "windows")
SCOPE_NOTE = ("checked for GOOS linux, darwin and windows (GOARCH amd64) with the default build tags; "
              "code built only under a custom build tag is not covered")
RUN_MARK = re.compile(r'^\{"bomlens_run": (\d+)\}$', re.MULTILINE)
ERR_MARK = re.compile(r"^== bomlens run (\d+) ==$", re.MULTILINE)


def emit(status, code, **fields):
    print(json.dumps(dict({"status": status}, **fields)))
    return code


def read_text(path, limit=4000):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()[-limit:]
    except OSError:
        return ""


def last_line(text):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:400] if lines else ""


def reason_line(text):
    """The line that says what went wrong: for "loading packages" the first
    package error under it (the last line is a pointer to the Go docs)."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if LOADING_RE.search(text):
        for ln in lines:
            if re.search(r"\.go:\d+:\d+: |^go: |^err: ", ln):
                return ln[:400]
    return last_line(text)


def classify(rc, stderr):
    """(status, exit code, detail) of one govulncheck run that failed."""
    reason = reason_line(stderr) or "govulncheck exited with status %s" % rc
    if rc == "124":
        return "failed", 2, "govulncheck timed out"
    if DATABASE_RE.search(stderr):
        return "unavailable", 3, "the Go vulnerability database could not be reached: " + reason
    if LOADING_RE.search(stderr) and NETWORK_RE.search(stderr):
        return "failed", 2, ("a module could not be downloaded from the Go module proxy, so the source "
                             "could not be read (allow access to proxy.golang.org, or your GOPROXY): " + reason)
    return "failed", 2, reason


def read_stream(path):
    if os.path.getsize(path) > MAX_STREAM_BYTES:
        raise ValueError("govulncheck output over %d bytes" % MAX_STREAM_BYTES)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def parse_stream(path):
    return parse_text(read_stream(path))


def parse_text(text):
    """govulncheck's JSON stream: objects one after another, pretty-printed."""
    dec = json.JSONDecoder()
    pos, out = 0, []
    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos >= len(text):
            return out
        obj, pos = dec.raw_decode(text, pos)
        if isinstance(obj, dict):
            out.append(obj)


def norm_version(v):
    v = (v or "").strip()
    for prefix in ("go", "v"):
        if v.startswith(prefix) and len(v) > len(prefix) and v[len(prefix)].isdigit():
            v = v[len(prefix):]
    return v


def go_components(bom):
    """SBOM components with a pkg:golang purl, keyed by (module path, version).
    The path keeps its case: Go module paths are case-sensitive."""
    index = {}
    comps = list(bom.get("components") or [])
    i = 0
    while i < len(comps):
        comp = comps[i]
        i += 1
        if not isinstance(comp, dict):
            continue
        comps.extend(c for c in (comp.get("components") or []) if isinstance(c, dict))
        purl = comp.get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:golang/"):
            continue
        body = purl[len("pkg:golang/"):].split("?", 1)[0].split("#", 1)[0]
        path, _, version = body.rpartition("@")
        if not path:
            continue
        index.setdefault((unquote(path), norm_version(unquote(version))), comp)
    return index


def frame_name(frame):
    fn = frame.get("function") or ""
    if frame.get("receiver"):
        fn = "%s.%s" % (frame["receiver"].lstrip("*"), fn)
    pkg = frame.get("package") or frame.get("module") or ""
    return "%s.%s" % (pkg, fn) if fn else pkg


def affected_symbols(osv, module):
    pkgs, syms = [], []
    for aff in osv.get("affected") or []:
        if ((aff.get("package") or {}).get("name") or "") != module:
            continue
        for imp in (aff.get("ecosystem_specific") or {}).get("imports") or []:
            if imp.get("path"):
                pkgs.append(imp["path"])
            syms.extend(s for s in (imp.get("symbols") or []) if isinstance(s, str))
    return sorted(set(pkgs)), sorted(set(syms))


def short_list(items, limit=6):
    if len(items) <= limit:
        return ", ".join(items)
    return "%s and %d more" % (", ".join(items[:limit]), len(items) - limit)


def detail_for(mode, level, trace, pkgs, syms):
    if level == "symbol":
        if mode == "source":
            path = " -> ".join(frame_name(f) for f in reversed(trace))
            return "govulncheck (source, call graph): an affected function is called: %s" % path
        return ("govulncheck (binary): the affected symbol %s is in the executable's symbol table"
                % frame_name(trace[0]))
    if level == "package":
        pkg = trace[0].get("package") or short_list(pkgs)
        if mode == "source":
            return ("govulncheck (source, call graph): package %s is imported, but no call path reaches "
                    "an affected symbol (%s)" % (pkg, short_list(syms) or "any"))
        return ("govulncheck (binary): package %s is linked, but no affected symbol (%s) is in the executable"
                % (pkg, short_list(syms) or "any"))
    if mode == "source":
        return ("govulncheck (source): the module is required, but no affected package (%s) is in the build"
                % (short_list(pkgs) or "any"))
    return ("govulncheck (binary): the module is in the executable, but no affected package (%s) is linked"
            % (short_list(pkgs) or "any"))


def vuln_ids(osv):
    """(primary id, other ids): the CVE when there is one, then GHSA, then GO."""
    go_id = osv.get("id") or ""
    aliases = sorted(a for a in (osv.get("aliases") or []) if isinstance(a, str))
    cves = [a for a in aliases if a.startswith("CVE-")]
    ghsas = [a for a in aliases if a.startswith("GHSA-")]
    primary = (cves or ghsas or [go_id])[0]
    others = [i for i in [go_id] + aliases if i and i != primary]
    return primary, others


def reference(vid):
    if vid.startswith("GO-"):
        return {"id": vid, "source": {"name": "Go Vulnerability Database", "url": GO_VULN_URL + vid}}
    if vid.startswith("CVE-"):
        return {"id": vid, "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + vid}}
    if vid.startswith("GHSA-"):
        return {"id": vid, "source": {"name": "GitHub Advisory Database", "url": "https://github.com/advisories/" + vid}}
    return {"id": vid, "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/" + vid}}


def embedded(comp):
    out = {"type": comp.get("type") or "library", "bom-ref": comp.get("bom-ref") or comp.get("purl")}
    for key in ("group", "name", "version", "purl"):
        if comp.get(key):
            out[key] = comp[key]
    return out


def best_findings(messages, where, best, osvs, config):
    """Fold one run's findings into best[(osv, module, version)] = (level,
    trace, [where...]), keeping the deepest level any run confirmed and the
    runs that confirmed it."""
    for msg in messages:
        if isinstance(msg.get("config"), dict):
            config.setdefault("config", msg["config"])
        elif isinstance(msg.get("osv"), dict) and msg["osv"].get("id"):
            osvs[msg["osv"]["id"]] = msg["osv"]
        elif isinstance(msg.get("finding"), dict):
            f = msg["finding"]
            trace = [t for t in (f.get("trace") or []) if isinstance(t, dict)]
            if not f.get("osv") or not trace or not trace[0].get("module"):
                continue
            top = trace[0]
            level = "symbol" if top.get("function") else ("package" if top.get("package") else "module")
            key = (f["osv"], top["module"], top.get("version") or "")
            if key not in best or LEVELS[level] > LEVELS[best[key][0]]:
                best[key] = (level, trace, [where])
            elif LEVELS[level] == LEVELS[best[key][0]] and where not in best[key][2]:
                best[key][2].append(where)


def where_note(wheres, multi):
    """The runs that confirmed the level, when there was more than one run:
    " (module .: GOOS=linux, windows)"."""
    wheres = [w for w in wheres if w]
    if not multi or not wheres:
        return ""
    by_module = {}
    for goos, module in wheres:
        by_module.setdefault(module, set()).add(goos)
    order = {g: i for i, g in enumerate(GOOS_LIST)}
    return " (%s)" % "; ".join(
        "module %s: GOOS=%s" % (m, ", ".join(sorted(g, key=lambda x: (order.get(x, 99), x))))
        for m, g in sorted(by_module.items()))


def build(bom, runs, mode, stable, scope=None):
    """runs: [(messages, (goos, module dir) or None)]. scope: what source mode
    covered ({"goos": [...], "modules": [...]}), None in binary mode."""
    best, osvs, holder = {}, {}, {}
    for messages, where in runs:
        best_findings(messages, where, best, osvs, holder)
    config = holder.get("config") or {}
    multi = len(runs) > 1

    comps = go_components(bom)
    used, vulns = {}, []
    counts = {"exploitable": 0, "not_affected": 0}
    for (osv_id, module, version), (level, trace, wheres) in sorted(best.items(), key=lambda kv: kv[0]):
        comp = comps.get((module, norm_version(version)))
        osv = osvs.get(osv_id)
        if comp is None or osv is None:
            continue
        ref = comp.get("bom-ref") or comp.get("purl")
        used.setdefault(ref, embedded(comp))
        pkgs, syms = affected_symbols(osv, module)
        primary, others = vuln_ids(osv)
        analysis = {"state": "exploitable" if level == "symbol" else "not_affected"}
        if level != "symbol":
            analysis["justification"] = JUSTIFICATIONS[level]
        detail = detail_for(mode, level, trace, pkgs, syms)
        if level == "symbol":
            detail += where_note(wheres, multi)
        elif scope is not None:
            detail += "; " + SCOPE_NOTE
        analysis["detail"] = detail
        counts[analysis["state"]] += 1
        vulns.append({
            "bom-ref": "reachability-%d" % (len(vulns) + 1),
            "id": primary,
            "source": reference(primary)["source"],
            "references": [reference(i) for i in others],
            "analysis": analysis,
            "affects": [{"ref": ref}],
            "properties": [
                {"name": "bomlens:reachability:level", "value": level},
                {"name": "bomlens:reachability:mode", "value": mode},
            ],
        })

    meta_in = bom.get("metadata") or {}
    timestamp = meta_in.get("timestamp") if stable else None
    tool = {"type": "application", "name": "govulncheck"}
    if config.get("scanner_version"):
        tool["version"] = str(config["scanner_version"])
    metadata = {
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [tool, {"type": "application", "name": "bomlens"}]},
        "properties": [{"name": "bomlens:reachability:mode", "value": mode}],
    }
    for key, name in (("db", "database"), ("db_last_modified", "database-modified"), ("go_version", "go-version")):
        if config.get(key):
            metadata["properties"].append({"name": "bomlens:reachability:" + name, "value": str(config[key])})
    if scope is not None:
        metadata["properties"].extend([
            {"name": "bomlens:reachability:goos", "value": ",".join(scope["goos"])},
            {"name": "bomlens:reachability:goarch", "value": scope.get("goarch") or "amd64"},
            {"name": "bomlens:reachability:build-tags",
             "value": "default; code built only under a custom build tag is not covered"},
            {"name": "bomlens:reachability:modules", "value": ",".join(scope["modules"])},
        ])
    if isinstance(meta_in.get("component"), dict):
        metadata["component"] = meta_in["component"]
    doc = {"bomFormat": "CycloneDX", "specVersion": CDX_SPEC_VERSION}
    if not stable:
        doc["serialNumber"] = "urn:uuid:%s" % uuid.uuid4()
    doc.update({"version": 1, "metadata": metadata, "components": list(used.values()), "vulnerabilities": vulns})
    counts["components"] = len(used)
    return doc, counts


def split_marked(text, mark):
    """{run number: its part of the text} for text cut by `mark` lines."""
    parts, cuts = {}, list(mark.finditer(text))
    for i, m in enumerate(cuts):
        stop = cuts[i + 1].start() if i + 1 < len(cuts) else len(text)
        parts[int(m.group(1))] = text[m.end():stop]
    return parts


def read_run_list(path):
    """Stage 1's run list: [(n, rc, goos, how, module dir)] and its goarch."""
    runs, goarch = [], "amd64"
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            fields = line.rstrip("\n").split(" ", 5)
            if fields[0] == "goarch" and len(fields) > 1:
                goarch = fields[1]
            elif fields[0] == "run" and len(fields) == 6 and fields[1].isdigit():
                runs.append((int(fields[1]), fields[2], fields[3], fields[4], fields[5]))
    return runs, goarch


def read_err(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def main(argv):
    if len(argv) != 7 or argv[5] not in ("source", "binary"):
        sys.stderr.write("usage: assess-reachability.py <bom.json> <govulncheck.json> <rc|runs> <stderr.txt> "
                         "<source|binary> <output.cdx.json>\n")
        return 2
    bom_path, stream_path, rc, err_path, mode, out_path = argv[1:]
    scope = None
    try:
        if rc.isdigit():
            if rc != "0":
                status, code, detail = classify(rc, read_text(err_path))
                return emit(status, code, detail=detail)
            runs = [(parse_stream(stream_path), None)]
        else:
            listed, goarch = read_run_list(rc)
            if not listed:
                return emit("failed", 2, detail="stage 1 recorded no govulncheck run")
            errs = split_marked(read_err(err_path), ERR_MARK)
            # The database first: when it could not be read, every run says so.
            failures = []
            for n, rc_n, goos, _how, module in listed:
                if rc_n != "0":
                    status, code, detail = classify(rc_n, errs.get(n, "")[-4000:])
                    failures.append((code, status, "%s (module %s, GOOS=%s)" % (detail, module, goos)))
            if failures:
                hard = [f for f in failures if f[0] == 2]
                code, status, detail = (hard or failures)[0]
                if len(failures) > 1:
                    detail += "; %d of %d govulncheck runs failed" % (len(failures), len(listed))
                return emit(status, code, detail=detail)
            parts = split_marked(read_stream(stream_path), RUN_MARK)
            runs = []
            for n, _rc, goos, _how, module in listed:
                if n not in parts:
                    return emit("failed", 2, detail="govulncheck's output for module %s (GOOS=%s) is missing"
                                % (module, goos))
                runs.append((parse_text(parts[n]), (goos, module)))
            modules = sorted({m for _n, _rc, _g, _h, m in listed})
            goos_seen = [g for g in GOOS_LIST if any(r[2] == g for r in listed)]
            scope = {"goos": goos_seen, "goarch": goarch, "modules": modules}
        with open(bom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError) as err:
        return emit("failed", 2, detail="could not read govulncheck's output: %s" % err)
    if not isinstance(bom, dict):
        return emit("failed", 2, detail="the SBOM is not a JSON object")
    stable = os.environ.get("BYTE_STABLE", "false") == "true"
    doc, counts = build(bom, runs, mode, stable, scope)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, out_path)
    return emit("ok", 0, **counts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
