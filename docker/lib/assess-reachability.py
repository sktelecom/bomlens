#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Turn govulncheck's findings into a CycloneDX VEX document (--reachability).

Usage: assess-reachability.py <bom.json> <govulncheck.json> <rc> <stderr.txt> <mode> <output.cdx.json>

<govulncheck.json> is govulncheck's `-format json` stream (one JSON object
after another), <rc> its exit status and <stderr.txt> what it printed on
standard error; <mode> is `source` (call graph from the source tree, run in
the Go image of stage 1) or `binary` (`-mode=binary`, the symbols in a Go
executable).

govulncheck reports each advisory at the deepest level it could confirm:

    module    the module is required at an affected version
    package   an affected package is in the build (source) or linked (binary)
    symbol    an affected function is called (source) or present (binary)

An advisory confirmed only at module or package level is written with
`analysis.state = not_affected`. At module level no affected package is in the
build (source) or linked (binary), so the justification is `code_not_present`;
at package level the package is there but no affected function is called or
linked, so it is `code_not_reachable`. `detail` says which. One confirmed at
symbol level is
`exploitable`: CycloneDX defines it as "may be directly or indirectly
exploitable", which is what a call path (or the symbol in the binary) shows;
`in_triage` is a person's open question, not a tool's answer. `detail` gives
the call path or the symbol.

A statement is written only for a module and version that are a component of
the SBOM (pkg:golang purl, version compared without its `v`/`go` prefix), so
a stdlib that govulncheck read from a different Go toolchain than the one the
SBOM names is left without one. The SBOM is never modified. The vulnerability
`id` is the advisory's CVE when it has one (what a Trivy finding carries), and
its Go and other ids are listed in `references`.

Standard output is one JSON line. Exit 0 with {"status": "ok", "exploitable":
N, "not_affected": M, "components": K}; exit 3 with {"status": "unavailable",
"detail": ...} when govulncheck could not reach its vulnerability database;
exit 2 with {"status": "failed", "detail": ...} otherwise (nothing written).
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

# govulncheck reports a database it could not reach as "fetching
# vulnerabilities: <the Go http error>". The second list covers a client
# error that names the network without that prefix.
NETWORK_RE = re.compile(
    r"fetching vulnerabilities|vuln\.go\.dev|dial tcp|no such host|network is unreachable"
    r"|i/o timeout|connection refused|TLS handshake timeout|Client\.Timeout",
    re.IGNORECASE)


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


def parse_stream(path):
    """govulncheck's JSON stream: objects one after another, pretty-printed."""
    if os.path.getsize(path) > MAX_STREAM_BYTES:
        raise ValueError("govulncheck output over %d bytes" % MAX_STREAM_BYTES)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
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
    """SBOM components with a pkg:golang purl, keyed by (module path, version)."""
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
        index.setdefault((unquote(path).lower(), norm_version(unquote(version))), comp)
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


def build(bom, messages, mode, stable):
    config, osvs, best = {}, {}, {}
    for msg in messages:
        if isinstance(msg.get("config"), dict):
            config = msg["config"]
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
                best[key] = (level, trace)

    comps = go_components(bom)
    used, vulns = {}, []
    counts = {"exploitable": 0, "not_affected": 0}
    for (osv_id, module, version), (level, trace) in sorted(best.items()):
        comp = comps.get((module.lower(), norm_version(version)))
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
        analysis["detail"] = detail_for(mode, level, trace, pkgs, syms)
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
    if isinstance(meta_in.get("component"), dict):
        metadata["component"] = meta_in["component"]
    doc = {"bomFormat": "CycloneDX", "specVersion": CDX_SPEC_VERSION}
    if not stable:
        doc["serialNumber"] = "urn:uuid:%s" % uuid.uuid4()
    doc.update({"version": 1, "metadata": metadata, "components": list(used.values()), "vulnerabilities": vulns})
    counts["components"] = len(used)
    return doc, counts


def main(argv):
    if len(argv) != 7 or argv[5] not in ("source", "binary"):
        sys.stderr.write("usage: assess-reachability.py <bom.json> <govulncheck.json> <rc> <stderr.txt> "
                         "<source|binary> <output.cdx.json>\n")
        return 2
    bom_path, stream_path, rc, err_path, mode, out_path = argv[1:]
    stderr = read_text(err_path)
    if rc != "0":
        reason = last_line(stderr) or "govulncheck exited with status %s" % rc
        if rc == "124":
            return emit("failed", 2, detail="govulncheck timed out")
        if NETWORK_RE.search(stderr):
            return emit("unavailable", 3, detail="the Go vulnerability database could not be reached: " + reason)
        return emit("failed", 2, detail=reason)
    try:
        with open(bom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
        messages = parse_stream(stream_path)
    except (OSError, ValueError) as err:
        return emit("failed", 2, detail="could not read govulncheck's output: %s" % err)
    if not isinstance(bom, dict):
        return emit("failed", 2, detail="the SBOM is not a JSON object")
    stable = os.environ.get("BYTE_STABLE", "false") == "true"
    doc, counts = build(bom, messages, mode, stable)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, out_path)
    return emit("ok", 0, **counts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
