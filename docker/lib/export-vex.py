#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Turn the CVE judgements a supplier recorded into a CycloneDX VEX document.

Usage: export-vex.py <bom.json> <vex-verdicts.json> <output.json>

<vex-verdicts.json> is the `<prefix>_vex.json` sidecar the web UI writes
(POST /vex-verdict): {"verdicts": [{cve, state, detail, purl, pkg, installed,
...}]}. The output is a standalone CycloneDX 1.6 document whose
`vulnerabilities[]` carry each judgement in the standard `analysis` object, so
another tool can read it without knowing anything about BomLens.

The UI's four states are named after CycloneDX's `analysis.state` but are not
the same words, so they are mapped to the values the CycloneDX schema defines:

    affected             -> exploitable
    not_affected         -> not_affected
    fixed                -> resolved
    under_investigation  -> in_triage

No `justification` is written. CycloneDX restricts it to a fixed list of
values and the UI collects free text, so the note goes into `analysis.detail`
and nothing is invented to fill a field the supplier never chose.

Each verdict is attached to the component of the scanned SBOM it was recorded
against, matched by normalized purl, else by name and version (a Maven
`group:artifact` name is matched too). The referenced components are copied into
the document's own `components[]` (bom-ref, type, name, version, purl only) and
`affects[].ref` is the plain bom-ref of that copy, so every reference resolves
inside this document whether or not the SBOM carries a serialNumber (a
byte-stable scan drops it). The root component stays in `metadata.component`.
A verdict whose component is not in the SBOM (or whose state is not one of the
four above) is left out. Firmware findings are the usual case: their name and
version come from the binary, not from an SBOM component.

Standard output is one JSON line, {"exported": N, "skipped": M}, counted in
judgements, so the caller can tell the user when some did not make it in.

The SBOM and the sidecar are never modified. Exit status is 0 whenever the
document was written, including when it holds no vulnerabilities.
"""
import json
import sys
import uuid
from datetime import datetime, timezone

CDX_SPEC_VERSION = "1.6"

STATE_MAP = {
    "affected": "exploitable",
    "not_affected": "not_affected",
    "fixed": "resolved",
    "under_investigation": "in_triage",
}

# Same advisory namespaces the web UI accepts for a judgement id.
SOURCES = (
    ("CVE-", "NVD", "https://nvd.nist.gov/vuln/detail/"),
    ("GHSA-", "GitHub Advisory Database", "https://github.com/advisories/"),
)
OSV_URL = "https://osv.dev/vulnerability/"


def norm_purl(purl):
    """Same normalization as server.py's _norm_purl: qualifiers and subpath
    dropped, lowercased, so an SBOM purl and a saved verdict purl compare equal."""
    if not purl:
        return ""
    return purl.split("?", 1)[0].split("#", 1)[0].strip().lower()


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as err:
        sys.stderr.write("[vex-export] cannot read %s: %s\n" % (path, err))
        return None


def source_for(vuln_id):
    for prefix, name, base in SOURCES:
        if vuln_id.startswith(prefix):
            return {"name": name, "url": base + vuln_id}
    return {"name": "OSV", "url": OSV_URL + vuln_id}


def component_index(bom):
    """Components of the SBOM keyed by normalized purl and by (name, version).
    The root component is included: a judgement can be recorded against it.
    Returns (by_purl, by_nv, root_ref); each value is the component itself."""
    by_purl, by_nv = {}, {}
    comps = list(bom.get("components") or [])
    root = (bom.get("metadata") or {}).get("component")
    root_ref = None
    if isinstance(root, dict):
        comps.append(root)
        root_ref = root.get("bom-ref") or root.get("purl")
    for comp in comps:
        if not isinstance(comp, dict) or not (comp.get("bom-ref") or comp.get("purl")):
            continue
        purl = norm_purl(comp.get("purl"))
        if purl:
            by_purl.setdefault(purl, comp)
        version = comp.get("version") or ""
        name = (comp.get("name") or "").lower()
        if name:
            by_nv.setdefault((name, version), comp)
            group = (comp.get("group") or "").lower()
            if group:
                # Trivy names a Maven finding group:artifact.
                by_nv.setdefault((group + ":" + name, version), comp)
    return by_purl, by_nv, root_ref


def resolve(verdict, by_purl, by_nv):
    """The component a verdict was recorded against. A verdict saved with a
    purl is matched by purl only, never by name, mirroring the web UI."""
    purl = verdict.get("purl")
    if purl:
        return by_purl.get(norm_purl(purl))
    name = (verdict.get("pkg") or "").lower()
    if name:
        return by_nv.get((name, verdict.get("installed") or ""))
    return None


def embedded(comp):
    """The few fields a VEX consumer needs to recognise the component again."""
    out = {"type": comp.get("type") or "library", "bom-ref": comp.get("bom-ref") or comp.get("purl")}
    for key in ("group", "name", "version", "purl"):
        if comp.get(key):
            out[key] = comp[key]
    return out


def build(bom, verdicts):
    by_purl, by_nv, root_ref = component_index(bom)
    # One vulnerability entry per (id, state, note): components that share a
    # judgement are listed together under `affects`, and the same id can still
    # appear again with a different state for a different component.
    groups = {}
    used = {}
    exported = skipped = 0
    for v in verdicts:
        vuln_id = v.get("cve")
        state = STATE_MAP.get(v.get("state"))
        comp = resolve(v, by_purl, by_nv) if vuln_id and state else None
        if not comp:
            skipped += 1
            continue
        ref = comp.get("bom-ref") or comp.get("purl")
        if ref != root_ref:
            used.setdefault(ref, embedded(comp))
        detail = (v.get("detail") or "").strip()
        key = (vuln_id, state, detail)
        entry = groups.get(key)
        if entry is None:
            analysis = {"state": state}
            if detail:
                analysis["detail"] = detail
            entry = {
                "bom-ref": "vex-%d" % (len(groups) + 1),
                "id": vuln_id,
                "source": source_for(vuln_id),
                "analysis": analysis,
                "affects": [],
            }
            groups[key] = entry
        target = {"ref": ref}
        if target not in entry["affects"]:
            entry["affects"].append(target)
        exported += 1

    metadata = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [{"type": "application", "name": "bomlens"}]},
    }
    root = (bom.get("metadata") or {}).get("component")
    if isinstance(root, dict):
        metadata["component"] = root
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": metadata,
    }
    if used:
        doc["components"] = list(used.values())
    doc["vulnerabilities"] = list(groups.values())
    return doc, exported, skipped


def main(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: export-vex.py <bom.json> <vex-verdicts.json> <output.json>\n")
        return 2
    bom = load_json(argv[1])
    sidecar = load_json(argv[2])
    if not isinstance(bom, dict):
        return 1
    verdicts = sidecar.get("verdicts") if isinstance(sidecar, dict) else None
    verdicts = [v for v in verdicts if isinstance(v, dict)] if isinstance(verdicts, list) else []
    doc, exported, skipped = build(bom, verdicts)
    with open(argv[3], "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(json.dumps({"exported": exported, "skipped": skipped}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
