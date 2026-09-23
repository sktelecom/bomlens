#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read a CycloneDX VEX document a supplier sent and keep the statements that
apply to the scanned SBOM.

Usage: import-vex.py <bom.json> <vex-input.json> <output.json>

The output (`<prefix>_vex_imported.json`) is kept apart from the judgements the
user recorded themselves (`_vex.json`): a received statement never overwrites
one, and the screen shows the two side by side with their own labels. Importing
again replaces the previous received file; the user's own judgements are never
touched. The SBOM is never modified.

Only what CycloneDX defines is read: `vulnerabilities[].id`,
`analysis.state`/`detail`/`justification` and `affects[].ref`. States are
mapped to the four the screen already uses:

    exploitable                          -> affected
    not_affected, false_positive         -> not_affected
    resolved, resolved_with_pedigree     -> fixed
    in_triage                            -> under_investigation

A statement with any other state is ignored, not guessed at.

A VEX describes one product, and "not affected" depends on how that product
uses a component. So the document is refused outright, and nothing is written,
when its `metadata.component` names a different product or version than the
scanned SBOM's root. Below that, each statement must resolve to a component of
the scanned SBOM (by purl, else by name and version); the rest are counted as
unmatched and left out. `affects[].ref` may be a plain bom-ref or a
`urn:cdx:<serial>/<version>#<bom-ref>` link; either is looked up in the
document's own `components[]` first, then in the scanned SBOM.

A ref that points at the product itself (the document's or the SBOM's root
component) is a product-level statement: it is kept with `scope: "product"` and
no component identity, and the screen applies it to every finding with that CVE
that has no statement of its own. A statement with no `affects` at all names
nothing to apply to and is counted as ignored. A statement that resolves to a
component is stored with the purl (when it has one) and the name and version
both, because a finding the scanner reported without a purl can only be matched
by name and version.

Nothing in the document is trusted for its type: a field of the wrong type makes
that component or statement unusable, and a document that cannot be read at all
is refused as invalid (exit 2), never a traceback. A document that yields more
than MAX_STATEMENTS statements is refused (exit 4).

Standard output is one JSON line. On success: {"imported": N, "unmatched": M,
"ignored": K}. On refusal: {"error": "target_mismatch", "vexProduct": ...,
"scanProduct": ...} (exit 3), {"error": "invalid"} (exit 2) or
{"error": "too_many"} (exit 4).
"""
import json
import re
import sys
from datetime import datetime, timezone

MAX_BYTES = 8 * 1024 * 1024
MAX_DETAIL = 2000
MAX_STATEMENTS = 20000  # a real VEX names hundreds; this bounds what one file can add
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

STATE_MAP = {
    "exploitable": "affected",
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "in_triage": "under_investigation",
}


def text(value):
    """The value when it is a string, else "": a field of the wrong type in a
    document we did not write is unusable, not an error."""
    return value if isinstance(value, str) else ""


def norm_purl(purl):
    """Same normalization as server.py's _norm_purl."""
    return text(purl).split("?", 1)[0].split("#", 1)[0].strip().lower()


def load_json(path, limit=None):
    """The parsed document, or None. `limit` caps what is read: it applies to
    the received document only, never to the scanned SBOM."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read() if limit is None else fh.read(limit + 1)
        if limit is not None and len(raw) > limit:
            return None
        return json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return None


def root_of(doc):
    meta = doc.get("metadata")
    comp = meta.get("component") if isinstance(meta, dict) else None
    return comp if isinstance(comp, dict) else None


def product(doc):
    comp = root_of(doc)
    if not comp or not text(comp.get("name")):
        return None
    return {"name": comp["name"], "version": text(comp.get("version"))}


def index_components(doc):
    """(by_ref, by_purl, by_nv) over a document's components and root."""
    by_ref, by_purl, by_nv = {}, {}, {}
    listed = doc.get("components")
    comps = list(listed) if isinstance(listed, list) else []
    root = root_of(doc)
    if root:
        comps.append(root)
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        ref = text(comp.get("bom-ref"))
        if ref:
            by_ref.setdefault(ref, comp)
        purl = norm_purl(comp.get("purl"))
        if purl:
            by_purl.setdefault(purl, comp)
        name = text(comp.get("name")).lower()
        if name:
            version = text(comp.get("version"))
            by_nv.setdefault((name, version), comp)
            group = text(comp.get("group")).lower()
            if group:
                by_nv.setdefault((group + ":" + name, version), comp)
    return by_ref, by_purl, by_nv


def ref_key(ref):
    """The bom-ref part of a plain ref or a urn:cdx link."""
    if isinstance(ref, str) and ref.startswith("urn:cdx:") and "#" in ref:
        return ref.split("#", 1)[1]
    return ref


def match_scanned(comp, scan_purl, scan_nv):
    purl = norm_purl(comp.get("purl"))
    if purl:
        return scan_purl.get(purl)
    name = text(comp.get("name")).lower()
    group = text(comp.get("group")).lower()
    version = text(comp.get("version"))
    if not name:
        return None
    if group and (group + ":" + name, version) in scan_nv:
        return scan_nv[(group + ":" + name, version)]
    return scan_nv.get((name, version))


def identity(scan_comp):
    """How the web UI keys a finding to this component. Both keys are kept: the
    purl when the component has one, and always the name Trivy reports
    (group:artifact for Maven) with the version, because a finding the scanner
    reported without a purl can only be matched that way."""
    name = text(scan_comp.get("name"))
    group = text(scan_comp.get("group"))
    ident = {
        "pkg": (group + ":" + name) if group else name,
        "installed": text(scan_comp.get("version")),
    }
    purl = text(scan_comp.get("purl"))
    if purl:
        ident["purl"] = purl
    return ident


def run(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: import-vex.py <bom.json> <vex-input.json> <output.json>\n")
        return 2
    bom = load_json(argv[1])
    vex = load_json(argv[2], MAX_BYTES)
    if not isinstance(bom, dict):
        print(json.dumps({"error": "invalid"}))
        return 2
    if (
        not isinstance(vex, dict)
        or vex.get("bomFormat") != "CycloneDX"
        or not isinstance(vex.get("vulnerabilities"), list)
    ):
        print(json.dumps({"error": "invalid"}))
        return 2

    scan_root, vex_root = product(bom), product(vex)
    if scan_root and vex_root:
        same_name = scan_root["name"].lower() == vex_root["name"].lower()
        same_version = (
            not scan_root["version"] or not vex_root["version"]
            or scan_root["version"] == vex_root["version"]
        )
        if not (same_name and same_version):
            print(json.dumps({
                "error": "target_mismatch",
                "vexProduct": "%s %s" % (vex_root["name"], vex_root["version"]),
                "scanProduct": "%s %s" % (scan_root["name"], scan_root["version"]),
            }))
            return 3

    scan_by_ref, scan_purl, scan_nv = index_components(bom)
    vex_by_ref = index_components(vex)[0]
    product_objects = [c for c in (root_of(vex), root_of(bom)) if c is not None]

    statements = {}
    unmatched = ignored = 0
    for vuln in vex["vulnerabilities"]:
        if not isinstance(vuln, dict):
            ignored += 1
            continue
        vuln_id = vuln.get("id")
        analysis = vuln.get("analysis") if isinstance(vuln.get("analysis"), dict) else {}
        received_state = text(analysis.get("state"))
        state = STATE_MAP.get(received_state)
        if not isinstance(vuln_id, str) or not ID_RE.match(vuln_id) or not state:
            ignored += 1
            continue
        detail = text(analysis.get("detail")).strip()[:MAX_DETAIL]
        justification = text(analysis.get("justification"))
        justification = justification if len(justification) <= 64 else ""
        affects = vuln.get("affects")
        if not isinstance(affects, list) or not affects:
            # Names nothing to apply to; counted so the caller can see it.
            ignored += 1
            continue
        for target in affects:
            key = ref_key(target.get("ref") if isinstance(target, dict) else None)
            comp = (vex_by_ref.get(key) or scan_by_ref.get(key)) if isinstance(key, str) else None
            if comp is None:
                unmatched += 1
                continue
            if any(comp is root for root in product_objects):
                # The product itself: applies to every finding of this CVE
                # without a statement of its own.
                ident, dedupe = {"scope": "product"}, (vuln_id, "product")
            else:
                scan_comp = match_scanned(comp, scan_purl, scan_nv)
                if not scan_comp:
                    unmatched += 1
                    continue
                ident = identity(scan_comp)
                dedupe = (vuln_id, ident.get("purl") or (ident["pkg"], ident["installed"]))
            record = {"cve": vuln_id, "state": state, **ident}
            if received_state in ("false_positive", "resolved_with_pedigree"):
                # Mapped onto the nearest state the screen has; keep the word
                # the sender used.
                record["receivedState"] = received_state
            if detail:
                record["detail"] = detail
            if justification:
                record["justification"] = justification
            statements[dedupe] = record
            if len(statements) > MAX_STATEMENTS:
                print(json.dumps({"error": "too_many"}))
                return 4

    source = {"importedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if vex_root:
        source["product"] = "%s %s" % (vex_root["name"], vex_root["version"])
    if isinstance(vex.get("serialNumber"), str):
        source["serialNumber"] = vex["serialNumber"][:80]
    with open(argv[3], "w", encoding="utf-8") as fh:
        json.dump({"source": source, "statements": list(statements.values())}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(json.dumps({"imported": len(statements), "unmatched": unmatched, "ignored": ignored}))
    return 0


def main(argv):
    try:
        return run(argv)
    except (RecursionError, TypeError, AttributeError, ValueError, KeyError, IndexError):
        # A document built to break the reader is an invalid document.
        print(json.dumps({"error": "invalid"}))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
