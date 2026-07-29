#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# describe-input-sbom.py — summarize a supplier SBOM for the "what was scanned"
# view (ANALYZE mode).
#
# Usage: describe-input-sbom.py <input_sbom> <out.json> [original_name]
#
# Why: an ANALYZE scan converts the supplier's document to CycloneDX so one
# pipeline can process every input, and the result screens then describe the
# CONVERSION. Everything that identifies the document the supplier actually sent
# — the format and version it was written in, the tool that produced it, when,
# and on whose authority — is lost on the way, and that is exactly what a
# reviewer of a supplier SBOM needs to see. Reading the raw JSON is the current
# alternative; this reads the original and writes the facts the view lists.
#
# Reads the ORIGINAL input, before conversion, and only the document header —
# the components themselves are already in the result's own component view, and
# repeating them here would duplicate a table that does more.
#
# Handles CycloneDX and SPDX in JSON, plus CycloneDX/SPDX XML for the format and
# component count. Anything it cannot read is reported as unknown rather than
# guessed: a wrong "produced by" line on a compliance screen is worse than a
# blank one. Best-effort — a failure leaves no summary and never breaks a scan.

import json
import os
import sys
import xml.etree.ElementTree as ET

# A supplier document is a header plus a component list; only the header is read,
# but json.load still parses the whole file. Refuse absurd inputs rather than
# stalling the scan on a pathological upload.
MAX_BYTES = 256 * 1024 * 1024


def text(v):
    """A trimmed string, or "" for anything that is not usable text."""
    return v.strip() if isinstance(v, str) and v.strip() else ""


def as_list(v):
    return v if isinstance(v, list) else []


def cyclonedx_tools(meta):
    """CycloneDX tools moved from a list of objects (1.4) to {components:[…]}
    (1.5+). Read both, and fall back to the plain string form some writers emit."""
    tools = meta.get("tools")
    entries = []
    if isinstance(tools, dict):
        entries = as_list(tools.get("components")) + as_list(tools.get("services"))
    elif isinstance(tools, list):
        entries = tools
    out = []
    for t in entries:
        if isinstance(t, str):
            name, version = text(t), ""
        elif isinstance(t, dict):
            name, version = text(t.get("name")), text(t.get("version"))
        else:
            continue
        if name:
            out.append("%s %s" % (name, version) if version else name)
    return out


def party(v):
    """A CycloneDX supplier/manufacturer object, or an author entry, as a name."""
    if isinstance(v, str):
        return text(v)
    if isinstance(v, dict):
        return text(v.get("name")) or text(v.get("email"))
    return ""


def describe_cyclonedx(doc):
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    root = meta.get("component") if isinstance(meta.get("component"), dict) else {}
    licenses = []
    for entry in as_list(root.get("licenses")):
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            got = text(lic.get("id")) or text(lic.get("name"))
        else:
            got = text(entry.get("expression"))
        if got:
            licenses.append(got)
    authors = [party(a) for a in as_list(meta.get("authors"))]
    return {
        "format": "CycloneDX",
        "specVersion": text(doc.get("specVersion")),
        "documentId": text(doc.get("serialNumber")),
        "documentName": text(root.get("name")),
        "created": text(meta.get("timestamp")),
        "tools": cyclonedx_tools(meta),
        "authors": [a for a in authors if a],
        "supplier": party(meta.get("supplier")) or party(meta.get("manufacture")),
        "rootComponent": {
            "name": text(root.get("name")),
            "version": text(root.get("version")),
            "type": text(root.get("type")),
            "purl": text(root.get("purl")),
            "licenses": licenses,
        },
        "componentCount": len(as_list(doc.get("components"))),
    }


def describe_spdx2(doc):
    ci = doc.get("creationInfo") if isinstance(doc.get("creationInfo"), dict) else {}
    creators = [text(c) for c in as_list(ci.get("creators"))]
    # SPDX creators are prefixed strings: "Tool: syft-1.0", "Organization: Acme",
    # "Person: Jo". Split them so the view can label each properly instead of
    # printing the prefix.
    tools, authors, supplier = [], [], ""
    for c in creators:
        low = c.lower()
        if low.startswith("tool:"):
            tools.append(c.split(":", 1)[1].strip())
        elif low.startswith("organization:"):
            supplier = supplier or c.split(":", 1)[1].strip()
        elif low.startswith("person:"):
            authors.append(c.split(":", 1)[1].strip())
        elif c:
            authors.append(c)
    return {
        "format": "SPDX",
        "specVersion": text(doc.get("spdxVersion")).replace("SPDX-", ""),
        "documentId": text(doc.get("documentNamespace")),
        "documentName": text(doc.get("name")),
        "created": text(ci.get("created")),
        "tools": tools,
        "authors": authors,
        "supplier": supplier,
        "rootComponent": {
            "name": text(doc.get("name")),
            "version": "",
            "type": "",
            "purl": "",
            "licenses": [text(doc.get("dataLicense"))] if text(doc.get("dataLicense")) else [],
        },
        "componentCount": len(as_list(doc.get("packages"))),
    }


def describe_spdx3(doc):
    """SPDX 3.0 is JSON-LD: every element is a node in @graph, and the header
    points at the others by id. CreationInfo, the tool that wrote the document
    and the organization behind it are three separate nodes, so the references
    have to be resolved — reading the header alone yields blanks."""
    graph = as_list(doc.get("@graph"))
    by_id, header, packages = {}, {}, 0
    for node in graph:
        if not isinstance(node, dict):
            continue
        node_id = text(node.get("spdxId")) or text(node.get("@id"))
        if node_id:
            by_id[node_id] = node
        node_type = text(node.get("type")) or text(node.get("@type"))
        if node_type.endswith("SpdxDocument") and not header:
            header = node
        elif node_type.endswith("Package"):
            packages += 1

    def resolve(ref):
        """A node reference (an id string) or an inline node, as a node."""
        if isinstance(ref, str):
            return by_id.get(ref.strip(), {})
        return ref if isinstance(ref, dict) else {}

    ci = resolve(header.get("creationInfo"))
    tools, authors, supplier = [], [], ""
    for ref in as_list(ci.get("createdUsing")):
        name = text(resolve(ref).get("name"))
        if name:
            tools.append(name)
    for ref in as_list(ci.get("createdBy")):
        agent = resolve(ref)
        name = text(agent.get("name"))
        if not name:
            continue
        if text(agent.get("type")).endswith("Organization"):
            supplier = supplier or name
        else:
            authors.append(name)

    return {
        "format": "SPDX",
        "specVersion": text(ci.get("specVersion")) or "3.0",
        "documentId": text(header.get("spdxId")) or text(header.get("@id")),
        "documentName": text(header.get("name")),
        "created": text(ci.get("created")),
        "tools": tools,
        "authors": authors,
        "supplier": supplier,
        "rootComponent": {
            "name": text(header.get("name")),
            "version": "",
            "type": "",
            "purl": "",
            "licenses": [],
        },
        "componentCount": packages,
    }


def describe_xml(path):
    """XML input: read the format, its version and the component count. The rest
    of the header varies enough between writers that guessing is not worth it."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    tag = root.tag.split("}")[-1].lower()
    ns = root.tag.split("}")[0].strip("{") if "}" in root.tag else ""
    if tag != "bom":
        return None
    version = root.get("specVersion") or ""
    if not version and "cyclonedx" in ns:
        # Pre-1.3 CycloneDX carried the version only in the namespace URI.
        version = ns.rstrip("/").rsplit("/", 1)[-1]
    count = 0
    for child in root.iter():
        if child.tag.split("}")[-1] == "component":
            count += 1
    return {
        "format": "CycloneDX",
        "specVersion": version,
        "documentId": root.get("serialNumber") or "",
        "documentName": "",
        "created": "",
        "tools": [],
        "authors": [],
        "supplier": "",
        "rootComponent": {"name": "", "version": "", "type": "", "purl": "", "licenses": []},
        "componentCount": count,
    }


def describe(path):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return describe_xml(path)
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX" or doc.get("specVersion"):
        return describe_cyclonedx(doc)
    if doc.get("spdxVersion"):
        return describe_spdx2(doc)
    if doc.get("@graph") or doc.get("@context"):
        return describe_spdx3(doc)
    return None


def main():
    if len(sys.argv) < 3:
        sys.exit(0)
    src, out_file = sys.argv[1], sys.argv[2]
    original = sys.argv[3] if len(sys.argv) > 3 else os.path.basename(src)
    if not os.path.isfile(src):
        sys.exit(0)
    try:
        size = os.path.getsize(src)
    except OSError:
        sys.exit(0)
    if size > MAX_BYTES:
        print("[WARN] describe-input-sbom: input is %d MiB (over the %d MiB limit); "
              "no input summary written." % (size // 1048576, MAX_BYTES // 1048576),
              file=sys.stderr)
        sys.exit(0)

    summary = describe(src)
    if summary is None:
        print("[WARN] describe-input-sbom: unrecognized SBOM format; "
              "no input summary written.", file=sys.stderr)
        sys.exit(0)

    summary["originalName"] = os.path.basename(original)
    summary["originalBytes"] = size
    try:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, ensure_ascii=False, sort_keys=True)
    except OSError as exc:
        print("[WARN] describe-input-sbom: could not write %s (%s)." % (out_file, exc),
              file=sys.stderr)
        sys.exit(0)

    label = summary["format"]
    if summary["specVersion"]:
        label += " " + summary["specVersion"]
    print("[INFO] describe-input-sbom: input is %s with %d component(s)."
          % (label, summary["componentCount"]))


if __name__ == "__main__":
    main()
