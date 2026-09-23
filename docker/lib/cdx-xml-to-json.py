#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# cdx-xml-to-json.py: read a CycloneDX XML document and write the same document
# as CycloneDX JSON, so the rest of the pipeline sees one input format.
#
# Usage: cdx-xml-to-json.py <bom.xml> <out.json>
# Exit:  0 written, 2 not a CycloneDX XML document (nothing written), 1 unreadable.
# Also importable: read_document(raw_bytes) returns the JSON document or None.
#
# Why not `syft convert`: it reads CycloneDX XML but drops every component hash,
# empties metadata.component (the root moves into components) and rewrites
# dependency references so the root no longer connects to anything. Hashes and
# the root are what a supplier review measures, so the mapping is done here.
#
# The document is untrusted supplier input. A CycloneDX document has no use for a
# DTD, so a DOCTYPE in the prolog (the only place an entity can be declared) is
# refused before parsing, which shuts out entity expansion and external entities
# together. The text is decoded first, so UTF-16 gets the same check. Size and
# nesting are bounded.
#
# Read: metadata (timestamp, tools, authors, supplier, manufacturer, lifecycles,
# root component), components (nested) with hashes, licenses, external
# references, properties, authors and supplier, dependencies (nested form
# included) and compositions. Not read: services, vulnerabilities, pedigree,
# evidence, release notes, formulation and the like. Whatever is present and
# skipped is named on stderr, wherever in the document it sits, so a reader never
# mistakes the result for the whole document.

import json
import os
import re
import sys
import xml.etree.ElementTree as ET

MAX_BYTES = 100 * 1024 * 1024  # the web upload limit; parsing takes about 12x this in memory
NS_MARK = "cyclonedx.org/schema/bom"
SKIPPED = ("services", "vulnerabilities", "formulation", "annotations", "definitions",
           "pedigree", "evidence", "releaseNotes", "modelCard", "data", "cryptoProperties",
           "signature", "swid", "omniborId", "swhid", "patches")


def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def txt(el):
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def children(el, name):
    return [c for c in el if local(c.tag) == name]


def put(d, key, value):
    if value not in (None, "", [], {}):
        d[key] = value


def contact(el):
    """organizationalEntity / organizationalContact."""
    out = {}
    put(out, "name", txt(child(el, "name")))
    urls = [u for u in (txt(x) for x in children(el, "url")) if u]
    put(out, "url", urls)
    contacts = []
    for c in children(el, "contact"):
        p = {}
        put(p, "name", txt(child(c, "name")))
        put(p, "email", txt(child(c, "email")))
        put(p, "phone", txt(child(c, "phone")))
        if p:
            contacts.append(p)
    put(out, "contact", contacts)
    return out


def hashes(el):
    box = child(el, "hashes")
    if box is None:
        return []
    return [{"alg": h.get("alg"), "content": txt(h)} for h in children(box, "hash")
            if h.get("alg") and txt(h)]


def licenses(el):
    box = child(el, "licenses")
    if box is None:
        return []
    out = []
    for item in box:
        kind = local(item.tag)
        if kind == "expression" and txt(item):
            out.append({"expression": txt(item)})
        elif kind == "license":
            lic = {}
            put(lic, "id", txt(child(item, "id")))
            put(lic, "name", txt(child(item, "name")))
            put(lic, "url", txt(child(item, "url")))
            t = child(item, "text")
            if t is not None and txt(t):
                body = {"content": txt(t)}
                put(body, "contentType", t.get("content-type"))
                put(body, "encoding", t.get("encoding"))
                lic["text"] = body
            if lic:
                out.append({"license": lic})
    return out


def ext_refs(el):
    box = child(el, "externalReferences")
    if box is None:
        return []
    out = []
    for r in children(box, "reference"):
        e = {"type": r.get("type") or "other"}
        put(e, "url", txt(child(r, "url")))
        put(e, "comment", txt(child(r, "comment")))
        if "url" in e:
            out.append(e)
    return out


def props(el):
    box = child(el, "properties")
    if box is None:
        return []
    return [{"name": p.get("name"), "value": (p.text or "").strip()}
            for p in children(box, "property") if p.get("name")]


def component(el):
    c = {"type": el.get("type") or "library"}
    put(c, "bom-ref", el.get("bom-ref"))
    put(c, "mime-type", el.get("mime-type"))
    sup = child(el, "supplier")
    if sup is not None:
        put(c, "supplier", contact(sup))
    man = child(el, "manufacturer")
    if man is not None:
        put(c, "manufacturer", contact(man))
    au = child(el, "authors")
    if au is not None:
        put(c, "authors", [contact(a) for a in children(au, "author") if contact(a)])
    put(c, "author", txt(child(el, "author")))
    put(c, "publisher", txt(child(el, "publisher")))
    put(c, "group", txt(child(el, "group")))
    c["name"] = txt(child(el, "name")) or ""
    put(c, "version", txt(child(el, "version")))
    put(c, "description", txt(child(el, "description")))
    put(c, "scope", txt(child(el, "scope")))
    put(c, "hashes", hashes(el))
    put(c, "licenses", licenses(el))
    put(c, "copyright", txt(child(el, "copyright")))
    put(c, "cpe", txt(child(el, "cpe")))
    put(c, "purl", txt(child(el, "purl")))
    put(c, "externalReferences", ext_refs(el))
    put(c, "properties", props(el))
    nested = child(el, "components")
    if nested is not None:
        put(c, "components", [component(x) for x in children(nested, "component")])
    return c


def tools(el):
    box = child(el, "tools")
    if box is None:
        return None
    old = children(box, "tool")
    if old:  # 1.2 to 1.4: a list of {vendor, name, version, hashes}
        out = []
        for t in old:
            e = {}
            put(e, "vendor", txt(child(t, "vendor")))
            put(e, "name", txt(child(t, "name")))
            put(e, "version", txt(child(t, "version")))
            put(e, "hashes", hashes(t))
            if e:
                out.append(e)
        return out
    out = {}  # 1.5 and later: {components: [...], services: [...]}
    comps = child(box, "components")
    if comps is not None:
        put(out, "components", [component(x) for x in children(comps, "component")])
    servs = child(box, "services")
    if servs is not None:
        put(out, "services", [{"name": txt(child(s, "name")) or "",
                               "version": txt(child(s, "version"))}
                              for s in children(servs, "service")])
    return out


def dependencies(root):
    """The XML form nests: <dependency ref=a><dependency ref=b><dependency ref=c/>
    is a graph a -> b -> c. Every dependency element with a ref becomes one entry
    whose dependsOn is its direct children, merged by ref, so a nested tree and the
    flat form give the same graph."""
    box = child(root, "dependencies")
    if box is None:
        return []
    merged = {}
    stack = list(reversed(children(box, "dependency")))
    while stack:
        d = stack.pop()
        ref = d.get("ref")
        if not ref:
            continue
        kids = [x for x in children(d, "dependency") if x.get("ref")]
        entry = merged.setdefault(ref, [])
        for k in kids:
            if k.get("ref") not in entry:
                entry.append(k.get("ref"))
        stack.extend(reversed(kids))
    return [{"ref": r, "dependsOn": on} for r, on in merged.items()]


def compositions(root):
    box = child(root, "compositions")
    if box is None:
        return []
    out = []
    for c in children(box, "composition"):
        agg = txt(child(c, "aggregate"))
        if not agg:
            continue
        e = {"aggregate": agg}
        for xml_name, key in (("assemblies", "assemblies"), ("dependencies", "dependencies")):
            b = child(c, xml_name)
            if b is not None:
                refs = [x.get("ref") for x in b if x.get("ref")]
                put(e, key, refs)
        out.append(e)
    return out


def count_components(container):
    """Components under a <components> element, following nested <components>
    only: the tree component() converts, so the count is checked against what was
    read rather than against every element named component (a pedigree holds
    some too)."""
    n = 0
    stack = [container]
    while stack:
        box = stack.pop()
        for c in children(box, "component"):
            n += 1
            inner = child(c, "components")
            if inner is not None:
                stack.append(inner)
    return n


def convert(root):
    doc = {"bomFormat": "CycloneDX"}
    m = re.search(r"schema/bom/(\d+\.\d+)", root.tag)
    spec = m.group(1) if m else "1.4"
    if tuple(int(x) for x in spec.split(".")) < (1, 2):
        # CycloneDX JSON starts at 1.2; a 1.0 or 1.1 document is written as 1.2 so
        # the result is a valid document, and the change is said out loud.
        print("[cdx-xml] WARN: the document is CycloneDX %s; written as 1.2, the first "
              "version that has a JSON form." % spec, file=sys.stderr)
        spec = "1.2"
    doc["specVersion"] = spec
    put(doc, "serialNumber", root.get("serialNumber"))
    try:
        doc["version"] = max(1, int(root.get("version") or 1))
    except ValueError:
        doc["version"] = 1
    meta = child(root, "metadata")
    if meta is not None:
        md = {}
        put(md, "timestamp", txt(child(meta, "timestamp")))
        put(md, "tools", tools(meta))
        au = child(meta, "authors")
        if au is not None:
            put(md, "authors", [contact(a) for a in children(au, "author")])
        mc = child(meta, "component")
        if mc is not None:
            md["component"] = component(mc)
        sup = child(meta, "supplier")
        if sup is not None:
            put(md, "supplier", contact(sup))
        # 1.6 renamed manufacture to manufacturer.
        for xml_name, key in (("manufacture", "manufacture"), ("manufacturer", "manufacturer")):
            man = child(meta, xml_name)
            if man is not None:
                put(md, key, contact(man))
        lc = child(meta, "lifecycles")
        if lc is not None:
            phases = []
            for x in children(lc, "lifecycle"):
                e = {}
                put(e, "phase", txt(child(x, "phase")))
                put(e, "name", txt(child(x, "name")))
                put(e, "description", txt(child(x, "description")))
                if e:
                    phases.append(e)
            put(md, "lifecycles", phases)
        put(md, "licenses", licenses(meta))
        put(md, "properties", props(meta))
        put(doc, "metadata", md)
    box = child(root, "components")
    doc["components"] = [component(c) for c in children(box, "component")] if box is not None else []
    put(doc, "externalReferences", ext_refs(root))
    put(doc, "dependencies", dependencies(root))
    put(doc, "compositions", compositions(root))
    put(doc, "properties", props(root))

    # Every component in the XML body must come out the other side.
    want = count_components(box) if box is not None else 0  # same tree as component()
    got = sum(1 for _ in walk(doc["components"]))
    if want != got:
        raise ValueError("component count changed in conversion (%d in, %d out)" % (want, got))
    return doc


def walk(comps):
    for c in comps:
        yield c
        yield from walk(c.get("components", []))


def decode(raw):
    """Bytes to text. A UTF-16 or UTF-8 BOM, or the NUL pattern of BOM-less UTF-16,
    decides the encoding; anything else is read as UTF-8. Returns None if it does
    not decode."""
    try:
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return raw.decode("utf-16")
        if raw[:3] == b"\xef\xbb\xbf":
            return raw[3:].decode("utf-8")
        if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00" and raw[0:1] != b"\x00":
            return raw.decode("utf-16-le")
        if len(raw) >= 4 and raw[0:1] == b"\x00" and raw[2:3] == b"\x00" and raw[1:2] != b"\x00":
            return raw.decode("utf-16-be")
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


class Refused(Exception):
    """The document is refused, with a reason a person can act on."""


def read_document(raw):
    """CycloneDX XML bytes to the JSON document (a dict), or None when the bytes
    are not a CycloneDX XML document. Raises Refused for a DTD or a document that
    cannot be converted."""
    text = decode(raw)
    if text is None:
        return None
    # Entities are declared in a DOCTYPE, which can only sit in the prolog: look
    # there, after comments are set aside, and do not look at the body (a comment
    # or a license text may legitimately mention the string).
    first = re.search(r"<[A-Za-z_:]", text)
    prolog = text[: first.start()] if first else text
    prolog = re.sub(r"<!--.*?-->", "", prolog, flags=re.DOTALL)
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", prolog, re.IGNORECASE):
        raise Refused("the document declares a DTD or an entity. A CycloneDX "
                      "document does not need one.")
    # The declaration names an encoding the text no longer has once decoded.
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as exc:
        # Text that is not XML at all is somebody else's format. A CycloneDX
        # document that is broken gets a refusal that says so.
        if NS_MARK in text[:4096]:
            raise Refused("not well-formed XML: %s" % exc)
        return None
    if local(root.tag) != "bom" or NS_MARK not in root.tag:
        return None
    try:
        doc = convert(root)
    except (ValueError, RecursionError) as exc:
        raise Refused("cannot convert: %s" % exc)
    skipped = sorted({local(e.tag) for e in root.iter() if local(e.tag) in SKIPPED})
    if skipped:
        print("[cdx-xml] WARN: not carried over from the XML: %s." % ", ".join(skipped),
              file=sys.stderr)
    return doc


def main():
    if len(sys.argv) != 3:
        print("usage: cdx-xml-to-json.py <bom.xml> <out.json>", file=sys.stderr)
        return 1
    src, dst = sys.argv[1], sys.argv[2]
    try:
        size = os.path.getsize(src)
        if size > MAX_BYTES:
            print("[cdx-xml] input is %d MiB, over the %d MiB limit." % (size >> 20, MAX_BYTES >> 20),
                  file=sys.stderr)
            return 1
        with open(src, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print("[cdx-xml] cannot read %s: %s" % (src, exc), file=sys.stderr)
        return 1
    try:
        doc = read_document(raw)
    except Refused as exc:
        print("[cdx-xml] refused: %s" % exc, file=sys.stderr)
        return 1
    if doc is None:
        return 2
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
