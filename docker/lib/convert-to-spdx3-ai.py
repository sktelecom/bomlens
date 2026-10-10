#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Write an AI SBOM as an SPDX 3.0.1 AI and Dataset profile document.

The CycloneDX ML-BOM a scan produced stays the authoritative record. This reads
it, together with an optional declaration file holding what only the model's
publisher knows, and writes three files next to it:

  {prefix}_bom.spdx3.json      the SPDX 3.0.1 JSON-LD document
  {prefix}_spdx3-check.json    which fields came from where, and what is missing
  {prefix}_spdx3-check.md      the same, for a person

Nothing is estimated. A field is written from the CycloneDX document, from a
fixed rule over what the CycloneDX document records, or from the declaration;
otherwise it is left out. Fields the specification makes required and that have
no "unknown" value (agents, dates, the download location) stay empty until the
publisher declares them, and the document is marked a draft until then. Values
for a base model are never copied from the model itself, and the reverse.

Subcommands
  convert   --bom F --out-dir D --prefix=P [--declaration F [--declaration-fallback]]
            [--map M] [--stable]
  check     --bom F [--declaration F] [--map M]          (check JSON on stdout)
  template  --bom F --out-dir D --prefix=P [--map M]     (empty declaration)

Exit status: 0 done (a draft is still done), 1 bad input, 2 declaration refused
(with --declaration-fallback the document is still written, without it), 3 the
SBOM holds no model or dataset. Pass the prefix as --prefix=P: a scan's prefix
can begin with "-".
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.parse

DECLARATION_SCHEMA = "bomlens-ai-declaration/1"
CHECK_SCHEMA = "bomlens-spdx3-check/1"
CREATION_INFO = "_:creationinfo"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HUB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$")
REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# The scan's own file-name prefix: entrypoint.sh keeps [A-Za-z0-9.-] and joins
# project and version with "_", so a project named only in Korean gives "_1.0".
# No path separator can get through; "." and ".." are refused below.
PREFIX_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,200}$")
# Exit codes: 0 written, 1 a fault (unreadable input, bad arguments), 2 the
# declaration was refused, 3 the SBOM holds no model or dataset to describe.
EXIT_REFUSED = 2
EXIT_NO_AI = 3
LICENSE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
# A value as the check shows it is cut here; the document holds it in full.
DISPLAY_MAX = 200
MAX_DECLARATION_BYTES = 1024 * 1024
MAX_TEXT = 4000
AGENT_TYPES = ("Organization", "Person", "Agent")
URI_SCHEMES = ("http", "https", "s3", "gs", "ftp", "sftp", "git", "git+https", "git+ssh", "hf")
ROLES = ("trainedOn", "testedOn", "other")
PLACEHOLDER_DESCRIPTION = "no description available"
DISCLAIMER = "This check is guidance, not legal advice."


class Refused(Exception):
    """The declaration file was refused; each message says why."""

    def __init__(self, messages):
        super().__init__("; ".join(messages))
        self.messages = messages


def _empty(v):
    return v is None or v == "" or v == [] or v == {}


# ---- the mapping ------------------------------------------------------------

def load_map(path):
    with open(path) as fh:
        m = json.load(fh)
    fields = {}
    for etype, spec in m["elements"].items():
        fields[etype] = {f["id"]: f for f in spec["fields"]}
    m["_fields"] = fields
    return m


# ---- reading the CycloneDX document -------------------------------------------

def _props(comp):
    out = {}
    for p in comp.get("properties") or []:
        if isinstance(p, dict) and p.get("name") is not None:
            out.setdefault(str(p["name"]), []).append(str(p.get("value", "")))
    return out


def _one(props, name):
    v = props.get(name)
    return v[0] if v else None


def find_root(bom):
    """The component the document is about: the model, or for a dataset scan
    the dataset. The generator can leave its scan job at the root and the model
    under components[], so a model anywhere wins over a non-model root."""
    root = (bom.get("metadata") or {}).get("component")
    root = root if isinstance(root, dict) else None
    if root and root.get("type") == "machine-learning-model":
        return root
    for c in bom.get("components") or []:
        if isinstance(c, dict) and c.get("type") == "machine-learning-model":
            return c
    if root and root.get("type") == "data":
        return root
    return None


def data_components(bom, root):
    comps = [c for c in (bom.get("components") or []) if isinstance(c, dict) and c.get("type") == "data"]
    if root is not None and root.get("type") == "data" and root not in comps:
        comps.insert(0, root)
    return comps


def _refs(comp, rtype):
    return [str(r.get("url")) for r in comp.get("externalReferences") or []
            if isinstance(r, dict) and r.get("type") == rtype and r.get("url")]


def extract(comp, what, bom):
    """What the CycloneDX document records for one mapped field, or None."""
    if what == "name":
        return comp.get("name") or None
    if what == "version":
        return str(comp["version"]) if comp.get("version") else None
    if what == "purl":
        return comp.get("purl") or None
    if what == "homePage":
        refs = _refs(comp, "website")
        return refs[0] if refs else None
    if what == "modelDownload":
        refs = [u for u in _refs(comp, "distribution") if "/datasets/" not in u]
        return refs[0] if refs else None
    if what == "datasetDownload":
        refs = _refs(comp, "distribution")
        return refs[0] if refs else None
    if what == "supplier":
        name = (comp.get("supplier") or {}).get("name") if isinstance(comp.get("supplier"), dict) else None
        return {"type": "Agent", "name": str(name)} if name else None
    if what == "description":
        d = comp.get("description")
        if not d or str(d).strip().lower() == PLACEHOLDER_DESCRIPTION:
            return None
        return str(d)
    card = comp.get("modelCard") if isinstance(comp.get("modelCard"), dict) else {}
    if what == "architecture":
        a = (card.get("modelParameters") or {}).get("modelArchitecture")
        return [str(a)] if a else None
    if what == "limitations":
        lim = (card.get("considerations") or {}).get("technicalLimitations")
        lim = [str(x) for x in (lim or []) if str(x).strip()]
        return "\n".join(lim) if lim else None
    if what == "metrics":
        ms = (card.get("quantitativeAnalysis") or {}).get("performanceMetrics") or []
        out = [{"key": str(m.get("type")), "value": str(m.get("value"))}
               for m in ms if isinstance(m, dict) and m.get("type") and m.get("value") is not None]
        return out or None
    if what == "weightsScope":
        return _one(_props(comp), "bomlens:weights:scope")
    if what == "documentAuthors":
        authors = [str(a.get("name")) for a in ((bom.get("metadata") or {}).get("authors") or [])
                   if isinstance(a, dict) and a.get("name")]
        return [{"type": "Agent", "name": n} for n in authors] or None
    raise ValueError(f"unknown CycloneDX source '{what}' in the mapping")


def _facets(comp):
    out = []
    for d in comp.get("data") or []:
        if not isinstance(d, dict):
            continue
        for p in ((d.get("contents") or {}).get("properties") or []):
            if isinstance(p, dict) and p.get("name"):
                out.append((str(p["name"]), [v.strip() for v in str(p.get("value", "")).split(",") if v.strip()]))
    return out


def apply_rule(name, comp, mapping):
    rule = mapping["rules"].get(name)
    props = _props(comp)
    if name == "datasetType":
        found = []
        facets = _facets(comp)
        for r in rule:
            for fname, values in facets:
                if fname != r["facet"]:
                    continue
                for v in values:
                    hit = (v == r["equals"]) if "equals" in r else v.startswith(r["prefix"])
                    if hit and r["value"] not in found:
                        found.append(r["value"])
        return found or None
    if name == "piiSignal":
        return rule["value"] if rule["equals"] in props.get(rule["property"], []) else None
    if name == "availability":
        if any(props.get(p) for p in rule["unless"]):
            return None
        return rule["value"]
    raise ValueError(f"unknown rule '{name}' in the mapping")


# ---- the declaration ----------------------------------------------------------

MODEL_KEYS_EXTRA = ("baseModels", "license")
DATASET_KEYS_EXTRA = ("ref", "local", "name", "role", "sources")
SOURCE_RELATIONS = ("extended", "other")
# A licence a person writes for a source the tool could not read: a hub
# licence tag (the list in ai-risk-knowledge.json) or an SPDX licence id.
SPDX_ID_RE = re.compile(r"^(LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]{0,99})$")


def _hub_license_tags():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-risk-knowledge.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return {str(t).lower() for t in (json.load(fh).get("hfLicenseTags") or [])}
    except (OSError, ValueError):
        return set()


HUB_LICENSE_TAGS = _hub_license_tags()


def _check_sources(v, where, self_ref, errs):
    """Sources a person declares for a dataset: a hub dataset by id (read from
    the hub on the next scan) or one named in words with the licence they
    know. Returns the normalized list."""
    if _empty(v):
        return []
    if not isinstance(v, list):
        errs.append(f"{where}: expected a list")
        return []
    out, seen = [], set()
    for j, src in enumerate(v):
        w = f"{where}[{j}]"
        if not isinstance(src, dict) or set(src) - {"ref", "name", "license", "relation"}:
            errs.append(f"{w}: a source is {{\"ref\" or \"name\", \"license\", \"relation\"}}")
            continue
        has_ref = not _empty(src.get("ref"))
        has_name = isinstance(src.get("name"), str) and bool(src["name"].strip())
        if has_ref == has_name:
            errs.append(f"{w}: give exactly one of 'ref' (a hub dataset) or 'name' (one named in words)")
            continue
        relation = src.get("relation") or "other"
        if relation not in SOURCE_RELATIONS:
            errs.append(f"{w}.relation: must be one of {', '.join(SOURCE_RELATIONS)}")
            continue
        entry = {"relation": relation}
        if has_ref:
            ref = src["ref"]
            ds_id = ref[len("huggingface:"):] if isinstance(ref, str) and ref.startswith("huggingface:") else None
            if not ds_id or not HUB_ID_RE.match(ds_id) or ".." in ds_id:
                errs.append(f"{w}.ref: expected huggingface:<owner>/<name>")
                continue
            if self_ref and ("dataset:huggingface/" + ds_id).lower() == self_ref.lower():
                errs.append(f"{w}.ref: a dataset is not its own source")
                continue
            if not _empty(src.get("license")):
                errs.append(f"{w}.license: the licence of a hub dataset is read from the hub; "
                            "'license' is only for a source named in words")
                continue
            entry["ref"], key = ds_id, "ref:" + ds_id.lower()
        else:
            name = src["name"]
            if not isinstance(name, str) or len(name) > MAX_TEXT:
                errs.append(f"{w}.name: expected text up to {MAX_TEXT} characters")
                continue
            entry["name"], key = name.strip(), "name:" + name.strip().lower()
            lic = src.get("license")
            if not _empty(lic):
                if not isinstance(lic, str) or not (lic.strip().lower() in HUB_LICENSE_TAGS
                                                    or SPDX_ID_RE.match(lic.strip())):
                    errs.append(f"{w}.license: a hub licence tag or an SPDX licence id")
                    continue
                entry["license"] = lic.strip()
        if key in seen:
            errs.append(f"{w}: listed twice")
            continue
        seen.add(key)
        out.append(entry)
    return out


def _check_agent(v, where, errs):
    if not isinstance(v, dict) or set(v) - {"type", "name"}:
        errs.append(f"{where}: an agent is an object with 'name' and an optional 'type'")
        return None
    name = v.get("name")
    if not isinstance(name, str) or not name.strip():
        errs.append(f"{where}: an agent needs a name")
        return None
    t = v.get("type") or "Agent"
    if t not in AGENT_TYPES:
        errs.append(f"{where}: agent type must be one of {', '.join(AGENT_TYPES)}")
        return None
    if len(name) > MAX_TEXT:
        errs.append(f"{where}: an agent name is limited to {MAX_TEXT} characters")
        return None
    return {"type": t, "name": name.strip()}


def _check_value(field, v, where, errs):
    """Validate one declared value against its mapped field. Returns the value
    to use, or None when the value is empty or refused."""
    if _empty(v):
        return None
    t, many = field["type"], field["max"] == "*"
    if t == "Agent":
        if many:
            if not isinstance(v, list):
                errs.append(f"{where}: expected a list of agents")
                return None
            agents = [a for a in (_check_agent(x, where, errs) for x in v) if a]
            return agents or None
        return _check_agent(v, where, errs)
    if t == "DateTime":
        if not isinstance(v, str) or not DATE_RE.match(v):
            errs.append(f"{where}: a date must be written YYYY-MM-DDThh:mm:ssZ (UTC)")
            return None
        try:
            datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            errs.append(f"{where}: '{v}' is not a real date")
            return None
        return v
    if t == "anyURI":
        try:
            p = urllib.parse.urlparse(v) if isinstance(v, str) else None
        except ValueError:  # e.g. an unclosed IPv6 bracket
            p = None
        if not p or not p.scheme or not p.netloc or any(ch.isspace() for ch in v):
            errs.append(f"{where}: expected an absolute address such as https://...")
            return None
        if p.scheme.lower() not in URI_SCHEMES:
            errs.append(f"{where}: an address must use one of {', '.join(URI_SCHEMES)}")
            return None
        if len(v) > MAX_TEXT:
            errs.append(f"{where}: an address is limited to {MAX_TEXT} characters")
            return None
        return v
    if t == "DictionaryEntry":
        ok = isinstance(v, list) and all(
            isinstance(e, dict) and set(e) <= {"key", "value"} and isinstance(e.get("key"), str)
            and e["key"].strip() and len(e["key"]) <= 200
            and (e.get("value") is None or (isinstance(e.get("value"), (str, int, float))
                                            and not isinstance(e.get("value"), bool)
                                            and len(str(e.get("value"))) <= MAX_TEXT))
            for e in v)
        if not ok:
            errs.append(f"{where}: expected a list of {{\"key\": text, \"value\": text or number}}")
            return None
        keys = [e["key"].strip() for e in v]
        if len(keys) != len(set(keys)):
            errs.append(f"{where}: a key appears twice")
            return None
        return [{"key": e["key"].strip(), "value": "" if e.get("value") is None else str(e["value"])} for e in v]
    if "enum" in field:
        values = v if many else [v]
        if many and not isinstance(v, list):
            errs.append(f"{where}: expected a list")
            return None
        bad = [x for x in values if x not in field["enum"]]
        if bad:
            errs.append(f"{where}: {bad[0]!r} is not one of {', '.join(field['enum'])}")
            return None
        if many and "noAssertion" in values and len(values) > 1:
            errs.append(f"{where}: noAssertion cannot be combined with other values")
            return None
        if "noAssertion" in values and not field.get("noAssertion"):
            errs.append(f"{where}: this field has no 'unknown' value; leave it empty instead")
            return None
        return list(dict.fromkeys(values)) if many else v
    if t == "string":
        if many:
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                errs.append(f"{where}: expected a list of text")
                return None
            if any(len(x) > MAX_TEXT for x in v):
                errs.append(f"{where}: each entry is limited to {MAX_TEXT} characters")
                return None
            vals = [x.strip() for x in v if x.strip()]
            return vals or None
        if not isinstance(v, str):
            errs.append(f"{where}: expected text")
            return None
        if len(v) > MAX_TEXT:
            errs.append(f"{where}: limited to {MAX_TEXT} characters")
            return None
        return v.strip() or None
    errs.append(f"{where}: unsupported field type {t}")
    return None


def _user_fields(mapping, etype):
    return {fid: f for fid, f in mapping["_fields"][etype].items()
            if f["source"]["kind"] == "user" or f.get("declarable")}


def validate_declaration(raw, mapping, bom, root):
    """Check a declaration against the mapping and the document it applies to.
    Returns a normalized dict; raises Refused listing every problem."""
    errs = []
    if not isinstance(raw, dict):
        raise Refused(["the declaration must be a JSON object"])
    unknown = set(raw) - {"schema", "document", "model", "datasets", "relationships"}
    if unknown:
        errs.append(f"unknown key(s): {', '.join(sorted(unknown))}")
    if raw.get("schema") != DECLARATION_SCHEMA:
        errs.append(f"'schema' must be {DECLARATION_SCHEMA!r}")
    out = {"document": {}, "model": {}, "baseModels": {}, "datasets": {}, "locals": []}

    doc = raw.get("document") or {}
    if not isinstance(doc, dict) or set(doc) - {"createdBy"}:
        errs.append("document: only 'createdBy' is accepted")
    else:
        v = _check_value(mapping["_fields"]["document"]["createdBy"], doc.get("createdBy"),
                         "document.createdBy", errs)
        if v:
            out["document"]["createdBy"] = v

    model_root = root if root is not None and root.get("type") == "machine-learning-model" else None
    card_refs = set()
    if model_root is not None:
        card_refs = {x for d in (bom.get("dependencies") or []) if isinstance(d, dict)
                     and d.get("ref") == model_root.get("bom-ref") for x in (d.get("dependsOn") or [])}
    chain_ids = []
    if model_root is not None:
        props = _props(model_root)
        chain_ids = [item.rsplit(":", 1)[0] for item in
                     (_one(props, "bomlens:lineage:chain") or "").split(" > ") if item]
        chain_ids += [x.strip() for x in (_one(props, "bomlens:lineage:otherParents") or "").split(",")
                      if x.strip()]

    model = raw.get("model") or {}
    if model and model_root is None:
        errs.append("model: this document describes no model")
    elif not isinstance(model, dict):
        errs.append("model: expected an object")
    else:
        mfields = _user_fields(mapping, "ai_AIPackage")
        bad = set(model) - set(mfields) - set(MODEL_KEYS_EXTRA)
        if bad:
            errs.append(f"model: unknown key(s): {', '.join(sorted(bad))}")
        for k, v in model.items():
            if k in mfields:
                val = _check_value(mfields[k], v, f"model.{k}", errs)
                if val is not None:
                    out["model"][k] = val
        lic = model.get("license")
        if lic is not None and not (isinstance(lic, str) and not lic.strip()):
            if not isinstance(lic, str) or not (lic.strip().lower() in HUB_LICENSE_TAGS
                                                or SPDX_ID_RE.match(lic.strip())):
                errs.append("model.license: a hub licence tag or an SPDX licence id")
            else:
                out["modelLicense"] = lic.strip()
        bms = model.get("baseModels") or []
        if not isinstance(bms, list):
            errs.append("model.baseModels: expected a list")
            bms = []
        seen_bases = set()
        for i, bm in enumerate(bms):
            where = f"model.baseModels[{i}]"
            if not isinstance(bm, dict) or set(bm) - {"ref", "revision"}:
                errs.append(f"{where}: expected {{\"ref\": ..., \"revision\": ...}}")
                continue
            ref = bm.get("ref")
            if not isinstance(ref, str) or not HUB_ID_RE.match(ref):
                errs.append(f"{where}.ref: expected a HuggingFace model id (owner/name)")
                continue
            if ref not in chain_ids:
                errs.append(f"{where}.ref: {ref} is not a base model this scan found "
                            f"({', '.join(chain_ids) or 'none found'})")
                continue
            if ref in out["baseModels"] or ref in seen_bases:
                errs.append(f"{where}.ref: {ref} is listed twice")
                continue
            seen_bases.add(ref)
            rev = bm.get("revision")
            if _empty(rev):
                continue
            if not isinstance(rev, str) or not REVISION_RE.match(rev):
                errs.append(f"{where}.revision: expected a commit hash or tag")
                continue
            out["baseModels"][ref] = rev

    known_ds = {c.get("bom-ref"): c for c in data_components(bom, root) if c.get("bom-ref")}
    datasets = raw.get("datasets") or []
    if not isinstance(datasets, list):
        errs.append("datasets: expected a list")
        datasets = []
    dfields = _user_fields(mapping, "dataset_DatasetPackage")
    seen = set()
    for i, d in enumerate(datasets):
        where = f"datasets[{i}]"
        if not isinstance(d, dict):
            errs.append(f"{where}: expected an object")
            continue
        bad = set(d) - set(dfields) - set(DATASET_KEYS_EXTRA)
        if bad:
            errs.append(f"{where}: unknown key(s): {', '.join(sorted(bad))}")
        has_ref, has_local = not _empty(d.get("ref")), not _empty(d.get("local"))
        if has_ref == has_local:
            errs.append(f"{where}: give exactly one of 'ref' (a scanned dataset) or 'local' (one the hub does not hold)")
            continue
        entry = {}
        for k, v in d.items():
            if k in dfields:
                val = _check_value(dfields[k], v, f"{where}.{k}", errs)
                if val is not None:
                    entry[k] = val
        own = ("dataset:huggingface/" + d["ref"][len("huggingface:"):]
               if isinstance(d.get("ref"), str) and d["ref"].startswith("huggingface:") else None)
        srcs = _check_sources(d.get("sources"), f"{where}.sources", own, errs)
        if has_local and any("ref" in x for x in srcs):
            # Nothing reads the sources of data the hub does not hold, so a hub
            # id there would stay "to be read" for good.
            errs.append(f"{where}.sources: data the hub does not hold takes sources named in words only")
            srcs = []
        if srcs:
            entry["sources"] = srcs
        role = d.get("role")
        if not _empty(role):
            if role not in ROLES:
                errs.append(f"{where}.role: must be one of {', '.join(ROLES)}")
            elif model_root is None:
                errs.append(f"{where}.role: this document describes no model to relate the dataset to")
            else:
                entry["role"] = role
        if has_ref and not _empty(d.get("name")):
            errs.append(f"{where}.name: a scanned dataset keeps the name the hub gives it; "
                        "'name' is only for a dataset given with 'local'")
        if has_ref:
            ref = d["ref"]
            ds_id = ref[len("huggingface:"):] if isinstance(ref, str) and ref.startswith("huggingface:") else None
            if not ds_id or not HUB_ID_RE.match(ds_id):
                errs.append(f"{where}.ref: expected huggingface:<owner>/<name>")
                continue
            bref = "dataset:huggingface/" + ds_id
            if bref not in known_ds:
                errs.append(f"{where}.ref: {ds_id} is not a dataset in this scan")
                continue
            if entry.get("role") and bref not in card_refs:
                errs.append(f"{where}.role: {ds_id} is a source of another dataset, not one the model "
                            "card names; a role says how the model used a dataset")
                continue
            if bref in seen:
                errs.append(f"{where}.ref: {ds_id} is declared twice")
                continue
            seen.add(bref)
            out["datasets"][bref] = entry
        else:
            if model_root is None:
                errs.append(f"{where}.local: this document describes a dataset, not a model; "
                            "a dataset the hub does not hold can only be added to a model")
                continue
            slug = d["local"]
            if not isinstance(slug, str) or not LOCAL_RE.match(slug):
                errs.append(f"{where}.local: lowercase letters, digits, '.', '_' and '-', up to 64")
                continue
            if ("local:" + slug) in seen:
                errs.append(f"{where}.local: {slug} is declared twice")
                continue
            seen.add("local:" + slug)
            name = d.get("name")
            if not isinstance(name, str) or not name.strip():
                errs.append(f"{where}.name: a dataset the hub does not hold needs a name")
                continue
            if "downloadLocation" not in entry:
                errs.append(f"{where}.downloadLocation: a dataset the hub does not hold needs an address")
                continue
            if len(name) > MAX_TEXT:
                errs.append(f"{where}.name: limited to {MAX_TEXT} characters")
                continue
            entry["local"], entry["name"] = slug, name.strip()
            out["locals"].append(entry)

    rels = raw.get("relationships")
    if not _empty(rels):
        errs.append("relationships: not accepted yet; leave it empty")
    if errs:
        raise Refused(errs)
    return out


def read_declaration(path, mapping, bom, root):
    if not path:
        return None
    size = os.path.getsize(path)
    if size > MAX_DECLARATION_BYTES:
        raise Refused([f"the declaration is larger than {MAX_DECLARATION_BYTES} bytes"])
    try:
        # utf-8-sig: an editor on Windows may save the file with a byte-order mark.
        with open(path, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
    except UnicodeDecodeError:
        raise Refused(["the declaration is not UTF-8 text"])
    except RecursionError:
        raise Refused(["the declaration is nested too deeply"])
    except json.JSONDecodeError as e:
        raise Refused([f"the declaration is not valid JSON ({e.msg}, line {e.lineno})"])
    return validate_declaration(raw, mapping, bom, root)


# ---- building the SPDX graph -------------------------------------------------

def _utc(ts):
    if not ts:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Builder:
    def __init__(self, mapping, prefix):
        self.mapping = mapping
        self.base = mapping["idPrefix"].format(prefix=urllib.parse.quote(prefix, safe=""))
        self.graph = []
        self.ids = set()
        self.agents = {}
        self.licenses = {}
        self.seq = {"relationship": 0, "annotation": 0}
        self.check_elements = []
        self.check_relationships = []
        self.messages = []
        # The licence each source named in words was first declared with.
        self.declared_source_license = {}

    def ident(self, kind, key):
        return self.base + kind + "/" + urllib.parse.quote(str(key), safe="")

    def add(self, el):
        if el["spdxId"] in self.ids:
            return el["spdxId"]
        self.ids.add(el["spdxId"])
        self.graph.append(el)
        return el["spdxId"]

    def agent(self, a):
        key = (a.get("type", "Agent"), a["name"])
        if key not in self.agents:
            self.agents[key] = self.add({
                "type": key[0], "spdxId": self.ident("agent", f"{key[0]}:{key[1]}"),
                "creationInfo": CREATION_INFO, "name": key[1]})
        return self.agents[key]

    def spdx_id_for_name(self, name):
        """An SPDX id for a licence written as a hub tag, only when the tag names
        exactly one SPDX licence (the mapping's table); otherwise None."""
        table = (self.mapping["rules"].get("hubLicenseToSpdx") or {}).get("map") or {}
        return table.get(str(name or "").strip().lower())

    def declared_expr(self, lic):
        """The SPDX expression for a licence a person declared: a hub tag that
        names exactly one SPDX licence, or a LicenseRef-; otherwise None."""
        if not lic:
            return None
        return self.spdx_id_for_name(lic) or (lic if lic.startswith("LicenseRef-") else None)

    def license_el(self, expr):
        if expr is None:
            return "expandedlicensing_NoAssertionLicense"
        if expr not in self.licenses:
            self.licenses[expr] = self.add({
                "type": "simplelicensing_LicenseExpression", "spdxId": self.ident("license", expr),
                "creationInfo": CREATION_INFO, "simplelicensing_licenseExpression": expr})
        return self.licenses[expr]

    def relationship(self, frm, rtype, to, comment=None, scope=None, status="rule", note=None):
        self.seq["relationship"] += 1
        rel = {"type": "LifecycleScopedRelationship" if scope else "Relationship",
               "spdxId": self.ident("relationship", self.seq["relationship"]),
               "creationInfo": CREATION_INFO, "from": frm, "relationshipType": rtype,
               "to": to if isinstance(to, list) else [to]}
        if scope:
            rel["scope"] = scope
        if comment:
            rel["comment"] = comment
        self.add(rel)
        if status is not None:
            entry = {"type": rtype, "from": frm, "to": rel["to"], "status": status}
            if note:
                entry["note"] = note
            self.check_relationships.append(entry)
        return rel["spdxId"]

    def annotate(self, subject, statement, review=False):
        self.seq["annotation"] += 1
        self.add({"type": "Annotation", "spdxId": self.ident("annotation", self.seq["annotation"]),
                  "creationInfo": CREATION_INFO, "annotationType": "review" if review else "other",
                  "subject": subject, "statement": statement})

    def scanned_licenses(self, comp):
        """(SPDX expressions, licence names that are not SPDX ids) a component
        declares. A licence named but not given as an SPDX id is not guessed
        into one."""
        exprs, names = [], []
        for e in comp.get("licenses") or []:
            if not isinstance(e, dict):
                continue
            if e.get("expression"):
                exprs.append(str(e["expression"]))
                continue
            lic = e.get("license") if isinstance(e.get("license"), dict) else {}
            lid = lic.get("id")
            mapped = self.spdx_id_for_name(lic.get("name")) if not lid else None
            if lid and LICENSE_ID_RE.match(str(lid)):
                # CycloneDX restricts license.id to SPDX identifiers.
                exprs.append(str(lid))
            elif mapped:
                exprs.append(mapped)
            elif lid or lic.get("name"):
                names.append(str(lid or lic.get("name")))
        return list(dict.fromkeys(exprs)), names

    def declared_licenses(self, el_id, comp):
        """hasDeclaredLicense for an element, from what the component declares."""
        exprs, names = self.scanned_licenses(comp)
        targets = [self.license_el(x) for x in exprs]
        if names:
            self.annotate(el_id, "Declared licence named "
                          + ", ".join(repr(n) for n in names)
                          + "; not an SPDX identifier, recorded as NoAssertionLicense.")
            targets.append(self.license_el(None))
        if not targets:
            targets.append(self.license_el(None))
        targets = list(dict.fromkeys(targets))
        self.relationship(el_id, "hasDeclaredLicense", targets,
                          status="auto" if any(t != "expandedlicensing_NoAssertionLicense" for t in targets)
                          else "noAssertion")

    def fill(self, etype, el, label, comp, bom, declared, key=None):
        """Write every mapped field of one element and record where each came from.
        `key` is how a declaration names the element ("model", "huggingface:<id>",
        "local:<slug>"); None for one a declaration cannot address."""
        rows = []
        overrides = []
        for fid, f in self.mapping["_fields"][etype].items():
            src = f["source"]
            auto, status = None, None
            if src["kind"] == "const":
                auto = src["value"]
            elif src["kind"] == "cdx" and comp is not None:
                auto = extract(comp, src["from"], bom)
            elif src["kind"] == "rule" and comp is not None:
                auto = apply_rule(src["rule"], comp, self.mapping)
            value, origin = auto, ("auto" if auto is not None else None)
            dv = declared.get(fid) if declared else None
            if dv is not None and (src["kind"] == "user" or f.get("declarable")):
                if auto is not None and dv != auto:
                    overrides.append(fid)
                value, origin = dv, "declared"
            if value is None and src["kind"] == "rule" and src.get("fallback"):
                # The vocabulary's own "unknown": no signal said otherwise.
                value, origin = (src["fallback"] if f["max"] == 1 else [src["fallback"]]), "noAssertion"
            if value is None:
                if f["min"] >= 1:
                    status = "missingRequired"
                elif f.get("judgment"):
                    status = "judgment"
                elif src["kind"] == "user" or f.get("declarable"):
                    status = "optional"
                else:
                    status = "omitted"
            else:
                # A declared "unknown" is a declaration; only the rule's
                # fallback counts as unknown-by-default.
                status = origin
                self._write(el, f, value)
            row = {"id": fid, "status": status}
            if value is not None:
                row["display"] = _display(value)
            if origin == "auto" and src["kind"] == "cdx":
                row["source"] = "cdx:" + src["from"]
                if src.get("meaning"):
                    row["meaning"] = src["meaning"]
            elif origin == "auto" and src["kind"] == "rule":
                row["source"] = "rule:" + src["rule"]
            rows.append(row)
        if overrides:
            self.annotate(el["spdxId"], "Declared values replaced what the scan recorded for: "
                          + ", ".join(overrides) + ".")
        declared_ids = [r["id"] for r in rows if r["status"] == "declared"]
        if declared_ids:
            self.annotate(el["spdxId"], "Values from the publisher's declaration: "
                          + ", ".join(declared_ids) + ".")
        entry = {"spdxId": el["spdxId"], "type": etype, "label": label, "fields": rows}
        if key:
            entry["declarationKey"] = key
        self.check_elements.append(entry)

    def _write(self, el, f, value):
        key, t = f["json"], f["type"]
        if key.startswith("extension:"):
            el.setdefault("extension", []).append({
                "type": "extension_CdxPropertiesExtension",
                "extension_cdxProperty": [{"type": "extension_CdxPropertyEntry",
                                           "extension_cdxPropName": key[len("extension:"):],
                                           "extension_cdxPropValue": str(value)}]})
            return
        array = f["max"] == "*" or f.get("jsonArray")
        if t == "Agent":
            agents = value if isinstance(value, list) else [value]
            refs = [self.agent(a) for a in agents]
            el[key] = refs if array else refs[0]
        elif t == "DictionaryEntry":
            el[key] = [{"type": "DictionaryEntry", "key": e["key"], "value": e["value"]} for e in value]
        elif array and not isinstance(value, list):
            el[key] = [value]
        else:
            el[key] = value


def build(bom, mapping, prefix, declaration, stable):
    root = find_root(bom)
    if root is None:
        raise ValueError("the SBOM holds no machine-learning-model or dataset component")
    decl = declaration or {"document": {}, "model": {}, "baseModels": {}, "datasets": {}, "locals": []}
    b = Builder(mapping, prefix)
    doc_id = b.ident("document", prefix)

    # CreationInfo: the author is whoever ran the scan or the declaration names;
    # BomLens itself is a tool, never the author.
    created = "1970-01-01T00:00:00Z" if stable else (
        _utc((bom.get("metadata") or {}).get("timestamp"))
        or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ci = {"type": "CreationInfo", "@id": CREATION_INFO, "specVersion": mapping["spec"]["version"],
          "created": created}
    b.graph.append(ci)
    doc = {"type": "SpdxDocument", "spdxId": doc_id, "creationInfo": CREATION_INFO, "name": prefix}
    b.graph.append(doc)
    b.ids.add(doc_id)
    scanned_authors = extract(bom, "documentAuthors", bom)
    declared_authors = decl["document"].get("createdBy")
    # A model described from its declaration alone (no --sbom-author) carries
    # the declaration's authors in metadata.authors, marked as such. They are
    # the publisher's declaration, not a scan setting: the declared createdBy
    # (with its Organization/Person type) is used, and only without one do the
    # recorded names stand in for it.
    meta_props = _props((bom.get("metadata") or {}))
    if "declaration" in meta_props.get("bomlens:sbom-author-source", []):
        declared_authors = declared_authors or scanned_authors
        scanned_authors = None
    if scanned_authors and declared_authors:
        b.annotate(doc_id, "The scan named its author (--sbom-author); the declaration's createdBy was not used.")
    elif declared_authors:
        b.annotate(doc_id, "createdBy is from the publisher's declaration.")
    authors = scanned_authors or declared_authors
    if authors:
        ci["createdBy"] = [b.agent(a) for a in authors]
    row = {"id": "createdBy",
           "status": "auto" if scanned_authors else ("declared" if declared_authors else "missingRequired")}
    if authors:
        row["display"] = _display(authors)
    if scanned_authors:
        row["source"] = "cdx:documentAuthors"
    b.check_elements.append({"spdxId": doc_id, "type": "CreationInfo", "label": "document", "fields": [row],
                             "declarationKey": "document"})
    tools = []
    for t in ((bom.get("metadata") or {}).get("tools") or {}).get("components") or []:
        if isinstance(t, dict) and t.get("name"):
            label = str(t["name"]) + (" " + str(t["version"]) if t.get("version") else "")
            tools.append(b.add({"type": "Tool", "spdxId": b.ident("tool", label),
                                "creationInfo": CREATION_INFO, "name": label}))
    if tools:
        ci["createdUsing"] = tools

    data = data_components(bom, root)
    ds_ids = {}
    local_ids = []
    if root.get("type") == "machine-learning-model":
        root_id = _build_model(b, bom, root, decl)
    else:
        root_id = None
    for i, c in enumerate(data):
        ds_ids[_dkey(c, i)] = _build_dataset(b, bom, c, decl["datasets"].get(c.get("bom-ref")), _dkey(c, i))
    if root_id is None:
        root_id = ds_ids[_dkey(root, data.index(root))]
    _dataset_sources(b, data, ds_ids)

    if root.get("type") == "machine-learning-model":
        model_ref = root.get("bom-ref")
        card = [x for d in (bom.get("dependencies") or []) if isinstance(d, dict) and d.get("ref") == model_ref
                for x in (d.get("dependsOn") or [])]
        # A model described from its declaration alone has no card: the
        # datasets it uses are the ones the publisher named.
        from_declaration = _one(_props(root), "bomlens:origin") == "declared-input"
        for dref in [x for x in card if x in ds_ids]:
            role = (decl["datasets"].get(dref) or {}).get("role")
            if role:
                b.relationship(root_id, role, ds_ids[dref], status="declared")
            elif from_declaration:
                b.relationship(root_id, "other", ds_ids[dref],
                               comment="named in the publisher's declaration; role not stated", status="review",
                               note="declared dataset, role not stated")
            else:
                b.relationship(root_id, "other", ds_ids[dref],
                               comment="declared in the model card; role not stated", status="review",
                               note="card-declared dataset, role not stated")
        for local in decl["locals"]:
            lid = _build_local_dataset(b, local)
            local_ids.append((local, lid))
            if local.get("sources"):
                _declared_sources(b, lid, local["sources"], ds_ids)
            role = local.get("role")
            if role:
                b.relationship(root_id, role, lid, status="declared")
            else:
                b.relationship(root_id, "other", lid, comment="role not stated", status="review",
                               note="declared dataset, role not stated")

    for i, c in enumerate(data):
        declared = decl["datasets"].get(c.get("bom-ref")) or {}
        if declared.get("sources"):
            _declared_sources(b, ds_ids[_dkey(c, i)], declared["sources"], ds_ids)
    primary = ({root.get("bom-ref")} if root.get("type") != "machine-learning-model" else
               {x for d in (bom.get("dependencies") or []) if isinstance(d, dict)
                and d.get("ref") == root.get("bom-ref") for x in (d.get("dependsOn") or [])})
    _sources_not_stated(b, data, decl, ds_ids, primary, local_ids)

    b.relationship(doc_id, "describes", root_id, status=None)
    doc["rootElement"] = [root_id]
    doc["element"] = [el["spdxId"] for el in b.graph if el.get("spdxId") and el["spdxId"] != doc_id]
    doc["profileConformance"] = mapping["profiles"]
    doc["dataLicense"] = b.license_el("CC0-1.0")
    if doc["dataLicense"] not in doc["element"]:
        doc["element"].append(doc["dataLicense"])

    counts = {k: 0 for k in ("auto", "declared", "optional", "judgment", "missingRequired",
                             "noAssertion", "omitted", "review")}
    for el in b.check_elements:
        for f in el["fields"]:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
    counts["review"] = sum(1 for r in b.check_relationships if r["status"] == "review") + \
        sum(1 for m in b.messages if m.get("level") == "review")
    draft = counts["missingRequired"] > 0
    if draft:
        doc["comment"] = (f"DRAFT: {counts['missingRequired']} required field(s) are not filled; "
                          f"see {prefix}_spdx3-check.json. Generated by BomLens from {prefix}_bom.json.")
    else:
        doc["comment"] = f"Generated by BomLens from {prefix}_bom.json."
    check = {"schema": CHECK_SCHEMA, "spec": mapping["spec"]["version"], "draft": draft, "counts": counts,
             "elements": b.check_elements, "relationships": b.check_relationships,
             "messages": b.messages + [{"level": "info", "text": DISCLAIMER}]}
    document = {"@context": mapping["spec"]["context"], "@graph": b.graph}
    return document, check


def _build_model(b, bom, comp, decl):
    purl = comp.get("purl")
    el = {"type": "ai_AIPackage", "spdxId": b.ident("model", purl or comp.get("name") or "model"),
          "creationInfo": CREATION_INFO}
    b.add(el)
    b.fill("ai_AIPackage", el, comp.get("name") or "model", comp, bom, decl["model"], key="model")
    props = _props(comp)
    for rtype, refs in (("vcs", _refs(comp, "vcs")), ("documentation", _refs(comp, "documentation"))):
        for u in refs:
            el.setdefault("externalRef", []).append({"type": "ExternalRef", "externalRefType": rtype,
                                                     "locator": [u]})
    if any(r.get("source") == "cdx:supplier" for r in b.check_elements[-1]["fields"]
           if r["id"] == "suppliedBy"):
        b.annotate(el["spdxId"], "suppliedBy is the account that publishes the repository on HuggingFace.")
    _model_license(b, el["spdxId"], comp, decl.get("modelLicense"))

    # Weight files: name next to digest, kept by enrich-aibom.sh.
    files = []
    for v in props.get("bomlens:weights:file", []):
        sha, _, path = v.partition("  ")
        if re.fullmatch(r"[0-9a-f]{64}", sha) and path:
            files.append(b.add({"type": "software_File", "spdxId": b.ident("file", f"{path}@{sha[:12]}"),
                                "creationInfo": CREATION_INFO, "name": path,
                                "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": sha}]}))
    if files:
        b.relationship(el["spdxId"], "contains", files, status="auto")

    _base_models(b, el["spdxId"], props, decl)
    return el["spdxId"]


# A card licence that says nothing about the terms: a declared one may take its place.
UNSTATED_LICENSE_NAMES = {"other", "unknown", "none", "noassertion"}


def _model_license(b, el_id, comp, declared):
    """hasDeclaredLicense for the model.

    A scanned model: the licence the scan read stands, and a declared one that
    differs from it (compared without case) is listed for review. A declared
    licence fills the place only when the scan read none, or only "other".

    A model described from the declaration alone (bomlens:origin=declared-input):
    its SBOM carries the licence declare-ai-model.py wrote from the declaration,
    and that is the licence the risk assessment judged, so it is the one
    recorded, as declared. A declaration saved later with another licence is
    listed for review until the model is scanned again with it."""
    exprs, names = b.scanned_licenses(comp)
    seen = {x.lower() for x in exprs + names}
    if _one(_props(comp), "bomlens:origin") == "declared-input":
        targets = [b.license_el(x) for x in exprs]
        unmapped = []
        for n in names:
            expr = b.declared_expr(n)
            if expr:
                targets.append(b.license_el(expr))
            else:
                unmapped.append(n)
        if unmapped or not targets:
            targets.append(b.license_el(None))
        targets = list(dict.fromkeys(targets))
        real = any(t != "expandedlicensing_NoAssertionLicense" for t in targets)
        if exprs or names:
            b.relationship(el_id, "hasDeclaredLicense", targets, status="declared" if real else "noAssertion")
            note = "Licence from the publisher's declaration: " + ", ".join(exprs + names) + "."
            if unmapped:
                note += (" " + ", ".join(repr(n) for n in unmapped)
                         + " is not an SPDX identifier, recorded as NoAssertionLicense.")
            b.annotate(el_id, note)
        else:
            b.relationship(el_id, "hasDeclaredLicense", targets, status="noAssertion")
        if declared and declared.lower() not in seen:
            b.messages.append({"level": "review", "element": el_id,
                               "text": f"declared model licence {declared!r} is not the one this SBOM was built "
                                       f"with ({', '.join(exprs + names) or 'none'}); scan again to apply it"})
        return
    if not declared:
        b.declared_licenses(el_id, comp)
        return
    expr = b.declared_expr(declared)
    stated = exprs or [n for n in names if n.strip().lower() not in UNSTATED_LICENSE_NAMES]
    if stated:
        b.declared_licenses(el_id, comp)
        if declared.lower() not in seen and (expr is None or expr not in exprs):
            b.annotate(el_id, f"The publisher's declaration gives the licence {declared!r}; the licence the "
                       "scan read is kept.", review=True)
            b.messages.append({"level": "review", "element": el_id,
                               "text": f"declared model licence {declared!r} differs from the one the scan read "
                                       f"({', '.join(stated)})"})
        return
    b.relationship(el_id, "hasDeclaredLicense", b.license_el(expr), status="declared" if expr else "noAssertion")
    if expr:
        note = f"Licence from the publisher's declaration: {declared}."
    else:
        note = (f"Licence declared by the publisher as {declared!r}; not an SPDX identifier, recorded as "
                "NoAssertionLicense.")
    if names:
        note += " The scan read the licence named " + ", ".join(repr(n) for n in names) + "."
    b.annotate(el_id, note)


def _base_models(b, model_id, props, decl):
    """Base models are identified, not described: a software_Package with the
    id, a purl, the licence the ancestor's own card declares, and a revision
    only when the publisher declared one. Nothing flows in from the model."""
    chain = [item for item in (_one(props, "bomlens:lineage:chain") or "").split(" > ") if item]
    others = [x.strip() for x in (_one(props, "bomlens:lineage:otherParents") or "").split(",") if x.strip()]
    relation = _one(props, "bomlens:lineage:relation")
    revisions = decl["baseModels"]
    ids = []

    rule = b.mapping["rules"]["baseModel"]

    def base_el(anc, lic):
        rev = revisions.get(anc)
        purl_t = rule["packageUrlAtRevision"] if rev else rule["packageUrl"]
        loc_t = rule["downloadLocationAtRevision"] if rev else rule["downloadLocation"]
        el = {"type": "software_Package", "spdxId": b.ident("base", anc), "creationInfo": CREATION_INFO,
              "name": anc,
              "software_packageUrl": purl_t.format(id=anc, revision=rev),
              "software_downloadLocation": loc_t.format(id=anc, revision=rev),
              "software_primaryPurpose": "model"}
        if rev:
            el["software_packageVersion"] = rev
        bid = b.add(el)
        notes = ["Identified from the base-model chain the hub records; written as software_Package "
                 "because only its identity is known."]
        notes.append(f"Revision {rev} is from the publisher's declaration." if rev
                     else "The revision this model was built from is not declared.")
        if lic == "unreadable":
            notes.append("The base model's card could not be read.")
        b.annotate(bid, " ".join(notes))
        expr = b.spdx_id_for_name(lic) if lic and lic not in ("none", "unreadable") else None
        if lic and lic not in ("none", "unreadable") and expr is None:
            b.annotate(bid, f"Declared licence named {lic!r}; not an SPDX identifier, recorded as NoAssertionLicense.")
        b.relationship(bid, "hasDeclaredLicense", b.license_el(expr),
                       status="auto" if expr else "noAssertion")
        return bid

    for item in chain:
        anc, _, lic = item.rpartition(":")
        if not anc:
            anc, lic = item, None
        ids.append(base_el(anc, lic))
    prev = model_id
    for i, bid in enumerate(ids):
        comment = (f"hub relation: {relation}" if relation else None) if i == 0 else None
        b.relationship(prev, "descendantOf", bid, comment=comment, status="auto")
        prev = bid
    for other in others:
        if b.ident("base", other) in b.ids:
            continue
        oid = base_el(other, None)
        b.relationship(model_id, "descendantOf", oid, comment="another parent of a merged model", status="auto")
        ids.append(oid)

    scope = decl["model"].get("weightsScope") or _one(props, "bomlens:weights:scope")
    if scope == "adapter":
        if ids:
            b.relationship(model_id, "dependsOn", ids[0], scope="runtime",
                           comment="an adapter: running it needs the base model's weights", status="auto")
        else:
            b.messages.append({"level": "review", "element": model_id,
                               "text": "The weights are an adapter but no base model is recorded."})
    signals = _one(props, "bomlens:weights:scopeSignals")
    if signals and "weightsScope" not in decl["model"]:
        b.messages.append({"level": "review", "element": model_id,
                           "text": f"The hub's signals disagree on the distributed weights ({signals})."})


def _display(v):
    """A short text form of a written value, for the check and the screens."""
    if isinstance(v, dict):
        if "key" in v:
            return f"{v['key']}={v.get('value', '')}"
        return str(v.get("name", ""))
    if isinstance(v, list):
        return ", ".join(_display(x) for x in v)[:DISPLAY_MAX]
    return str(v)[:DISPLAY_MAX]


def _dkey(comp, index):
    """The key a dataset is known by: its bom-ref, or for one without, its name
    and position, so two unreferenced datasets with one name stay two."""
    return comp.get("bom-ref") or f"{comp.get('name') or 'dataset'}#{index}"


def _build_dataset(b, bom, comp, declared, key):
    el = {"type": "dataset_DatasetPackage",
          "spdxId": b.ident("dataset", key), "creationInfo": CREATION_INFO}
    b.add(el)
    bref = comp.get("bom-ref") or ""
    dkey = ("huggingface:" + bref[len("dataset:huggingface/"):]) if bref.startswith("dataset:huggingface/") else None
    b.fill("dataset_DatasetPackage", el, comp.get("name") or "dataset", comp, bom, declared or {}, key=dkey)
    props = _props(comp)
    if any(r.get("source") == "cdx:supplier" for r in b.check_elements[-1]["fields"] if r["id"] == "suppliedBy"):
        b.annotate(el["spdxId"], "suppliedBy is the account that publishes the repository on HuggingFace.")
    if props.get("bomlens:dataset:unresolved"):
        b.annotate(el["spdxId"], "The repository could not be read ("
                   + props["bomlens:dataset:unresolved"][0] + "); only its name and address are known.")
    if any(v.strip().lower() == "original" for v in props.get("bomlens:dataset:sourceDataset", [])):
        el["comment"] = "card declares this dataset original"
    for text in props.get("bomlens:dataset:sourceDataset:unverified", []):
        b.annotate(el["spdxId"], f"The card names a source in words, not as a dataset id: {text!r}. "
                   "It was not looked up and needs checking.", review=True)
        b.messages.append({"level": "review", "element": el["spdxId"], "text": f"unverified source {text!r}"})
    b.declared_licenses(el["spdxId"], comp)
    return el["spdxId"]


def _dataset_sources(b, data, ds_ids):
    """descendantOf from a dataset to each source the scan traced and linked."""
    for i, c in enumerate(data):
        props = _props(c)
        frm = ds_ids.get(_dkey(c, i))
        declared = set(props.get("bomlens:dataset:derivedFrom:declared", []))
        for v in props.get("bomlens:dataset:derivedFrom", []):
            relation, _, ref = v.partition(" ")
            if ref not in ds_ids:
                continue
            if v in declared:
                # Read from the hub, but named by the publisher, not the card.
                b.relationship(frm, "descendantOf", ds_ids[ref], comment=f"declared by the publisher: {relation}",
                               status="declared")
            else:
                b.relationship(frm, "descendantOf", ds_ids[ref], comment=f"source_datasets: {relation}",
                               status="auto")


def _declared_sources(b, frm, sources, ds_ids):
    """The sources a publisher declared for one dataset. A hub dataset the scan
    has read is linked by _dataset_sources (apply-declared-sources.py put it in
    the SBOM); one it has not read yet (declared after the scan) and one named
    only in words get an element of their own, marked as declared and not read
    by the tool."""
    linked = {(r["from"], t) for r in b.check_relationships if r["type"] == "descendantOf" for t in r["to"]}
    for src in sources:
        comment = f"declared by the publisher: {src['relation']}"
        if "ref" in src:
            ref = "dataset:huggingface/" + src["ref"]
            if ref in ds_ids:
                to = ds_ids[ref]
                if (frm, to) not in linked:
                    b.relationship(frm, "descendantOf", to, comment=comment, status="declared")
                continue
            el = {"type": "dataset_DatasetPackage", "spdxId": b.ident("dataset/declared", src["ref"]),
                  "creationInfo": CREATION_INFO}
            if el["spdxId"] not in b.ids:
                b.add(el)
                b.fill("dataset_DatasetPackage", el, src["ref"], None, {}, {})
                el["name"] = src["ref"]
                url = "https://huggingface.co/datasets/" + src["ref"]
                el["software_downloadLocation"] = url
                for row in b.check_elements[-1]["fields"]:
                    if row["id"] == "name":
                        row["status"], row["display"] = "declared", src["ref"]
                    elif row["id"] == "downloadLocation":
                        row["status"], row["display"] = "declared", url
                b.relationship(el["spdxId"], "hasDeclaredLicense", b.license_el(None), status="noAssertion")
                b.annotate(el["spdxId"], "A source the publisher named by its hub id; the next scan reads it "
                           "from the hub.", review=True)
                b.messages.append({"level": "review", "element": el["spdxId"],
                                   "text": f"declared source {src['ref']} is read at the next scan"})
            if (frm, el["spdxId"]) not in linked:
                b.relationship(frm, "descendantOf", el["spdxId"], comment=comment, status="declared")
        else:
            el = {"type": "dataset_DatasetPackage",
                  "spdxId": b.ident("dataset/source", src["name"].lower()), "creationInfo": CREATION_INFO}
            lic = src.get("license")
            if el["spdxId"] not in b.ids:
                b.add(el)
                b.fill("dataset_DatasetPackage", el, src["name"], None, {}, {})
                el["name"] = src["name"]
                for row in b.check_elements[-1]["fields"]:
                    if row["id"] == "name":
                        row["status"], row["display"] = "declared", src["name"]
                # Only a licence that is an SPDX id is written as one (a hub tag
                # that names exactly one, or a LicenseRef-); anything else is
                # kept in words and the expression is NoAssertion, as for a card.
                expr = (b.spdx_id_for_name(lic) or (lic if lic.startswith("LicenseRef-") else None)) if lic else None
                b.relationship(el["spdxId"], "hasDeclaredLicense", b.license_el(expr),
                               status="declared" if expr else "noAssertion")
                note = "A source the publisher named in words"
                if lic and expr:
                    note += f", with the licence {lic} as they declared it"
                elif lic:
                    note += (f", with a licence declared as {lic!r}; not an SPDX identifier, recorded as "
                             "NoAssertionLicense")
                b.annotate(el["spdxId"], note + "; not verified by the tool.", review=True)
                b.messages.append({"level": "review", "element": el["spdxId"],
                                   "text": f"source {src['name']!r} declared by the publisher, not verified"})
                b.declared_source_license[el["spdxId"]] = lic
            elif lic and b.declared_source_license.get(el["spdxId"]) != lic:
                b.annotate(el["spdxId"], f"Another dataset declares the licence {lic!r} for this source; "
                           "the first one declared is recorded.", review=True)
            if (frm, el["spdxId"]) not in linked:
                b.relationship(frm, "descendantOf", el["spdxId"], comment=comment, status="declared")


def _sources_not_stated(b, data, decl, ds_ids, primary, local_ids):
    """A dataset the model was built from (or the dataset a scan describes)
    with no source on record anywhere: not in its card, not traced, not marked
    original, not declared. Listed for review, since a mixture's terms can come
    from where it was built from. Sources found only by tracing are not listed:
    the publisher has nothing to decide about them."""
    for i, c in enumerate(data):
        if c.get("bom-ref") not in primary:
            continue
        props = _props(c)
        if any(props.get(n) for n in ("bomlens:dataset:sourceDataset", "bomlens:dataset:derivedFrom",
                                       "bomlens:dataset:sourceDataset:unverified", "bomlens:dataset:unresolved")):
            continue
        if (decl["datasets"].get(c.get("bom-ref")) or {}).get("sources"):
            continue
        b.messages.append({"level": "review", "element": ds_ids[_dkey(c, i)],
                           "text": f"no sources stated for {c.get('name') or 'a dataset'}"})
    for local, lid in local_ids:
        if not local.get("sources"):
            b.messages.append({"level": "review", "element": lid,
                               "text": f"no sources stated for {local['name']}"})


def _build_local_dataset(b, local):
    el = {"type": "dataset_DatasetPackage", "spdxId": b.ident("dataset/local", local["local"]),
          "creationInfo": CREATION_INFO}
    b.add(el)
    b.fill("dataset_DatasetPackage", el, local["name"], None, {}, local, key="local:" + local["local"])
    el["name"] = local["name"]
    for row in b.check_elements[-1]["fields"]:
        if row["id"] == "name":
            row["status"], row["display"] = "declared", local["name"]
    b.relationship(el["spdxId"], "hasDeclaredLicense", b.license_el(None), status="noAssertion")
    b.annotate(el["spdxId"], "A dataset the publisher declared; the hub does not hold it, so nothing "
               "about it was read by the tool.")
    return el["spdxId"]


# ---- the person-readable check ------------------------------------------------

STATUS_WORDS = {"auto": "filled from the scan", "declared": "declared by the publisher",
                "noAssertion": "unknown (no signal to fill it)",
                "missingRequired": "REQUIRED, not filled", "judgment": "needs a decision by the publisher",
                "optional": "optional, not filled", "omitted": "not recorded"}


def check_markdown(check, prefix):
    c = check["counts"]
    lines = [f"# SPDX 3.0.1 AI document check: {prefix}", ""]
    if check["draft"]:
        lines.append(f"**Draft.** {c['missingRequired']} required field(s) are not filled, so the document "
                     "does not yet meet the SPDX 3.0.1 AI and Dataset profiles. Fill them in the declaration "
                     "file and convert again.")
    else:
        lines.append("All required fields are filled.")
    lines += ["", "| Filled from the scan | Declared | Unknown (no signal) | Needs a decision | Required, not filled | Optional, not filled |",
              "|---|---|---|---|---|---|",
              f"| {c['auto']} | {c['declared']} | {c['noAssertion']} | {c['judgment']} | {c['missingRequired']} | {c['optional']} |",
              ""]
    for el in check["elements"]:
        missing = [f["id"] for f in el["fields"] if f["status"] == "missingRequired"]
        judge = [f["id"] for f in el["fields"] if f["status"] == "judgment"]
        if not missing and not judge:
            continue
        lines.append(f"## {el['label']} ({el['type']})")
        if missing:
            lines.append("- Required, not filled: " + ", ".join(f"`{m}`" for m in missing))
        if judge:
            lines.append("- Needs a decision by the publisher: " + ", ".join(f"`{j}`" for j in judge))
        lines.append("")
    reviews = [r for r in check["relationships"] if r["status"] == "review"]
    msgs = [m for m in check["messages"] if m.get("level") == "review"]
    if reviews or msgs:
        lines.append("## To review")
        for r in reviews:
            lines.append(f"- {r.get('note', r['type'])}")
        for m in msgs:
            lines.append(f"- {m['text']}")
        lines.append("")
    lines.append(DISCLAIMER)
    return "\n".join(lines) + "\n"


# ---- the empty declaration ---------------------------------------------------

def _blank(f):
    if f["type"] == "Agent":
        return [] if f["max"] == "*" else None
    return [] if f["max"] == "*" else ""


def template(bom, mapping, root):
    out = {"schema": DECLARATION_SCHEMA, "document": {"createdBy": []}}
    if root is not None and root.get("type") == "machine-learning-model":
        model = {}
        for fid, f in _user_fields(mapping, "ai_AIPackage").items():
            src = f["source"]
            if src["kind"] == "user" or extract(root, src["from"], bom) is None:
                model[fid] = _blank(f)
        props = _props(root)
        chain = [i.rpartition(":")[0] or i for i in (_one(props, "bomlens:lineage:chain") or "").split(" > ") if i]
        chain += [x.strip() for x in (_one(props, "bomlens:lineage:otherParents") or "").split(",") if x.strip()]
        model["baseModels"] = [{"ref": c, "revision": ""} for c in dict.fromkeys(chain)]
        exprs, names = Builder(mapping, "template").scanned_licenses(root)
        if _one(props, "bomlens:origin") != "declared-input" and not exprs \
                and all(n.strip().lower() in UNSTATED_LICENSE_NAMES for n in names):
            model["license"] = ""
        out["model"] = model
    # A role says how the model used a dataset, so only the datasets its card
    # names get one; a traced source of another dataset does not.
    card_refs = set()
    if root is not None and root.get("type") == "machine-learning-model":
        card_refs = {x for d in (bom.get("dependencies") or []) if isinstance(d, dict)
                     and d.get("ref") == root.get("bom-ref") for x in (d.get("dependsOn") or [])}
    datasets = []
    for c in data_components(bom, root):
        ref = c.get("bom-ref") or ""
        if not ref.startswith("dataset:huggingface/"):
            continue
        entry = {"ref": "huggingface:" + ref[len("dataset:huggingface/"):]}
        if ref in card_refs:
            entry["role"] = ""
        entry["sources"] = []
        for fid, f in _user_fields(mapping, "dataset_DatasetPackage").items():
            src = f["source"]
            auto = (extract(c, src["from"], bom) if src["kind"] == "cdx"
                    else apply_rule(src["rule"], c, mapping) if src["kind"] == "rule" else None)
            if src["kind"] == "user" or auto is None:
                entry[fid] = _blank(f)
        datasets.append(entry)
    out["datasets"] = datasets
    out["relationships"] = []
    return out


# ---- files ---------------------------------------------------------------------

def file_digest(path):
    """SHA-256 of a file's bytes, or None when it cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def tool_digest(map_path):
    """SHA-256 over this converter and its mapping: a new release that writes
    the document differently makes earlier documents out of date."""
    h = hashlib.sha256()
    for path in (os.path.abspath(__file__), map_path):
        h.update((file_digest(path) or "-").encode())
    return h.hexdigest()


def write_json(path, obj):
    tmp = f"{path}.{secrets.token_hex(6)}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)


def write_text(path, text):
    tmp = f"{path}.{secrets.token_hex(6)}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def main(argv):
    ap = argparse.ArgumentParser(prog="convert-to-spdx3-ai.py", description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=("convert", "check", "template"))
    ap.add_argument("--bom", required=True)
    ap.add_argument("--declaration")
    ap.add_argument("--map", default=os.environ.get("BOMLENS_SPDX3_MAP")
                    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "spdx3-ai-map.json"))
    ap.add_argument("--out-dir")
    ap.add_argument("--prefix")
    ap.add_argument("--stable", action="store_true")
    ap.add_argument("--declaration-fallback", action="store_true",
                    help="convert: when the declaration is refused, write the document without it "
                         "(the check records the refusal) and still exit 2")
    a = ap.parse_args(argv)

    if a.command in ("convert", "template"):
        if not a.out_dir or not a.prefix:
            print("[spdx3] --out-dir and --prefix are required for " + a.command, file=sys.stderr)
            return 1
        if not PREFIX_RE.match(a.prefix) or a.prefix in (".", ".."):
            print(f"[spdx3] --prefix {a.prefix!r} must be a plain file-name prefix", file=sys.stderr)
            return 1
        if not os.path.isdir(a.out_dir):
            print(f"[spdx3] output folder not found: {a.out_dir}", file=sys.stderr)
            return 1
    try:
        mapping = load_map(a.map)
        with open(a.bom, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError, KeyError) as e:
        print(f"[spdx3] cannot read input: {e}", file=sys.stderr)
        return 1
    root = find_root(bom)
    if root is None:
        print("[spdx3] the SBOM holds no machine-learning-model or dataset component; nothing to write.",
              file=sys.stderr)
        return EXIT_NO_AI

    if a.command == "template":
        write_json(os.path.join(a.out_dir, f"{a.prefix}_ai-declaration.template.json"),
                   template(bom, mapping, root))
        print(f"[spdx3] wrote {a.prefix}_ai-declaration.template.json", file=sys.stderr)
        return 0

    refused = None
    try:
        declaration = read_declaration(a.declaration, mapping, bom, root)
    except Refused as e:
        if a.command == "check":
            json.dump({"schema": CHECK_SCHEMA, "refused": e.messages}, sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write("\n")
        for m in e.messages:
            print(f"[spdx3] declaration refused: {m}", file=sys.stderr)
        if a.command != "convert" or not a.declaration_fallback:
            return EXIT_REFUSED
        declaration, refused = None, e.messages
    except OSError as e:
        print(f"[spdx3] cannot read the declaration: {e}", file=sys.stderr)
        if a.command != "convert" or not a.declaration_fallback:
            return 1
        declaration, refused = None, [f"the declaration could not be read: {e.strerror or e}"]

    prefix = a.prefix or str(root.get("name") or "ai").replace("/", "_")
    document, check = build(bom, mapping, prefix, declaration, a.stable)
    # What this check was made from, so a reader (the web UI) can tell whether
    # the files still match the SBOM, the declaration and this converter.
    check["inputs"] = {"bom": file_digest(a.bom),
                       "declaration": file_digest(a.declaration) if a.declaration else None,
                       "tool": tool_digest(a.map)}
    if refused is not None:
        check["declaration"] = {"state": "refused", "reasons": refused[:50]}
    else:
        check["declaration"] = {"state": "applied" if declaration is not None else "none"}
    if a.command == "check":
        json.dump(check, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    write_json(os.path.join(a.out_dir, f"{a.prefix}_bom.spdx3.json"), document)
    write_json(os.path.join(a.out_dir, f"{a.prefix}_spdx3-check.json"), check)
    write_text(os.path.join(a.out_dir, f"{a.prefix}_spdx3-check.md"), check_markdown(check, a.prefix))
    state = "draft, {} required field(s) open".format(check["counts"]["missingRequired"]) \
        if check["draft"] else "complete"
    print(f"[spdx3] wrote {a.prefix}_bom.spdx3.json ({state}).", file=sys.stderr)
    return EXIT_REFUSED if refused is not None else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
