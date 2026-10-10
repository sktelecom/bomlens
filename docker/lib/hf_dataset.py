#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read HuggingFace datasets and the datasets they were built from.

A dataset card can name the datasets it was derived from (`source_datasets`).
A mixture published under a permissive licence can contain a source whose terms
are narrower, and that only shows when the source is read too. This module reads
a dataset, describes it as a CycloneDX `data` component, and follows the sources
its card names, breadth first, within a depth and a lookup budget.

Standard library only, so the base image can run it. The REST endpoint is the
one `HfApi.dataset_info(files_metadata=True)` calls.

Nothing is inferred. A source is followed only when the card names something
shaped like a hub id. Any other wording is kept verbatim and marked for review.
A dataset that cannot be read becomes a component with its name and the reason,
never one with a guessed licence.

Environment
  BOMLENS_HF_API_BASE  hub base url. Defaults to HF_ENDPOINT (the mirror
                       setting huggingface_hub reads), then https://huggingface.co.
                       A file:// directory serves <dir>/datasets/<id>.json
                       instead, which is how the tests run offline; a missing
                       file reads as 401, like a missing repository on the hub.
  HF_TOKEN             sent as a Bearer token, only over https and only to the
                       host asked; never to a host a redirect points at. Never
                       printed.
  REQUESTS_CA_BUNDLE   a certificate bundle for a network that inspects TLS,
                       read as huggingface_hub reads it (SSL_CERT_FILE also works).
"""
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30
USER_AGENT = "BomLens (+https://github.com/sktelecom/bomlens)"
DEFAULT_BASE = "https://huggingface.co"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Marks every component this module writes, so a re-run drops its own output.
DATASET_MARK = "bomlens:dataset:collectedBy"
# A dataset repository can hold thousands of shards. The hash list is evidence
# that digests exist, not a manifest, so it is capped and the true count kept.
DATASET_HASH_CAP = 64

# The id shape the hub accepts: one or two segments. Anything else is not
# looked up, which also keeps a crafted value from walking out of a file:// base.
HUB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$")
RELATION_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# Words that fill a source_datasets slot without naming a dataset: the hub's
# own documented markers and the placeholders cards use. Looking them up would
# read whatever repository happens to carry that name.
NOT_AN_ID = {"original", "extended", "unknown", "n/a", "na", "none", "other", "crowdsourced",
             "found", "machine-generated", "expert-generated", "no", "yes", "-"}


def dataset_ref(ds_id):
    return "dataset:huggingface/" + ds_id


def _log(msg):
    print(f"[datasets] {msg}", file=sys.stderr)


def _valid_id(ds_id):
    return bool(HUB_ID_RE.match(ds_id or "")) and ".." not in ds_id


def fetch_dataset(ds_id):
    """Read one dataset's metadata.

    Returns (status, info). status is the HTTP status (200 on success), or None
    when nothing answered. info is the decoded JSON on 200 and None otherwise.
    """
    return _fetch("datasets", ds_id)


def fetch_model(model_id):
    """Read one model's metadata (the endpoint `HfApi.model_info` calls), with
    the same return shape, limits and credentials as fetch_dataset. A file://
    base serves <dir>/models/<id>.json."""
    return _fetch("models", model_id)


def _fetch(kind, ds_id):
    if not _valid_id(ds_id):
        return 400, None
    base = (os.environ.get("BOMLENS_HF_API_BASE") or os.environ.get("HF_ENDPOINT") or DEFAULT_BASE).rstrip("/")
    if base.startswith("file://"):
        root = os.path.realpath(urllib.parse.urlparse(base).path)
        path = os.path.realpath(os.path.join(root, kind, ds_id + ".json"))
        if not path.startswith(root + os.sep):
            return 400, None
        calls = os.path.join(root, "calls.log")
        try:
            with open(calls, "a") as fh:
                fh.write(ds_id + "\n")
        except OSError:
            pass
        if not os.path.isfile(path):
            return 401, None
        with open(path) as fh:
            doc = json.load(fh)
        status = doc.get("__status") if isinstance(doc, dict) else None
        if status:
            return int(status), None
        return (200, doc) if isinstance(doc, dict) else (None, None)
    url = f"{base}/api/{kind}/{urllib.parse.quote(ds_id, safe='/')}" + ("?blobs=true" if kind == "datasets" else "")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    token = os.environ.get("HF_TOKEN")
    if token and base.startswith("https://"):
        # Unredirected: urllib would otherwise carry it to whatever host a
        # redirect names. Never over plain http.
        request.add_unredirected_header("Authorization", "Bearer " + token)
    cafile = os.environ.get("REQUESTS_CA_BUNDLE") or None
    try:
        context = ssl.create_default_context(cafile=cafile) if cafile else None
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=context) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return None, None
            doc = json.loads(body.decode("utf-8"))
            # A proxy or a captive portal can answer 200 with something else.
            return (response.status, doc) if isinstance(doc, dict) else (None, None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, OSError, ValueError) as e:
        # The reason goes to the log only; the SBOM records the fact.
        _log(f"{ds_id}: no answer ({type(e).__name__})")
        return None, None


def classify_source(value):
    """What one `source_datasets` value names.

    Returns one of
      ("original", None, None)     the card says the data is original
      ("ref", relation, hub_id)    something shaped like a hub id, to look up
      ("text", None, value)        anything else, kept verbatim for review
    The hub documents only 'original' and 'extended'; cards also write
    "extended|<id>" and bare ids, so the shape decides, not the documentation.
    """
    v = str(value or "").strip()
    if not v:
        return ("text", None, v)
    if v.lower() == "original":
        return ("original", None, None)
    if v.lower() in NOT_AN_ID:
        return ("text", None, v)
    relation, rest = "listed", v
    if "|" in v:
        relation, rest = v.split("|", 1)
        relation, rest = relation.strip(), rest.strip()
        if not RELATION_RE.match(relation):
            return ("text", None, v)
    low = rest.lower()
    if HUB_ID_RE.match(rest) and ".." not in rest and low not in NOT_AN_ID and not low.startswith("other-"):
        return ("ref", relation.lower(), rest)
    return ("text", None, v)


def _card(info):
    cd = info.get("cardData") if isinstance(info, dict) else None
    return cd if isinstance(cd, dict) else {}


def build_component(ds_id, info, tag_signals=None, unresolved=None):
    """CycloneDX `data` component for one dataset.

    `info` is the REST answer, or None when the repository could not be read;
    `unresolved` then says why. The repository owner is recorded either way:
    a dataset that cannot be opened still says who published it.
    """
    url = "https://huggingface.co/datasets/" + ds_id
    props = [{"name": DATASET_MARK, "value": "huggingface"}]
    owner = ds_id.split("/")[0] if "/" in ds_id else None
    comp = {
        "type": "data",
        "bom-ref": dataset_ref(ds_id),
        "name": ds_id,
        "externalReferences": [
            {"type": "distribution", "url": url, "comment": "Dataset repository"}
        ],
        "properties": props,
    }
    if owner:
        comp["authors"] = [{"name": owner}]
        comp["supplier"] = {"name": owner, "url": ["https://huggingface.co/" + owner]}
    cdata = {"type": "dataset", "name": ds_id, "contents": {"url": url}}
    if owner:
        cdata["governance"] = {"owners": [{"organization": {"name": owner}}]}

    if info is None:
        props.append({"name": "bomlens:dataset:unresolved", "value": unresolved or "not-readable"})
        comp["data"] = [cdata]
        return comp

    card = _card(info)
    rev = info.get("sha") if isinstance(info.get("sha"), str) else None
    if rev:
        comp["version"] = str(rev)[:8]
        props.append({"name": "bomlens:dataset:revision", "value": str(rev)})

    lic = card.get("license")
    if isinstance(lic, list):
        lic = lic[0] if lic else None
    if lic:
        # Raw hub spelling; normalize-sbom.sh maps it to an SPDX id downstream.
        comp["licenses"] = [{"license": {"name": str(lic)}}]

    desc = info.get("description") or card.get("pretty_name")
    if desc:
        comp["description"] = str(desc)[:500]
        cdata["description"] = comp["description"]

    shas, total_files = [], 0
    for s in (info.get("siblings") if isinstance(info.get("siblings"), list) else []):
        if not isinstance(s, dict):
            continue
        total_files += 1
        sha = (s.get("lfs") or {}).get("sha256") if isinstance(s.get("lfs"), dict) else None
        if sha and sha not in shas:
            shas.append(sha)
    if shas:
        comp["hashes"] = [{"alg": "SHA-256", "content": h} for h in shas[:DATASET_HASH_CAP]]
        props.append({"name": "bomlens:dataset:hashedFiles",
                      "value": f"{min(len(shas), DATASET_HASH_CAP)} of {len(shas)}"})
    if total_files:
        props.append({"name": "bomlens:dataset:fileCount", "value": str(total_files)})

    facets = []
    for key in ("task_categories", "size_categories", "language", "annotations_creators",
                "multilinguality", "configs"):
        val = card.get(key)
        if not val:
            continue
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val if v is not None)
        facets.append({"name": "hf:" + key, "value": str(val)[:200]})
    all_tags = [str(t) for t in (info.get("tags") if isinstance(info.get("tags"), list) else [])
                if t is not None]
    card_tags = card.get("tags")
    if isinstance(card_tags, list):
        all_tags += [str(t) for t in card_tags if t is not None]
    all_tags = list(dict.fromkeys(all_tags))
    if all_tags:
        facets.append({"name": "hf:tags", "value": ", ".join(all_tags)[:300]})
    for tag in dict.fromkeys(t.lower() for t in all_tags):
        sig = (tag_signals or {}).get(tag)
        if sig:
            props.append({"name": "bomlens:dataset:signal", "value": sig})
    if facets:
        cdata["contents"]["properties"] = facets

    sources = card.get("source_datasets") or []
    if not isinstance(sources, list):
        sources = [sources]
    for src in sources:
        props.append({"name": "bomlens:dataset:sourceDataset", "value": str(src)[:200]})

    if not owner:
        api_owner = info.get("author")
        if api_owner:
            comp["authors"] = [{"name": str(api_owner)}]
            comp["supplier"] = {"name": str(api_owner),
                                "url": ["https://huggingface.co/" + str(api_owner)]}
            cdata["governance"] = {"owners": [{"organization": {"name": str(api_owner)}}]}

    if info.get("private"):
        props.append({"name": "bomlens:dataset:visibility", "value": "private"})
    elif info.get("gated"):
        props.append({"name": "bomlens:dataset:visibility", "value": "gated"})

    comp["data"] = [cdata]
    return comp


def _sources_of(info):
    s = _card(info).get("source_datasets") or []
    return s if isinstance(s, list) else [s]


def trace(roots, max_depth=3, budget=40, tag_signals=None):
    """Read the datasets a card names and, within limits, the datasets they
    were built from.

    roots      dataset ids the model card names (depth 0)
    max_depth  how many source levels to follow; 0 reads the roots only and
               writes exactly what the single-level collector always wrote:
               every root is tried, and no budget or merging applies
    budget     the most lookups one run makes, roots included

    Returns (components, root_refs, resolved_roots, edges). edges are
    (from_ref, to_ref) pairs from a dataset to a source it names.
    """
    tracing = max_depth > 0
    comps, by_ref = [], {}
    root_refs, edges = [], []
    seen_id = {}            # requested (and, when tracing, canonical) id -> ref
    lookups, rate_limited, resolved_roots = 0, False, 0
    queue = []

    def prop(comp, name, value):
        comp["properties"].append({"name": name, "value": value})

    def edge(frm, to):
        # A card that names itself among its sources is not a dependency.
        if frm != to and (frm, to) not in edges:
            edges.append((frm, to))

    for raw in roots if isinstance(roots, list) else [roots]:
        rid = str(raw or "").strip()
        if rid and rid not in seen_id and rid not in [q[0] for q in queue]:
            queue.append((rid, 0, None))

    while queue:
        ds_id, depth, parent = queue.pop(0)
        # A source named twice (by two datasets, or by an id the hub resolves to
        # one already read) is read once; the second mention only adds an edge.
        if ds_id in seen_id:
            if parent:
                edge(parent, seen_id[ds_id])
            continue

        info, unresolved = None, None
        if tracing and rate_limited:
            unresolved = "rate-limited"
        elif tracing and lookups >= budget:
            unresolved = "lookup-budget"
        else:
            lookups += 1
            status, info = fetch_dataset(ds_id)
            if status == 429:
                info, unresolved = None, "rate-limited"
                if tracing:
                    rate_limited = True
                    _log("the hub is rate limiting; remaining datasets are left unread.")
            elif status != 200 or info is None:
                info, unresolved = None, "not-readable"
                _log(f"{ds_id}: could not be read (status {status}).")

        canonical = info.get("id") if info else None
        canonical = canonical if isinstance(canonical, str) and canonical else None
        if tracing and canonical and canonical != ds_id and canonical in seen_id:
            seen_id[ds_id] = seen_id[canonical]
            if parent:
                edge(parent, seen_id[canonical])
            continue

        comp = build_component(ds_id, info, tag_signals, unresolved)
        ref = comp["bom-ref"]
        comps.append(comp)
        by_ref[ref] = comp
        seen_id[ds_id] = ref
        if tracing and canonical:
            seen_id[canonical] = ref
        if tracing:
            prop(comp, "bomlens:dataset:depth", str(depth))
            if canonical and canonical != ds_id:
                prop(comp, "bomlens:dataset:canonicalId", canonical[:200])
        if parent is None:
            root_refs.append(ref)
            resolved_roots += 1 if info is not None else 0
        else:
            edge(parent, ref)
        if info is None or not tracing:
            continue

        limited = False
        for value in _sources_of(info):
            kind, relation, target = classify_source(value)
            if kind == "original":
                continue
            if kind == "text":
                prop(comp, "bomlens:dataset:sourceDataset:unverified", str(target)[:200])
                continue
            if seen_id.get(target) == ref:
                continue
            if target in seen_id:
                prop(comp, "bomlens:dataset:derivedFrom", f"{relation} {seen_id[target]}")
                edge(ref, seen_id[target])
                continue
            if depth + 1 > max_depth:
                # Named, not read: the verbatim value stays in sourceDataset.
                limited = True
                continue
            prop(comp, "bomlens:dataset:derivedFrom", f"{relation} {dataset_ref(target)}")
            queue.append((target, depth + 1, ref))
        if limited:
            prop(comp, "bomlens:dataset:sourceTrace", "depth-limit")

    # derivedFrom names the ref a source would have had under its requested id;
    # a source the hub resolved to an already-read dataset keeps the real one.
    for comp in comps:
        for p in comp["properties"]:
            if p["name"] == "bomlens:dataset:derivedFrom":
                rel, tref = p["value"].split(" ", 1)
                tid = tref[len("dataset:huggingface/"):]
                if tid in seen_id and seen_id[tid] != tref:
                    p["value"] = f"{rel} {seen_id[tid]}"
    _mark_cycles(by_ref, edges)
    return comps, root_refs, resolved_roots, edges


def _mark_cycles(by_ref, edges):
    """Mark every dataset whose sources lead back to itself. Checked on the
    finished graph, so a cycle that closes through a branch read later is
    found too."""
    succ = {}
    for frm, to in edges:
        succ.setdefault(frm, []).append(to)
    for start in by_ref:
        stack, seen = list(succ.get(start, [])), set()
        while stack:
            n = stack.pop()
            if n == start:
                props = by_ref[start]["properties"]
                if not any(p["name"] == "bomlens:dataset:sourceTrace" and p["value"] == "cycle" for p in props):
                    props.append({"name": "bomlens:dataset:sourceTrace", "value": "cycle"})
                break
            if n in seen:
                continue
            seen.add(n)
            stack.extend(succ.get(n, []))


def dataset_exists(ds_id):
    """Whether the hub can open a dataset id (used to tell a real dataset name
    from a word lifted out of prose). Does not count against a trace budget."""
    status, _ = fetch_dataset(ds_id)
    return status == 200
