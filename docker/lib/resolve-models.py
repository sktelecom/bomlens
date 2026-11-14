#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Fill in what the hub says about the models a source scan found the code using.

Usage: resolve-models.py <sbom.json> [<model-sbom.json> ...]

A source scan records the models the code references (bomlens:ai:usage=model),
by name and purl only. For each Hugging Face model among them this reads the
hub's own record and writes a short summary onto the component:

    licenses                       the licence tag the model card declares
    bomlens:weights:*              weight file formats, how many are pickle
                                   (they run code on load) and each file's
                                   SHA-256 where the hub holds one (LFS)
    bomlens:hf:gated               auto or manual, when the repository is gated
    bomlens:hf:revision            the hub's current revision and its time; not
                                   necessarily what the code loads
    bomlens:lineage:chain          the base models the card names, one by one
    externalReferences[website]    the model's page on the hub

Each model is marked bomlens:ai:resolved: `huggingface` when the hub answered,
`unreadable` (with bomlens:ai:resolvedStatus) when it answered with an error for
this model, such as a private repository or one that does not exist (the hub
answers 401 for both), `unreachable` when it did not answer, answered 429 or a
5xx status, or took too long, and `not-attempted` for the models past the
limits. A gated repository is not an error: the hub describes it, and the state
is recorded as bomlens:hf:gated. Nothing is guessed: a model the hub could not
be asked about keeps only what the scan saw, and a licence is never filled from
a name.

The base-model chain is judged the way enrich-aibom.sh judges a scanned model's:
a base model whose licence passes its terms on to derivatives (the registry's
`inheritable` flag, ai-risk-knowledge.json), when the model declares other
terms, is recorded as bomlens:lineage:conflict. Weight file formats and digests
are recorded but not judged here: the risk assessment reads a file scan result
this step does not have.

The summary is not the model's own SBOM. A full model SBOM (model card, risk
assessment, G7 checks) comes from `--model <id>`, which needs the opt-in
bomlens-aibom image. Pass the CycloneDX file that scan wrote and the model here
is linked to it with a CycloneDX BOM-Link (externalReferences[bom],
urn:cdx:<serial number>/<version>#<bom-ref>). A file that matches no model, or
that carries no serial number to link to, is reported and ignored.

Environment
  BOMLENS_HF_API_BASE, HF_ENDPOINT, HF_TOKEN, REQUESTS_CA_BUNDLE
                         as for hf_dataset.py (a file:// base serves
                         <dir>/models/<owner>/<name>.json for tests)
  MODEL_RESOLVE_MAX      models looked up per scan (default 20); the rest
                         are marked not-attempted
  MODEL_RESOLVE_BUDGET   seconds the lookups may take in total (default 240),
                         base-model lookups included; the models not reached
                         are marked not-attempted
  AI_RISK_KNOWLEDGE      the licence registry (default ai-risk-knowledge.json
                         beside this file)

Exit status: 0 when every lookup got an answer from the hub, or there was
nothing to look up. 3 when the hub could not be reached or was overloaded for at
least one model (the step is then recorded as failed, with the SBOM still
written), 2 for input that is not a CycloneDX document. The SBOM is written in
every case but 2.

Standard library only, so the base image can run it.
"""
import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hf_dataset  # noqa: E402

WEIGHT_EXTS = (".safetensors", ".bin", ".gguf", ".pt", ".pth", ".onnx", ".h5", ".ckpt", ".msgpack")
PICKLE_EXTS = (".bin", ".pt", ".pth", ".ckpt")
WEIGHT_FILE_CAP = 64
LINEAGE_DEPTH = 5
UNREACHABLE_STOP = 2          # consecutive no-answer lookups before the rest are skipped
MAX_MODEL_SBOM_BYTES = 16 * 1024 * 1024
HUB = "https://huggingface.co/"
HERE = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE = os.environ.get("AI_RISK_KNOWLEDGE") or os.path.join(HERE, "ai-risk-knowledge.json")
# A hub answer that says "not now" rather than "not this model".
BUSY_STATUSES = (429,)
PURL_RE = re.compile(r"^pkg:huggingface/(?:([^/@?#]+)/)?([^/@?#]+)(?:@[^?#]*)?(?:[?#].*)?$", re.I)
SERIAL_RE = re.compile(r"^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)


def _load_terms():
    try:
        with open(KNOWLEDGE, encoding="utf-8") as fh:
            terms = json.load(fh).get("licenseTerms")
        return terms if isinstance(terms, list) else []
    except (OSError, ValueError, AttributeError):
        return []


LICENSE_TERMS = _load_terms()


def _norm_lic(v):
    return re.sub(r"[ ._/-]+", " ", str(v or "").lower()).strip()


def match_term(lic):
    """First registry entry matching a licence string, as enrich-aibom.sh and
    assess-ai-risk.sh match it."""
    n = _norm_lic(lic)
    if not n:
        return None
    for t in LICENSE_TERMS:
        if isinstance(t, dict) and any(_norm_lic(i) == n for i in (t.get("ids") or [])):
            return t
    for t in LICENSE_TERMS:
        rx = t.get("match") if isinstance(t, dict) else None
        if rx:
            try:
                if re.search(rx, n):
                    return t
            except re.error:
                pass
    return None


def silent(status):
    """No answer, or an answer that says the hub is busy or failing."""
    return status is None or status in BUSY_STATUSES or (isinstance(status, int) and status >= 500)


def log(msg):
    print(f"[resolve-models] {msg}", file=sys.stderr)


def props_of(c):
    return c.get("properties") if isinstance(c.get("properties"), list) else []


def prop(c, name):
    for p in props_of(c):
        if isinstance(p, dict) and p.get("name") == name:
            return p.get("value")
    return None


def set_prop(c, name, value):
    c["properties"] = [p for p in props_of(c) if not (isinstance(p, dict) and p.get("name") == name)]
    c["properties"].append({"name": name, "value": str(value)})


def hub_id(c):
    """The hub id (owner/name, or a single name such as gpt2) from a hub model's
    purl, or None."""
    purl = c.get("purl")
    m = PURL_RE.match(purl) if isinstance(purl, str) else None
    if not m:
        return None
    owner = urllib.parse.unquote(m.group(1)) if m.group(1) else None
    name = urllib.parse.unquote(m.group(2))
    ident = f"{owner}/{name}" if owner else name
    if (owner or "").lower() in ("datasets", "docs", "spaces") or not hf_dataset.HUB_ID_RE.match(ident) or ".." in ident:
        return None
    return ident


def card(info, key):
    cd = info.get("cardData") if isinstance(info, dict) else None
    v = cd.get(key) if isinstance(cd, dict) else None
    if isinstance(v, list):
        v = v[0] if v else None
    return v if isinstance(v, str) and v.strip() else None


def licence_of(info):
    lic = card(info, "license")
    if lic is None:
        for t in info.get("tags") or []:
            if isinstance(t, str) and t.startswith("license:"):
                lic = t[len("license:"):]
                break
    return lic.strip()[:100] if isinstance(lic, str) and lic.strip() else None


def weights_props(info):
    files = [s for s in (info.get("siblings") or []) if isinstance(s, dict) and isinstance(s.get("rfilename"), str)]
    names = [s["rfilename"] for s in files]
    weights = [n for n in names if n.lower().endswith(WEIGHT_EXTS)]
    out = []
    if weights:
        fmts = sorted({os.path.splitext(n.lower())[1].lstrip(".") for n in weights})
        out.append(("bomlens:weights:formats", ",".join(fmts)))
        out.append(("bomlens:weights:pickleFiles", sum(1 for n in weights if n.lower().endswith(PICKLE_EXTS))))
    hashed = []
    for s in files:
        lfs = s.get("lfs") if isinstance(s.get("lfs"), dict) else {}
        sha = lfs.get("sha256")
        if sha and s["rfilename"].lower().endswith(WEIGHT_EXTS) and re.fullmatch(r"[0-9a-f]{64}", str(sha)):
            hashed.append((s["rfilename"], sha))
    hashed.sort()
    for name, sha in hashed[:WEIGHT_FILE_CAP]:
        out.append(("bomlens:weights:file", f"{sha}  {name}"))
    if len(hashed) > WEIGHT_FILE_CAP:
        out.append(("bomlens:weights:filesRecorded", f"{WEIGHT_FILE_CAP} of {len(hashed)}"))
    return out


class Budget:
    """Seconds the lookups may take in total, base-model lookups included."""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def spent(self):
        return time.monotonic() > self.deadline


class Hub:
    """One lookup per id, with what went wrong remembered for the exit status."""

    def __init__(self, budget):
        self.cache = {}
        self.budget = budget
        self.silent_in_a_row = 0
        self.trouble = False

    def blocked(self):
        return self.silent_in_a_row >= UNREACHABLE_STOP or self.budget.spent()

    def fetch(self, ident, blobs=False):
        key = (ident, blobs)
        if key in self.cache:
            return self.cache[key]
        if self.blocked():
            return None, None
        status, info = hf_dataset.fetch_model(ident, blobs=blobs)
        self.cache[key] = (status, info)
        if silent(status):
            self.silent_in_a_row += 1
            self.trouble = True
        else:
            self.silent_in_a_row = 0
        return status, info


def lineage(ident, info, own_license, hub):
    """The base-model chain the card names, walked while the hub answers, and
    the first base model whose licence passes on to derivatives."""
    chain, visited, conflict = [], {ident}, None
    own_term = match_term(own_license)
    nxt = card(info, "base_model")
    while nxt and nxt not in visited and len(chain) < LINEAGE_DEPTH:
        visited.add(nxt)
        if not hf_dataset.HUB_ID_RE.match(nxt) or ".." in nxt:
            chain.append(f"{nxt[:80]}:unreadable")
            break
        status, base = hub.fetch(nxt)
        if status != 200 or base is None:
            chain.append(f"{nxt}:unreadable")
            break
        blic = licence_of(base)
        chain.append(f"{nxt}:{blic or 'none'}")
        bterm = match_term(blic)
        if conflict is None and bterm and bterm.get("inheritable") \
                and (own_term is None or own_term.get("key") != bterm.get("key")):
            conflict = f"{nxt} ({blic})"
        nxt = card(base, "base_model")
    return chain, conflict


RESOLVED_PROPS = ("bomlens:ai:resolved", "bomlens:ai:resolvedStatus", "bomlens:hf:gated", "bomlens:hf:revision",
                  "bomlens:hf:revisionTime", "bomlens:lineage:chain", "bomlens:lineage:rootLicense",
                  "bomlens:lineage:conflict", "bomlens:lineage:conflictWith")


def reset(c):
    """Take off what an earlier run wrote, so a different answer now does not sit
    beside the old one."""
    was_resolved = prop(c, "bomlens:ai:resolved") == "huggingface"
    c["properties"] = [p for p in props_of(c) if not (
        isinstance(p, dict) and isinstance(p.get("name"), str)
        and (p["name"] in RESOLVED_PROPS or p["name"].startswith("bomlens:weights:")))]
    if was_resolved:
        c.pop("licenses", None)
    refs = [r for r in (c.get("externalReferences") if isinstance(c.get("externalReferences"), list) else [])
            if not (isinstance(r, dict) and r.get("type") == "website"
                    and isinstance(r.get("url"), str) and r["url"].startswith(HUB))]
    if refs:
        c["externalReferences"] = refs
    else:
        c.pop("externalReferences", None)


def summarize(c, ident, info, hub):
    lic = licence_of(info)
    if lic and not c.get("licenses"):
        c["licenses"] = [{"license": {"name": lic}}]
    # One bomlens:weights:file per weight file: those repeat, the rest are single.
    for name, value in weights_props(info):
        c["properties"].append({"name": name, "value": str(value)})
    gated = info.get("gated")
    if gated in ("auto", "manual"):
        set_prop(c, "bomlens:hf:gated", gated)
    if isinstance(info.get("sha"), str) and re.fullmatch(r"[0-9a-f]{7,64}", info["sha"]):
        set_prop(c, "bomlens:hf:revision", info["sha"])
    if isinstance(info.get("lastModified"), str):
        set_prop(c, "bomlens:hf:revisionTime", info["lastModified"][:40])
    chain, conflict = lineage(ident, info, lic, hub)
    if chain:
        set_prop(c, "bomlens:lineage:chain", " > ".join(chain)[:500])
        set_prop(c, "bomlens:lineage:rootLicense", chain[-1].rsplit(":", 1)[-1])
    if conflict:
        set_prop(c, "bomlens:lineage:conflict", "true")
        set_prop(c, "bomlens:lineage:conflictWith", conflict[:200])
    refs = c.get("externalReferences") if isinstance(c.get("externalReferences"), list) else []
    refs.append({"type": "website", "url": HUB + urllib.parse.quote(ident, safe="/"),
                 "comment": "model page on the Hugging Face hub"})
    c["externalReferences"] = refs
    set_prop(c, "bomlens:ai:resolved", "huggingface")


def read_model_sbom(path, name=None):
    name = name or os.path.basename(path)
    try:
        if os.path.getsize(path) > MAX_MODEL_SBOM_BYTES:
            log(f"{name}: larger than {MAX_MODEL_SBOM_BYTES // (1024 * 1024)} MiB; not linked")
            return None
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, RecursionError):
        log(f"{name}: not a JSON document; not linked")
        return None
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        log(f"{name}: not a CycloneDX document; not linked")
        return None
    return doc


def model_refs(doc):
    """(hub id, bom-ref) for each model component a model SBOM describes."""
    found = []
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    listed = doc.get("components") if isinstance(doc.get("components"), list) else []
    for c in [meta.get("component")] + listed:
        if not isinstance(c, dict) or c.get("type") != "machine-learning-model":
            continue
        bom_ref = c.get("bom-ref")
        if not isinstance(bom_ref, str) or not bom_ref:
            continue
        ident = hub_id(c)
        if ident is None:
            name, group = c.get("name"), c.get("group")
            if isinstance(name, str) and "/" in name and hf_dataset.HUB_ID_RE.match(name):
                ident = name
            elif isinstance(name, str) and isinstance(group, str) and hf_dataset.HUB_ID_RE.match(f"{group}/{name}"):
                ident = f"{group}/{name}"
        if ident:
            found.append((ident.lower(), bom_ref))
    return found


def bom_link(doc, bom_ref):
    serial = doc.get("serialNumber")
    m = SERIAL_RE.match(serial) if isinstance(serial, str) else None
    if not m:
        return None
    v = doc.get("version")
    version = v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 1
    return f"urn:cdx:{m.group(1).lower()}/{version}#{urllib.parse.quote(bom_ref, safe='')}"


def link_one(models_by_id, doc, name):
    refs = model_refs(doc)
    if not refs:
        log(f"{name}: describes no Hugging Face model; not linked")
        return 0
    linked = 0
    for ident, bom_ref in refs:
        targets = models_by_id.get(ident)
        if not targets:
            log(f"{name}: describes {ident}, which the scanned code does not reference; not linked")
            continue
        link = bom_link(doc, bom_ref)
        if link is None:
            log(f"{name}: has no serial number (urn:uuid:...) to link to; not linked")
            continue
        for c in targets:
            c["externalReferences"] = [r for r in (c.get("externalReferences") or [])
                                       if not (isinstance(r, dict) and r.get("type") == "bom")]
            c["externalReferences"].append({"type": "bom", "url": link, "comment": f"the model's own SBOM ({name})"})
            set_prop(c, "bomlens:ai:modelSbom", name[:120])
            linked += 1
    return linked


def link_model_sboms(models, paths, labels=()):
    """Add a BOM-Link to each model a given model SBOM describes."""
    by_id = {}
    for c, ident in models:
        by_id.setdefault(ident.lower(), []).append(c)
    linked = 0
    for i, path in enumerate(paths):
        # The container holds each file under an index name; the label is the
        # name the user gave it.
        name = os.path.basename(labels[i].strip()) if i < len(labels) and labels[i].strip() else os.path.basename(path)
        doc = read_model_sbom(path, name)
        if doc is None:
            continue
        try:
            linked += link_one(by_id, doc, name)
        except Exception as e:  # a model SBOM of an unexpected shape costs its own link only
            log(f"{name}: could not be read for linking ({type(e).__name__}); not linked")
    return linked


def main(argv):
    if len(argv) < 2:
        print("usage: resolve-models.py <sbom.json> [<model-sbom.json> ...]", file=sys.stderr)
        return 2
    sbom_path, model_sboms = argv[1], argv[2:]
    labels = (os.environ.get("MODEL_SBOM_LABELS") or "").split("\n")
    try:
        with open(sbom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError):
        log(f"{sbom_path}: not a JSON document")
        return 2
    if not isinstance(bom, dict) or not isinstance(bom.get("components"), list):
        log("no components to look at")
        return 0
    try:
        limit = max(1, int(os.environ.get("MODEL_RESOLVE_MAX", "20")))
    except ValueError:
        limit = 20
    try:
        seconds = max(1, int(os.environ.get("MODEL_RESOLVE_BUDGET", "240")))
    except ValueError:
        seconds = 240

    models = []
    for c in bom["components"]:
        if (isinstance(c, dict) and c.get("type") == "machine-learning-model"
                and prop(c, "bomlens:ai:usage") == "model"):
            ident = hub_id(c)
            if ident:
                models.append((c, ident))
    if not models:
        log("no Hugging Face model referenced by the code; nothing to look up")
        if model_sboms:
            log("the model SBOM file(s) given have nothing to link to")
        return 0

    hub = Hub(Budget(seconds))
    answers, asked = {}, 0
    for c, ident in models:
        reset(c)
        if ident not in answers:
            if asked >= limit or hub.blocked():
                set_prop(c, "bomlens:ai:resolved", "not-attempted")
                if hub.blocked():
                    hub.trouble = True
                continue
            asked += 1
            answers[ident] = hub.fetch(ident, blobs=True)
        status, info = answers[ident]
        if status == 200 and info is not None:
            summarize(c, ident, info, hub)
        elif silent(status):
            set_prop(c, "bomlens:ai:resolved", "unreachable")
            if status is not None:
                set_prop(c, "bomlens:ai:resolvedStatus", status)
        else:
            set_prop(c, "bomlens:ai:resolved", "unreadable")
            set_prop(c, "bomlens:ai:resolvedStatus", status)

    linked = link_model_sboms(models, model_sboms, labels) if model_sboms else 0
    tmp = sbom_path + ".resolve-models.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, sbom_path)

    kinds = {}
    for c, _ in models:
        k = prop(c, "bomlens:ai:resolved") or "unknown"
        kinds[k] = kinds.get(k, 0) + 1
    log(f"{len(models)} model(s): " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        + (f"; {linked} linked to a model SBOM" if model_sboms else ""))
    if hub.trouble:
        log("the hub could not be reached, was busy or ran out of time for some lookups; "
            "check the network, proxy or HF_ENDPOINT, and raise MODEL_RESOLVE_BUDGET if needed")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
