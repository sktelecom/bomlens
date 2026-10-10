#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Build an AI model SBOM from the publisher's declaration alone.

Usage: declare-ai-model.py <declaration.json> <output.json> <project_name> <project_version> [--offline]

For a model that has no hub repository and no file to read yet (one being
prepared for release), the declaration is the only input. This writes the
CycloneDX ML-BOM the rest of the pipeline works from:

    the model          -> metadata.component, named and versioned by the scan,
                          marked bomlens:origin=declared-input
    baseModels[].ref   -> the base-model lineage, read from the hub the same way
                          a model scan reads it (bomlens:lineage:chain from the
                          first, the others as bomlens:lineage:otherParents)
    datasets[].ref     -> data components read from the hub with the sources
                          their cards name (hf_dataset.trace, the same limits)
    model.license      -> the model's licence, as the name it was declared with,
                          so the risk assessment judges the model on it

What else the declaration says about the model itself (dates, makers,
revisions, the weights scope, judgments) is not written here: the CycloneDX
document holds what was observed, and the SPDX 3.0.1 document is where
declared values go, each marked as declared (convert-to-spdx3-ai.py reads the
same file). The licence is the exception: the whole SBOM is the publisher's
statement here (bomlens:origin=declared-input), and a model with no licence
could only be judged "review".

--offline reads nothing from the network: base models and datasets are written
by id only. The web UI uses it to check a declaration against the document it
will produce before a scan starts.

A declaration that is not a JSON object, names an id the hub could never hold,
or is larger than 1 MiB is refused (exit 2) before anything is written.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hf_dataset  # noqa: E402

CDX_SPEC_VERSION = "1.7"
MAX_DECLARATION_BYTES = 1024 * 1024
LINEAGE_DEPTH = 5
HERE = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE = os.environ.get("AI_RISK_KNOWLEDGE") or os.path.join(HERE, "ai-risk-knowledge.json")


class Refused(Exception):
    pass


def _load_kb():
    try:
        with open(KNOWLEDGE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


KB = _load_kb()
LICENSE_TERMS = KB.get("licenseTerms") or []
HUB_LICENSE_TAGS = {str(t).lower() for t in (KB.get("hfLicenseTags") or [])}
# A hub licence tag or an SPDX licence id, as convert-to-spdx3-ai.py takes it.
LICENSE_RE = re.compile(r"^(LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]{0,99})$")
TAG_SIGNALS = {str(e.get("tag", "")).lower(): str(e.get("signal", ""))
               for e in (KB.get("datasetTagSignals") or []) if e.get("tag") and e.get("signal")}


def _norm_lic(s):
    return re.sub(r"[ ._/-]+", " ", str(s or "").lower()).strip()


def _match_term(lic):
    """First registry entry matching a license string (the rule enrich-aibom.sh
    and assess-ai-risk.sh apply)."""
    n = _norm_lic(lic)
    if not n:
        return None
    for t in LICENSE_TERMS:
        if any(_norm_lic(i) == n for i in (t.get("ids") or [])):
            return t
    for t in LICENSE_TERMS:
        rx = t.get("match")
        if rx:
            try:
                if re.search(rx, n):
                    return t
            except re.error:
                pass
    return None


def _card_get(info, key):
    cd = info.get("cardData") if isinstance(info, dict) else None
    return cd.get(key) if isinstance(cd, dict) else None


def read_declaration(path):
    try:
        if os.path.getsize(path) > MAX_DECLARATION_BYTES:
            raise Refused(f"the declaration is larger than {MAX_DECLARATION_BYTES} bytes")
        with open(path, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("the declaration is not a JSON document")
    if not isinstance(raw, dict):
        raise Refused("the declaration must be a JSON object")
    return raw


def declared_ids(raw):
    """(base model ids, dataset ids) the declaration names, checked as hub ids."""
    model = raw.get("model") if isinstance(raw.get("model"), dict) else {}
    if not isinstance(model.get("baseModels") or [], list):
        raise Refused("model.baseModels: expected a list")
    if not isinstance(raw.get("datasets") or [], list):
        raise Refused("datasets: expected a list")
    bases = []
    for i, b in enumerate(model.get("baseModels") or []):
        ref = b.get("ref") if isinstance(b, dict) else None
        if not isinstance(ref, str) or not hf_dataset.HUB_ID_RE.match(ref) or ".." in ref:
            raise Refused(f"model.baseModels[{i}].ref: expected a HuggingFace model id (owner/name)")
        if ref not in bases:
            bases.append(ref)
    datasets = []
    for i, d in enumerate(raw.get("datasets") or []):
        ref = d.get("ref") if isinstance(d, dict) else None
        if ref is None:
            continue  # a dataset the hub does not hold: SPDX only
        ds_id = ref[len("huggingface:"):] if isinstance(ref, str) and ref.startswith("huggingface:") else None
        if not ds_id or not hf_dataset.HUB_ID_RE.match(ds_id) or ".." in ds_id:
            raise Refused(f"datasets[{i}].ref: expected huggingface:<owner>/<name>")
        if ds_id not in datasets:
            datasets.append(ds_id)
    return bases, datasets


def declared_license(raw):
    """The model's licence as declared, checked as convert-to-spdx3-ai.py checks it."""
    model = raw.get("model") if isinstance(raw.get("model"), dict) else {}
    lic = model.get("license")
    if lic is None or (isinstance(lic, str) and not lic.strip()):
        return None
    if not isinstance(lic, str) or not (lic.strip().lower() in HUB_LICENSE_TAGS or LICENSE_RE.match(lic.strip())):
        raise Refused("model.license: a hub licence tag or an SPDX licence id")
    return lic.strip()


def lineage(bases, offline, own_license=None):
    """The properties a model scan writes for its base models."""
    if not bases:
        return [], [], [], []
    chain, items, visited, walked = [], [], set(), []
    cur, depth = bases[0], 0
    while cur and cur not in visited and depth < LINEAGE_DEPTH:
        visited.add(cur)
        walked.append(cur)
        depth += 1
        if offline:
            chain.append(f"{cur}:unread")
            break
        status, info = hf_dataset.fetch_model(cur)
        if status != 200 or info is None:
            print(f"[declare] lineage: {cur} unreadable ({status})", file=sys.stderr)
            chain.append(f"{cur}:unreadable")
            break
        lic = _card_get(info, "license")
        if isinstance(lic, list):
            lic = lic[0] if lic else None
        chain.append(f"{cur}:{lic or 'none'}")
        items.append((cur, lic))
        nxt = _card_get(info, "base_model")
        if isinstance(nxt, list):
            nxt = nxt[0] if nxt else None
        cur = str(nxt) if nxt else None
    props = [{"name": "bomlens:lineage:chain", "value": " > ".join(chain)[:500]},
             {"name": "bomlens:lineage:rootLicense", "value": chain[-1].rsplit(":", 1)[-1]}]
    # An ancestor whose terms pass to derivatives is a condition this model
    # carries, unless the model is declared under those same terms (the rule
    # enrich-aibom.sh applies to a scanned model).
    own_term = _match_term(own_license)
    for anc, lic in items:
        term = _match_term(lic)
        if term and term.get("inheritable") and (own_term is None or own_term.get("key") != term.get("key")):
            props += [{"name": "bomlens:lineage:conflict", "value": "true"},
                      {"name": "bomlens:lineage:conflictWith", "value": f"{anc} ({lic})"}]
            break
    # Other parents of a merge: a declared id the walk already reached is an
    # ancestor of the first base, not another parent.
    others = [b for b in bases[1:] if b not in walked]
    if others:
        props.append({"name": "bomlens:lineage:otherParents", "value": ", ".join(others)[:500]})
    return props, items, walked, others


def pedigree(items, walked, others):
    """pedigree.ancestors[] as enrich-aibom.sh builds it from a model scan's
    chain: id, a purl without a version, the licence the ancestor's card
    declares, marked as coming from the chain."""
    lic_of = dict(items)
    ancestors = []
    for anc in walked + others:
        props = [{"name": "bomlens:lineage:source", "value": "chain"}]
        if anc in walked and anc not in lic_of:
            props.append({"name": "bomlens:lineage:unreadable", "value": "true"})
        comp = {"type": "machine-learning-model", "bom-ref": "lineage:huggingface/" + anc, "name": anc,
                "purl": "pkg:huggingface/" + anc, "properties": props}
        lic = lic_of.get(anc)
        if lic and lic != "none":
            comp["licenses"] = [{"license": {"name": str(lic)}}]
        ancestors.append(comp)
    return ancestors


def build(raw, project_name, project_version, offline):
    bases, ds_ids = declared_ids(raw)
    own_license = declared_license(raw)
    lineage_props, items, walked, others = lineage(bases, offline, own_license)
    model = {
        "type": "machine-learning-model",
        "bom-ref": f"model:declared/{project_name}@{project_version}",
        "name": project_name,
        "version": project_version,
        "properties": [{"name": "bomlens:origin", "value": "declared-input"}] + lineage_props,
    }
    if own_license:
        # Kept as the name it was declared with: a hub tag is not an SPDX id,
        # and the SPDX 3.0.1 converter maps one only where the tag names one.
        model["licenses"] = [{"license": {"name": own_license}}]
    if walked and not offline:
        model["pedigree"] = {"ancestors": pedigree(items, walked, others)}
    if offline:
        comps = [hf_dataset.build_component(d, None, unresolved="offline") for d in ds_ids]
        roots, edges = [c["bom-ref"] for c in comps], []
    else:
        depth = _env_count("AIBOM_DATASET_DEPTH", 3)
        budget = _env_count("AIBOM_DATASET_MAX_LOOKUPS", 40)
        comps, roots, _, edges = hf_dataset.trace(ds_ids, max_depth=depth, budget=budget,
                                                  tag_signals=TAG_SIGNALS) if ds_ids else ([], [], 0, [])
    # The hub can answer two declared ids with one dataset (a renamed
    # repository, a different spelling). Its component then carries one of the
    # ids only, and the declaration would name a dataset this document lacks.
    present = {c["bom-ref"] for c in comps}
    for ds_id in ds_ids:
        if hf_dataset.dataset_ref(ds_id) not in present:
            raise Refused(f"datasets: huggingface:{ds_id} is the same hub dataset as another declared one "
                          "(renamed or spelled differently); declare it once")
    # A declared dataset that is also a traced source of another declared one
    # is that dataset's source, not something the model was built from directly.
    below = set()
    frontier = [t for f, t in edges if f in roots]
    while frontier:
        n = frontier.pop()
        if n not in below:
            below.add(n)
            frontier += [t for f, t in edges if f == n]
    direct = [r for r in dict.fromkeys(roots) if r not in below] or list(dict.fromkeys(roots))
    deps = [{"ref": model["bom-ref"], "dependsOn": direct}]
    deps += [{"ref": c["bom-ref"], "dependsOn": list(dict.fromkeys(t for f, t in edges if f == c["bom-ref"]))}
             for c in comps]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": model,
        },
        "components": comps,
        "dependencies": deps,
    }


def _env_count(name, default):
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    try:
        val = int(raw)
        if val < 0:
            raise ValueError
        return val
    except ValueError:
        print(f"[declare] {name}={raw!r} is not a whole number of zero or more; using {default}.", file=sys.stderr)
        return default


def main(argv):
    # --offline only as the fifth argument, so a project named "--offline" is
    # still a project name.
    offline = len(argv) == 5 and argv[4] == "--offline"
    args = argv[:4] if offline else argv
    if len(args) != 4:
        print("usage: declare-ai-model.py <declaration.json> <output.json> <project_name> <project_version> "
              "[--offline]", file=sys.stderr)
        return 1
    decl_path, output, name, version = args
    if not name or not version:
        print("[declare] ERROR: a project name and version are required.", file=sys.stderr)
        return 1
    try:
        raw = read_declaration(decl_path)
        sbom = build(raw, name, version, offline)
    except Refused as e:
        print(f"[declare] declaration refused: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"[declare] ERROR: cannot read the declaration: {e.strerror or e}", file=sys.stderr)
        return 1
    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)
    except OSError as e:
        print(f"[declare] ERROR: could not write {output}: {e}", file=sys.stderr)
        return 1
    chain = next((p["value"] for p in sbom["metadata"]["component"]["properties"]
                  if p["name"] == "bomlens:lineage:chain"), "none declared")
    print(f"[declare] {name} {version}: base models {chain}; "
          f"{len(sbom['components'])} dataset component(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
