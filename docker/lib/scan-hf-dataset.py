#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Describe a HuggingFace dataset as a CycloneDX data SBOM.

Usage: scan-hf-dataset.py <reference> <output.json> [project_version]

The same reading a model scan does for each dataset its card names, applied to
one dataset given on its own: the hub's public metadata becomes the document's
root `data` component (licence, revision, file digests, card facets), and the
datasets its card names under `source_datasets` are read in turn, within the
same limits (AIBOM_DATASET_DEPTH, AIBOM_DATASET_MAX_LOOKUPS), as components of
their own linked from it in `dependencies`. All of it comes from hf_dataset.py,
so a dataset reads the same here as under a model.

`reference` is what a person pastes: hf:<owner>/<name>, a dataset address
(https://huggingface.co/datasets/<owner>/<name>, with or without the scheme,
and with any /tree/... after it), or datasets/<owner>/<name>.

A dataset that cannot be read is an error, not an empty SBOM (the contract of
scan-figshare.py): a dataset silently described with no licence would be worse
than no description at all.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hf_dataset  # noqa: E402

CDX_SPEC_VERSION = "1.7"
KNOWLEDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-risk-knowledge.json")
_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_REF_RE = re.compile(
    r"^(?:hf:|(?:https?://)?(?:www\.)?huggingface\.co/datasets/|datasets/)"
    rf"(?P<id>{_SEGMENT}(?:/{_SEGMENT})?)(?:/.*)?$")


def parse_reference(reference):
    """The dataset id a reference names, or None when it names none."""
    m = _REF_RE.match((reference or "").strip())
    if not m:
        return None
    ds_id = m.group("id")
    return ds_id if ".." not in ds_id else None


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
        print(f"[hf-dataset] {name}={raw!r} is not a whole number of zero or more; using {default}.",
              file=sys.stderr)
        return default


def _tag_signals():
    try:
        with open(KNOWLEDGE, encoding="utf-8") as fh:
            kb = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {str(e.get("tag", "")).lower(): str(e.get("signal", ""))
            for e in (kb.get("datasetTagSignals") or []) if e.get("tag") and e.get("signal")}


def _prop(comp, name):
    return next((p["value"] for p in comp.get("properties") or [] if p.get("name") == name), None)


def build(ds_id, project_version, depth, budget):
    """(sbom, None) for a dataset read from the hub, or (None, reason)."""
    comps, root_refs, resolved, edges = hf_dataset.trace([ds_id], max_depth=depth, budget=budget,
                                                         tag_signals=_tag_signals())
    if not root_refs:
        return None, "not a dataset id"
    root_ref = root_refs[0]
    root = next(c for c in comps if c["bom-ref"] == root_ref)
    if not resolved:
        return None, _prop(root, "bomlens:dataset:unresolved") or "not readable"
    if project_version:
        # The hub revision stays in bomlens:dataset:revision; the version is the
        # one the scan was asked to record, as for a Figshare item.
        root["version"] = project_version
    others = [c for c in comps if c["bom-ref"] != root_ref]
    deps = [{"ref": c["bom-ref"],
             "dependsOn": list(dict.fromkeys(t for f, t in edges if f == c["bom-ref"]))}
            for c in [root] + others]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": root,
        },
        "components": others,
        "dependencies": deps,
    }, None


def main():
    if len(sys.argv) < 3:
        print("usage: scan-hf-dataset.py <reference> <output.json> [project_version]", file=sys.stderr)
        return 2
    reference, output = sys.argv[1], sys.argv[2]
    project_version = sys.argv[3] if len(sys.argv) > 3 else ""
    ds_id = parse_reference(reference)
    if not ds_id:
        print(f"[hf-dataset] ERROR: {reference!r} is not a HuggingFace dataset reference "
              "(hf:<owner>/<name>, https://huggingface.co/datasets/<owner>/<name> or "
              "datasets/<owner>/<name>).", file=sys.stderr)
        return 1
    depth = _env_count("AIBOM_DATASET_DEPTH", 3)
    # The dataset asked for is always read; the budget limits its sources.
    budget = max(_env_count("AIBOM_DATASET_MAX_LOOKUPS", 40), 1)
    print(f"[hf-dataset] reading {ds_id} (sources up to {depth} level(s), at most {budget} lookups)")
    sbom, reason = build(ds_id, project_version, depth, budget)
    if sbom is None:
        # The hub answers a missing repository and one it will not show the
        # same way, so both are named.
        hint = {"not-readable": " Check the id; if the dataset is gated or private, set HF_TOKEN "
                                "to a token that can read it.",
                "rate-limited": " The hub is limiting requests; try again later or set HF_TOKEN."}.get(reason, "")
        print(f"[hf-dataset] ERROR: the dataset {ds_id} could not be read ({reason}).{hint}", file=sys.stderr)
        return 1
    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)
    except OSError as err:
        print(f"[hf-dataset] ERROR: could not write {output}: {err}", file=sys.stderr)
        return 1
    root = sbom["metadata"]["component"]
    lic = (root.get("licenses") or [{}])[0].get("license", {})
    shown = lic.get("id") or lic.get("name") or "none declared"
    print(f"[hf-dataset] {root['name']}: license {shown}, "
          f"{len(sbom['components'])} source dataset(s) traced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
