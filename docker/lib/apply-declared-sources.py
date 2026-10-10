#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read the dataset sources a publisher declared by hub id, into the SBOM.

Usage: apply-declared-sources.py <bom.json> <declaration.json>

A card that lists no `source_datasets` leaves a dataset's sources unknown to
the scan; the publisher can name them in the declaration
(datasets[].sources[].ref = huggingface:<id>). Those ids are read from the hub
here, before the risk assessment, the same way a traced source is read
(hf_dataset.trace), and linked from the dataset in `dependencies`. So a
declared source is observed, not taken on word: its licence is what the hub
records, and it is judged with the dataset.

The dataset gets the same `bomlens:dataset:derivedFrom` a traced source gets,
plus `bomlens:dataset:derivedFrom:declared` with the same value, saying who
named it. A source read here sits one level below the dataset that names it,
and its own sources are followed only as far as AIBOM_DATASET_DEPTH reaches
from the top; the lookups count against what is left of
AIBOM_DATASET_MAX_LOOKUPS.

Only a declaration the SPDX converter accepts is applied, so the SBOM and the
SPDX 3.0.1 document never disagree about it. A declaration it refuses, or one
that cannot be read, leaves the SBOM as it is (the SPDX step reports why).
Exit 0 unless the SBOM itself cannot be written.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hf_dataset  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_DECLARATION_BYTES = 1024 * 1024
MARK = "bomlens:dataset:derivedFrom:declared"
DERIVED = "bomlens:dataset:derivedFrom"
DEPTH = "bomlens:dataset:depth"
CANONICAL = "bomlens:dataset:canonicalId"
RELATIONS = ("extended", "other")


def _env_count(name, default):
    try:
        val = int(os.environ.get(name, "") or default)
        return val if val >= 0 else default
    except ValueError:
        return default


def _depth(comp):
    for p in comp.get("properties") or []:
        if p.get("name") == DEPTH:
            try:
                return int(p.get("value"))
            except (TypeError, ValueError):
                return 0
    return 0


def accepted(bom_path, decl_path):
    """Whether the SPDX converter accepts this declaration for this SBOM."""
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "convert-to-spdx3-ai.py"), "check",
                            "--bom", bom_path, "--declaration", decl_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def declared(path):
    """{dataset bom-ref: [(relation, source id)]} from the declaration."""
    try:
        if os.path.getsize(path) > MAX_DECLARATION_BYTES:
            return {}
        with open(path, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return {}
    out = {}
    for d in (raw.get("datasets") if isinstance(raw, dict) and isinstance(raw.get("datasets"), list) else []):
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str) or not d["ref"].startswith("huggingface:"):
            continue
        for s in d.get("sources") if isinstance(d.get("sources"), list) else []:
            ref = s.get("ref") if isinstance(s, dict) else None
            if not isinstance(ref, str) or not ref.startswith("huggingface:"):
                continue
            sid = ref[len("huggingface:"):]
            rel = s.get("relation") if s.get("relation") in RELATIONS else "other"
            if hf_dataset.HUB_ID_RE.match(sid) and ".." not in sid:
                out.setdefault(hf_dataset.dataset_ref(d["ref"][len("huggingface:"):]), []).append((rel, sid))
    return out


def apply(bom, wanted):
    comps = bom.setdefault("components", [])
    root = (bom.get("metadata") or {}).get("component") or {}
    data = [c for c in comps if isinstance(c, dict) and c.get("type") == "data"]
    if root.get("type") == "data":
        data.append(root)
    by_ref = {c.get("bom-ref"): c for c in data if c.get("bom-ref")}

    # The hub treats ids without regard to case and answers a renamed
    # repository under its new id: a declared id that is already here under
    # another spelling is the same dataset, not a new one.
    alias = {}
    for ref, c in by_ref.items():
        alias[ref.lower()] = ref
        for p in c.get("properties") or []:
            if p.get("name") == CANONICAL and isinstance(p.get("value"), str):
                alias[hf_dataset.dataset_ref(p["value"]).lower()] = ref

    def present(sid):
        return alias.get(hf_dataset.dataset_ref(sid).lower())

    deps = bom.setdefault("dependencies", [])
    dep_of = {d.get("ref"): d for d in deps if isinstance(d, dict)}
    max_depth = _env_count("AIBOM_DATASET_DEPTH", 3)
    budget = _env_count("AIBOM_DATASET_MAX_LOOKUPS", 40)
    already_read = sum(1 for c in data if any(p.get("name") == hf_dataset.DATASET_MARK
                                              for p in c.get("properties") or []))
    left = max(budget - already_read, 0)

    def dep_entry(ref):
        entry = dep_of.get(ref)
        if entry is None:
            entry = dep_of[ref] = {"ref": ref, "dependsOn": []}
            deps.append(entry)
        entry.setdefault("dependsOn", [])
        return entry

    added = linked = 0
    # A source of a dataset that is not in this scan is not read: nothing
    # would link to it.
    for ds_ref in [r for r in wanted if r in by_ref]:
        level = _depth(by_ref[ds_ref]) + 1
        new_ids = list(dict.fromkeys(sid for _, sid in wanted[ds_ref] if not present(sid)))
        if new_ids:
            # The declared ids themselves are read even past the limits (the
            # publisher asked for them); their own sources only within them.
            comps_new, _, _, edges = hf_dataset.trace(new_ids, max_depth=max(max_depth - level, 0),
                                                      budget=max(left, len(new_ids)))
            left = max(left - len(comps_new), 0)
            for c in comps_new:
                if present(c["bom-ref"][len("dataset:huggingface/"):]):
                    continue
                props = c.setdefault("properties", [])
                d = _depth(c)
                props[:] = [p for p in props if p.get("name") != DEPTH]
                props.append({"name": DEPTH, "value": str(d + level)})
                comps.append(c)
                by_ref[c["bom-ref"]] = c
                alias[c["bom-ref"].lower()] = c["bom-ref"]
                added += 1
            for frm, to in edges:
                frm, to = alias.get(frm.lower(), frm), alias.get(to.lower(), to)
                if frm != to and to not in dep_entry(frm)["dependsOn"]:
                    dep_entry(frm)["dependsOn"].append(to)
        ds = by_ref[ds_ref]
        props = ds.setdefault("properties", [])
        for rel, sid in wanted[ds_ref]:
            to = present(sid)
            if not to or to == ds_ref:
                continue
            entry = dep_entry(ds_ref)
            if to not in entry["dependsOn"]:
                entry["dependsOn"].append(to)
            value = f"{rel} {to}"
            if not any(p.get("name") == DERIVED and str(p.get("value", "")).endswith(" " + to) for p in props):
                props.append({"name": DERIVED, "value": value})
            if not any(p.get("name") == MARK and str(p.get("value", "")).endswith(" " + to) for p in props):
                props.append({"name": MARK, "value": value})
                linked += 1

    # A declared source can close a loop with what the cards say; mark it the
    # way a trace marks one it found itself.
    edges = [(d.get("ref"), t) for d in deps if isinstance(d, dict) and d.get("ref") in by_ref
             for t in d.get("dependsOn") or [] if t in by_ref]
    hf_dataset._mark_cycles(by_ref, edges)
    return added, linked


def main(argv):
    if len(argv) != 2:
        print("usage: apply-declared-sources.py <bom.json> <declaration.json>", file=sys.stderr)
        return 1
    bom_path, decl_path = argv
    wanted = declared(decl_path)
    if not wanted:
        return 0
    if not accepted(bom_path, decl_path):
        print("[sources] the declaration is refused (see the SPDX 3.0.1 step); its sources are not read",
              file=sys.stderr)
        return 0
    try:
        with open(bom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"[sources] cannot read the SBOM: {e}", file=sys.stderr)
        return 0
    added, linked = apply(bom, wanted)
    tmp = bom_path + ".sources.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)
        os.replace(tmp, bom_path)
    except OSError as e:
        print(f"[sources] could not write the SBOM: {e}", file=sys.stderr)
        return 1
    print(f"[sources] declared sources: {linked} linked, {added} dataset(s) read from the hub")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
