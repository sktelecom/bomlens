#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# diff-ai-model.py — compare two already-generated CycloneDX documents that
# each describe "the same" AI model, and report what moved between them.
#
# Usage: diff-ai-model.py <old.json> <new.json> <out.json>
#
# Why: a HuggingFace repo id or a model file name is a label, not an identity.
# The same label can point at a different artifact tomorrow — a maintainer
# force-pushes new weights over an existing tag, a supplier re-delivers a
# "v1.0" file with the bug fixed and the filename unchanged, a model card's
# license line is edited after the fact. None of that shows up by reading one
# scan in isolation; it only shows up by comparing two. This is the offline,
# read-only comparison: given an older scan and a newer one, it says whether
# the two are actually looking at the same weights, and if not, what else
# moved along with them.
#
# Three things are worth a reader's attention, in the order they are checked:
#   1. hash mismatch   — same declared name/purl/HuggingFace id, different
#                        SHA-256 on the weight file. This is the loudest signal:
#                        a name that is supposed to be stable pointed at a
#                        different artifact, and everything else in the SBOM
#                        (license, risk verdict, model card) describes whichever
#                        copy was scanned, not necessarily what is deployed now.
#   2. license change  — the model component's own declared license text
#                        differs between the two scans.
#   3. verdict escalation — a bomlens:assessment:* axis, or the overall
#                        verdict, ranks worse in the new scan than the old one.
#                        The rank order (worst to best: caution > review >
#                        conditional > ok) is restated here rather than
#                        imported: it is assess-ai-risk.sh's own vocabulary
#                        (docker/lib/assess-ai-risk.sh, "vrank"), and there is
#                        no cross-language import convention in this codebase
#                        for two shell/python call sites to share a jq def.
#
# "Same logical model" is decided by matching, not by the caller naming which
# component is which: each machine-learning-model component in both documents
# is given a set of identity keys (HuggingFace id, purl name, plain name), and
# pairs are matched tier by tier, strongest signal first, each component used
# at most once. A component with no match on either side is not a defect —
# a model can legitimately be added or dropped between two scans — so it is
# reported separately, distinctly from a matched pair that changed.
#
# Never a gate: like validate-sbom.sh, this always exits 0 once it has
# something to compare, whatever the comparison finds — a diff report is
# information for a human, not a pass/fail check that should stop a pipeline.
# Exit 1 is reserved for a reason this tool could not run at all (a file
# missing, unreadable, or not JSON, or neither side having anything to
# compare).
#
# Deliberately stdlib-only, so it runs in the base image with no new
# dependency and works offline on two files nothing else has to fetch.

import datetime
import json
import os
import re
import sys
import urllib.parse

# assess-ai-risk.sh's own verdict vocabulary and severity order, restated (see
# the header above for why this is copied rather than imported). Do not widen
# or reorder this without checking that script first — a mismatch here would
# make an escalation invisible or invent one that assess-ai-risk.sh would not.
VRANK = {"caution": 4, "review": 3, "conditional": 2, "ok": 1}

# The bomlens:assessment:* axes assess-ai-risk.sh stamps on a model component.
# Not every axis applies to every scan (security/datasets/trainingData are
# conditional on what was actually evaluated), so a missing axis on either
# side is simply skipped rather than treated as a change.
ASSESSMENT_AXES = ("overall", "license", "security", "datasets", "trainingData")

# https://huggingface.co/<owner>/<repo>[/...] — the owner/repo pair is the
# HuggingFace identity even when the purl itself is not pkg:huggingface (e.g.
# after a supplier SBOM has been converted to a different shape).
HF_URL_RE = re.compile(r"huggingface\.co/([^/\s?#]+/[^/\s?#]+)")


def model_components(doc):
    """Every machine-learning-model component in the document, wherever it sits.

    Mirrors enrich-aibom.sh's model_components(): the AIBOM generator leaves
    the model in components[] and puts its own scan job in metadata.component,
    while identify-model-file.py and a hand-written AI SBOM put the model at
    the root. A comparison that only looked in one place would silently find
    nothing for the other tool's output.
    """
    if not isinstance(doc, dict):
        return []
    found = []
    root = doc.get("metadata")
    root = root.get("component") if isinstance(root, dict) else None
    if isinstance(root, dict) and root.get("type") == "machine-learning-model":
        found.append(root)
    for comp in doc.get("components") or []:
        if isinstance(comp, dict) and comp.get("type") == "machine-learning-model":
            found.append(comp)
    return found


def purl_parts(purl):
    """(type, namespace, name) from a purl, version/qualifiers/subpath dropped.

    A minimal parse on purpose: this only ever needs to tell whether two
    components name the same package, not validate purl syntax (that is
    validate-sbom.sh's job).
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:"):].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    rest = rest.rsplit("@", 1)[0]
    segments = [urllib.parse.unquote(s) for s in rest.split("/") if s]
    if not segments:
        return None
    return {
        "type": ptype.strip().lower(),
        "namespace": "/".join(segments[:-1]),
        "name": segments[-1],
    }


def identity_keys(component):
    """The identity signals a component carries, from strongest to weakest.

    Returned as a dict keyed by tier name so match_models() can walk the tiers
    in a fixed, documented order rather than guessing which key "should" win.
    """
    keys = {}
    purl = purl_parts(component.get("purl"))

    hf_id = None
    if purl and purl["type"] == "huggingface" and purl["namespace"]:
        hf_id = "%s/%s" % (purl["namespace"], purl["name"])
    if hf_id is None:
        for ref in component.get("externalReferences") or []:
            if not isinstance(ref, dict):
                continue
            match = HF_URL_RE.search(str(ref.get("url") or ""))
            if match:
                hf_id = match.group(1)
                break
    if hf_id:
        keys["huggingface-id"] = hf_id.lower()

    if purl:
        keys["purl-name"] = "%s:%s/%s" % (purl["type"], purl["namespace"], purl["name"])
        keys["purl-name"] = keys["purl-name"].lower()

    name = str(component.get("name") or "").strip().lower()
    if name:
        group = str(component.get("group") or "").strip().lower()
        keys["qualified-name"] = ("%s/%s" % (group, name)) if group else name
        keys["name"] = name

    return keys


# Checked in this order: a HuggingFace id match is a near-certainty that both
# scans describe the same repo; a bare name match is the weakest evidence (two
# unrelated models are often named the same thing, e.g. "model" or "adapter")
# but still better than declaring every component unmatched.
MATCH_TIERS = ("huggingface-id", "purl-name", "qualified-name", "name")


def match_models(old_models, new_models):
    """Pair components across the two documents, strongest signal first.

    Each component is used in at most one pair. A tier is only tried for
    components neither side has already matched at a stronger tier, so a
    weak name-only match never steals a component that a later, unexamined
    HuggingFace-id match would have paired correctly — ties are broken by
    document order, which is the only order available.
    """
    old_keys = [identity_keys(c) for c in old_models]
    new_keys = [identity_keys(c) for c in new_models]
    matched_old, matched_new, pairs = set(), set(), []

    for tier in MATCH_TIERS:
        for i, ok in enumerate(old_keys):
            if i in matched_old:
                continue
            value = ok.get(tier)
            if not value:
                continue
            for j, nk in enumerate(new_keys):
                if j in matched_new:
                    continue
                if nk.get(tier) == value:
                    pairs.append((i, j, tier, value))
                    matched_old.add(i)
                    matched_new.add(j)
                    break

    unmatched_old = [old_models[i] for i in range(len(old_models)) if i not in matched_old]
    unmatched_new = [new_models[j] for j in range(len(new_models)) if j not in matched_new]
    return pairs, unmatched_old, unmatched_new


def props_map(component):
    return {p.get("name"): p.get("value")
            for p in (component.get("properties") or []) if isinstance(p, dict)}


def verdict_changes(old_c, new_c):
    """Axis-by-axis bomlens:assessment:* changes, escalation flagged per axis.

    An axis present on only one side (e.g. a security scan that only the newer
    run had metadata for) is not a change to report — there is nothing on the
    other side to compare it against.
    """
    old_props, new_props = props_map(old_c), props_map(new_c)
    changes = []
    for axis in ASSESSMENT_AXES:
        old_v = old_props.get("bomlens:assessment:" + axis)
        new_v = new_props.get("bomlens:assessment:" + axis)
        if old_v is None or new_v is None or old_v == new_v:
            continue
        changes.append({
            "axis": axis,
            "old": old_v,
            "new": new_v,
            "escalated": VRANK.get(new_v, 0) > VRANK.get(old_v, 0),
        })
    return changes


def license_strings(component):
    out = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license") or {}
        value = lic.get("id") or lic.get("name") or entry.get("expression")
        if value:
            out.append(str(value))
    return out


def license_change(old_c, new_c):
    old_lic, new_lic = license_strings(old_c), license_strings(new_c)
    if sorted(old_lic) == sorted(new_lic):
        return None
    return {"old": old_lic, "new": new_lic}


def sha256_set(component):
    return sorted({str(h["content"]).lower() for h in (component.get("hashes") or [])
                   if isinstance(h, dict) and h.get("alg") == "SHA-256" and h.get("content")})


def hash_change(old_c, new_c):
    """SHA-256 drift on a matched component — None when there is nothing to
    compare (either side has no hash at all: silence, not a clean bill)."""
    old_hashes, new_hashes = sha256_set(old_c), sha256_set(new_c)
    if not old_hashes or not new_hashes or old_hashes == new_hashes:
        return None
    return {"old": old_hashes, "new": new_hashes}


def summarize(component):
    return {
        "name": component.get("name"),
        "version": component.get("version"),
        "purl": component.get("purl"),
    }


def build_report(old_path, new_path, old_models, new_models):
    pairs, unmatched_old, unmatched_new = match_models(old_models, new_models)

    matched, escalations, license_changes, hash_mismatches = [], 0, 0, 0
    for i, j, tier, value in pairs:
        old_c, new_c = old_models[i], new_models[j]
        v_changes = verdict_changes(old_c, new_c)
        lic = license_change(old_c, new_c)
        hsh = hash_change(old_c, new_c)
        flags = []
        if any(c["escalated"] for c in v_changes):
            flags.append("verdict-escalation")
            escalations += 1
        if lic is not None:
            flags.append("license-change")
            license_changes += 1
        if hsh is not None:
            flags.append("hash-mismatch")
            hash_mismatches += 1
        matched.append({
            "matchedOn": tier,
            "matchedValue": value,
            "old": summarize(old_c),
            "new": summarize(new_c),
            "verdictChanges": v_changes,
            "licenseChange": lic,
            "hashChange": hsh,
            "flags": flags,
        })

    unmatched = (
        [dict(side="old", **summarize(c)) for c in unmatched_old]
        + [dict(side="new", **summarize(c)) for c in unmatched_new]
    )

    return {
        "generatedAt": datetime.datetime.now(datetime.timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "old": {"file": os.path.basename(old_path), "models": len(old_models)},
        "new": {"file": os.path.basename(new_path), "models": len(new_models)},
        "matched": matched,
        "unmatched": unmatched,
        "summary": {
            "matchedPairs": len(pairs),
            "verdictEscalations": escalations,
            "licenseChanges": license_changes,
            "hashMismatches": hash_mismatches,
            "unmatched": len(unmatched),
        },
    }


def print_summary(report):
    old_n, new_n = report["old"]["models"], report["new"]["models"]
    sys.stderr.write("[diff] %s (%d model(s)) vs %s (%d model(s))\n" % (
        report["old"]["file"], old_n, report["new"]["file"], new_n))
    for pair in report["matched"]:
        name = pair["new"].get("name") or pair["old"].get("name") or "(unnamed)"
        if not pair["flags"]:
            sys.stderr.write("[diff] MATCH %s: no change (matched on %s)\n" % (name, pair["matchedOn"]))
            continue
        sys.stderr.write("[diff] MATCH %s (matched on %s):\n" % (name, pair["matchedOn"]))
        if pair["hashChange"]:
            sys.stderr.write("[diff]   HASH MISMATCH: weight file SHA-256 changed under the same "
                              "name — this is a different artifact\n")
        if pair["licenseChange"]:
            lc = pair["licenseChange"]
            sys.stderr.write("[diff]   LICENSE CHANGED: %s -> %s\n" % (
                ", ".join(lc["old"]) or "(none)", ", ".join(lc["new"]) or "(none)"))
        for change in pair["verdictChanges"]:
            tag = "ESCALATED" if change["escalated"] else "changed"
            sys.stderr.write("[diff]   VERDICT %s (%s): %s -> %s\n" % (
                tag, change["axis"], change["old"], change["new"]))
    for entry in report["unmatched"]:
        sys.stderr.write("[diff] UNMATCHED (%s only): %s\n" % (entry["side"], entry.get("name") or "(unnamed)"))
    s = report["summary"]
    sys.stderr.write("[diff] %d matched pair(s), %d escalation(s), %d license change(s), "
                      "%d hash mismatch(es), %d unmatched\n" % (
                          s["matchedPairs"], s["verdictEscalations"], s["licenseChanges"],
                          s["hashMismatches"], s["unmatched"]))


def load_cdx(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("usage: diff-ai-model.py <old.json> <new.json> <out.json>\n")
        return 2

    old_path, new_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    for label, path in (("old", old_path), ("new", new_path)):
        if not os.path.isfile(path):
            sys.stderr.write("[diff] %s SBOM not found: %s\n" % (label, path))
            return 1

    try:
        old_doc = load_cdx(old_path)
        new_doc = load_cdx(new_path)
    except (OSError, ValueError) as exc:
        sys.stderr.write("[diff] could not read a CycloneDX document: %s\n" % exc)
        return 1

    old_models = model_components(old_doc)
    new_models = model_components(new_doc)
    if not old_models and not new_models:
        sys.stderr.write("[diff] neither document has a machine-learning-model component; "
                          "nothing to compare.\n")
        return 1

    report = build_report(old_path, new_path, old_models, new_models)

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    print_summary(report)
    # Always 0 once there was something to compare — see the header docstring:
    # a diff report is information for a human, not a pipeline gate (same
    # contract as validate-sbom.sh's conformance result).
    return 0


if __name__ == "__main__":
    sys.exit(main())
