#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-aibom.sh — post-generation enrichment for an AI SBOM (CycloneDX 1.7
# ML-BOM). Fills fields the OWASP AIBOM Generator leaves empty but that the G7
# minimum elements call for, from sources it does not consult:
#
#   1. Model integrity hashes   — the HuggingFace API exposes a SHA-256 for every
#                                 LFS-tracked weight file (info.siblings[].lfs.sha256).
#                                 No generator writes these; we read and inject them.
#   2. Model openness (4 axes)  — derived from HF signals (gated/private, weight
#                                 files, declared datasets, training docs) and
#                                 written as openness:* properties. Grounded in the
#                                 Model Openness Framework (arXiv 2403.13784).
#   3. Referenced datasets      — the model card names its training datasets and
#                                 says nothing else about them. Each id is resolved
#                                 against the datasets API into a CycloneDX `data`
#                                 component (license, upstream, content digests)
#                                 linked to the model through dependencies[].
#   4. Pedigree / performance   — harvested from `cdxgen -t ai` when that tool is
#                                 present (it fills model ancestors, performance
#                                 metrics, and cdx:huggingface:* properties the
#                                 OWASP tool omits), merged into the model component.
#
# All steps are best-effort: no network, no huggingface_hub, or no cdxgen simply
# skips that step, leaving the field unfilled so the G7 conformance report shows
# it honestly as "not present" rather than fabricated. Non-LFS files carry only a
# git SHA-1 (not a content SHA-256), so only LFS weight files get a hash here.
#
# Auth contract: HF_TOKEN, when present in the environment, is read implicitly by
# huggingface_hub, which is what lets a private or gated repo enrich. We pass no
# explicit token argument — keeping it out of argv and out of exception text is
# the point. Never print the value.
#
# Usage: enrich-aibom.sh <sbom.json> <hf_model_id>
set -e

SBOM="$1"
MODEL_ID="$2"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[enrich] SBOM file not found: $SBOM" >&2
    echo "[enrich]   Run the AIBOM generation step first (scan-aibom.sh) so there is an SBOM to enrich." >&2
    exit 1
fi
if [ -z "$MODEL_ID" ]; then
    echo "[enrich] no model id given; nothing to enrich." >&2
    exit 0
fi

# Locate cdxgen so the Python step can decide whether to harvest pedigree/metrics.
# ENRICH_CDXGEN=false disables the harvest (it makes a network call and is off by
# default in offline test runs); HuggingFace hash/openness enrichment still runs.
CDXGEN_BIN=""
if [ "${ENRICH_CDXGEN:-true}" != "false" ]; then
    CDXGEN_BIN="$(command -v cdxgen 2>/dev/null || true)"
fi

# Everything runs inside one Python pass so the SBOM JSON is parsed/written once.
# Each feature is guarded independently; a failure in one leaves the others (and
# the original SBOM) intact.
python3 - "$SBOM" "$MODEL_ID" "$CDXGEN_BIN" <<'PY' || echo "[enrich] enrichment skipped (python/network/tool unavailable)" >&2
import json, os, subprocess, sys, tempfile

sbom_path, model_id, cdxgen_bin = sys.argv[1], sys.argv[2], sys.argv[3]

WEIGHT_EXTS = (".safetensors", ".bin", ".gguf", ".pt", ".pth", ".onnx", ".h5", ".ckpt", ".msgpack")

with open(sbom_path) as f:
    sbom = json.load(f)

comps = sbom.get("components") or []
models = [c for c in comps if isinstance(c, dict) and c.get("type") == "machine-learning-model"]
if not models:
    print("[enrich] no machine-learning-model component; nothing to enrich.", file=sys.stderr)
    sys.exit(0)

# ---- HuggingFace API: hashes + openness signals -----------------------------
# The client is kept around: the dataset step below reuses it, so one failed
# import or one dead network disables both rather than half-enriching.
hf_info = None
hf_api = None
try:
    from huggingface_hub import HfApi
    hf_api = HfApi()
    try:
        # securityStatus adds HuggingFace's repo-level scan rollup to the same
        # call. Older hub versions lack the parameter; fall back cleanly.
        hf_info = hf_api.model_info(model_id, files_metadata=True, securityStatus=True)
    except TypeError:
        hf_info = hf_api.model_info(model_id, files_metadata=True)
except Exception as e:  # network down, no read access, or lib absent
    # Report only whether a token was in play, never the token itself.
    auth = "authenticated" if os.environ.get("HF_TOKEN") else "anonymous"
    print(f"[enrich] HuggingFace metadata unavailable ({auth}): {e}", file=sys.stderr)

def card_get(info, key):
    cd = getattr(info, "card_data", None)
    if cd is None:
        return None
    if hasattr(cd, "get"):
        try:
            return cd.get(key)
        except Exception:
            pass
    return getattr(cd, key, None)


# ---- Referenced training datasets -------------------------------------------
# A model card names the datasets it trained on and stops there: no license, no
# upstream, no integrity value. Resolving each id against the datasets API turns
# the bare name into a real component, which is what the G7 dataset cluster asks
# for and what a provider writes an EU AI Act training-content summary from.
#
# A dataset that cannot be opened (private, gated, renamed, withdrawn) still
# gets a component carrying its name and an explicit unresolved marker. Leaving
# the gap visible is the point — a fabricated license would read as a reviewed
# dataset. Same contract as the rest of this file.

# Marks the components this step wrote, so a re-run can drop its own previous
# output instead of appending a second copy of every dataset.
DATASET_MARK = "bomlens:dataset:collectedBy"
# A dataset repo can hold thousands of shards. The component hash list is
# evidence that content digests exist and are recorded, not a manifest, so it is
# capped and the true file count is recorded alongside it.
DATASET_HASH_CAP = 64


def dataset_ref(ds_id):
    return "dataset:huggingface/" + ds_id


def build_dataset_component(api, ds_id):
    """CycloneDX `data` component for one HuggingFace dataset id.

    Returns (component, resolved). `resolved` is False when the repository could
    not be read, in which case the component holds the name and nothing else.
    """
    url = "https://huggingface.co/datasets/" + ds_id
    props = [{"name": DATASET_MARK, "value": "huggingface"}]
    comp = {
        "type": "data",
        "bom-ref": dataset_ref(ds_id),
        "name": ds_id,
        "externalReferences": [
            {"type": "distribution", "url": url, "comment": "Dataset repository"}
        ],
        "properties": props,
    }
    # componentData (spec: component.data[]) is where CycloneDX describes what a
    # data component actually holds.
    cdata = {"type": "dataset", "name": ds_id, "contents": {"url": url}}

    if api is None:
        props.append({"name": "bomlens:dataset:unresolved", "value": "huggingface-unavailable"})
        comp["data"] = [cdata]
        return comp, False

    try:
        info = api.dataset_info(ds_id, files_metadata=True)
    except Exception as e:
        # Never put the exception text in the SBOM: it can carry request detail.
        # The reason goes to the log, the fact goes to the BOM.
        print(f"[enrich] dataset {ds_id} could not be read: {e}", file=sys.stderr)
        props.append({"name": "bomlens:dataset:unresolved", "value": "not-readable"})
        comp["data"] = [cdata]
        return comp, False

    # A dataset repo has no release version, only a commit. Recording it pins the
    # snapshot that was read, which is what makes the hashes below meaningful.
    # Short form in `version` to match the model component the generator writes;
    # the full revision rides along as a property.
    rev = getattr(info, "sha", None)
    if rev:
        comp["version"] = str(rev)[:8]
        props.append({"name": "bomlens:dataset:revision", "value": str(rev)})

    lic = card_get(info, "license")
    if isinstance(lic, list):
        lic = lic[0] if lic else None
    if lic:
        # Raw HuggingFace spelling ("cc-by-sa-4.0"). normalize-sbom.sh maps it to
        # an SPDX id downstream, so it is recorded as a name rather than guessed
        # into an id here.
        comp["licenses"] = [{"license": {"name": str(lic)}}]

    desc = getattr(info, "description", None) or card_get(info, "pretty_name")
    if desc:
        comp["description"] = str(desc)[:500]
        cdata["description"] = comp["description"]

    # Content digests: LFS-tracked files are the only ones exposing a SHA-256.
    shas, total_files = [], 0
    for s in (getattr(info, "siblings", None) or []):
        total_files += 1
        lfs = getattr(s, "lfs", None) or (s.get("lfs") if isinstance(s, dict) else None)
        if lfs is None:
            continue
        sha = getattr(lfs, "sha256", None) or (lfs.get("sha256") if isinstance(lfs, dict) else None)
        if sha and sha not in shas:
            shas.append(sha)
    if shas:
        comp["hashes"] = [{"alg": "SHA-256", "content": s} for s in shas[:DATASET_HASH_CAP]]
        props.append({"name": "bomlens:dataset:hashedFiles",
                      "value": f"{min(len(shas), DATASET_HASH_CAP)} of {len(shas)}"})
    if total_files:
        props.append({"name": "bomlens:dataset:fileCount", "value": str(total_files)})

    # What the dataset holds — the card's declared facets, recorded as-is.
    facets = []
    for key in ("task_categories", "size_categories", "language", "annotations_creators",
                "multilinguality", "configs"):
        val = card_get(info, key)
        if not val:
            continue
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val if v is not None)
        facets.append({"name": "hf:" + key, "value": str(val)[:200]})
    if facets:
        cdata["contents"]["properties"] = facets

    # Provenance: the upstream this dataset derives from. HuggingFace allows both
    # a bare marker ("original") and a reference ("extended|other/name"), so the
    # values are carried verbatim rather than reinterpreted as ids.
    for src in (card_get(info, "source_datasets") or []):
        props.append({"name": "bomlens:dataset:sourceDataset", "value": str(src)[:200]})

    owner = ds_id.split("/")[0] if "/" in ds_id else None
    if owner:
        cdata["governance"] = {"owners": [{"organization": {"name": owner}}]}

    if getattr(info, "private", False):
        props.append({"name": "bomlens:dataset:visibility", "value": "private"})
    elif getattr(info, "gated", None):
        props.append({"name": "bomlens:dataset:visibility", "value": "gated"})

    comp["data"] = [cdata]
    return comp, True


def collect_datasets(api, declared):
    """Resolve every dataset the model card declares.

    Returns (components, bom-refs, resolved_count).
    """
    if not declared:
        return [], [], 0
    ids = declared if isinstance(declared, list) else [declared]
    seen, comps, refs, resolved = set(), [], [], 0
    for raw in ids:
        ds_id = str(raw).strip()
        if not ds_id or ds_id in seen:
            continue
        seen.add(ds_id)
        comp, ok = build_dataset_component(api, ds_id)
        comps.append(comp)
        refs.append(comp["bom-ref"])
        resolved += 1 if ok else 0
    return comps, refs, resolved

if hf_info is not None:
    siblings = getattr(hf_info, "siblings", None) or []
    # file name -> LFS SHA-256 (only LFS-tracked files expose a content hash)
    file_sha = {}
    filenames = []
    for s in siblings:
        name = getattr(s, "rfilename", None) or (s.get("rfilename") if isinstance(s, dict) else None)
        if not name:
            continue
        filenames.append(name)
        lfs = getattr(s, "lfs", None) or (s.get("lfs") if isinstance(s, dict) else None)
        sha = None
        if lfs is not None:
            sha = getattr(lfs, "sha256", None) or (lfs.get("sha256") if isinstance(lfs, dict) else None)
        if sha:
            file_sha[name] = sha

    weight_hashes = [
        {"alg": "SHA-256", "content": sha}
        for name, sha in file_sha.items()
        if name.lower().endswith(WEIGHT_EXTS)
    ]

    gated = getattr(hf_info, "gated", None)          # False | "auto" | "manual" | None
    private = bool(getattr(hf_info, "private", False))
    has_weight = any(n.lower().endswith(WEIGHT_EXTS) for n in filenames)
    has_config = any(n.lower() == "config.json" for n in filenames)
    datasets = card_get(hf_info, "datasets")
    has_datasets = bool(datasets)
    dataset_comps, dataset_refs, resolved_datasets = collect_datasets(hf_api, datasets)
    # Training reproducibility is the weakest signal from metadata alone: treat a
    # declared base_model or an explicit training/library hint as "open training".
    library = card_get(hf_info, "library_name")
    base_model = card_get(hf_info, "base_model")
    tags = getattr(hf_info, "tags", None) or []
    has_training = bool(base_model) or any("train" in str(t).lower() for t in tags)

    is_open_weight = (gated in (False, None)) and (not private) and has_weight

    # Training data: a name in the card is a claim, not open data. The axis reads
    # open-data only when at least one declared dataset actually opened; a card
    # that names datasets nobody can retrieve is reported as declared-unverified
    # so the distinction survives into the SBOM instead of being flattened.
    if resolved_datasets > 0:
        training_data = "open-data"
    elif has_datasets:
        training_data = "declared-unverified"
    else:
        training_data = "undisclosed"

    openness = {
        "openness:weights": "open-weight" if is_open_weight else ("gated" if gated else "closed"),
        "openness:architecture": "open-architecture" if (has_config or any((m.get("modelCard", {}) or {}).get("modelParameters") for m in models)) else "undisclosed",
        "openness:training-data": training_data,
        "openness:training": "open-training" if has_training else "undisclosed",
    }

    # ---- Weight-file formats (no extra API call) ----------------------------
    # A pickle-family weight file (.bin/.pt/.pth/.ckpt) can execute code on
    # load; safetensors and friends cannot. The format itself is a risk signal
    # the assessment reads, computed from the siblings already fetched.
    # PICKLE_EXTS mirrors weightFormats.pickleExts in ai-risk-knowledge.json.
    PICKLE_EXTS = (".bin", ".pt", ".pth", ".ckpt")
    weight_fmts = sorted({os.path.splitext(n.lower())[1].lstrip(".")
                          for n in filenames if n.lower().endswith(WEIGHT_EXTS)})
    pickle_files = sum(1 for n in filenames if n.lower().endswith(PICKLE_EXTS))
    weights_props = []
    if weight_fmts:
        weights_props.append({"name": "bomlens:weights:formats", "value": ",".join(weight_fmts)})
        weights_props.append({"name": "bomlens:weights:pickleFiles", "value": str(pickle_files)})

    # ---- File security: HuggingFace's own scan results ----------------------
    # HuggingFace runs ClamAV and picklescan over every repository and exposes
    # per-file results through the tree API — one metadata call, no file
    # download. The repo-level rollup (security_repo_status) is recorded
    # verbatim but never judged: scansDone reads False even on long-scanned
    # popular models, so only the per-file statuses carry meaning. Best-effort:
    # a failure leaves no scan properties, and the assessment then reports the
    # security axis honestly as not evaluated.
    def _get(o, name, default=None):
        if isinstance(o, dict):
            camel = "".join(w.capitalize() if i else w for i, w in enumerate(name.split("_")))
            return o.get(name, o.get(camel, default))
        return getattr(o, name, default)

    scan_props = []
    repo_status = getattr(hf_info, "security_repo_status", None)
    if repo_status is not None:
        try:
            scan_props.append({"name": "bomlens:hf:scan:repoStatus",
                               "value": json.dumps(repo_status, separators=(",", ":"), sort_keys=True)[:500]})
        except Exception:
            pass

    if os.environ.get("ENRICH_HF_SECURITY", "true") != "false":
        SCAN_FILE_CAP = 1000
        try:
            agg = 0            # 0 safe, 1 queued (pending weight), 2 suspicious, 3 unsafe
            n_files = n_scanned = n_flagged = 0
            issues, truncated = [], False
            for f in hf_api.list_repo_tree(model_id, expand=True):
                path = str(_get(f, "path", "") or "")
                if not path:
                    continue
                n_files += 1
                if n_files > SCAN_FILE_CAP:
                    truncated = True
                    break
                sec = _get(f, "security", None)
                is_weight = path.lower().endswith(WEIGHT_EXTS)
                status = _get(sec, "status", None) if sec is not None else None
                fr, why = 0, ""
                if sec is None or status in (None, "queued"):
                    # An unscanned file only matters where code can hide.
                    if is_weight:
                        fr, why = 1, "scan pending"
                elif status != "safe" or _get(sec, "safe", True) is False:
                    fr, why = 3, f"scan status {status}"
                else:
                    n_scanned += 1
                pk = _get(sec, "pickle_import_scan", None) if sec is not None else None
                if pk is not None:
                    imports = _get(pk, "pickle_imports", None) or _get(pk, "pickleImports", None) or []
                    safeties = {str(_get(i, "safety", "")) for i in imports}
                    if "dangerous" in safeties and fr < 3:
                        fr, why = 3, "dangerous pickle import"
                    elif "suspicious" in safeties and fr < 2:
                        fr, why = 2, "suspicious pickle import"
                if fr >= 2:
                    n_flagged += 1
                    if len(issues) < 5:
                        issues.append(f"{path}: {why}")
                agg = max(agg, fr)
            if n_scanned or agg:
                status_val = {0: "safe", 1: "queued", 2: "suspicious", 3: "unsafe"}[agg]
            else:
                status_val = "unavailable"
            scan_props.append({"name": "bomlens:hf:scan:status", "value": status_val})
            scan_props.append({"name": "bomlens:hf:scan:files", "value": str(min(n_files, SCAN_FILE_CAP))})
            scan_props.append({"name": "bomlens:hf:scan:filesFlagged", "value": str(n_flagged)})
            if issues:
                scan_props.append({"name": "bomlens:hf:scan:issue", "value": "; ".join(issues)[:500]})
            if truncated:
                scan_props.append({"name": "bomlens:hf:scan:truncated", "value": "true"})
            scan_props.append({"name": "bomlens:hf:scan:source", "value": "huggingface-api"})
            print(f"[enrich] file security: {status_val} "
                  f"({n_scanned} scanned safe, {n_flagged} flagged).", file=sys.stderr)
        except Exception as e:
            # The reason goes to the log, the fact goes to the BOM (same
            # contract as the dataset step: no exception text in the SBOM).
            print(f"[enrich] file-security lookup failed: {e}", file=sys.stderr)
            scan_props.append({"name": "bomlens:hf:scan:status", "value": "unavailable"})
            scan_props.append({"name": "bomlens:hf:scan:source", "value": "huggingface-api"})

    for m in models:
        if weight_hashes:
            existing = m.get("hashes") or []
            seen = {(h.get("alg"), h.get("content")) for h in existing if isinstance(h, dict)}
            for h in weight_hashes:
                if (h["alg"], h["content"]) not in seen:
                    existing.append(h)
                    seen.add((h["alg"], h["content"]))
            m["hashes"] = existing
        # Replace any prior openness/scan/weights properties so re-runs stay
        # idempotent (same contract as the DATASET_MARK components below).
        props = [p for p in (m.get("properties") or [])
                 if not str(p.get("name", "")).startswith(("openness:", "bomlens:hf:scan:", "bomlens:weights:"))]
        for name, value in openness.items():
            props.append({"name": name, "value": value})
        props.extend(scan_props)
        props.extend(weights_props)
        m["properties"] = props
    print(f"[enrich] HuggingFace: {len(weight_hashes)} weight hash(es), openness assessed "
          f"(weights={openness['openness:weights']}).", file=sys.stderr)

    # Attach the dataset components and link each model to them. A previous run's
    # output is dropped first (matched on DATASET_MARK) so enriching twice does
    # not leave two copies of every dataset behind.
    if dataset_comps:
        def ours(c):
            return isinstance(c, dict) and any(
                p.get("name") == DATASET_MARK for p in (c.get("properties") or [])
            )

        comps[:] = [c for c in comps if not ours(c)]
        comps.extend(dataset_comps)
        sbom["components"] = comps

        # dependencies[]: the model depends on the data it was trained on. This
        # is the relationship the G7 dataset cluster names, and what makes the
        # dependency graph in the UI show the training data.
        deps = sbom.get("dependencies") or []
        stale = set(dataset_refs)
        deps = [d for d in deps if not (isinstance(d, dict) and d.get("ref") in stale)]
        by_ref = {d.get("ref"): d for d in deps if isinstance(d, dict)}
        for m in models:
            mref = m.get("bom-ref")
            if not mref:
                continue
            entry = by_ref.get(mref)
            if entry is None:
                entry = {"ref": mref, "dependsOn": []}
                deps.append(entry)
                by_ref[mref] = entry
            on = entry.get("dependsOn") or []
            for r in dataset_refs:
                if r not in on:
                    on.append(r)
            entry["dependsOn"] = on
        # Every referenced ref needs its own node, even a leaf one.
        for r in dataset_refs:
            deps.append({"ref": r, "dependsOn": []})
        sbom["dependencies"] = deps
        print(f"[enrich] datasets: {len(dataset_comps)} referenced, {resolved_datasets} resolved "
              f"(training-data={training_data}).", file=sys.stderr)

# ---- cdxgen -t ai: pedigree / performance metrics ---------------------------
# Gated on the HuggingFace fetch having succeeded: cdxgen hits the same API over
# the same network, so when hf_info is None (offline, gated model, or the hub
# unreachable) the harvest can only fail too — skipping it avoids stalling an
# offline AIBOM scan for up to the 300 s subprocess timeout on a dead network.
if cdxgen_bin and hf_info is not None:
    try:
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "cdxgen-ai.json")
            subprocess.run(
                [cdxgen_bin, "-t", "ai", "-o", out, f"pkg:huggingface/{model_id}"],
                check=True, capture_output=True, timeout=300,
            )
            with open(out) as f:
                cg = json.load(f)
        cg_models = [c for c in (cg.get("components") or [])
                     if isinstance(c, dict) and c.get("type") == "machine-learning-model"]
        cg_model = cg_models[0] if cg_models else None
        if cg_model:
            for m in models:
                # Model pedigree (ancestors / base-model lineage) — Model training
                # properties + dataset provenance clusters.
                if cg_model.get("pedigree") and not m.get("pedigree"):
                    m["pedigree"] = cg_model["pedigree"]
                # Performance metrics — KPI cluster.
                cg_qa = ((cg_model.get("modelCard") or {}).get("quantitativeAnalysis"))
                if cg_qa:
                    mc = m.setdefault("modelCard", {})
                    mc.setdefault("quantitativeAnalysis", cg_qa)
                # cdx:huggingface:* / cdx:ai:* properties (gated, parameterCount, …).
                cg_props = [p for p in (cg_model.get("properties") or [])
                            if str(p.get("name", "")).startswith(("cdx:huggingface:", "cdx:ai:"))]
                if cg_props:
                    have = {p.get("name") for p in (m.get("properties") or [])}
                    m["properties"] = (m.get("properties") or []) + [p for p in cg_props if p.get("name") not in have]
            print("[enrich] cdxgen: merged pedigree/metrics/properties.", file=sys.stderr)
        else:
            print("[enrich] cdxgen produced no model component; nothing to merge.", file=sys.stderr)
    except Exception as e:
        print(f"[enrich] cdxgen harvest skipped: {e}", file=sys.stderr)
elif cdxgen_bin:
    print("[enrich] cdxgen harvest skipped (HuggingFace unreachable, so it would fail too).", file=sys.stderr)
else:
    print("[enrich] cdxgen harvest disabled or not present; skipping pedigree/metrics.", file=sys.stderr)

with open(sbom_path, "w") as f:
    json.dump(sbom, f, indent=2)
print("[enrich] enrichment complete.", file=sys.stderr)
PY

exit 0
