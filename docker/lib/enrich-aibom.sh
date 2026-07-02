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
#   3. Pedigree / performance   — harvested from `cdxgen -t ai` when that tool is
#                                 present (it fills model ancestors, performance
#                                 metrics, and cdx:huggingface:* properties the
#                                 OWASP tool omits), merged into the model component.
#
# All steps are best-effort: no network, no huggingface_hub, or no cdxgen simply
# skips that step, leaving the field unfilled so the G7 conformance report shows
# it honestly as "not present" rather than fabricated. Non-LFS files carry only a
# git SHA-1 (not a content SHA-256), so only LFS weight files get a hash here.
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
hf_info = None
try:
    from huggingface_hub import HfApi
    hf_info = HfApi().model_info(model_id, files_metadata=True)
except Exception as e:  # network down, private/gated, or lib absent
    print(f"[enrich] HuggingFace metadata unavailable: {e}", file=sys.stderr)

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
    # Training reproducibility is the weakest signal from metadata alone: treat a
    # declared base_model or an explicit training/library hint as "open training".
    library = card_get(hf_info, "library_name")
    base_model = card_get(hf_info, "base_model")
    tags = getattr(hf_info, "tags", None) or []
    has_training = bool(base_model) or any("train" in str(t).lower() for t in tags)

    is_open_weight = (gated in (False, None)) and (not private) and has_weight

    openness = {
        "openness:weights": "open-weight" if is_open_weight else ("gated" if gated else "closed"),
        "openness:architecture": "open-architecture" if (has_config or any((m.get("modelCard", {}) or {}).get("modelParameters") for m in models)) else "undisclosed",
        "openness:training-data": "open-data" if has_datasets else "undisclosed",
        "openness:training": "open-training" if has_training else "undisclosed",
    }

    for m in models:
        if weight_hashes:
            existing = m.get("hashes") or []
            seen = {(h.get("alg"), h.get("content")) for h in existing if isinstance(h, dict)}
            for h in weight_hashes:
                if (h["alg"], h["content"]) not in seen:
                    existing.append(h)
                    seen.add((h["alg"], h["content"]))
            m["hashes"] = existing
        # Replace any prior openness:* properties so re-runs stay idempotent.
        props = [p for p in (m.get("properties") or []) if not str(p.get("name", "")).startswith("openness:")]
        for name, value in openness.items():
            props.append({"name": name, "value": value})
        m["properties"] = props
    print(f"[enrich] HuggingFace: {len(weight_hashes)} weight hash(es), openness assessed "
          f"(weights={openness['openness:weights']}).", file=sys.stderr)

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
