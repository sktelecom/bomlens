#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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

# Hand the curated registry path to the Python step: the dataset tag-signal
# mapping (pii, not-for-all-audiences, …) lives there, shared with
# assess-ai-risk.sh so stamping and judging never disagree. Overridable for
# tests, absent file tolerated.
export AI_RISK_KNOWLEDGE="${AI_RISK_KNOWLEDGE:-$(dirname "$0")/ai-risk-knowledge.json}"

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
python3 - "$SBOM" "$MODEL_ID" "$CDXGEN_BIN" "$(dirname "$0")" <<'PY' || echo "[enrich] enrichment skipped (python/network/tool unavailable)" >&2
import json, os, re, subprocess, sys, tempfile

sbom_path, model_id, cdxgen_bin = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, sys.argv[4])
import hf_dataset  # noqa: E402  (shared dataset reader, same directory)

WEIGHT_EXTS = (".safetensors", ".bin", ".gguf", ".pt", ".pth", ".onnx", ".h5", ".ckpt", ".msgpack")

# Curated registry (ai-risk-knowledge.json, path handed in by the bash
# wrapper): dataset tag signals, custom-license text patterns, and the
# license-terms entries the lineage check needs. All judgement data lives in
# the registry, not here, so this stamping and assess-ai-risk.sh can never
# disagree; a missing registry just means the extra signals are not stamped.
KB = {}
try:
    _kb_path = os.environ.get("AI_RISK_KNOWLEDGE", "")
    if _kb_path and os.path.isfile(_kb_path):
        with open(_kb_path) as _f:
            KB = json.load(_f)
except Exception as e:
    print(f"[enrich] risk registry unreadable ({e}); registry-driven signals skipped.", file=sys.stderr)
TAG_SIGNALS = {str(e.get("tag", "")).lower(): str(e.get("signal", ""))
               for e in (KB.get("datasetTagSignals") or [])
               if e.get("tag") and e.get("signal")}
CUSTOM_PATTERNS = KB.get("customLicensePatterns") or []
LICENSE_TERMS = KB.get("licenseTerms") or []


def _norm_lic(s):
    return re.sub(r"[ ._/-]+", " ", str(s or "").lower()).strip()


def _match_term(lic):
    """First registry entry matching a license string — ids exactly, then the
    match regexes in registry order (mirrors assess-ai-risk.sh)."""
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

with open(sbom_path) as f:
    sbom = json.load(f)

comps = sbom.get("components") or []


def model_components(doc):
    """Every machine-learning-model in the document, wherever it sits.

    The AIBOM generator leaves the model in components[] and fills
    metadata.component with its own scan job; a spec-shaped AI SBOM names the
    model as the document's component. Enrichment has to reach it either way.
    """
    found = []
    root = ((doc.get("metadata") or {}) if isinstance(doc.get("metadata"), dict) else {}).get("component")
    for c in ([root] if isinstance(root, dict) else []) + [c for c in (doc.get("components") or [])]:
        if isinstance(c, dict) and c.get("type") == "machine-learning-model":
            found.append(c)
    return found


CARD_TEXT_CAP = 256 * 1024
LIMITATION_CAP = 12


def _reads_as_sentence(text):
    """Whether a harvested fragment can stand as a statement on its own.

    A value cut out of a heading keeps the marks of where it was cut: it starts
    mid-sentence (lowercase, or a conjunction) or still carries the markdown
    around it. Neither is a judgement about the content, only about whether this
    is a whole sentence at all.
    """
    t = str(text or "").strip()
    if len(t) < 12 or "**" in t or t.startswith(("-", "*", "#")):
        return False
    first = t.split()[0].lower() if t.split() else ""
    if first in ("and", "or", "but", "with", "of", "to", "the"):
        # "the" starts plenty of real sentences, but a fragment beginning with a
        # bare article after a cut heading is the common shape here, and the cost
        # of dropping a true one is an empty field rather than a false claim.
        return t[0].isupper()
    return t[0].isupper() or t[0].isdigit()


def card_limitations(text):
    """Bullet items under a heading that is about limitations and nothing else.

    "Limitations", "Limitations and Biases", "Known limitations" all describe
    limitations. "Performance and Limitations" does not: it opens with what the
    model does well, and nothing in the text says where that stops and the
    limitations begin. Sections like the latter return nothing on purpose.
    """
    lines = str(text or "").splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if not m:
            continue
        title = m.group(1).strip()
        if not re.match(r"^(known\s+|technical\s+)?limitations?\b", title, re.IGNORECASE):
            continue
        out = []
        for nxt in lines[i + 1:]:
            if re.match(r"^#{1,6}\s+", nxt):
                break
            b = re.match(r"^\s*[-*+]\s+(.*\S)\s*$", nxt)
            if not b:
                continue
            item = re.sub(r"\*\*(.+?)\*\*", r"\1", b.group(1))
            item = re.sub(r"[*_`]", "", item).strip()
            if item:
                out.append(item[:500])
        return out[:LIMITATION_CAP]
    return []


models = model_components(sbom)
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

# The lookup, the component shape and the source walk live in hf_dataset.py, a
# standard-library module shared with the dataset-only scan and the declaration
# path, so every route reads a dataset the same way.
DATASET_MARK = hf_dataset.DATASET_MARK


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
        print(f"[enrich] {name}={raw!r} is not a whole number of zero or more; using {default}.",
              file=sys.stderr)
        return default


# How many levels of a dataset's own sources to follow, and how many datasets
# one scan may read in total. 0 depth reads only what the card names.
DATASET_DEPTH = _env_count("AIBOM_DATASET_DEPTH", 3)
DATASET_MAX_LOOKUPS = _env_count("AIBOM_DATASET_MAX_LOOKUPS", 40)


def collect_datasets(declared):
    """Read every dataset the model card declares, and their sources.

    Returns (components, root bom-refs, resolved_root_count, source edges).
    """
    if not declared:
        return [], [], 0, []
    ids = declared if isinstance(declared, list) else [declared]
    return hf_dataset.trace([str(i).strip() for i in ids if str(i or "").strip()],
                            max_depth=DATASET_DEPTH, budget=DATASET_MAX_LOOKUPS,
                            tag_signals=TAG_SIGNALS)


def _card_dataset_name(entry):
    """The dataset id an entry names, or "" when it names none.

    An entry carrying a `ref` points at a component elsewhere in this document
    and is left alone — resolving that reference is not this step's business.
    """
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, dict) and not entry.get("ref"):
        name = entry.get("name") or (entry.get("componentData") or {}).get("name") or ""
        return str(name).strip()
    return ""


def prune_prose_dataset_names(models, api, declared):
    """Drop dataset names the generator lifted out of the card's prose.

    The generator scrapes modelCard.modelParameters.datasets from the card text,
    so "pretrained on approximately 12.5 trillion tokens" leaves a dataset named
    "approximately" behind, and a table footnote "(*: public dataset only)"
    leaves "only". The G7 dataset cluster counts any name it finds as a declared
    dataset, so prose becomes a score for training data nobody disclosed.

    A name survives when the card's own frontmatter declares it, or when the
    datasets API can open it. One that is neither has nothing behind it. The
    frontmatter is trusted without a lookup, so a declared dataset that is gated,
    private or withdrawn is never removed for being unreadable.

    Returns the list of dropped names. Without an API nothing is dropped: "cannot
    be resolved right now" is not the same fact as "does not exist".
    """
    if api is None:
        return []
    frontmatter = declared if isinstance(declared, list) else ([declared] if declared else [])
    known = {str(d).strip() for d in frontmatter if str(d or "").strip()}
    dropped, checked = [], {}
    for m in models:
        params = (m.get("modelCard") or {}).get("modelParameters")
        if not isinstance(params, dict) or not isinstance(params.get("datasets"), list):
            continue
        kept = []
        for entry in params["datasets"]:
            name = _card_dataset_name(entry)
            if not name or name in known:
                kept.append(entry)
                continue
            if name not in checked:
                checked[name] = hf_dataset.dataset_exists(name)
            if checked[name]:
                kept.append(entry)
            elif name not in dropped:
                dropped.append(name)
        if kept:
            params["datasets"] = kept
        else:
            params.pop("datasets", None)
    return dropped

# Filled by the lineage walk below and read after the cdxgen harvest; empty when
# the hub could not be read.
lineage_items, _bases, relation = [], [], None
# Marks a pedigree this step built, so a re-run replaces its own and never a
# pedigree that came from cdxgen or from the generator.
PEDIGREE_MARK = "bomlens:lineage:source"

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
    # hashes[] above keeps the digests and drops the names, so a reader cannot
    # tell which digest belongs to which file. The pairs are kept here as well,
    # one property per file in sha256sum's "<digest>  <path>" layout, so a later
    # step can describe each weight file on its own. Capped like the dataset
    # digests; the true count rides along.
    WEIGHT_FILE_CAP = 256
    weight_files = sorted((n, s) for n, s in file_sha.items() if n.lower().endswith(WEIGHT_EXTS))

    gated = getattr(hf_info, "gated", None)          # False | "auto" | "manual" | None
    private = bool(getattr(hf_info, "private", False))
    has_weight = any(n.lower().endswith(WEIGHT_EXTS) for n in filenames)
    has_config = any(n.lower() == "config.json" for n in filenames)
    datasets = card_get(hf_info, "datasets")
    has_datasets = bool(datasets)
    try:
        dataset_comps, dataset_refs, resolved_datasets, source_edges = collect_datasets(datasets)
    except Exception as e:
        # A dataset answer of a shape nobody expected must not cost the model
        # the rest of its enrichment. The datasets stay as the card named them.
        print(f"[enrich] datasets skipped: {type(e).__name__}: {e}", file=sys.stderr)
        dataset_comps, dataset_refs, resolved_datasets, source_edges = [], [], 0, []
    # Names the generator scraped out of the card's prose are removed here, before
    # the openness axis and the conformance report read them as disclosed training
    # data. The fact of the removal is stamped so the report can be traced back.
    prose_dropped = prune_prose_dataset_names(models, hf_api, datasets)
    if prose_dropped:
        print(f"[enrich] datasets: dropped {len(prose_dropped)} card name(s) with no dataset "
              f"behind them ({', '.join(prose_dropped[:5])}).", file=sys.stderr)
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
    for name, sha in weight_files[:WEIGHT_FILE_CAP]:
        weights_props.append({"name": "bomlens:weights:file", "value": f"{sha}  {name}"})
    if len(weight_files) > WEIGHT_FILE_CAP:
        weights_props.append({"name": "bomlens:weights:filesRecorded",
                              "value": f"{WEIGHT_FILE_CAP} of {len(weight_files)}"})

    # ---- Repository facts kept for later steps ------------------------------
    # The gate kind (auto-approved or manually reviewed) and the time of the
    # revision that was read. Neither is a judgement: the time is when the
    # repository last changed, not when the model was released, and nothing
    # downstream may read it as a release date.
    repo_props = []
    if gated in ("auto", "manual"):
        repo_props.append({"name": "bomlens:hf:gated", "value": str(gated)})
    _rev_time = getattr(hf_info, "last_modified", None)
    if _rev_time:
        try:
            _rev_time = _rev_time.isoformat()
        except AttributeError:
            pass
        repo_props.append({"name": "bomlens:hf:revisionTime", "value": str(_rev_time)[:40]})

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

    # ---- Custom license text (license: other) -------------------------------
    # A model tagged "other" keeps its terms in the repository's LICENSE file.
    # Reading that one small text file (capped, still no weight download) lets
    # the assessment quote the restrictive wording instead of saying only
    # "unclassified". No match does NOT mean no restriction — the scan can
    # only raise concerns, so the property says "no-known-restriction" and the
    # verdict stays review either way.
    lic_props = []
    # What the card declares, for the licence-correction step in the model loop
    # below: None means the card named a licence and the component can keep it.
    declared_license = None
    model_license = card_get(hf_info, "license")
    if isinstance(model_license, list):
        model_license = model_license[0] if model_license else None
    if str(model_license or "").lower() == "other":
        LICENSE_TEXT_CAP = 256 * 1024
        lic_file = next((n for n in filenames
                         if re.match(r"^license([._-].*)?$", n.rsplit("/", 1)[-1], re.IGNORECASE)), None)
        lic_name = card_get(hf_info, "license_name")
        if lic_name:
            lic_props.append({"name": "bomlens:license:customName", "value": str(lic_name)[:120]})
        # The card is the declaration and it says the terms are not one of the
        # known ids, so that is what the component has to carry. Recorded as a
        # name, never guessed into an id — the same rule the dataset step follows.
        declared_license = {"name": str(lic_name)[:120] if lic_name else "other"}
        lic_link = card_get(hf_info, "license_link")
        if lic_link:
            lic_link = str(lic_link)
            if not lic_link.lower().startswith("http"):
                lic_link = f"https://huggingface.co/{model_id}/blob/main/{lic_link.lstrip('/')}"
            declared_license["url"] = lic_link[:500]
        text = ""
        if lic_file:
            try:
                from huggingface_hub import hf_hub_download
                _p = hf_hub_download(model_id, lic_file)
                with open(_p, "r", errors="replace") as fh:
                    text = fh.read(LICENSE_TEXT_CAP)
            except Exception as e:
                print(f"[enrich] custom license text unavailable: {e}", file=sys.stderr)
        else:
            print("[enrich] license tagged other but no LICENSE file found.", file=sys.stderr)
        if text:
            RANKS = {"ok": 1, "conditional": 2, "review": 3, "caution": 4}
            flat = re.sub(r"\s+", " ", text)
            hits, worst = [], "review"
            for pat in CUSTOM_PATTERNS:
                rx = pat.get("pattern")
                if not rx:
                    continue
                try:
                    m = re.search(rx, flat, re.IGNORECASE)
                except re.error:
                    continue
                if m:
                    quote = flat[m.start():m.start() + 200].strip()
                    hits.append(f"{pat.get('label', rx)}: \"{quote}\"")
                    v = str(pat.get("verdict", "review"))
                    if RANKS.get(v, 3) > RANKS.get(worst, 3):
                        worst = v
            if hits:
                lic_props.append({"name": "bomlens:license:customScan", "value": "matched"})
                lic_props.append({"name": "bomlens:license:customScan:verdict", "value": worst})
                lic_props.append({"name": "bomlens:license:customScan:quote", "value": "; ".join(hits)[:500]})
            else:
                lic_props.append({"name": "bomlens:license:customScan", "value": "no-known-restriction"})
            lic_props.append({"name": "bomlens:license:customScan:file", "value": lic_file})
            print(f"[enrich] custom license text scanned: {len(hits)} restrictive pattern(s).", file=sys.stderr)

    # ---- Model card: limitations and description ----------------------------
    # The generator harvests limitations with a regex over the whole README
    # (limitation[s]?[:\s]+([^.]+)): whatever follows the word, up to the first
    # full stop. On a card whose section is "Limitations and Biases" that yields
    # a heading fragment ("and Biases - **Factual reliability"); on one titled
    # "Performance and Limitations" it yields the section's opening sentence,
    # which says what the model does WELL. Both reached the reader as the model's
    # stated limitations.
    #
    # Read the card ourselves and keep only what is structurally unambiguous: the
    # bullet list under a heading that is about limitations and nothing else. A
    # heading naming a second subject yields nothing rather than a sentence we
    # cannot vouch for. An empty field reads as "not documented", which is true;
    # the old one read as documented and was wrong.
    card_text = ""
    try:
        from huggingface_hub import hf_hub_download
        _p = hf_hub_download(model_id, "README.md")
        with open(_p, "r", errors="replace") as fh:
            card_text = fh.read(CARD_TEXT_CAP)
    except Exception as e:
        print(f"[enrich] model card text unavailable: {e}", file=sys.stderr)

    harvested = card_limitations(card_text) if card_text else []
    for m in models:
        mc = m.get("modelCard")
        if not isinstance(mc, dict):
            continue
        cons = mc.get("considerations")
        if not isinstance(cons, dict):
            continue
        current = [str(x) for x in (cons.get("technicalLimitations") or [])]
        if harvested:
            cons["technicalLimitations"] = harvested
        elif card_text:
            # The card was read and holds no limitations section we can trust.
            cons.pop("technicalLimitations", None)
        else:
            # No card to check against: drop only what is visibly not a
            # statement: a fragment starting mid-sentence, or one carrying the
            # markdown it was cut out of.
            kept = [x for x in current if _reads_as_sentence(x)]
            if kept:
                cons["technicalLimitations"] = kept
            else:
                cons.pop("technicalLimitations", None)
        if not cons:
            mc.pop("considerations", None)
    if harvested:
        print(f"[enrich] model card: {len(harvested)} limitation(s) from the card's own list.",
              file=sys.stderr)

    # "No description available" is the generator's placeholder, not a
    # description. Carried into the SBOM it becomes a sentence the UI renders as
    # the model's summary and the conformance report counts as a filled field.
    for m in models:
        for holder in (m, m.get("modelCard") if isinstance(m.get("modelCard"), dict) else None):
            if not isinstance(holder, dict):
                continue
            if str(holder.get("description") or "").strip().lower() == "no description available":
                holder.pop("description", None)

    # ---- Base-model lineage -------------------------------------------------
    # A fine-tune inherits its base model's terms even when its own tag says
    # otherwise — a common mislabeling on the hub. Walk the base_model chain
    # (depth-capped, cycle-guarded, one light metadata call per ancestor) and
    # flag an ancestor whose license the registry marks inheritable when this
    # model declares something else.
    lineage_props = []
    # (id, license, unreadable) per ancestor walked, nearest first. Kept for the pedigree
    # built after the cdxgen harvest, which may supply its own.
    lineage_items = []
    _base = card_get(hf_info, "base_model")
    _bases = _base if isinstance(_base, list) else ([_base] if _base else [])
    _bases = [str(b).strip() for b in _bases if str(b or "").strip()]
    # How this model relates to its direct parent, as the hub tags it:
    # base_model:<relation>:<id>. Only the four relations the hub documents are
    # read; a bare base_model:<id> tag says nothing about the relation.
    LINEAGE_RELATIONS = ("finetune", "quantized", "adapter", "merge")
    relation = None
    if _bases:
        rels = set()
        for t in tags:
            parts = str(t).split(":", 2)
            if len(parts) == 3 and parts[0] == "base_model" and parts[1] in LINEAGE_RELATIONS \
               and parts[2] == _bases[0]:
                rels.add(parts[1])
        # Two relations to the same parent is a contradiction, not a choice.
        relation = rels.pop() if len(rels) == 1 else None
    if _bases:
        chain, visited = [], {model_id}
        own_term = _match_term(model_license)
        conflict = None
        cur, depth = str(_bases[0]), 0
        while cur and cur not in visited and depth < 5:
            visited.add(cur)
            depth += 1
            try:
                binfo = hf_api.model_info(cur)
            except Exception as e:
                print(f"[enrich] lineage: {cur} unreadable: {e}", file=sys.stderr)
                chain.append(f"{cur}:unreadable")
                lineage_items.append((cur, None, True))
                break
            blic = card_get(binfo, "license")
            if isinstance(blic, list):
                blic = blic[0] if blic else None
            chain.append(f"{cur}:{blic or 'none'}")
            lineage_items.append((cur, str(blic) if blic else None, False))
            bterm = _match_term(blic)
            if conflict is None and bterm and bterm.get("inheritable") \
               and (own_term is None or own_term.get("key") != bterm.get("key")):
                conflict = (cur, str(blic))
            nxt = card_get(binfo, "base_model")
            if isinstance(nxt, list):
                nxt = nxt[0] if nxt else None
            cur = str(nxt) if nxt else None
        if chain:
            lineage_props.append({"name": "bomlens:lineage:chain", "value": " > ".join(chain)[:500]})
            lineage_props.append({"name": "bomlens:lineage:rootLicense",
                                  "value": chain[-1].rsplit(":", 1)[-1]})
            if conflict:
                lineage_props.append({"name": "bomlens:lineage:conflict", "value": "true"})
                lineage_props.append({"name": "bomlens:lineage:conflictWith",
                                      "value": f"{conflict[0]} ({conflict[1]})"})
            print(f"[enrich] lineage: {len(chain)} ancestor(s), "
                  f"conflict={'yes' if conflict else 'no'}.", file=sys.stderr)
        if relation:
            lineage_props.append({"name": "bomlens:lineage:relation", "value": relation})
        # The chain follows the first parent only. A merge names several; the
        # others are recorded by id so they are not silently lost, and are not
        # walked (their licenses are not read).
        if len(_bases) > 1:
            lineage_props.append({"name": "bomlens:lineage:otherParents",
                                  "value": ", ".join(dict.fromkeys(_bases[1:]))[:500]})

    # ---- Distributed weights scope (observed signals only) ------------------
    # Whether the repository ships full weights, an adapter that needs its base
    # model to run, a quantized copy, or a merge. Read from what the hub states:
    # the base_model relation tag, the file list, and the declared library. A
    # value is written only when the signals agree; when they disagree the
    # signals themselves are recorded and the scope is left for a person.
    scope_signals = {}
    if relation == "adapter":
        scope_signals["tag"] = "adapter"
    elif relation == "quantized":
        scope_signals["tag"] = "quantized"
    elif relation == "merge":
        scope_signals["tag"] = "merged"
    base_names = [n.rsplit("/", 1)[-1].lower() for n in filenames]
    adapter_files = any(b == "adapter_config.json" for b in base_names) and \
        any(b.startswith("adapter_model.") for b in base_names)
    full_weights = any(n.lower().endswith(WEIGHT_EXTS)
                       and not n.rsplit("/", 1)[-1].lower().startswith("adapter_model.")
                       for n in filenames)
    if adapter_files and not full_weights:
        scope_signals["files"] = "adapter"
    if str(library or "").lower() == "peft":
        scope_signals["library"] = "adapter"
    if relation == "finetune" and full_weights and not adapter_files:
        scope_signals["tag"] = "full"
    scope_values = set(scope_signals.values())
    if len(scope_values) == 1:
        weights_props.append({"name": "bomlens:weights:scope", "value": scope_values.pop()})
    elif len(scope_values) > 1:
        weights_props.append({"name": "bomlens:weights:scopeSignals",
                              "value": ", ".join(f"{k}:{v}" for k, v in sorted(scope_signals.items()))})

    # A card that says "other" leaves the generator with no id to copy, so it
    # guesses one from the LICENSE text by substring — "limited" or "submit" in an
    # Apache-derived custom licence is enough to make it read as MIT, and the SBOM
    # then names terms the model was never released under. The declaration wins;
    # the guess is kept as a property so the correction is traceable rather than
    # silent. Runs before the property assembly below so the note lands with it.
    if declared_license is not None:
        guessed = []
        for m in models:
            guessed += [str((e.get("license") or {}).get("id"))
                        for e in (m.get("licenses") or [])
                        if isinstance(e, dict) and (e.get("license") or {}).get("id")]
            m["licenses"] = [{"license": dict(declared_license)}]
        if guessed:
            lic_props.append({"name": "bomlens:license:replacedGuess",
                              "value": ", ".join(sorted(set(guessed)))[:120]})
            print("[enrich] licence: the card declares 'other'; replaced the generated id "
                  f"({', '.join(sorted(set(guessed)))}) with the declared terms.", file=sys.stderr)

    for m in models:
        if weight_hashes:
            existing = m.get("hashes") or []
            seen = {(h.get("alg"), h.get("content")) for h in existing if isinstance(h, dict)}
            for h in weight_hashes:
                if (h["alg"], h["content"]) not in seen:
                    existing.append(h)
                    seen.add((h["alg"], h["content"]))
            m["hashes"] = existing
        # A second run finds the prose names already gone, so it drops nothing;
        # the note from the first run is carried over instead of being erased.
        prior_dropped = [str(p.get("value")) for p in (m.get("properties") or [])
                         if p.get("name") == "bomlens:card:datasetNameDropped" and p.get("value")]
        dropped_note = ", ".join(prose_dropped)[:300] if prose_dropped else (prior_dropped[0] if prior_dropped else "")
        # Replace any prior openness/scan/weights properties so re-runs stay
        # idempotent (same contract as the DATASET_MARK components below).
        props = [p for p in (m.get("properties") or [])
                 if not str(p.get("name", "")).startswith(
                     ("openness:", "bomlens:hf:scan:", "bomlens:weights:",
                      "bomlens:license:", "bomlens:lineage:",
                      "bomlens:hf:gated", "bomlens:hf:revisionTime",
                      "bomlens:card:datasetName"))]
        for name, value in openness.items():
            props.append({"name": name, "value": value})
        props.extend(scan_props)
        props.extend(weights_props)
        props.extend(repo_props)
        props.extend(lic_props)
        props.extend(lineage_props)
        if dropped_note:
            props.append({"name": "bomlens:card:datasetNameDropped", "value": dropped_note})
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

        removed = {c.get("bom-ref") for c in comps if ours(c) and c.get("bom-ref")}
        comps[:] = [c for c in comps if not ours(c)]
        comps.extend(dataset_comps)
        sbom["components"] = comps

        # dependencies[]: the model depends on the data it was trained on. This
        # is the relationship the G7 dataset cluster names, and what makes the
        # dependency graph in the UI show the training data. Only the datasets
        # the card names hang off the model; a dataset's sources hang off that
        # dataset, so the model reaches them through it.
        new_refs = {c["bom-ref"] for c in dataset_comps}
        deps = sbom.get("dependencies") or []
        stale = removed | new_refs
        deps = [d for d in deps if not (isinstance(d, dict) and d.get("ref") in stale)]
        gone = removed - new_refs
        for d in deps:
            if isinstance(d, dict) and isinstance(d.get("dependsOn"), list):
                d["dependsOn"] = [x for x in d["dependsOn"] if x not in gone]
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
            # The model's dataset edges are exactly the datasets its card names:
            # a dataset that was a root on an earlier run and is now only a
            # source must not keep its edge from the model.
            on = [x for x in (entry.get("dependsOn") or []) if x not in removed and x not in new_refs]
            entry["dependsOn"] = on + [r for r in dataset_refs if r not in on]
        # Every referenced ref needs its own node, even a leaf one.
        for c in dataset_comps:
            ref = c["bom-ref"]
            deps.append({"ref": ref, "dependsOn": [t for f, t in source_edges if f == ref]})
        sbom["dependencies"] = deps
        print(f"[enrich] datasets: {len(dataset_refs)} referenced, {resolved_datasets} resolved, "
              f"{len(dataset_comps) - len(dataset_refs)} source(s) traced "
              f"(training-data={training_data}).", file=sys.stderr)

def _ours(pedigree):
    anc = (pedigree or {}).get("ancestors") if isinstance(pedigree, dict) else None
    return bool(anc) and all(
        any(p.get("name") == PEDIGREE_MARK for p in (a.get("properties") or []))
        for a in anc if isinstance(a, dict))


# A pedigree this step wrote on an earlier run is dropped first, so the harvest
# below and the rebuild after it see the document as the generator left it.
for m in models:
    if _ours(m.get("pedigree")):
        m.pop("pedigree", None)

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
        cg_models = model_components(cg)
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

# ---- Pedigree from the lineage chain ----------------------------------------
# CycloneDX records where a component came from in pedigree.ancestors[]. When
# cdxgen supplied none, the chain walked above is turned into ancestor
# components: the id, a purl without a version, and the license the ancestor's
# own card declares. No version is written. The revision the walk saw is the
# ancestor's current head, not the one this model was trained from, and writing
# it would read as that.
def _lineage_ancestor(idx, anc_id, lic, rel, unreadable=False):
    props = [{"name": PEDIGREE_MARK, "value": "chain"}]
    if idx == 0 and rel:
        props.append({"name": "bomlens:lineage:relation", "value": rel})
    if unreadable:
        props.append({"name": "bomlens:lineage:unreadable", "value": "true"})
    comp = {
        "type": "machine-learning-model",
        "bom-ref": "lineage:huggingface/" + anc_id,
        "name": anc_id,
        "purl": "pkg:huggingface/" + anc_id,
        "properties": props,
    }
    if lic and lic != "none":
        comp["licenses"] = [{"license": {"name": lic}}]
    return comp


if lineage_items or len(_bases) > 1:
    ancestors = [_lineage_ancestor(i, a, lic, relation, unreadable=bad)
                 for i, (a, lic, bad) in enumerate(lineage_items)]
    seen_ids = {a for a, _, _ in lineage_items}
    for other in _bases[1:]:
        if other not in seen_ids:
            seen_ids.add(other)
            ancestors.append(_lineage_ancestor(len(ancestors), other, None, None))
    built = 0
    for m in models:
        if not m.get("pedigree") and ancestors:
            m["pedigree"] = {"ancestors": [dict(a) for a in ancestors]}
            built += 1
    if built:
        print(f"[enrich] pedigree: {len(ancestors)} ancestor(s) from the lineage chain.", file=sys.stderr)

# ---- The document's subject is the model ------------------------------------
# CycloneDX names what an SBOM is about in metadata.component. The generator puts
# its own scan job there (job-<timestamp>, supplied by "OWASP AIBOM Generator")
# and leaves the model under components[], which makes the document say it
# describes a generator run that happens to contain a model. Everything that reads
# an SBOM as "one subject plus its parts" then reads it wrong: the 2026 minimum
# elements score the job as a component with no licence and no hash, the
# dependency root points at an id nothing in the document defines, and the web UI
# had to special-case the job name out of its scan list.
#
# So the model is promoted to the subject and the job is dropped. Nothing is lost:
# the generator is already named in metadata.tools, and the job id was a
# timestamp. Only a generator-shaped document is rewritten — a model already at
# the root is left exactly as it is.
def _defined_refs():
    """Every bom-ref the document defines, root included."""
    refs = set()
    root = (sbom.get("metadata") or {}).get("component")
    for c in ([root] if isinstance(root, dict) else []) + [
            c for c in (sbom.get("components") or []) if isinstance(c, dict)]:
        if c.get("bom-ref"):
            refs.add(c["bom-ref"])
    return refs


def promote_model_to_root():
    meta = sbom.setdefault("metadata", {})
    if not isinstance(meta, dict):
        return None
    root = meta.get("component")
    if isinstance(root, dict) and root.get("type") == "machine-learning-model":
        return None
    body = sbom.get("components")
    if not isinstance(body, list):
        return None
    model = next((c for c in body
                  if isinstance(c, dict) and c.get("type") == "machine-learning-model"), None)
    if model is None:
        return None
    old_ref = root.get("bom-ref") if isinstance(root, dict) else None
    model_ref = model.get("bom-ref")
    body.remove(model)
    meta["component"] = model
    # Dependency edges: the generator writes a root edge under an id it never
    # defines as a component, whose only dependsOn is the model. Fold that edge
    # into the model's own, then drop every reference to the ids that are gone —
    # a dangling ref is worse than a missing edge, because a consumer reads it as
    # a component it failed to find.
    deps = sbom.get("dependencies")
    if isinstance(deps, list) and model_ref:
        stale = {r for r in (old_ref, model.get("purl")) if r and r != model_ref}
        # An edge keyed on a stale id contributes its dependsOn to the model.
        adopted, kept = [], []
        for d in deps:
            if not isinstance(d, dict):
                continue
            ref = d.get("ref")
            if ref in stale or (ref is not None and ref not in _defined_refs() and ref != model_ref):
                adopted += [x for x in (d.get("dependsOn") or []) if x != model_ref]
                continue
            kept.append(d)
        # The subject always gets its own entry, even with nothing to depend on: a
        # document that lists no relationships at all is a different (and worse)
        # statement than one that says the subject depends on nothing recorded.
        model_edge = next((d for d in kept if d.get("ref") == model_ref), None)
        if model_edge is None:
            model_edge = {"ref": model_ref, "dependsOn": []}
            kept.append(model_edge)
        if adopted:
            model_edge["dependsOn"] = list(dict.fromkeys(
                (model_edge.get("dependsOn") or []) + adopted))
        defined = _defined_refs()
        for d in kept:
            if isinstance(d.get("dependsOn"), list):
                d["dependsOn"] = [x for x in d["dependsOn"] if x in defined]
        sbom["dependencies"] = kept
    return model.get("name")


promoted = promote_model_to_root()
if promoted:
    print(f"[enrich] subject: {promoted} is now the document's component "
          "(the generator's scan job is not what this SBOM describes).", file=sys.stderr)

with open(sbom_path, "w") as f:
    json.dump(sbom, f, indent=2)
print("[enrich] enrichment complete.", file=sys.stderr)
PY

exit 0
