#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Write the AI service a publisher declared, and the model values the
declaration states, into the CycloneDX SBOM.

Usage: apply-declared-service.py <bom.json> <declaration.json>

The declaration's 'service' (the application or API the model runs in) is
written as CycloneDX services[], so the SBOM and the G7 system-level checks
see it:

    services[] (application)  bom-ref service:declared/<slug of the name>
        name, version, provider.name (suppliedBy), endpoints[0]
        (downloadLocation), description (informationAboutApplication),
        data[] (dataFlows, as CycloneDX serviceData), externalReferences
        documentation (disclosureUrl), and properties
        bomlens:service:domain, :autonomyType, :input, :output, :releaseTime
    services[] (external-model)  bom-ref service:declared-external/<key>
        one per externalModels[]: name, version, provider.name, endpoints
    dependencies[]  the service -> the model's bom-ref and each external model
    declarations.claims[]  one per standardCompliance entry, targeting the
        service, predicate the standard's name, reasoning saying it is the
        publisher's declaration, not verified by BomLens

Every service written here carries bomlens:origin=declared-input and
bomlens:service:kind (application or external-model); the application service
also carries bomlens:service:declarationDigest, the digest the SPDX
converter's check reports, so the check can tell whether the SBOM follows the
current declaration (service.state applied or pendingScan).

The model's declared values go on the model component:

    properties bomlens:regulatory:trainingComputeFlops, :trainingComputeBasis,
               :adversarialTesting
    modelCard.modelParameters.inputs[] / outputs[]  {"format": <kind>} from
               inputModality / outputModality, only where the scan wrote none

What came from the declaration is named on the model with one
`bomlens:declared` property per item, its value the CycloneDX location written
(a property name such as bomlens:regulatory:trainingComputeFlops, or
modelCard.modelParameters.inputs; modelCard and modelCard.modelParameters too
when this step had to create them). Where the scan already recorded inputs or
outputs, those observed values win and are kept; the declared kinds are then
not written and `bomlens:declared:observedKept` names the location. The model
also carries bomlens:model:declarationDigest, the same digest.

Only a declaration the SPDX converter accepts is applied (the same reading of
the same file), so the SBOM and the SPDX 3.0.1 document never disagree about
it. A declaration it refuses, or one that cannot be read, leaves the SBOM as it
is. Applying is idempotent: whatever an earlier run wrote (the services marked
declared-input, their dependencies and claims, and the model values named by
bomlens:declared) is removed first, so a declaration that no longer has a
service removes it. Nothing here reads the network or the clock; the bom-refs
come from the declaration, so the output is the same bytes on every run.
Exit 0 unless the SBOM itself cannot be written.
"""
import copy
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVICE_REF = "service:declared/"
EXTERNAL_REF = "service:declared-external/"
CLAIM_REF = "claim:declared/"
CLAIM_REASONING = "publisher's declaration, not verified by BomLens"
DECLARED_PROP = "bomlens:declared"
OBSERVED_KEPT_PROP = "bomlens:declared:observedKept"
REGULATORY = (("trainingComputeFlops", "bomlens:regulatory:trainingComputeFlops"),
              ("trainingComputeBasis", "bomlens:regulatory:trainingComputeBasis"),
              ("adversarialTesting", "bomlens:regulatory:adversarialTesting"))
MODEL_CARD = "modelCard"
MODEL_PARAMS = "modelCard.modelParameters"
IO_FIELDS = (("inputModality", "inputs"), ("outputModality", "outputs"))


def _converter():
    spec = importlib.util.spec_from_file_location("convert_to_spdx3_ai", os.path.join(HERE, "convert-to-spdx3-ai.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _slug(name):
    s = re.sub(r"[^a-z0-9._-]+", "-", str(name).lower()).strip("-._")
    return s[:64].rstrip("-._") or "service"


def _prop_value(obj, name):
    for p in obj.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == name:
            return p.get("value")
    return None


def _is_declared(svc):
    return isinstance(svc, dict) and _prop_value(svc, "bomlens:origin") == "declared-input"


def remove_previous(bom, model):
    """Take out everything an earlier run wrote. Returns nothing; edits bom."""
    gone = set()
    services = bom.get("services")
    if isinstance(services, list):
        gone = {s.get("bom-ref") for s in services if _is_declared(s)}
        kept = [s for s in services if not _is_declared(s)]
        if kept:
            bom["services"] = kept
        else:
            del bom["services"]
    deps = bom.get("dependencies")
    if isinstance(deps, list) and gone:
        out = []
        for d in deps:
            if isinstance(d, dict) and d.get("ref") in gone:
                continue
            if isinstance(d, dict) and isinstance(d.get("dependsOn"), list):
                d["dependsOn"] = [x for x in d["dependsOn"] if x not in gone]
            out.append(d)
        bom["dependencies"] = out
    decls = bom.get("declarations")
    if isinstance(decls, dict) and isinstance(decls.get("claims"), list):
        claims = [c for c in decls["claims"]
                  if not (isinstance(c, dict) and str(c.get("bom-ref", "")).startswith(CLAIM_REF))]
        if claims:
            decls["claims"] = claims
        else:
            del decls["claims"]
        if not decls:
            del bom["declarations"]
    if model is None:
        return
    props = model.get("properties") if isinstance(model.get("properties"), list) else []
    written = {p.get("value") for p in props if isinstance(p, dict) and p.get("name") == DECLARED_PROP}
    ours = {DECLARED_PROP, OBSERVED_KEPT_PROP, CONV.MODEL_DIGEST_PROP} | {n for _, n in REGULATORY if n in written}
    if "properties" in model:
        kept = [p for p in props if not (isinstance(p, dict) and p.get("name") in ours)]
        if kept:
            model["properties"] = kept
        else:
            del model["properties"]
    card = model.get("modelCard")
    params = card.get("modelParameters") if isinstance(card, dict) else None
    if isinstance(params, dict):
        for _, key in IO_FIELDS:
            if f"{MODEL_PARAMS}.{key}" in written:
                params.pop(key, None)
        if MODEL_PARAMS in written and not params:
            del card["modelParameters"]
    if isinstance(card, dict) and MODEL_CARD in written and not card:
        del model["modelCard"]


def _service_entry(svc, digest):
    entry = {"bom-ref": SERVICE_REF + _slug(svc["name"])}
    if svc.get("suppliedBy"):
        entry["provider"] = {"name": svc["suppliedBy"]["name"]}
    entry["name"] = svc["name"]
    if svc.get("packageVersion"):
        entry["version"] = svc["packageVersion"]
    if svc.get("informationAboutApplication"):
        entry["description"] = svc["informationAboutApplication"]
    if svc.get("downloadLocation"):
        entry["endpoints"] = [svc["downloadLocation"]]
    if svc.get("dataFlows"):
        entry["data"] = [{k: f[k] for k in CONV.DATA_FLOW_KEYS if k in f} for f in svc["dataFlows"]]
    if svc.get("disclosureUrl"):
        entry["externalReferences"] = [{"type": "documentation", "url": svc["disclosureUrl"],
                                        "comment": "AI disclosure page, from the publisher's declaration"}]
    props = [{"name": "bomlens:origin", "value": CONV.DECLARED_ORIGIN},
             {"name": CONV.SERVICE_KIND_PROP, "value": "application"}]
    props += [{"name": "bomlens:service:domain", "value": d} for d in svc.get("domain") or []]
    if svc.get("autonomyType"):
        props.append({"name": "bomlens:service:autonomyType", "value": svc["autonomyType"]})
    props += [{"name": "bomlens:service:input", "value": m} for m in svc.get("inputModality") or []]
    props += [{"name": "bomlens:service:output", "value": m} for m in svc.get("outputModality") or []]
    if svc.get("releaseTime"):
        props.append({"name": "bomlens:service:releaseTime", "value": svc["releaseTime"]})
    props.append({"name": CONV.SERVICE_DIGEST_PROP, "value": digest})
    entry["properties"] = props
    return entry


def _external_entry(em):
    entry = {"bom-ref": EXTERNAL_REF + em["key"]}
    if em.get("suppliedBy"):
        entry["provider"] = {"name": em["suppliedBy"]["name"]}
    entry["name"] = em["name"]
    if em.get("packageVersion"):
        entry["version"] = em["packageVersion"]
    if em.get("endpoint"):
        entry["endpoints"] = [em["endpoint"]]
    entry["properties"] = [{"name": "bomlens:origin", "value": CONV.DECLARED_ORIGIN},
                           {"name": CONV.SERVICE_KIND_PROP, "value": "external-model"},
                           {"name": "bomlens:service:declarationKey", "value": em["key"]}]
    return entry


def write_service(bom, svc, model, digest, notes):
    if not svc.get("name"):
        notes.append("the declared service has no name, which CycloneDX requires; it is not written")
        return
    app = _service_entry(svc, digest)
    taken = {x.get("bom-ref") for x in (bom.get("components") or []) + (bom.get("services") or [])
             if isinstance(x, dict)}
    meta = (bom.get("metadata") or {}).get("component")
    if isinstance(meta, dict):
        taken.add(meta.get("bom-ref"))
    if app["bom-ref"] in taken:
        notes.append(f"bom-ref {app['bom-ref']} is already used in this SBOM; the service is not written")
        return
    externals = [_external_entry(em) for em in svc.get("externalModels") or []]
    bom.setdefault("services", []).extend([app] + externals)

    targets = []
    model_ref = model.get("bom-ref") if isinstance(model, dict) else None
    if model_ref:
        targets.append(model_ref)
    else:
        notes.append("the model component has no bom-ref, so the service's dependency on it is not written")
    targets += [e["bom-ref"] for e in externals]
    deps = bom.setdefault("dependencies", [])
    deps.append({"ref": app["bom-ref"], "dependsOn": targets})
    deps.extend({"ref": e["bom-ref"], "dependsOn": []} for e in externals)

    standards = svc.get("standardCompliance") or []
    if standards:
        decls = bom.setdefault("declarations", {})
        claims = decls.setdefault("claims", [])
        slug = _slug(svc["name"])
        for i, std in enumerate(standards, 1):
            claims.append({"bom-ref": f"{CLAIM_REF}{slug}/{i}", "target": app["bom-ref"],
                           "predicate": std, "reasoning": CLAIM_REASONING})


def write_model_values(model, values, digest):
    props = model.setdefault("properties", [])
    declared = []
    for field, name in REGULATORY:
        if field in values:
            props.append({"name": name, "value": values[field]})
            declared.append(name)
    observed_kept = []
    for field, key in IO_FIELDS:
        kinds = values.get(field)
        if not kinds:
            continue
        card = model.get("modelCard")
        params = card.get("modelParameters") if isinstance(card, dict) else None
        if isinstance(params, dict) and params.get(key):
            observed_kept.append(f"{MODEL_PARAMS}.{key}")
            continue
        if not isinstance(card, dict):
            card = model["modelCard"] = {}
            declared.append(MODEL_CARD)
        if not isinstance(card.get("modelParameters"), dict):
            card["modelParameters"] = {}
            declared.append(MODEL_PARAMS)
        card["modelParameters"][key] = [{"format": k} for k in kinds]
        declared.append(f"{MODEL_PARAMS}.{key}")
    props += [{"name": DECLARED_PROP, "value": d} for d in declared]
    props += [{"name": OBSERVED_KEPT_PROP, "value": o} for o in observed_kept]
    props.append({"name": CONV.MODEL_DIGEST_PROP, "value": digest})
    return observed_kept


def apply(bom, decl):
    """Edit bom for the normalized declaration. Returns notes for the log."""
    root = CONV.find_root(bom)
    model = root if isinstance(root, dict) and root.get("type") == "machine-learning-model" else None
    remove_previous(bom, model)
    notes = []
    service = (decl or {}).get("service")
    values = CONV.declared_model_values(decl)
    if not service and not values:
        return notes
    digest = CONV.service_digest(service, values)
    if service:
        write_service(bom, service, model, digest, notes)
    if values and model is not None:
        for loc in write_model_values(model, values, digest):
            notes.append(f"the scan already recorded {loc}; the observed values are kept")
    return notes


def main(argv):
    if len(argv) != 2:
        print("usage: apply-declared-service.py <bom.json> <declaration.json>", file=sys.stderr)
        return 1
    bom_path, decl_path = argv
    try:
        with open(bom_path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"[service] cannot read the SBOM: {e}", file=sys.stderr)
        return 0
    if not isinstance(bom, dict):
        print("[service] the SBOM is not a JSON object; nothing applied", file=sys.stderr)
        return 0
    try:
        mapping = CONV.load_map(os.environ.get("BOMLENS_SPDX3_MAP") or os.path.join(HERE, "spdx3-ai-map.json"))
    except (OSError, ValueError, KeyError) as e:
        print(f"[service] cannot read the SPDX 3.0.1 mapping: {e}", file=sys.stderr)
        return 0
    root = CONV.find_root(bom)
    if root is None:
        return 0
    try:
        decl = CONV.read_declaration(decl_path, mapping, bom, root)
    except CONV.Refused:
        print("[service] the declaration is refused (see the SPDX 3.0.1 step); nothing from it is written "
              "to the CycloneDX SBOM", file=sys.stderr)
        return 0
    except OSError as e:
        print(f"[service] cannot read the declaration: {e}", file=sys.stderr)
        return 0
    before = copy.deepcopy(bom)
    notes = apply(bom, decl)
    for n in notes:
        print(f"[service] {n}", file=sys.stderr)
    if bom == before:
        return 0
    tmp = bom_path + ".service.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, bom_path)
    except OSError as e:
        print(f"[service] could not write the SBOM: {e}", file=sys.stderr)
        return 1
    svc = (decl or {}).get("service")
    written = [s for s in bom.get("services") or [] if _is_declared(s)]
    if svc and written:
        print(f"[service] declared service written: {svc.get('name')} "
              f"({len(written) - 1} external model(s), {len((svc.get('standardCompliance') or []))} standard claim(s))")
    elif not svc:
        print("[service] no service declared; any earlier declared service removed")
    if CONV.declared_model_values(decl):
        print("[service] the model's declared values written, marked bomlens:declared")
    return 0


CONV = _converter()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
