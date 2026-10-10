#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Regenerate spdx-json-schema-extract.json from the SPDX 3.0.1 JSON schema.

Usage: extract-spdx-schema.py <spdx-json-schema.json> > spdx-json-schema-extract.json

Keeps only what tests/test-spdx3-ai.sh compares the mapping file against: the
property names and required lists of the classes the converter writes, and the
allowed values of the enumerated properties it uses. See README.md for the
source and its licence.
"""
import hashlib
import json
import sys

CLASSES = [
    "ai_AIPackage", "dataset_DatasetPackage", "software_Package", "software_File", "CreationInfo",
    "SpdxDocument", "Relationship", "LifecycleScopedRelationship", "Annotation", "Hash", "ExternalRef",
    "DictionaryEntry", "simplelicensing_LicenseExpression", "extension_CdxPropertiesExtension",
    "extension_CdxPropertyEntry", "Organization", "Person", "Agent", "Tool",
]


def _is_array(prop):
    """Whether the schema writes this property as a JSON array."""
    if prop.get("type") == "array":
        return True
    return any(alt.get("type") == "array" for alt in prop.get("anyOf", []) if isinstance(alt, dict))


def props_of(defs, name, seen=None):
    seen = seen or set()
    if name in seen or name not in defs:
        return {}, set()
    seen.add(name)
    keys, required = {}, set()
    node = defs[name]
    for part in node.get("allOf", [node]):
        ref = part.get("$ref")
        if ref:
            k, r = props_of(defs, ref.split("/")[-1], seen)
            keys.update(k)
            required |= r
            continue
        for k, v in (part.get("properties") or {}).items():
            keys[k] = _is_array(v) if isinstance(v, dict) else False
        required |= set(part.get("required") or [])
    return keys, required


def main(path):
    raw = open(path, "rb").read()
    defs = json.loads(raw)["$defs"]
    classes = {}
    for c in CLASSES:
        keys, required = props_of(defs, c + "_props")
        classes[c] = {"properties": sorted(keys), "arrays": sorted(k for k, a in keys.items() if a),
                      "required": sorted(required)}
    enums = {k: sorted(v["enum"]) for k, v in sorted(defs.items())
             if k.startswith("prop_") and isinstance(v, dict) and "enum" in v}
    out = {
        "source": "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        "sourceSha256": hashlib.sha256(raw).hexdigest(),
        "classes": classes,
        "enums": enums,
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
