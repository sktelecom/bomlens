// @no-unit-test: static guidance data table (CycloneDX snippets + doc links); no logic to unit test.
/**
 * Static, per-G7-element guidance for the conformance view: a small CycloneDX
 * fragment showing the correct shape, plus a link to authoritative docs. Ids
 * mirror docker/lib/g7-registry.json exactly. The map may be a subset — an
 * element without an entry simply renders no snippet/link (na "human review"
 * elements have no meaningful fragment). The snippets carry SBOM/CycloneDX
 * field names, so they are not localized — the locale files hold only the
 * surrounding labels (g7.example / g7.learnMore). URLs were verified to resolve
 * at the time of writing.
 */
export interface G7Guidance {
  /** A correct CycloneDX fragment that would satisfy this element. */
  snippet: string;
  /** Authoritative documentation for providing this element. */
  docUrl: string;
}

export const G7_GUIDANCE: Record<string, G7Guidance> = {
  // ---- Metadata ----
  "g7-meta-signature": {
    snippet: `"signature": {
  "algorithm": "ES256",
  "value": "MEUCIQD…"
}`,
    docUrl: "https://cyclonedx.org/capabilities/signing/",
  },
  // ---- Models ----
  "g7-model-name": {
    snippet: `{
  "type": "machine-learning-model",
  "name": "Qwen2.5-0.5B"
}`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-id": {
    snippet: `{
  "type": "machine-learning-model",
  "name": "Qwen2.5-0.5B",
  "purl": "pkg:huggingface/Qwen/Qwen2.5-0.5B"
}`,
    docUrl: "https://github.com/package-url/purl-spec",
  },
  "g7-model-version": {
    snippet: `{
  "type": "machine-learning-model",
  "name": "Qwen2.5-0.5B",
  "version": "0.5B"
}`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-description": {
    snippet: `{
  "type": "machine-learning-model",
  "description": "0.5B-parameter causal language model."
}`,
    docUrl: "https://huggingface.co/docs/hub/model-cards",
  },
  "g7-model-license": {
    snippet: `"licenses": [
  { "license": { "id": "Apache-2.0" } }
]`,
    docUrl: "https://huggingface.co/docs/hub/repositories-licenses",
  },
  "g7-model-openness": {
    snippet: `"properties": [
  { "name": "openness:weights", "value": "open-weight" },
  { "name": "openness:training-data", "value": "open-data" }
]`,
    docUrl: "https://isitopen.ai/",
  },
  "g7-model-card": {
    snippet: `"modelCard": {
  "modelParameters": {
    "architectureFamily": "transformer",
    "modelArchitecture": "Qwen2ForCausalLM"
  }
}`,
    docUrl: "https://huggingface.co/docs/hub/model-cards",
  },
  "g7-model-io": {
    snippet: `"modelCard": {
  "modelParameters": {
    "inputs": [ { "format": "text" } ],
    "outputs": [ { "format": "text" } ]
  }
}`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-training": {
    snippet: `"modelCard": {
  "modelParameters": {
    "datasets": [ { "ref": "dataset:wikipedia" } ],
    "modelArchitecture": "Qwen2ForCausalLM"
  }
}`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-hash-value": {
    snippet: `"hashes": [
  { "alg": "SHA-256", "content": "9f86d081884c7d65…" }
]`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-hash-alg": {
    snippet: `"hashes": [
  { "alg": "SHA-256", "content": "9f86d081884c7d65…" }
]`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-model-extref": {
    snippet: `"externalReferences": [
  { "type": "distribution", "url": "https://huggingface.co/Qwen/Qwen2.5-0.5B" }
]`,
    docUrl: "https://cyclonedx.org/docs/1.7/json/#components_items_externalReferences",
  },
  // ---- Datasets Properties ----
  "g7-ds-name": {
    snippet: `{
  "type": "data",
  "bom-ref": "dataset:wikipedia",
  "name": "wikipedia"
}`,
    docUrl: "https://huggingface.co/docs/hub/datasets-cards",
  },
  "g7-ds-description": {
    snippet: `{
  "type": "data",
  "name": "wikipedia",
  "description": "Cleaned Wikipedia article dumps."
}`,
    docUrl: "https://huggingface.co/docs/hub/datasets-cards",
  },
  "g7-ds-identifier": {
    snippet: `{
  "type": "data",
  "bom-ref": "dataset:wikipedia",
  "purl": "pkg:huggingface/datasets/wikipedia"
}`,
    docUrl: "https://github.com/package-url/purl-spec",
  },
  "g7-ds-license": {
    snippet: `{
  "type": "data",
  "name": "wikipedia",
  "licenses": [ { "license": { "id": "CC-BY-SA-3.0" } } ]
}`,
    docUrl: "https://huggingface.co/docs/hub/datasets-cards",
  },
  "g7-ds-provenance": {
    snippet: `"componentData": {
  "governance": { "custodians": [ { "organization": { "name": "Wikimedia" } } ] }
}`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  // ---- Infrastructure ----
  "g7-infra-hardware": {
    snippet: `"externalReferences": [
  { "type": "bom", "url": "https://example.com/hbom.json" }
]`,
    docUrl: "https://cyclonedx.org/capabilities/hbom/",
  },
};
