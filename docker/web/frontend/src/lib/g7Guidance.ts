// @no-unit-test: static guidance data table (CycloneDX snippets + doc links); no logic to unit test.
/**
 * Static, per-G7-element guidance for the conformance view: a small CycloneDX
 * fragment showing the correct shape, plus a link to authoritative docs. The
 * snippets carry SBOM/CycloneDX field names, so they are not localized — the
 * locale files hold only the surrounding labels (g7.example / g7.learnMore).
 * URLs were verified to resolve at the time of writing.
 */
export interface G7Guidance {
  /** A correct CycloneDX fragment that would satisfy this element. */
  snippet: string;
  /** Authoritative documentation for providing this element. */
  docUrl: string;
}

export const G7_GUIDANCE: Record<string, G7Guidance> = {
  "g7-model-id": {
    snippet: `{
  "type": "machine-learning-model",
  "name": "Qwen2.5-0.5B",
  "purl": "pkg:huggingface/Qwen/Qwen2.5-0.5B"
}`,
    docUrl: "https://github.com/package-url/purl-spec",
  },
  "g7-model-license": {
    snippet: `"licenses": [
  { "license": { "id": "Apache-2.0" } }
]`,
    docUrl: "https://huggingface.co/docs/hub/repositories-licenses",
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
  "g7-model-hash": {
    snippet: `"hashes": [
  { "alg": "SHA-256", "content": "9f86d081884c7d65..." }
]`,
    docUrl: "https://cyclonedx.org/capabilities/mlbom/",
  },
  "g7-datasets": {
    snippet: `{
  "type": "data",
  "bom-ref": "dataset:wikipedia",
  "name": "wikipedia"
}`,
    docUrl: "https://huggingface.co/docs/hub/datasets-cards",
  },
  "g7-openness": {
    snippet: `"properties": [
  { "name": "openness:weights", "value": "open-weight" },
  { "name": "openness:training-data", "value": "open-data" }
]`,
    docUrl: "https://isitopen.ai/",
  },
};
