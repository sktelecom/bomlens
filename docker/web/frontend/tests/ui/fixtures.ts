// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Stub scan data shared by the shell and accessibility specs. Moved verbatim
 * from shell.spec.ts so both render the same content; do not edit values here
 * without regenerating the visual baselines.
 */

// A finished scan with an SBOM, a ScanCode artifact and vulnerabilities — enough
// to exercise data-gated rail sections (Dependencies, Source tree) and counts.
export const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [
    { name: "demo_1.0_bom.json", size: 100 },
    { name: "demo_1.0_scancode.json", size: 50 },
  ],
  security: {
    CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 2,
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", title: "buffer overflow", cvss: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L", description: "A heap buffer overflow in the TLS handshake.", url: "https://example.test/CVE-2024-0001", epss: 0.972, kev: true },
      { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.0", fixed: "1.2.1", title: "oob read", cvss: 7.5, epss: 0.004 },
    ],
  },
  conformance: null,
  sbom: {
    // readline is here to keep a copyleft license in frame. Without one, every
    // row in the license distribution is permissive and renders neutral, so the
    // tier colouring and the badge beside a flagged row are invisible to the
    // visual baseline — which is how a highlight nobody could see survived.
    components: 3,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 1 },
      { name: "zlib", version: "1.2.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"], scope: "transitive" },
      { name: "readline", version: "8.2", group: "", purl: "pkg:generic/readline@8.2", type: "library", licenses: ["GPL-3.0-only"], scope: "transitive" },
    ],
  },
};

// Raw SBOM served by /file for the dependency views: openssl (direct,
// vulnerable per the component join) → zlib (transitive).
export const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o", licenses: [{ license: { id: "Apache-2.0" } }] },
    { "bom-ref": "z", name: "zlib", version: "1.2.0", type: "library", purl: "z" },
  ],
  dependencies: [
    { ref: "root", dependsOn: ["o"] },
    { ref: "o", dependsOn: ["z"] },
  ],
};

// An AI scan: the SBOM carries a machine-learning-model component, so the rail
// exposes Models & Datasets. /file returns the matching ML-BOM (CycloneDX 1.7).
// The Conformance section only shows for a document actually submitted for
// review (nav.ts gates it on the _input.json artifact, not on `mode` — see
// that file's comment), so this ANALYZE fixture carries one, matching what a
// real ANALYZE run always writes.
export const AI_DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "model_1.0",
  results: [
    { name: "model_1.0_bom.json", size: 200 },
    { name: "model_1.0_input.json", size: 100 },
  ],
  security: null,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    checks: [
      { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
      { id: "license", label: "License coverage (recommended)", required: false, status: "warn", detail: "0%" },
      { id: "g7-meta-author", label: "SBOM author", required: false, status: "pass", detail: "author present", cluster: "metadata", source: "auto" },
      { id: "g7-meta-timestamp", label: "SBOM timestamp", required: false, status: "pass", detail: "1 found", cluster: "metadata", source: "auto" },
      { id: "g7-slp-data-flow", label: "System data flow", required: false, status: "warn", detail: "no automated source", cluster: "slp", source: "na" },
      { id: "g7-model-id", label: "Model identifier", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["pkg:huggingface/google-bert/bert-base-uncased@86b5e093"], regulations: [{ framework: "eu-ai-act", short: "EU AI Act", short_ko: "EU 인공지능법", ref: "Annex IV(1)", basis: "general description of the AI system" }] },
      { id: "g7-model-license", label: "Model license", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto", evidence: ["Apache-2.0"], regulations: [{ framework: "kr-ai-framework-act", short: "AI Framework Act", short_ko: "AI 기본법", ref: "제31조", basis: "documentation of the AI system" }] },
      { id: "g7-model-card", label: "Model properties (model card)", required: false, status: "pass", detail: "1/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-hash-value", label: "Model hash value", required: false, status: "warn", detail: "0/1 model component(s)", cluster: "models", source: "auto" },
      { id: "g7-model-openness", label: "Model license — openness (weight/architecture/data/training)", required: false, status: "warn", detail: "not declared in the SBOM", cluster: "models", source: "inferred" },
      { id: "g7-ds-name", label: "Dataset name", required: false, status: "pass", detail: "2 dataset reference(s)", cluster: "dp", source: "auto" },
      { id: "cisa-sbom-timestamp", label: "SBOM timestamp", labelKo: "SBOM 생성 시각", required: false, status: "pass", detail: "present", cluster: "cisa-metadata", source: "auto" },
      { id: "cisa-sbom-generation-context", label: "SBOM generation context", labelKo: "SBOM 생성 시점", required: false, status: "warn", detail: "not present in the SBOM", cluster: "cisa-metadata", source: "auto", guidance: { snippet: "\"lifecycles\": [ { \"phase\": \"post-build\" } ]", docUrl: "https://cyclonedx.org/docs/1.6/json/#metadata_lifecycles" } },
      { id: "cisa-coverage", label: "Coverage", labelKo: "포함 범위", required: false, status: "warn", detail: "requires human review (no automated source)", cluster: "cisa-practices", source: "na", reviewGuide: { how: "Establish that the SBOM lists every component.", howKo: "SBOM이 구성요소를 빠짐없이 담았는지 확인합니다.", docUrl: "https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom" } },
    ],
    // Detailed crosswalk (present only for AI SBOMs) — per-framework element
    // rollup with the mapped documentation obligations. source + elements[] are
    // the detail view (unlike the aiProfile card view below).
    regulatoryCrosswalk: {
      disclaimer: "Documentation-preparation aid, not a compliance verdict.",
      frameworks: [
        {
          id: "eu-ai-act", title: "EU AI Act — Annex IV", source: "Regulation (EU) 2024/1689",
          total: 2, present: 1, gap: 1, review: 0,
          elements: [
            { label: "Model identifier", status: "pass", source: "auto", refs: ["Annex IV(1)"] },
            { label: "Model hash value", status: "warn", source: "auto", refs: ["Annex IV(2)(d)"] },
          ],
        },
        {
          id: "kr-ai-framework-act", title: "Korean AI Framework Act", source: "AI Framework Act",
          total: 1, present: 1, gap: 0, review: 0,
          elements: [
            { label: "Model license", status: "pass", source: "auto", refs: ["제31조"] },
          ],
        },
      ],
    },
  },
  // AI compliance profile card rollup (summary view: no per-element detail) —
  // feeds the Overview's AI summary card, not the conformance panel itself.
  aiProfile: {
    conformanceResult: "warn",
    g7: {
      total: 9, auto: 8, present: 6, gap: 2, review: 1,
      clusters: [
        { cluster: "metadata", total: 2, present: 2, gap: 0, review: 0 },
        { cluster: "models", total: 4, present: 3, gap: 1, review: 0 },
      ],
    },
    licenseReview: { total: 2, behavioral: 1, nonCommercial: 1 },
    regulatoryCrosswalk: {
      disclaimer: "Documentation-preparation aid, not a compliance verdict.",
      frameworks: [
        { id: "eu-ai-act", title: "EU AI Act — Annex IV", total: 2, present: 1, gap: 1, review: 0 },
        { id: "kr-ai-framework-act", title: "Korean AI Framework Act", total: 1, present: 1, gap: 0, review: 0 },
      ],
    },
    // Model risk verdict (assess-ai-risk.sh, re-aggregated by generate-ai-profile.sh).
    riskAssessment: {
      usageContext: "internal",
      disclaimer: "Guidance, not legal advice.",
      disclaimer_ko: "이 판정은 법적 자문이 아닌 안내입니다.",
      counts: { ok: 0, conditional: 1, caution: 0, review: 0 },
      models: [
        {
          name: "bert-base-uncased", version: "86b5e093", license: "Apache-2.0", overall: "conditional",
          usageContext: "internal", axes: { license: "conditional" },
          reasons: ["Non-commercial clause present"],
          summary: "A non-commercial clause allows internal testing only.",
          summary_ko: "비상업 조항이 있어 사내 시험 용도로만 조건부 허용됩니다.",
          conditions: [{ id: "internal-only", label: "Internal use only", label_ko: "사내 용도로만 사용" }],
          sourceUrls: ["https://huggingface.co/google-bert/bert-base-uncased"],
        },
      ],
    },
  },
  sbom: {
    components: 1,
    componentList: [
      { name: "bert-base-uncased", version: "86b5e093", group: "google-bert", purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};
export const AI_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  metadata: { component: { "bom-ref": "root", name: "model", version: "1.0" } },
  components: [
    {
      type: "machine-learning-model", "bom-ref": "m", name: "bert-base-uncased", version: "86b5e093", group: "google-bert",
      purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093", description: "A BERT model.",
      licenses: [{ license: { id: "Apache-2.0" } }], supplier: { name: "google-bert" }, authors: [{ name: "google-bert" }],
      externalReferences: [{ type: "distribution", url: "https://huggingface.co/google-bert/bert-base-uncased/tree/main" }],
      modelCard: {
        modelParameters: {
          task: "fill-mask", modelArchitecture: "bert",
          datasets: [
            { type: "dataset", name: "bookcorpus", contents: { url: "https://huggingface.co/datasets/bookcorpus" } },
            { type: "dataset", name: "wikipedia", contents: { url: "https://huggingface.co/datasets/wikipedia" } },
          ],
        },
        considerations: { technicalLimitations: ["Intended to be fine-tuned."] },
      },
    },
  ],
};
