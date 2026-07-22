import { describe, expect, it } from "vitest";

import type { DoneEvent } from "./api";
import { parseModelCards } from "./models";
import { isAiScan } from "./results";

// Mirrors the verified OWASP AIBOM Generator 1.7 shape
// (tests/fixtures/aibom-owasp-1_7.json): one machine-learning-model with a
// modelCard carrying task / modelArchitecture / datasets.
const ML_BOM = {
  specVersion: "1.7",
  components: [
    {
      type: "machine-learning-model",
      "bom-ref": "m",
      name: "bert-base-uncased",
      version: "86b5e093",
      group: "google-bert",
      purl: "pkg:huggingface/google-bert/bert-base-uncased@86b5e093",
      description: "A BERT model.",
      licenses: [{ license: { id: "Apache-2.0" } }],
      supplier: { name: "google-bert" },
      authors: [{ name: "google-bert" }],
      externalReferences: [
        { type: "website", url: "https://huggingface.co/google-bert/bert-base-uncased" },
        { type: "distribution", url: "https://huggingface.co/google-bert/bert-base-uncased/tree/main" },
      ],
      modelCard: {
        modelParameters: {
          task: "fill-mask",
          modelArchitecture: "bert",
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

describe("parseModelCards", () => {
  it("extracts the model card fields", () => {
    const { models } = parseModelCards(ML_BOM);
    expect(models).toHaveLength(1);
    const m = models[0];
    expect(m.name).toBe("bert-base-uncased");
    expect(m.architecture).toBe("bert");
    expect(m.task).toBe("fill-mask");
    expect(m.licenses).toEqual(["Apache-2.0"]);
    expect(m.supplier).toBe("google-bert");
    expect(m.purl).toContain("huggingface");
    expect(m.externalRefs.map((r) => r.type)).toEqual(["website", "distribution"]);
    expect(m.limitations).toHaveLength(1);
  });

  it("collects and dedupes datasets", () => {
    const { datasets } = parseModelCards(ML_BOM);
    expect(datasets.map((d) => d.name)).toEqual(["bookcorpus", "wikipedia"]);
    expect(datasets[0].url).toContain("bookcorpus");
  });

  it("derives disclosure axes from documented fields", () => {
    const d = parseModelCards(ML_BOM).models[0].disclosure;
    expect(d.architecture).toBe(true); // modelArchitecture present
    expect(d.trainingData).toBe(true); // datasets present
    expect(d.weights).toBe(true); // distribution external ref present
    expect(d.trainingProcess).toBe(true); // technicalLimitations present
  });

  // enrich-aibom.sh resolves each declared dataset into a standalone `data`
  // component. It carries the license, digests and upstream the card lacks, so
  // it must supersede the card's bare name rather than be discarded as a dupe.
  const RESOLVED = {
    ...ML_BOM,
    components: [
      ...ML_BOM.components,
      {
        type: "data",
        "bom-ref": "dataset:huggingface/wikipedia",
        name: "wikipedia",
        version: "deadbeef",
        licenses: [{ license: { id: "CC-BY-SA-4.0" } }],
        hashes: [{ alg: "SHA-256", content: "ab".repeat(32) }],
        properties: [
          { name: "bomlens:dataset:collectedBy", value: "huggingface" },
          { name: "bomlens:dataset:sourceDataset", value: "extended|org/upstream" },
        ],
        data: [{ type: "dataset", name: "wikipedia", contents: { url: "https://huggingface.co/datasets/wikipedia" } }],
      },
      {
        type: "data",
        "bom-ref": "dataset:huggingface/bookcorpus",
        name: "bookcorpus",
        properties: [
          { name: "bomlens:dataset:collectedBy", value: "huggingface" },
          { name: "bomlens:dataset:unresolved", value: "not-readable" },
        ],
        data: [{ type: "dataset", name: "bookcorpus", contents: { url: "https://huggingface.co/datasets/bookcorpus" } }],
      },
    ],
  };

  it("lets a resolved data component supersede the card's bare dataset name", () => {
    const { datasets } = parseModelCards(RESOLVED);
    expect(datasets).toHaveLength(2); // not four — merged by name
    const wiki = datasets.find((d) => d.name === "wikipedia")!;
    expect(wiki.licenses).toEqual(["CC-BY-SA-4.0"]);
    expect(wiki.hasIntegrity).toBe(true);
    expect(wiki.version).toBe("deadbeef");
    expect(wiki.sources).toEqual(["extended|org/upstream"]);
    expect(wiki.unresolved).toBe(false);
  });

  it("keeps an unreadable dataset distinct from one with no license", () => {
    const book = parseModelCards(RESOLVED).datasets.find((d) => d.name === "bookcorpus")!;
    expect(book.unresolved).toBe(true);
    expect(book.licenses).toEqual([]);
    expect(book.hasIntegrity).toBe(false);
    expect(book.url).toContain("bookcorpus");
  });

  it("prefers the recorded openness verdict over counting dataset names", () => {
    const withProp = {
      ...ML_BOM,
      components: [
        { ...ML_BOM.components[0], properties: [{ name: "openness:training-data", value: "declared-unverified" }] },
      ],
    };
    // The card still names two datasets, but none of them resolved.
    expect(parseModelCards(withProp).models[0].disclosure.trainingData).toBe(false);
  });

  it("is defensive about partial / non-AI input", () => {
    expect(parseModelCards({}).models).toEqual([]);
    expect(parseModelCards({ components: [{ type: "library", name: "x" }] }).models).toEqual([]);
    const partial = parseModelCards({ components: [{ type: "machine-learning-model" }] });
    expect(partial.models[0].name).toBe("(unnamed model)");
    expect(partial.models[0].disclosure.architecture).toBe(false);
  });
});

describe("isAiScan", () => {
  const base: DoneEvent = {
    ok: true, mode: "ANALYZE", results: [], sbom: { components: 0, componentList: [] }, security: null, conformance: null,
  };
  it("is true when a machine-learning-model component is present", () => {
    expect(isAiScan({ ...base, sbom: { components: 1, componentList: [
      { name: "bert", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: [] },
    ] } })).toBe(true);
  });
  it("is false for ordinary software scans", () => {
    expect(isAiScan({ ...base, sbom: { components: 1, componentList: [
      { name: "openssl", version: "3", group: "", purl: "", type: "library", licenses: [] },
    ] } })).toBe(false);
    expect(isAiScan(base)).toBe(false);
  });
});
