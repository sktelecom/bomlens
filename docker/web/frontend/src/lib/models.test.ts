// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { DoneEvent } from "./api";
import { datasetTreeRows, parseDeclaredServices, parseModelCards } from "./models";
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

  // The shape the scanner actually writes for a model scan: the model is the
  // document's own component and components[] holds only the datasets it
  // references (docs/demo/data/files/BertBaseUncased_1.0/*_bom.json).
  const ROOT_MODEL_BOM = {
    specVersion: "1.7",
    metadata: { component: ML_BOM.components[0] },
    components: [
      { type: "data", "bom-ref": "d1", name: "bookcorpus", version: "d917559b" },
      { type: "data", "bom-ref": "d2", name: "wikipedia", version: "97a0b052" },
    ],
  };

  it("reads the model card when the model is the document's own component", () => {
    const { models, datasets } = parseModelCards(ROOT_MODEL_BOM);
    expect(models).toHaveLength(1);
    expect(models[0].name).toBe("bert-base-uncased");
    expect(models[0].architecture).toBe("bert");
    expect(datasets.map((d) => d.name)).toEqual(["bookcorpus", "wikipedia"]);
  });

  it("leaves every other root out — it is the scanned project, not a component", () => {
    const appRoot = {
      specVersion: "1.7",
      metadata: { component: { type: "application", name: "web-api", version: "2.0" } },
      components: [{ type: "library", name: "flask", version: "2.0" }],
    };
    expect(parseModelCards(appRoot).models).toHaveLength(0);
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

  // The pipeline stamps its risk verdict as bomlens:assessment:* properties.
  // The parser reads them verbatim — it never re-derives a grade — so these
  // cases only assert faithful transport, not classification.
  const ASSESSED = {
    ...ML_BOM,
    components: [
      {
        ...ML_BOM.components[0],
        properties: [
          { name: "bomlens:assessment:overall", value: "caution" },
          { name: "bomlens:assessment:license", value: "conditional" },
          { name: "bomlens:assessment:security", value: "ok" },
          { name: "bomlens:assessment:datasets", value: "review" },
          { name: "bomlens:assessment:axes", value: "license,security,datasets" },
          { name: "bomlens:assessment:usageContext", value: "product" },
          { name: "bomlens:assessment:reasons", value: "Custom license restricts commercial use; Weights include pickle files" },
          { name: "bomlens:license:customScan", value: "true" },
          { name: "bomlens:license:customScan:quote", value: "You may not use this model commercially." },
          { name: "bomlens:lineage:conflict", value: "true" },
          { name: "bomlens:lineage:conflictWith", value: "meta-llama/Llama-3-8B" },
          { name: "bomlens:hf:scan:status", value: "suspicious" },
          { name: "bomlens:hf:scan:issue", value: "pickle imports os.system" },
          { name: "bomlens:weights:formats", value: "bin,safetensors" },
        ],
      },
    ],
  };

  it("reads the stamped assessment verbatim", () => {
    const m = parseModelCards(ASSESSED).models[0];
    expect(m.assessment).toEqual({
      overall: "caution",
      license: "conditional",
      security: "ok",
      datasets: "review",
      usageContext: "product",
      reasons: [
        "Custom license restricts commercial use",
        "Weights include pickle files",
      ],
    });
    expect(m.scanStatus).toBe("suspicious");
    expect(m.scanIssue).toBe("pickle imports os.system");
    expect(m.weightFormats).toEqual(["bin", "safetensors"]);
    expect(m.customLicenseQuote).toBe("You may not use this model commercially.");
    expect(m.lineageConflictWith).toBe("meta-llama/Llama-3-8B");
  });

  it("reads the training-data axis a model with no declared datasets carries", () => {
    // A model that states no training set is graded on that fact instead of on
    // its datasets, so the two axes never appear together.
    const bom = {
      components: [
        {
          type: "machine-learning-model",
          name: "m",
          properties: [
            { name: "bomlens:assessment:overall", value: "review" },
            { name: "bomlens:assessment:license", value: "ok" },
            { name: "bomlens:assessment:trainingData", value: "review" },
            { name: "bomlens:assessment:axes", value: "license,trainingData" },
          ],
        },
      ],
    };
    const m = parseModelCards(bom).models[0];
    expect(m.assessment?.trainingData).toBe("review");
    expect(m.assessment?.datasets).toBeUndefined();
    expect(m.assessment?.overall).toBe("review");
  });

  // A dataset scan describes one published item: the dataset IS the document,
  // components[] is empty, and there is no model anywhere. Reading components[]
  // alone left this view with nothing to show on exactly the scan it exists for.
  const FIGSHARE_BOM = {
    specVersion: "1.7",
    metadata: {
      component: {
        type: "data",
        "bom-ref": "dataset:figshare/33412285",
        name: "SS-Cu-Ti multi-material structures study dataset",
        version: "v1",
        licenses: [{ license: { id: "CC-BY-4.0" } }],
        hashes: [{ alg: "MD5", content: "7b8123ec815a365c6f4d2cd8e8796583" }],
        externalReferences: [
          { type: "distribution", url: "https://figshare.com/articles/dataset/x/33412285" },
        ],
        properties: [
          { name: "bomlens:dataset:collectedBy", value: "figshare" },
          { name: "bomlens:dataset:doi", value: "10.25916/sut.33412285.v1" },
          { name: "bomlens:assessment:overall", value: "ok" },
        ],
      },
    },
    components: [],
  };

  it("reads a dataset that is the document root", () => {
    const { models, datasets } = parseModelCards(FIGSHARE_BOM);
    expect(models).toHaveLength(0);
    expect(datasets).toHaveLength(1);
    const d = datasets[0];
    expect(d.name).toContain("SS-Cu-Ti");
    expect(d.licenses).toEqual(["CC-BY-4.0"]);
    expect(d.hasIntegrity).toBe(true);
    expect(d.collectedBy).toBe("figshare");
    expect(d.url).toContain("figshare.com");
    expect(d.assessment).toBe("ok");
  });

  it("leaves a non-dataset root out of the dataset list", () => {
    const appRoot = {
      specVersion: "1.6",
      metadata: { component: { type: "application", name: "web-api", version: "2.0" } },
      components: [{ type: "library", name: "flask", version: "2.0" }],
    };
    expect(parseModelCards(appRoot).datasets).toHaveLength(0);
  });

  it("leaves the assessment absent when the pipeline stamped none", () => {
    const m = parseModelCards(ML_BOM).models[0];
    expect(m.assessment).toBeUndefined();
    expect(m.scanStatus).toBeUndefined();
    expect(m.scanIssue).toBeUndefined();
    expect(m.weightFormats).toBeUndefined();
    expect(m.customLicenseQuote).toBeUndefined();
    expect(m.lineageConflictWith).toBeUndefined();
  });

  it("keeps unevaluated axes absent when only the overall grade is stamped", () => {
    const overallOnly = {
      ...ML_BOM,
      components: [
        {
          ...ML_BOM.components[0],
          properties: [{ name: "bomlens:assessment:overall", value: "ok" }],
        },
      ],
    };
    const a = parseModelCards(overallOnly).models[0].assessment!;
    expect(a.overall).toBe("ok");
    expect(a.license).toBeUndefined();
    expect(a.security).toBeUndefined();
    expect(a.datasets).toBeUndefined();
    expect(a.usageContext).toBeUndefined();
    expect(a.reasons).toEqual([]);
  });

  it("treats an out-of-vocabulary grade as not stamped, never re-grades", () => {
    const weird = {
      ...ML_BOM,
      components: [
        {
          ...ML_BOM.components[0],
          properties: [{ name: "bomlens:assessment:overall", value: "banana" }],
        },
      ],
    };
    expect(parseModelCards(weird).models[0].assessment).toBeUndefined();
  });

  it("reads a dataset's stamped overall and signal grades", () => {
    const dsAssessed = {
      ...ML_BOM,
      components: [
        ...ML_BOM.components,
        {
          type: "data",
          "bom-ref": "dataset:huggingface/wikipedia",
          name: "wikipedia",
          properties: [
            { name: "bomlens:assessment:overall", value: "conditional" },
            { name: "bomlens:assessment:signals", value: "review" },
          ],
        },
      ],
    };
    const { datasets } = parseModelCards(dsAssessed);
    const wiki = datasets.find((d) => d.name === "wikipedia")!;
    expect(wiki.assessment).toBe("conditional");
    expect(wiki.signals).toBe("review");
    // The other dataset carries no stamp and stays unassessed.
    expect(datasets.find((d) => d.name === "bookcorpus")!.assessment).toBeUndefined();
  });

  it("is defensive about partial / non-AI input", () => {
    expect(parseModelCards({}).models).toEqual([]);
    expect(parseModelCards({ components: [{ type: "library", name: "x" }] }).models).toEqual([]);
    const partial = parseModelCards({ components: [{ type: "machine-learning-model" }] });
    expect(partial.models[0].name).toBe("(unnamed model)");
    expect(partial.models[0].disclosure.architecture).toBe(false);
  });
});

// The shape enrich-aibom.sh writes when it traces a dataset's sources: each
// source is a top-level data component, the dataset names it in
// bomlens:dataset:derivedFrom ("<relation> <bom-ref>"), and depth says how far
// below the model card it was reached.
const ds = (name: string, depth: number, props: [string, string][] = []) => ({
  type: "data",
  "bom-ref": `dataset:huggingface/${name}`,
  name,
  properties: [["bomlens:dataset:depth", String(depth)], ...props].map(([n, v]) => ({
    name: n,
    value: v,
  })),
});

describe("dataset source tree", () => {
  it("reads the traced-source fields", () => {
    const { datasets } = parseModelCards({
      components: [
        ds("org/mix", 0, [
          ["bomlens:dataset:derivedFrom", "extended dataset:huggingface/org/nc"],
          ["bomlens:dataset:sourceDataset:unverified", "Wikipedia dump 2023-01"],
          ["bomlens:dataset:sourceTrace", "depth-limit"],
        ]),
      ],
    });
    expect(datasets[0]).toMatchObject({
      ref: "dataset:huggingface/org/mix",
      depth: 0,
      derivedFrom: [{ relation: "extended", ref: "dataset:huggingface/org/nc" }],
      unverifiedSources: ["Wikipedia dump 2023-01"],
      trace: "depth-limit",
    });
  });

  it("indents each source under the dataset it was traced from", () => {
    const { datasets } = parseModelCards({
      components: [
        ds("org/nc", 1),
        ds("org/mix", 0, [["bomlens:dataset:derivedFrom", "extended dataset:huggingface/org/nc"]]),
        ds("org/other", 0),
      ],
    });
    const rows = datasetTreeRows(datasets).map((r) => [r.dataset.name, r.level, r.relation]);
    expect(rows).toEqual([
      ["org/mix", 0, undefined],
      ["org/nc", 1, "extended"],
      ["org/other", 0, undefined],
    ]);
  });

  it("gives a shared source one full row and a repeat row, and survives a cycle", () => {
    const { datasets } = parseModelCards({
      components: [
        ds("org/a", 0, [["bomlens:dataset:derivedFrom", "listed dataset:huggingface/org/c"]]),
        ds("org/b", 0, [["bomlens:dataset:derivedFrom", "listed dataset:huggingface/org/c"]]),
        ds("org/c", 1, [["bomlens:dataset:derivedFrom", "extended dataset:huggingface/org/a"]]),
      ],
    });
    const rows = datasetTreeRows(datasets).map((r) => [r.dataset.name, r.level, Boolean(r.repeat)]);
    expect(rows).toEqual([
      ["org/a", 0, false],
      ["org/c", 1, false],
      ["org/a", 2, true],
      ["org/b", 0, false],
      ["org/c", 1, true],
    ]);
  });

  it("keeps the old flat order when nothing was traced", () => {
    const { datasets } = parseModelCards(ML_BOM);
    const rows = datasetTreeRows(datasets);
    expect(rows.map((r) => r.dataset.name)).toEqual(datasets.map((d) => d.name));
    expect(rows.every((r) => r.level === 0)).toBe(true);
  });

  it("stays as long as the links on a densely connected graph", () => {
    const names = Array.from({ length: 12 }, (_, i) => `org/d${i}`);
    const comps = names.map((n, i) =>
      ds(
        n,
        i === 0 ? 0 : 1,
        names.filter((m) => m !== n).map((m) => ["bomlens:dataset:derivedFrom", `listed dataset:huggingface/${m}`] as [string, string]),
      ),
    );
    const rows = datasetTreeRows(parseModelCards({ components: comps }).datasets);
    expect(rows.filter((r) => !r.repeat)).toHaveLength(12);
    expect(rows.length).toBeLessThanOrEqual(12 + 12 * 11);
  });

  it("shows a source whose parent link is missing as a root", () => {
    const rows = datasetTreeRows(parseModelCards({ components: [ds("org/orphan", 2)] }).datasets);
    expect(rows).toHaveLength(1);
    expect(rows[0].level).toBe(0);
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

describe("parseDeclaredServices", () => {
  const prop = (name: string, value: string) => ({ name, value });
  const declared = (kind: string) => [prop("bomlens:origin", "declared-input"), prop("bomlens:service:kind", kind)];
  // The shape docker/lib/apply-declared-service.py writes.
  const BOM = {
    metadata: { component: { type: "machine-learning-model", "bom-ref": "pkg:huggingface/acme/m", group: "acme", name: "m" } },
    components: [{ type: "data", "bom-ref": "d", name: "ds" }],
    services: [
      {
        "bom-ref": "service:declared/acme-support-assistant",
        name: "Acme Support Assistant",
        version: "2.3.0",
        provider: { name: "Acme Corp" },
        endpoints: ["https://support.acme.example/assistant"],
        description: "Answers customer questions.",
        data: [
          { flow: "inbound", classification: "personal data" },
          { flow: "outbound", classification: "personal data" },
        ],
        properties: declared("application"),
      },
      {
        "bom-ref": "service:declared-external/translate",
        name: "Example Translate",
        version: "2025-05",
        provider: { name: "Example Inc" },
        endpoints: ["https://api.translate.example/v1"],
        properties: declared("external-model"),
      },
      // A service the scan found itself is not the publisher's declaration.
      { "bom-ref": "svc-scanned", name: "billing-api" },
    ],
    dependencies: [
      {
        ref: "service:declared/acme-support-assistant",
        dependsOn: ["pkg:huggingface/acme/m", "service:declared-external/translate"],
      },
    ],
  };

  it("reads the declared service, the model it runs and the external models it calls", () => {
    expect(parseDeclaredServices(BOM)).toEqual([
      {
        ref: "service:declared/acme-support-assistant",
        name: "Acme Support Assistant",
        version: "2.3.0",
        provider: "Acme Corp",
        endpoint: "https://support.acme.example/assistant",
        description: "Answers customer questions.",
        models: ["acme/m"],
        externalModels: [
          { name: "Example Translate", provider: "Example Inc", version: "2025-05", endpoint: "https://api.translate.example/v1" },
        ],
        dataFlows: 2,
      },
    ]);
  });

  it("without a dependency list, keeps the external models and names no model", () => {
    const [s] = parseDeclaredServices({ ...BOM, dependencies: [] });
    expect(s.models).toEqual([]);
    expect(s.externalModels.map((m) => m.name)).toEqual(["Example Translate"]);
  });

  it("is empty for an SBOM with no declared service", () => {
    expect(parseDeclaredServices({ services: [{ name: "billing-api" }] })).toEqual([]);
    expect(parseDeclaredServices(null)).toEqual([]);
    expect(parseDeclaredServices({ services: "x" })).toEqual([]);
  });
});
