// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  adapterWithoutBase,
  bandSegments,
  checkValue,
  COMMON_LICENSES,
  firstOpenIn,
  firstOpenStep,
  formatDay,
  missingByElement,
  openByStep,
  readDisplay,
  required,
  rolesNotStated,
  summaryGroups,
  createTemplate,
  dateToDeclared,
  startCreate,
  declaredToDate,
  emptyLocalDataset,
  hubDatasetEntry,
  isHubId,
  keepDeclaredIds,
  issues,
  judgmentFields,
  modelMainFields,
  parseCheck,
  parseMap,
  remainingRequired,
  saveBlockers,
  slugFor,
  startDeclaration,
  stepOf,
  stepsFor,
  toFile,
  type Declaration,
  type FieldIndex,
} from "./aiDeclaration";

// The real mapping the converter uses, so a field added there is seen here.
const MAP = JSON.parse(
  readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8"),
) as unknown;
const index = parseMap(MAP) as FieldIndex;

// The empty declaration the converter writes for tests/fixtures/spdx3/bom-ai-sample.json.
const TEMPLATE = {
  schema: "bomlens-ai-declaration/1",
  document: { createdBy: [] },
  model: {
    releaseTime: "",
    builtTime: "",
    originatedBy: [],
    domain: [],
    informationAboutApplication: "",
    informationAboutTraining: "",
    hyperparameter: [],
    modelDataPreprocessing: [],
    modelExplainability: [],
    standardCompliance: [],
    useSensitivePersonalInformation: "",
    autonomyType: "",
    safetyRiskAssessment: "",
    baseModels: [
      { ref: "org/base-instruct", revision: "" },
      { ref: "org/base", revision: "" },
    ],
  },
  datasets: [
    { ref: "huggingface:org/open-ds", role: "", originatedBy: null, builtTime: "", releaseTime: "", knownBias: [] },
    { ref: "huggingface:org/upstream", originatedBy: null, builtTime: "", releaseTime: "", datasetType: [] },
  ],
  relationships: [],
};

const fresh = () => startDeclaration(TEMPLATE) as Declaration;

describe("parseMap", () => {
  it("reads every element's fields from the converter's mapping", () => {
    expect(index.document.createdBy).toMatchObject({ type: "Agent", min: 1, max: "*" });
    expect(index.ai_AIPackage.releaseTime).toMatchObject({ type: "DateTime", min: 1, max: 1 });
    expect(index.ai_AIPackage.useSensitivePersonalInformation).toMatchObject({ noAssertion: true, judgment: true });
    // The distributed weights have no "unknown": the vocabulary is ours.
    expect(index.ai_AIPackage.weightsScope.noAssertion).toBe(false);
    expect(index.dataset_DatasetPackage.datasetType.enum).toContain("noAssertion");
  });

  it("refuses a shape that is not the mapping", () => {
    expect(parseMap(null)).toBeNull();
    expect(parseMap({ elements: { document: { fields: [] } } })).toBeNull();
  });
});

describe("parseCheck and bandSegments", () => {
  it("keeps the fields the screens read and drops what it does not know", () => {
    const c = parseCheck({
      draft: true,
      counts: { auto: 3, declared: 1, optional: 2, judgment: 1, missingRequired: 2, noAssertion: 1, review: 1, bogus: 9 },
      elements: [
        { spdxId: "urn:m", type: "ai_AIPackage", label: "m", declarationKey: "model",
          fields: [{ id: "name", status: "auto", display: "m", source: "cdx:name" }, { id: "x", status: "weird" }, 7] },
        "junk",
        { spdxId: "urn:d", type: "dataset_DatasetPackage", label: "org/ds", fields: [] },
      ],
      relationships: [
        { type: "other", from: "urn:m", to: ["urn:d"], status: "review", note: "card-declared dataset, role not stated" },
      ],
      messages: [{ level: "review", text: "t" }, { level: "info" }],
    });
    expect(c).not.toBeNull();
    expect(c!.elements).toHaveLength(2);
    // A relationship names what it points to, for the screens.
    expect(c!.relationships[0].toLabel).toBe("org/ds");
    expect(c!.elements[0].declarationKey).toBe("model");
    expect(c!.elements[0].fields.map((f) => f.status)).toEqual(["auto", "omitted"]);
    expect(c!.counts).not.toHaveProperty("bogus");
    expect(c!.messages).toEqual([{ level: "review", text: "t" }]);
    expect(bandSegments(c!.counts)).toEqual([
      { key: "filled", count: 4 },
      { key: "optional", count: 4 },
      { key: "judgment", count: 1 },
      { key: "missingRequired", count: 2 },
    ]);
  });

  it("is null for anything but a check", () => {
    expect(parseCheck({ elements: [] })).toBeNull();
    expect(parseCheck("x")).toBeNull();
  });
});

describe("startDeclaration", () => {
  it("lays a saved declaration over the scan's empty one", () => {
    const saved = {
      schema: "bomlens-ai-declaration/1",
      document: { createdBy: [{ type: "Organization", name: "Acme" }] },
      model: {
        releaseTime: "2025-04-15T00:00:00Z",
        weightsScope: "adapter",
        baseModels: [
          { ref: "org/base-instruct", revision: "abc123" },
          { ref: "org/gone", revision: "zzz" },
        ],
      },
      datasets: [
        { ref: "huggingface:org/open-ds", role: "trainedOn", builtTime: "2023-10-01T00:00:00Z" },
        { ref: "huggingface:org/upstream", role: "trainedOn", releaseTime: "2022-02-01T00:00:00Z" },
        { ref: "huggingface:org/gone", builtTime: "2020-01-01T00:00:00Z" },
        { local: "logs", name: "Logs", role: "trainedOn" },
      ],
    };
    const d = startDeclaration(TEMPLATE, saved)!;
    expect(d.document.createdBy).toEqual([{ type: "Organization", name: "Acme" }]);
    expect(d.model!.releaseTime).toBe("2025-04-15T00:00:00Z");
    // A declared value the scan now fills itself is kept: it is still the
    // publisher's statement.
    expect(d.model!.weightsScope).toBe("adapter");
    // Revisions follow the base models this scan found; one it lost is dropped.
    expect(d.model!.baseModels).toEqual([
      { ref: "org/base-instruct", revision: "abc123" },
      { ref: "org/base", revision: "" },
    ]);
    expect(d.datasets.map((x) => x.ref ?? `local:${x.local}`)).toEqual([
      "huggingface:org/open-ds",
      "huggingface:org/upstream",
      "local:logs",
    ]);
    expect(d.datasets[0].role).toBe("trainedOn");
    // A traced source has no role slot, so a saved role is not carried onto it.
    expect(d.datasets[1]).not.toHaveProperty("role");
    expect(d.datasets[1].releaseTime).toBe("2022-02-01T00:00:00Z");
  });

  it("starts empty without a saved declaration, and is null for a bad template", () => {
    expect(fresh().model!.releaseTime).toBe("");
    expect(startDeclaration("nope")).toBeNull();
    expect(startDeclaration(TEMPLATE, "garbage")).toEqual(fresh());
  });
});

describe("issues and remainingRequired", () => {
  it("counts the required fields still empty, the author included unless the scan named one", () => {
    const d = fresh();
    const all = issues(index, d, false);
    // author, model release time, and per dataset: originatedBy, builtTime, releaseTime
    expect(remainingRequired(all)).toBe(1 + 1 + 3 + 3);
    expect(remainingRequired(issues(index, d, true))).toBe(7);
    // The dataset type is required too, but left empty it is written as
    // NOASSERTION, so the check does not count it as open and neither does this.
    expect(all.some((i) => i.field === "datasetType")).toBe(false);
    // Optional fields never count.
    expect(all.some((i) => i.field === "informationAboutTraining" || i.field === "builtTime" && i.where === "model")).toBe(false);
  });

  it("reports a value the converter would refuse", () => {
    const d = fresh();
    d.model!.releaseTime = "2025-02-30T00:00:00Z";
    d.model!.hyperparameter = [
      { key: "lr", value: "1" },
      { key: "lr", value: "2" },
    ];
    d.model!.baseModels![0].revision = "not a revision!";
    d.datasets[1].datasetType = ["text", "noAssertion"];
    d.datasets[0].originatedBy = { type: "Organization", name: "  " };
    const got = issues(index, d, true).filter((i) => i.problem !== "required" || i.field === "originatedBy");
    expect(got).toEqual(
      expect.arrayContaining([
        { where: "model", field: "releaseTime", problem: "date" },
        { where: "model", field: "hyperparameter", problem: "duplicateKey" },
        { where: "model.baseModels[0]", field: "revision", problem: "revision" },
        { where: "datasets[1]", field: "datasetType", problem: "noAssertionMixed" },
        // An agent with a blank name is no answer: asked for again, and left
        // out of the saved file rather than refused by the server.
        { where: "datasets[0]", field: "originatedBy", problem: "required" },
      ]),
    );
  });

  it("leaves an added and untouched dataset out, and counts each open field of a started one once", () => {
    const d = fresh();
    d.datasets.push(emptyLocalDataset(index));
    expect(issues(index, d, true).filter((i) => i.where === "datasets[2]")).toEqual([]);
    d.datasets[2] = { ...d.datasets[2], local: "logs", name: "Logs" };
    const got = issues(index, d, true).filter((i) => i.where === "datasets[2]");
    expect(got.filter((i) => i.problem === "required").map((i) => i.field).sort()).toEqual(
      ["builtTime", "downloadLocation", "originatedBy", "releaseTime"],
    );
    // Without an address the server refuses the whole declaration.
    expect(saveBlockers(got)).toEqual([{ where: "datasets[2]", field: "local", problem: "localIncomplete" }]);
    d.datasets[2].downloadLocation = "https://data.example.com/logs";
    expect(saveBlockers(issues(index, d, true))).toEqual([]);
  });

  it("only a value the server would refuse blocks saving, not an open required field", () => {
    const d = fresh();
    expect(saveBlockers(issues(index, d, false))).toEqual([]);
    d.model!.releaseTime = "2025-13-01T00:00:00Z";
    expect(saveBlockers(issues(index, d, false))).toEqual([{ where: "model", field: "releaseTime", problem: "date" }]);
  });

  it("checks a revision as it will be saved (trimmed)", () => {
    const d = fresh();
    d.model!.baseModels![0].revision = "abc123 ";
    expect(issues(index, d, true).some((i) => i.field === "revision")).toBe(false);
  });

  it("counts text the way the converter does, in characters not UTF-16 units", () => {
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "😀".repeat(4000))).toBeNull();
  });
});

describe("checkValue", () => {
  it("follows the converter's address rules", () => {
    const f = index.ai_AIPackage.downloadLocation;
    expect(checkValue(f, "https://example.com/m")).toBeNull();
    expect(checkValue(f, "hf://org/m")).toBeNull();
    expect(checkValue(f, "file://host/etc/passwd")).toBe("uriScheme");
    // No host at all is not an absolute address, as the converter reads it.
    expect(checkValue(f, "file:///etc/passwd")).toBe("uri");
    expect(checkValue(f, "https://[::1")).toBe("uri");
    expect(checkValue(f, "https://[::1]/m")).toBeNull();
    expect(checkValue(f, "example.com/m")).toBe("uri");
    expect(checkValue(f, "https://a b")).toBe("uri");
    expect(checkValue(f, "")).toBeNull();
  });

  it("caps text at the converter's limit", () => {
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "x".repeat(4001))).toBe("tooLong");
    expect(checkValue(index.ai_AIPackage.informationAboutTraining, "x".repeat(4000))).toBeNull();
  });
});

describe("dates", () => {
  it("writes a picked day as midnight UTC and reads the day back", () => {
    expect(dateToDeclared("2025-04-15")).toBe("2025-04-15T00:00:00Z");
    expect(dateToDeclared("")).toBe("");
    expect(declaredToDate("2025-04-15T10:20:30Z")).toBe("2025-04-15");
    expect(declaredToDate(null)).toBe("");
  });
});

describe("toFile", () => {
  it("keeps only what was declared, and round-trips through startDeclaration", () => {
    const d = fresh();
    d.document.createdBy = [{ type: "Organization", name: " Acme " }];
    d.model!.releaseTime = "2025-04-15T00:00:00Z";
    d.model!.modelDataPreprocessing = ["masked", "  "];
    d.model!.baseModels![1].revision = "v1";
    d.datasets[0].role = "trainedOn";
    d.datasets.push({ ...emptyLocalDataset(index), local: "logs", name: "Logs" });
    const file = toFile(d);
    expect(file).toEqual({
      schema: "bomlens-ai-declaration/1",
      document: { createdBy: [{ type: "Organization", name: " Acme " }] },
      model: {
        releaseTime: "2025-04-15T00:00:00Z",
        modelDataPreprocessing: ["masked"],
        baseModels: [{ ref: "org/base", revision: "v1" }],
      },
      datasets: [
        { ref: "huggingface:org/open-ds", role: "trainedOn" },
        { local: "logs", name: "Logs" },
      ],
      relationships: [],
    });
    const again = startDeclaration(TEMPLATE, file)!;
    expect(toFile(again)).toEqual(file);
  });

  it("drops a setting row left blank and a dataset added but never filled", () => {
    const d = fresh();
    d.model!.hyperparameter = [
      { key: "lr", value: "2e-5" },
      { key: "", value: "" },
    ];
    d.datasets.push(emptyLocalDataset(index));
    const file = toFile(d);
    expect(file.model!.hyperparameter).toEqual([{ key: "lr", value: "2e-5" }]);
    expect(file.datasets).toEqual([]);
    expect(issues(index, d, true).some((i) => i.field === "hyperparameter")).toBe(false);
  });

  it("writes no model for a dataset scan", () => {
    const d = startDeclaration({ ...TEMPLATE, model: undefined })!;
    expect(toFile(d)).not.toHaveProperty("model");
  });
});

describe("steps", () => {
  it("asks base models, model, data, legal, preview for a model scan", () => {
    const d = fresh();
    expect(stepsFor(index, d)).toEqual(["base", "model", "data", "legal", "preview"]);
    expect(modelMainFields(index, d)).toEqual(["releaseTime", "builtTime", "originatedBy"]);
    expect(judgmentFields(index, d)).toEqual(["useSensitivePersonalInformation", "autonomyType", "safetyRiskAssessment"]);
  });

  it("asks only about the data for a dataset scan", () => {
    const d = startDeclaration({ ...TEMPLATE, model: undefined })!;
    expect(stepsFor(index, d)).toEqual(["data", "preview"]);
  });

  it("places an issue on the step that asks it", () => {
    expect(stepOf({ where: "document", field: "createdBy", problem: "required" })).toBe("model");
    expect(stepOf({ where: "model.baseModels[0]", field: "revision", problem: "revision" })).toBe("base");
    expect(stepOf({ where: "datasets[1]", field: "builtTime", problem: "required" })).toBe("data");
    expect(stepOf({ where: "model", field: "hyperparameter", problem: "duplicateKey" })).toBe("data");
    expect(stepOf({ where: "model", field: "autonomyType", problem: "required" })).toBe("legal");
    expect(stepOf({ where: "model", field: "releaseTime", problem: "required" })).toBe("model");
  });
});

describe("slugFor", () => {
  it("makes a file-safe slug and keeps it unique", () => {
    expect(slugFor("Support Logs 2025", [], 1)).toBe("support-logs-2025");
    expect(slugFor("Support Logs 2025", ["support-logs-2025"], 1)).toBe("support-logs-2025-2");
    expect(slugFor("고객상담 로그", [], 3)).toBe("dataset-3");
  });
});

describe("a declaration with no scan behind it", () => {
  it("asks every declarable model field but the version, and keeps the ids in the file", () => {
    const d = createTemplate(index);
    expect(Object.keys(d.model!)).toContain("downloadLocation");
    expect(Object.keys(d.model!)).toContain("weightsScope");
    expect(d.model).not.toHaveProperty("packageVersion");
    expect(stepsFor(index, d, true)[0]).toBe("base");
    d.model!.baseModels = [{ ref: "org/base", revision: "" }];
    d.datasets = [hubDatasetEntry(index, "org/ds")];
    const file = toFile(d, true);
    expect(file.model!.baseModels).toEqual([{ ref: "org/base", revision: "" }]);
    expect(file.datasets).toEqual([{ ref: "huggingface:org/ds" }]);
    // Without keepBases (a scan's declaration), an id with no revision says nothing.
    expect(toFile(d).model).not.toHaveProperty("baseModels");
  });

  it("re-running a declared model restores its base models, datasets and answers", () => {
    const saved = {
      schema: "bomlens-ai-declaration/1",
      model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/base", revision: "abc" }] },
      datasets: [
        { ref: "huggingface:org/ds", role: "trainedOn" },
        { local: "logs", name: "Logs", downloadLocation: "https://x.example/logs" },
      ],
    };
    const d = startCreate(index, saved);
    expect(d.model!.baseModels).toEqual([{ ref: "org/base", revision: "abc" }]);
    expect(d.model!.releaseTime).toBe("2025-04-15T00:00:00Z");
    expect(d.datasets.map((x) => x.ref ?? `local:${x.local}`)).toEqual(["huggingface:org/ds", "local:logs"]);
    expect(d.datasets[0].role).toBe("trainedOn");
    expect(toFile(d, true)).toEqual({
      schema: "bomlens-ai-declaration/1",
      document: {},
      model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/base", revision: "abc" }] },
      datasets: saved.datasets,
      relationships: [],
    });
  });

  it("filling a declared model's fields later keeps the ids its declaration named", () => {
    const original = {
      schema: "bomlens-ai-declaration/1",
      model: { baseModels: [{ ref: "org/base", revision: "" }] },
      datasets: [{ ref: "huggingface:org/ds", role: "trainedOn" }],
    };
    // What a fill writes: only answered fields; a base model without a
    // revision and a dataset with nothing new are left out.
    const filled: Declaration = {
      schema: "bomlens-ai-declaration/1",
      document: {},
      model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/root", revision: "v1" }] },
      datasets: [],
      relationships: [],
    };
    const out = keepDeclaredIds(filled, original);
    expect(out.model!.baseModels).toEqual([
      { ref: "org/base", revision: "" },
      { ref: "org/root", revision: "v1" },
    ]);
    expect(out.datasets).toEqual([{ ref: "huggingface:org/ds" }]);
    expect(out.model!.releaseTime).toBe("2025-04-15T00:00:00Z");
  });

  it("refuses a base model that is not a hub id", () => {
    const d = createTemplate(index);
    d.model!.baseModels = [{ ref: "not an id", revision: "" }];
    expect(saveBlockers(issues(index, d, false))).toEqual([{ where: "model.baseModels[0]", field: "ref", problem: "hubId" }]);
    expect(isHubId("org/x")).toBe(true);
    expect(isHubId("org/../x")).toBe(false);
  });

  it("asks for the model's licence, checks it as the converter does and saves it", () => {
    const d = createTemplate(index);
    expect(d.model!.license).toBe("");
    expect(toFile(d, true).model).not.toHaveProperty("license");
    d.model!.license = "my own terms";
    expect(saveBlockers(issues(index, d, false))).toEqual([{ where: "model", field: "license", problem: "license" }]);
    expect(stepOf({ where: "model", field: "license", problem: "license" })).toBe("model");
    d.model!.license = " llama3.1 ";
    expect(saveBlockers(issues(index, d, false))).toEqual([]);
    expect(toFile(d, true).model!.license).toBe("llama3.1");
    // A saved licence comes back on a re-run.
    expect(startCreate(index, toFile(d, true)).model!.license).toBe("llama3.1");
  });
});

describe("sources a publisher declares for a dataset", () => {
  it("keeps hub and named sources, drops an empty row, and reports what the converter would refuse", () => {
    const d = fresh();
    d.datasets[0].sources = [
      { ref: "huggingface:org/c4", relation: "extended" },
      { name: "Old crawl", license: "cc-by-4.0", relation: "other" },
      { name: "", license: "", relation: "other" },
    ];
    expect(issues(index, d, true).filter((i) => i.field === "sources")).toEqual([]);
    expect(toFile(d).datasets[0].sources).toEqual([
      { ref: "huggingface:org/c4", relation: "extended" },
      { name: "Old crawl", license: "cc-by-4.0", relation: "other" },
    ]);
    d.datasets[0].sources = [
      { name: "", license: "mit", relation: "other" },
      { name: "X", license: "my own terms", relation: "other" },
      { name: "x", relation: "other" },
    ];
    expect(saveBlockers(issues(index, d, true)).map((i) => i.problem)).toEqual(["sourceName", "sourceLicense", "sourceTwice"]);
  });

  it("refuses what the converter refuses: a dataset as its own source, a hub source on local data", () => {
    const d = fresh();
    d.datasets[0].sources = [{ ref: "huggingface:ORG/open-ds", relation: "extended" }];
    d.datasets[0].ref = "huggingface:org/open-ds";
    expect(saveBlockers(issues(index, d, true)).map((i) => i.problem)).toEqual(["sourceSelf"]);
    const l = fresh();
    l.datasets.push({ ...emptyLocalDataset(index), local: "logs", name: "Logs", downloadLocation: "https://x.example/l",
                      sources: [{ ref: "huggingface:a/b", relation: "other" }] });
    expect(saveBlockers(issues(index, l, true)).map((i) => i.problem)).toEqual(["sourceHubOnLocal"]);
  });
});


describe("where the open items are", () => {
  it("counts them by step, opens at the first step that has one, and finds the first of a step", () => {
    const d = fresh();
    const steps = stepsFor(index, d);
    const list = issues(index, d, false);
    const open = openByStep(list);
    // The author and release date on the model, the datasets' dates and makers.
    expect(open.model).toBe(2);
    expect(open.data).toBeGreaterThan(0);
    expect(open.base).toBeUndefined();
    // The base-model step has nothing open, so the questions start at the model.
    expect(steps[0]).toBe("base");
    expect(firstOpenStep(steps, list)).toBe("model");
    expect(firstOpenIn("model", list)).toEqual({ where: "document", field: "createdBy", problem: "required" });
    // With the model answered, the data step is the first with something open.
    d.document.createdBy = [{ type: "Organization", name: "Acme" }];
    d.model!.releaseTime = "2025-01-01T00:00:00Z";
    expect(firstOpenStep(steps, issues(index, d, false))).toBe("data");
    // Nothing open anywhere: the first step.
    expect(firstOpenStep(steps, [])).toBe("base");
  });

  it("does not call a required field with a fallback open", () => {
    // The dataset type is written as NOASSERTION when empty.
    expect(required(index.dataset_DatasetPackage.datasetType)).toBe(false);
    expect(required(index.ai_AIPackage.releaseTime)).toBe(true);
  });
});

describe("adapterWithoutBase", () => {
  it("is true only for adapter weights with no base model", () => {
    const d = createTemplate(index);
    d.model!.weightsScope = "adapter";
    expect(adapterWithoutBase(d)).toBe(true);
    d.model!.baseModels = [{ ref: "org/base", revision: "" }];
    expect(adapterWithoutBase(d)).toBe(false);
    d.model!.baseModels = [];
    d.model!.weightsScope = "quantized";
    expect(adapterWithoutBase(d)).toBe(false);
  });
});

describe("summaryGroups", () => {
  it("lists every answer by step, each dataset as its own group, and leaves empty answers out", () => {
    const d = fresh();
    d.document.createdBy = [{ type: "Organization", name: "Acme" }];
    d.model!.releaseTime = "2025-04-15T00:00:00Z";
    d.model!.informationAboutTraining = "LoRA, 3 epochs";
    d.model!.safetyRiskAssessment = "medium";
    d.datasets[0].builtTime = "2023-10-01T00:00:00Z";
    d.datasets[0].role = "trainedOn";
    const groups = summaryGroups(index, d, stepsFor(index, d));
    const model = groups.find((g) => g.step === "model")!;
    expect(model.rows.map((r) => `${r.ns}.${r.field.id}`)).toEqual(["document.createdBy", "model.releaseTime"]);
    const data = groups.filter((g) => g.step === "data");
    expect(data.map((g) => g.title)).toEqual(["org/open-ds", "org/upstream", null]);
    expect(data[0].datasetIndex).toBe(0);
    expect(data[0].rows.map((r) => r.field.id)).toEqual(["builtTime"]);
    // How it was trained sits with the data, as the step asks it.
    expect(data[2].rows.map((r) => r.field.id)).toEqual(["informationAboutTraining"]);
    expect(groups.find((g) => g.step === "legal")!.rows.map((r) => r.field.id)).toEqual(["safetyRiskAssessment"]);
  });

  it("names a dataset the hub does not hold by its name, and skips one never filled", () => {
    const d = fresh();
    d.datasets.push(emptyLocalDataset(index));
    d.datasets.push({ ...emptyLocalDataset(index), local: "logs", name: "Logs" });
    const titles = summaryGroups(index, d, ["data"])
      .filter((g) => g.datasetIndex !== undefined)
      .map((g) => g.title);
    expect(titles).toEqual(["org/open-ds", "org/upstream", "Logs"]);
  });
});

describe("how a value in the check reads", () => {
  it("reads dates, vocabulary words and text apart", () => {
    expect(readDisplay("releaseTime", "2026-10-01T00:00:00Z")).toEqual({ kind: "date", date: new Date("2026-10-01T00:00:00Z") });
    expect(readDisplay("weightsScope", "adapter")).toEqual({ kind: "enum", values: ["adapter"] });
    expect(readDisplay("datasetType", "text, audio")).toEqual({ kind: "enum", values: ["text", "audio"] });
    expect(readDisplay("primaryPurpose", "model")).toEqual({ kind: "enum", values: ["model"] });
    expect(readDisplay("name", "adapter")).toEqual({ kind: "text", text: "adapter" });
    // Not a real date: left as written.
    expect(readDisplay("releaseTime", "2026-02-30T00:00:00Z")).toEqual({ kind: "text", text: "2026-02-30T00:00:00Z" });
  });

  it("writes a declared day in the reader's locale, the same day in every time zone", () => {
    expect(formatDay("2026-10-01T00:00:00Z", "en")).toBe("Oct 1, 2026");
    expect(formatDay("2026-10-01T00:00:00Z", "ko")).toContain("2026");
    expect(formatDay("not a date", "en")).toBe("not a date");
  });
});

describe("what the band says about the check", () => {
  const c = parseCheck({
    draft: true,
    counts: { missingRequired: 3 },
    elements: [
      { spdxId: "urn:doc", type: "CreationInfo", label: "document", fields: [{ id: "createdBy", status: "missingRequired" }] },
      { spdxId: "urn:m", type: "ai_AIPackage", label: "acme/m", fields: [{ id: "releaseTime", status: "declared" }] },
      { spdxId: "urn:d", type: "dataset_DatasetPackage", label: "org/ds",
        fields: [{ id: "builtTime", status: "missingRequired" }, { id: "releaseTime", status: "missingRequired" }] },
      { spdxId: "urn:l", type: "dataset_DatasetPackage", label: "Logs", fields: [] },
    ],
    relationships: [
      { type: "other", from: "urn:m", to: ["urn:d"], status: "review", note: "card-declared dataset, role not stated" },
      { type: "other", from: "urn:m", to: ["urn:l"], status: "review", note: "declared dataset, role not stated" },
    ],
    messages: [],
  })!;

  it("names the elements with required fields still empty", () => {
    expect(missingByElement(c)).toEqual([
      { type: "CreationInfo", label: "document", count: 1 },
      { type: "dataset_DatasetPackage", label: "org/ds", count: 2 },
    ]);
  });

  it("tells datasets a model card named from those a declaration named", () => {
    expect(rolesNotStated(c)).toEqual({ card: ["org/ds"], declared: ["Logs"] });
  });
});

describe("COMMON_LICENSES", () => {
  it("offers only licence tags the converter accepts", () => {
    const knowledge = JSON.parse(
      readFileSync(new URL("../../../../lib/ai-risk-knowledge.json", import.meta.url), "utf-8"),
    ) as { hfLicenseTags: string[] };
    for (const l of COMMON_LICENSES) expect(knowledge.hfLicenseTags).toContain(l);
  });
});
