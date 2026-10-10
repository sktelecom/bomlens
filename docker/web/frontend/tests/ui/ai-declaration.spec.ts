// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

// The SPDX 3.0.1 AI document on the Models & datasets screen: the band says
// how its fields were filled, and "Fill in empty fields" opens the questions
// for exactly the fields the scan left open. Saving goes to the server, which
// rewrites the document; the band then follows.

const MAP = readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8");
const P = "model_1.0";

const field = (id: string, status: string, display?: string) => ({ id, status, ...(display ? { display } : {}) });

// The service the publisher declared, as the check reports it once saved.
const SERVICE_ELEMENTS = [
  { spdxId: "urn:s", type: "service", label: "Acme Support Assistant", declarationKey: "service",
    fields: [field("name", "declared", "Acme Support Assistant"), field("packageVersion", "declared", "2.3.0"),
             field("primaryPurpose", "auto", "application"), field("autonomyType", "declared", "no"),
             field("dataFlows", "declared", "inbound: personal data")] },
  { spdxId: "urn:e", type: "externalModel", label: "Example Translate", declarationKey: "externalModel:example-translate",
    fields: [field("name", "declared", "Example Translate"), field("primaryPurpose", "auto", "model")] },
];

function check(complete: boolean, declared = false, service = false) {
  return {
    schema: "bomlens-spdx3-check/1",
    draft: !complete,
    counts: { auto: 8, declared: complete ? 6 : 0, optional: 10, judgment: complete ? 2 : 3,
              missingRequired: complete ? 0 : 5, noAssertion: 0, omitted: 2, review: 1 },
    elements: [
      { spdxId: "urn:doc", type: "CreationInfo", label: "document", declarationKey: "document",
        fields: [complete ? field("createdBy", "declared", "Acme AI Lab") : field("createdBy", "missingRequired")] },
      { spdxId: "urn:m", type: "ai_AIPackage", label: "acme/model", declarationKey: "model",
        fields: [
          field("name", "auto", "acme/model"),
          field("downloadLocation", "auto", "https://huggingface.co/acme/model"),
          field("primaryPurpose", "auto", "model"),
          { ...field("suppliedBy", "auto", "acme"), meaning: "huggingface-publisher" },
          complete ? field("releaseTime", "declared", "2025-04-15T00:00:00Z") : field("releaseTime", "missingRequired"),
          field("builtTime", "declared", "2026-10-01T00:00:00Z"),
          field("weightsScope", "auto", "adapter"),
          field("informationAboutTraining", "optional"),
          field("safetyRiskAssessment", "judgment"),
        ] },
      { spdxId: "urn:d", type: "dataset_DatasetPackage", label: "org/ds", declarationKey: "huggingface:org/ds",
        fields: [field("name", "auto", "org/ds"), field("suppliedBy", "auto", "org"),
                 field("downloadLocation", "auto", "https://huggingface.co/datasets/org/ds"),
                 field("originatedBy", complete ? "declared" : "missingRequired"),
                 field("builtTime", complete ? "declared" : "missingRequired"),
                 field("releaseTime", complete ? "declared" : "missingRequired")] },
      ...(service ? SERVICE_ELEMENTS : []),
    ],
    relationships: [{ type: "other", from: "urn:m", to: ["urn:d"], status: "review",
                      note: declared ? "declared dataset, role not stated" : "card-declared dataset, role not stated" }],
    messages: [],
    declaration: { state: complete ? "applied" : "none" },
  };
}

const summary = (complete: boolean, upToDate = true, service: "none" | "applied" | "pendingScan" = "none") => ({
  draft: !complete,
  counts: check(complete).counts,
  name: `${P}_bom.spdx3.json`,
  check: `${P}_spdx3-check.json`,
  declaration: { state: complete ? "applied" : "none", reasons: [] },
  service: { state: service },
  upToDate,
});

// The blank service the converter's empty declaration holds for a model.
const BLANK_SERVICE = {
  name: "", packageVersion: "", downloadLocation: "", suppliedBy: null, releaseTime: "",
  informationAboutApplication: "", domain: [], autonomyType: "", inputModality: [], outputModality: [],
  dataFlows: [], standardCompliance: [], disclosureUrl: "", externalModels: [],
};

const TEMPLATE = {
  schema: "bomlens-ai-declaration/1",
  document: { createdBy: [] },
  model: {
    releaseTime: "", builtTime: "", originatedBy: [], weightsScope: "",
    domain: [], informationAboutApplication: "", informationAboutTraining: "", hyperparameter: [],
    modelDataPreprocessing: [], modelExplainability: [], standardCompliance: [],
    useSensitivePersonalInformation: "", autonomyType: "", safetyRiskAssessment: "",
    license: "",
    baseModels: [{ ref: "org/base", revision: "" }],
  },
  datasets: [{ ref: "huggingface:org/ds", role: "", originatedBy: null, builtTime: "", releaseTime: "",
               datasetType: [], hasSensitivePersonalInformation: "", intendedUse: "" }],
  relationships: [],
};

const RESULTS = [
  { name: `${P}_bom.json`, size: 200 },
  { name: `${P}_bom.spdx3.json`, size: 300 },
  { name: `${P}_spdx3-check.json`, size: 100 },
  { name: `${P}_ai-declaration.template.json`, size: 100 },
];

const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  metadata: { component: { type: "machine-learning-model", "bom-ref": "m", name: "acme/model" } },
  components: [{ type: "data", "bom-ref": "dataset:huggingface/org/ds", name: "org/ds" }],
  dependencies: [{ ref: "m", dependsOn: ["dataset:huggingface/org/ds"] }],
};

// The SBOM after a scan with a declared service: the service, the external
// model it calls, and what it depends on (docker/lib/apply-declared-service.py).
const SBOM_WITH_SERVICE = {
  ...SBOM,
  services: [
    { "bom-ref": "service:declared/acme-support-assistant", name: "Acme Support Assistant", version: "2.3.0",
      provider: { name: "Acme Corp" }, endpoints: ["https://support.acme.example/assistant"],
      data: [{ flow: "inbound", classification: "personal data" }, { flow: "outbound", classification: "personal data" }],
      properties: [{ name: "bomlens:origin", value: "declared-input" }, { name: "bomlens:service:kind", value: "application" }] },
    { "bom-ref": "service:declared-external/example-translate", name: "Example Translate", provider: { name: "Example Inc" },
      properties: [{ name: "bomlens:origin", value: "declared-input" }, { name: "bomlens:service:kind", value: "external-model" }] },
  ],
  dependencies: [
    ...SBOM.dependencies,
    { ref: "service:declared/acme-support-assistant", dependsOn: ["m", "service:declared-external/example-translate"] },
  ],
};

async function stub(
  page: Page,
  opts: {
    capable?: boolean;
    withSummary?: boolean;
    saved?: unknown;
    refuse?: string[];
    declared?: boolean;
    upToDate?: boolean;
    /** The empty declaration asks about the service (a v1.14 converter). */
    service?: boolean;
    /** The CycloneDX SBOM carries a declared service (the next scan wrote it). */
    sbomService?: boolean;
    conformance?: unknown;
    /** The scan's summary says the CycloneDX SBOM is behind the declaration. */
    serviceState?: "none" | "applied" | "pendingScan";
  } = {},
) {
  const state = { complete: false, saved: null as unknown, exported: 0, service: false };
  const results = opts.saved ? [...RESULTS, { name: `${P}_ai-declaration.json`, size: 50 }] : RESULTS;
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdx3: opts.capable !== false }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  const done = {
    ok: true, mode: "AIBOM", id: P, results, security: null, conformance: opts.conformance ?? null,
    spdx3: opts.withSummary === false ? null : summary(false, opts.upToDate !== false, opts.serviceState ?? "none"),
    scanConfig: opts.declared
      ? { source: "ai-declare", target: "", project: "model", version: "1.0" }
      : { source: "hf-model", target: "acme/model", project: "model", version: "1.0" },
    sbom: { components: 1, componentType: "machine-learning-model",
            componentList: [{ name: "acme/model", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: [] }] },
  };
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
  await page.route("**/file**", (r) => {
    const name = new URL(r.request().url()).searchParams.get("name") ?? "";
    const body = name.endsWith("_spdx3-check.json")
      ? check(state.complete, opts.declared, state.service)
      : name.endsWith(".template.json")
        ? opts.service ? { ...TEMPLATE, service: BLANK_SERVICE } : TEMPLATE
        : name.endsWith("_ai-declaration.json")
          ? opts.saved
          : opts.sbomService ? SBOM_WITH_SERVICE : SBOM;
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.route("**/spdx3-map", (r) => r.fulfill({ contentType: "application/json", body: MAP }));
  await page.route("**/ai-declaration-template**", (r) =>
    r.fulfill({ contentType: "application/json",
                body: JSON.stringify({ name: `${P}_ai-declaration.template.json`, results: RESULTS }) }),
  );
  await page.route("**/spdx3-export**", (r) => {
    state.exported += 1;
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: `${P}_bom.spdx3.json`, results, spdx3: summary(state.complete) }),
    });
  });
  await page.route("**/ai-declaration?**", (r) => {
    state.saved = JSON.parse(r.request().postData() ?? "null");
    if (opts.refuse) {
      return r.fulfill({ status: 422, contentType: "application/json",
                         body: JSON.stringify({ error: "declaration refused", reasons: opts.refuse }) });
    }
    state.complete = true;
    // A service saved after the scan is not in the CycloneDX SBOM until the next scan.
    state.service = Boolean((state.saved as { service?: unknown } | null)?.service);
    return r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        name: `${P}_bom.spdx3.json`,
        results: [...RESULTS, { name: `${P}_ai-declaration.json`, size: 50 }],
        spdx3: summary(true, true, state.service ? "pendingScan" : "none"),
      }),
    });
  });
  return state;
}

async function runScan(page: Page) {
  await page.goto("/#/new");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
}

async function openModels(page: Page) {
  await runScan(page);
  await page.getByRole("navigation").locator('a[href$="/models"]').first().click();
}

/** A step in the list on the left, by its name alone. */
const stepButton = (flow: ReturnType<Page["getByTestId"]>, name: string) =>
  flow.getByRole("navigation").getByRole("button", { name, exact: true });

test("the band shows how the fields were filled and where the open ones are", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const band = page.getByTestId("spdx3-band");
  await expect(band).toContainText("Draft");
  await expect(band.locator('[data-segment="missingRequired"]')).toContainText("5");
  await expect(band.locator('[data-segment="filled"]')).toContainText("8");
  await expect(band).toContainText("5 required fields are still empty");
  // Someone else's model: filling matters only if they publish the document.
  await expect(band).toContainText("only if you distribute this document yourself");
  await expect(page.getByTestId("spdx3-missing-where")).toHaveText(
    "Required fields still empty: Document (1), acme/model (1), org/ds (3)",
  );
  // The field table is folded, so the model card follows the band.
  await expect(page.getByTestId("spdx3-fields")).toBeHidden();
  await page.getByText("Show the document's fields").click();
  const release = page.locator('tr[data-field="releaseTime"]').first();
  await expect(release).toContainText("Required, empty");
  await expect(page.locator('tr[data-field="suppliedBy"]').first()).toContainText("HuggingFace publisher");
  await expect(page.getByText("Training or evaluation not stated")).toBeVisible();
  await expect(page.getByText("Datasets named on the model card")).toBeVisible();
  // Values read as the questions word them, not as the document writes them.
  await expect(page.locator('tr[data-field="weightsScope"]').first()).toContainText("Adapter only");
  await expect(page.locator('tr[data-field="primaryPurpose"]').first()).toContainText("Model");
  await expect(page.locator('tr[data-field="builtTime"]').first()).toContainText("Oct 1, 2026");
  // The datasets' fold opens by itself: it holds required fields still empty.
  await expect(page.getByTestId("spdx3-dataset-fields")).toContainText("3 required, empty");
  await expect(page.locator('tr[data-field="originatedBy"]').first()).toBeVisible();
  const axe = await new AxeBuilder({ page }).include('[data-testid="spdx3-band"]').include('[data-testid="spdx3-fields"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);
});

test("a declared model's fields are open from the start, and its datasets are not said to be on a card", async ({ page }) => {
  await stub(page, { declared: true });
  await openModels(page);
  await expect(page.getByTestId("spdx3-fields")).toBeVisible();
  await expect(page.getByTestId("spdx3-band")).not.toContainText("only if you distribute");
  await expect(page.getByText("Datasets named in the declaration")).toBeVisible();
  await expect(page.getByText("Datasets named on the model card")).toHaveCount(0);
});

test("filling the open fields: only what is open is asked, and saving completes the document", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  await page.getByRole("button", { name: "Fill in empty fields" }).click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow).toBeVisible();

  // The questions open at the first step with something open; the base-model
  // step has nothing required and can be visited from the list.
  await expect(flow.getByRole("heading", { name: "Tell us about the model" })).toBeVisible();
  // An empty required field says so quietly until the field or the step is left.
  await expect(flow.locator('[data-question="model.releaseTime"] [data-missing]')).toHaveAttribute("data-missing", "quiet");
  await stepButton(flow, "Base models").click();
  await expect(flow.getByLabel("Revision (commit or tag, optional)")).toHaveCount(1);
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Model: the author and release date fail validation while empty (now
  // shown as errors: the step was left once); the weights question has no
  // "Unknown"; the optional group starts folded.
  await expect(flow.locator('[data-question="document.createdBy"]')).toContainText("fails SPDX validation");
  await expect(flow.locator('[data-question="model.releaseTime"] [data-missing]')).toHaveAttribute("data-missing", "shown");
  await expect(flow.locator('[data-question="model.weightsScope"]').getByRole("radio")).toHaveCount(4);
  await expect(flow.locator('[data-question="model.weightsScope"]').getByText("Unknown")).toHaveCount(0);
  await expect(flow.locator("details").filter({ hasText: "Use and scope (optional)" })).not.toHaveAttribute("open", "");
  await expect(flow).toContainText("5 required fields left");
  await flow.locator('[data-question="document.createdBy"] input').first().fill("Acme AI Lab");
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await flow.locator('[data-question="model.weightsScope"]').getByRole("radio", { name: "Adapter only" }).click();
  await expect(flow).toContainText("3 required fields left");
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Data: a role for the card's dataset; "Unknown" only on the personal-data
  // question, which has one; the training group folded and not counted. The
  // dataset type is written as "Unknown" when empty, so it is not required.
  await flow.getByRole("radio", { name: "Training" }).click();
  await expect(flow.locator('[data-question="dataset.hasSensitivePersonalInformation"]').getByText("Unknown")).toHaveCount(1);
  const type = flow.locator('[data-question="dataset.datasetType"]');
  await expect(type.getByText("Required", { exact: true })).toHaveCount(0);
  await expect(type).toContainText('Left empty, it is recorded as "Unknown".');
  await expect(type.getByRole("button", { name: "Sentence structure" })).toHaveAttribute("title", /parse trees/);
  await expect(flow.locator("details").filter({ hasText: "How it was trained (optional)" })).not.toHaveAttribute("open", "");
  await flow.locator('[data-question="dataset.originatedBy"] input').fill("org");
  await flow.locator('[data-question="dataset.builtTime"] input').fill("2023-10-01");
  await flow.locator('[data-question="dataset.releaseTime"] input').fill("2023-10-24");
  await expect(flow).toContainText("0 required fields left");
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Decisions: one name in the list and the heading; "Unknown" exists for
  // personal data, not for the risk level.
  await expect(flow.getByRole("heading", { name: "Your decisions" })).toBeVisible();
  await expect(stepButton(flow, "Your decisions")).toHaveAttribute("aria-current", "step");
  await expect(flow.locator('[data-question="model.useSensitivePersonalInformation"]').getByText("Unknown")).toHaveCount(1);
  await expect(flow.locator('[data-question="model.safetyRiskAssessment"]').getByText("Unknown")).toHaveCount(0);
  await flow.locator('[data-question="model.safetyRiskAssessment"]').getByRole("radio", { name: "Medium" }).click();
  await flow.getByRole("button", { name: /^Next/ }).click();

  await expect(flow).toContainText("Every required field is filled");
  // What will be saved, as words, grouped like the steps.
  await expect(flow.locator('[data-summary="model"]')).toContainText("Acme AI Lab");
  await expect(flow.locator('[data-summary="model"]')).toContainText("Apr 15, 2025");
  await expect(flow.locator('[data-summary="model"]')).toContainText("Adapter only");
  await expect(flow.locator('[data-summary="data"]')).toContainText("Training");
  await expect(flow.locator('[data-summary="legal"]')).toContainText("Medium");
  await flow.getByRole("button", { name: "Save" }).click();

  await expect(page.getByTestId("spdx3-band")).toContainText("Complete");
  await expect(page.getByTestId("spdx3-band")).not.toContainText("Draft");
  expect(state.saved).toEqual({
    schema: "bomlens-ai-declaration/1",
    document: { createdBy: [{ type: "Organization", name: "Acme AI Lab" }] },
    model: { releaseTime: "2025-04-15T00:00:00Z", weightsScope: "adapter", safetyRiskAssessment: "medium" },
    datasets: [{ ref: "huggingface:org/ds", role: "trainedOn", originatedBy: { type: "Organization", name: "org" },
                 builtTime: "2023-10-01T00:00:00Z", releaseTime: "2023-10-24T00:00:00Z" }],
    relationships: [],
  });
});

test("a step left with required fields open is marked, and its empty fields turn red on return", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  // Each step says how many items it still holds.
  await expect(stepButton(flow, "Training data")).toHaveAccessibleDescription("3 open");
  await expect(stepButton(flow, "Model")).toHaveAccessibleDescription("2 open");
  await next(flow);
  // Left with two open: a warning mark, not a tick.
  await expect(stepButton(flow, "Model").locator("svg")).toHaveCount(1);
  await expect(stepButton(flow, "Model")).toHaveAccessibleDescription("2 open");
  await flow.getByRole("button", { name: "Back" }).click();
  await expect(flow.locator('[data-question="model.releaseTime"] [data-missing]')).toHaveAttribute("data-missing", "shown");
});

test("the review jumps to a step's first open field", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await flow.locator('[data-question="document.createdBy"] input').first().fill("Acme AI Lab");
  await stepButton(flow, "Review").click();
  await expect(flow.locator('[data-summary="base"]')).toContainText("org/base");
  await expect(flow.locator('[data-summary="base"]')).toContainText("no revision");
  await flow.getByRole("button", { name: "Model: 1 open" }).click();
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toBeFocused();
  await stepButton(flow, "Review").click();
  await flow.getByRole("button", { name: "Training data: 3 open" }).click();
  await expect(flow.locator('[data-question="dataset.originatedBy"] input').first()).toBeFocused();
});

test("the licence question says what the licence does for this model, and offers common ones", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  const lic = flow.locator('[data-question="model.license"]');
  await expect(lic).toContainText("Recorded in the SPDX 3.0.1 document only");
  await expect(lic).not.toContainText("next scan");
  const list = await lic.locator("input").getAttribute("list");
  expect(list).toBeTruthy();
  await expect(flow.locator(`datalist[id="${list}"] option[value="apache-2.0"]`)).toHaveCount(1);
});

test("a declared model's licence takes effect at its next scan", async ({ page }) => {
  await stub(page, { declared: true });
  await openModels(page);
  const flow = await openFlow(page);
  await expect(flow.locator('[data-question="model.license"]')).toContainText("from this model's next scan");
});

test("a scan from before the document offers to write it", async ({ page }) => {
  await stub(page, { withSummary: false });
  await openModels(page);
  await expect(page.getByRole("button", { name: "Write the SPDX 3.0.1 document" })).toBeVisible();
});

test("a server that cannot write the document hides the actions", async ({ page }) => {
  await stub(page, { capable: false });
  await openModels(page);
  await expect(page.getByTestId("spdx3-band")).toContainText("Draft");
  await expect(page.getByRole("button", { name: "Fill in empty fields" })).toHaveCount(0);
});

const openFlow = async (page: Page) => {
  await page.getByRole("button", { name: "Fill in empty fields" }).click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow).toBeVisible();
  return flow;
};
const next = (flow: ReturnType<Page["getByTestId"]>) => flow.getByRole("button", { name: /^Next/ }).click();

test("list answers take more rows, and an empty row stays while it is typed in", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  const author = flow.locator('[data-question="document.createdBy"]');
  await author.getByRole("textbox").first().fill("Acme AI Lab");
  await author.getByRole("button", { name: "Add another" }).click();
  await expect(author.getByRole("textbox")).toHaveCount(2);
  await author.getByRole("textbox").nth(1).fill("Partner Lab");
  await author.getByRole("textbox").nth(1).fill("");
  await expect(author.getByRole("textbox")).toHaveCount(2);
  await author.getByRole("textbox").nth(1).fill("Partner Lab");
  await stepButton(flow, "Review").click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toContainText("Complete");
  expect((state.saved as { document: unknown }).document).toEqual({
    createdBy: [
      { type: "Organization", name: "Acme AI Lab" },
      { type: "Organization", name: "Partner Lab" },
    ],
  });
});

test("data the hub does not hold: an untouched one is dropped, a started one needs a name and an address", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Training data").click();
  await flow.getByRole("button", { name: "Add data the hub does not hold" }).click();
  await flow.getByRole("button", { name: "Add data the hub does not hold" }).click();
  const locals = flow.locator('[data-dataset="local"]');
  await expect(locals).toHaveCount(2);
  await locals.nth(1).getByRole("button", { name: "Remove" }).click();
  await expect(locals).toHaveCount(1);
  await locals.first().getByLabel("Name").fill("Support logs 2025");
  await stepButton(flow, "Review").click();
  await expect(flow.getByRole("button", { name: "Save" })).toBeDisabled();
  await expect(flow).toContainText("the server would refuse them");
  await flow.getByRole("button", { name: /Training data: / }).click();
  await locals.first().locator('[data-question="dataset.downloadLocation"] input').fill("https://data.example.com/logs");
  await stepButton(flow, "Review").click();
  await expect(flow.getByRole("button", { name: "Save" })).toBeEnabled();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  expect((state.saved as { datasets: unknown[] }).datasets).toEqual([
    { local: "support-logs-2025", name: "Support logs 2025", downloadLocation: "https://data.example.com/logs" },
  ]);
});

test("a refused save shows the server's reasons and keeps the answers", async ({ page }) => {
  await stub(page, { refuse: ["model.releaseTime: a date must be written YYYY-MM-DDThh:mm:ssZ (UTC)"] });
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Review").click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(flow.getByRole("alert")).toContainText("The declaration was refused");
  await expect(flow.getByRole("alert")).toContainText("model.releaseTime");
  await expect(flow).toBeVisible();
});

test("a saved declaration is laid over the open fields when the questions reopen", async ({ page }) => {
  await stub(page, {
    saved: {
      schema: "bomlens-ai-declaration/1",
      model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/base", revision: "abc123" }] },
      datasets: [{ ref: "huggingface:org/ds", role: "testedOn" }],
    },
  });
  await openModels(page);
  const flow = await openFlow(page);
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("2025-04-15");
  await stepButton(flow, "Base models").click();
  await expect(flow.getByLabel("Revision (commit or tag, optional)")).toHaveValue("abc123");
  await stepButton(flow, "Training data").click();
  await expect(flow.getByRole("radio", { name: "Evaluation" })).toHaveAttribute("aria-checked", "true");
});

test("answers survive leaving the section; cancelling drops them and returns focus", async ({ page }) => {
  await stub(page);
  await openModels(page);
  let flow = await openFlow(page);
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await page.locator('a[href$="/components"]').first().click();
  await expect(page.getByTestId("ai-declaration")).toHaveCount(0);
  await page.locator('a[href$="/models"]').first().click();
  flow = page.getByTestId("ai-declaration");
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("2025-04-15");
  await flow.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Fill in empty fields" })).toBeFocused();
  flow = await openFlow(page);
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("");
});

test("single choices work from the keyboard as a radio group", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  const scope = flow.locator('[data-question="model.weightsScope"]');
  await scope.getByRole("radio", { name: "Full weights" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(scope.getByRole("radio", { name: "Adapter only" })).toBeFocused();
  await expect(scope.getByRole("radio", { name: "Adapter only" })).toHaveAttribute("aria-checked", "true");
  await expect(scope.getByRole("radio", { name: "Full weights" })).toHaveAttribute("tabindex", "-1");
});

test("the questions have no accessibility violations", async ({ page }) => {
  await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Base models").click();
  for (let i = 0; i < 5; i++) {
    const axe = await new AxeBuilder({ page }).include('[data-testid="ai-declaration"]')
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
    expect(axe.violations).toEqual([]);
    if (i < 4) await next(flow);
  }
});

test("the artifact cards label the check, rebuild only a document that is behind, and take a declaration file", async ({ page }) => {
  const state = await stub(page, { upToDate: false });
  await openModels(page);
  await page.getByRole("navigation").locator('a[href$="/artifacts"]').first().click();
  await expect(page.getByRole("link", { name: /^Check JSON/ })).toBeVisible();
  await expect(page.getByText("cannot be uploaded back as an SBOM input")).toHaveCount(0);
  await expect(page.getByText("Fill in empty fields on Models & datasets")).toBeVisible();
  await expect(page.getByText("rebuild it to bring it up to date")).toBeVisible();
  await page.getByRole("button", { name: "Rebuild with the saved declaration" }).click();
  await expect.poll(() => state.exported).toBe(1);
  await page.locator('input[type="file"][accept*="json"]').setInputFiles({
    name: "decl.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ schema: "bomlens-ai-declaration/1", model: { releaseTime: "2025-04-15T00:00:00Z" } })),
  });
  await expect.poll(() => state.saved).toEqual({ schema: "bomlens-ai-declaration/1", model: { releaseTime: "2025-04-15T00:00:00Z" } });
});

test("a document that matches its declaration offers no rebuild", async ({ page }) => {
  await stub(page);
  await openModels(page);
  await page.getByRole("navigation").locator('a[href$="/artifacts"]').first().click();
  await expect(page.getByRole("link", { name: /^Check JSON/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Rebuild with the saved declaration" })).toHaveCount(0);
});

test("the Overview says where the document stands and opens the questions", async ({ page }) => {
  await stub(page);
  await runScan(page);
  const line = page.getByTestId("ai-summary-spdx3");
  await expect(line).toContainText("Draft");
  await expect(line).toContainText("5 required fields left");
  await line.getByRole("link", { name: "Fill in empty fields in Models & datasets" }).click();
  await expect(page.getByTestId("ai-declaration")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Tell us about the model" })).toBeVisible();
});

test("filling a declared model's fields keeps the base models and datasets its declaration named", async ({ page }) => {
  const original = {
    schema: "bomlens-ai-declaration/1",
    model: { baseModels: [{ ref: "org/base", revision: "" }] },
    datasets: [{ ref: "huggingface:org/ds", role: "trainedOn" }],
  };
  const state = await stub(page, { declared: true, saved: original });
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Review").click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  const saved = state.saved as { model: { baseModels: unknown[] }; datasets: { ref?: string }[] };
  expect(saved.model.baseModels).toEqual([{ ref: "org/base", revision: "" }]);
  expect(saved.datasets.map((d) => d.ref)).toContain("huggingface:org/ds");
});

test("a dataset's sources can be declared: by hub id, or named in words with a licence", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Training data").click();
  const box = flow.locator('[data-sources="huggingface:org/ds"]');
  await expect(box).toContainText("No source is on record for this data.");
  await box.getByLabel("Source on HuggingFace (id)").fill("allenai/c4");
  await box.getByRole("button", { name: "Add source" }).click();
  await box.getByRole("button", { name: "Add a source named in words" }).click();
  await box.getByLabel("Source named in words 2", { exact: true }).fill("Old crawl");
  await box.getByLabel("Licence of source 2", { exact: true }).fill("my own terms");
  // Two rows can be told apart, and the sources box passes the automated checks.
  await expect(box.getByLabel("Source named in words 2", { exact: true })).toBeVisible();
  const axe = await new AxeBuilder({ page }).include('[data-testid="ai-declaration"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);
  await stepButton(flow, "Review").click();
  await expect(flow.getByRole("button", { name: "Save" })).toBeDisabled();
  await flow.getByRole("button", { name: /Training data: / }).click();
  await box.getByLabel("Licence of source 2", { exact: true }).fill("cc-by-4.0");
  await stepButton(flow, "Review").click();
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  const saved = state.saved as { datasets: { ref?: string; sources?: unknown[] }[] };
  expect(saved.datasets.find((d) => d.ref === "huggingface:org/ds")?.sources).toEqual([
    { ref: "huggingface:allenai/c4", relation: "extended" },
    { name: "Old crawl", license: "cc-by-4.0", relation: "other" },
  ]);
});

test("a hub source typed and not added is added when the step is left", async ({ page }) => {
  const state = await stub(page);
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Training data").click();
  const box = flow.locator('[data-sources="huggingface:org/ds"]');
  // Not an id: the step is not left, and the box says why.
  await box.getByLabel("Source on HuggingFace (id)").fill("not an id");
  await stepButton(flow, "Review").click();
  await expect(flow.getByRole("heading", { name: "What data did you use?" })).toBeVisible();
  await expect(box).toContainText("you stayed on this step");
  await expect(box.getByLabel("Source on HuggingFace (id)")).toBeFocused();
  await box.getByLabel("Source on HuggingFace (id)").fill("allenai/c4");
  await stepButton(flow, "Review").click();
  await expect(flow.locator('[data-summary="data"]')).toContainText("allenai/c4");
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  const saved = state.saved as { datasets: { ref?: string; sources?: unknown[] }[] };
  expect(saved.datasets.find((d) => d.ref === "huggingface:org/ds")?.sources).toEqual([
    { ref: "huggingface:allenai/c4", relation: "extended" },
  ]);
});

test("the service step is optional: no keeps the count, yes asks the service's required fields", async ({ page }) => {
  await stub(page, { service: true });
  await openModels(page);
  const flow = await openFlow(page);
  await expect(flow).toContainText("5 required fields left");
  // Not answered, it has nothing open.
  await expect(stepButton(flow, "Service (optional)")).not.toHaveAttribute("aria-describedby", /.+/);
  await stepButton(flow, "Service (optional)").click();
  await expect(flow.getByRole("heading", { name: "Do you run this model in a service, such as an app or an API?" })).toBeVisible();
  await expect(flow).toContainText("fills the G7 system elements");
  await flow.getByRole("radio", { name: "No, record the model only" }).click();
  await expect(flow.getByTestId("service-answer-note")).toContainText("records the model only");
  await expect(flow).toContainText("5 required fields left");
  await expect(flow.getByTestId("service-required")).toHaveCount(0);

  await flow.getByRole("radio", { name: "Yes, I will describe the service" }).click();
  await expect(flow).toContainText("10 required fields left");
  const required = flow.getByTestId("service-required");
  await expect(required.locator("[data-question]")).toHaveCount(5);
  // A provider is an organization: there is no kind to choose.
  await expect(flow.locator('[data-question="service.suppliedBy"] select')).toHaveCount(0);
  // Nothing open in the optional groups, so they start folded.
  for (const g of ["use", "io", "flows", "external", "standards"]) {
    await expect(flow.locator("details").filter({ has: page.locator(`[data-service-group="${g}"]`) })).not.toHaveAttribute("open", "");
    await flow.locator(`[data-service-group="${g}"]`).click();
  }
  // The person question reads as asked, in the order a person thinks of it.
  const autonomy = flow.locator('[data-question="service.autonomyType"]');
  await expect(autonomy).toContainText("Is a person involved in the AI's decisions?");
  await expect(autonomy.getByRole("radio")).toHaveText(["Involved", "Fully automatic", "Not known"]);
  const axe = await new AxeBuilder({ page }).include('[data-testid="ai-declaration"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);

  // Back to "later": the count returns and the review records no service.
  await flow.getByRole("radio", { name: "I will write it later" }).click();
  await expect(flow).toContainText("5 required fields left");
  await stepButton(flow, "Review").click();
  await expect(flow.getByTestId("service-summary-note")).toContainText("No service is recorded for now");
});

test("a service declared after the scan is saved, and the band says a new scan brings it to the CycloneDX SBOM", async ({ page }) => {
  const state = await stub(page, { service: true });
  await openModels(page);
  const flow = await openFlow(page);
  await stepButton(flow, "Service (optional)").click();
  await flow.getByRole("radio", { name: "Yes, I will describe the service" }).click();
  const q = (id: string) => flow.locator(`[data-question="service.${id}"]`);
  await q("name").locator("input").fill("Acme Support Assistant");
  await q("packageVersion").locator("input").fill("2.3.0");
  await q("downloadLocation").locator("input").fill("https://support.acme.example/assistant");
  await q("suppliedBy").locator("input").fill("Acme Corp");
  await q("releaseTime").locator("input").fill("2025-06-01");
  await flow.locator('[data-service-group="use"]').click();
  await q("autonomyType").getByRole("radio", { name: "Involved" }).click();
  // A data flow is added by what data it is, then given its direction.
  await flow.locator('[data-service-group="flows"]').click();
  await flow.getByLabel("What data is it?").fill("personal data");
  await flow.getByRole("button", { name: "Add data flow" }).click();
  const row = flow.locator('[data-flow-row="0"]');
  await row.locator('[data-question="dataFlow.flow"]').getByRole("radio", { name: "Comes in" }).click();
  // An external model typed and not added is added when the step is left.
  await flow.locator('[data-service-group="external"]').click();
  await flow.getByLabel("External AI model name").fill("Example Translate");

  // The decisions step no longer asks the model's autonomy: the service answered it.
  await stepButton(flow, "Your decisions").click();
  await expect(flow.locator('[data-question="model.autonomyType"]')).toHaveCount(0);
  await expect(flow.getByTestId("autonomy-in-service")).toBeVisible();

  await stepButton(flow, "Review").click();
  const sum = flow.locator('[data-summary="service"]');
  await expect(sum).toContainText("Acme Support Assistant");
  await expect(sum).toContainText("Involved");
  await expect(sum).toContainText("Comes in: personal data");
  await expect(sum).toContainText("Example Translate");
  await expect(flow.getByTestId("service-summary-note")).toContainText("include it after a new scan");
  await flow.getByRole("button", { name: "Save" }).click();

  const pending = page.getByTestId("spdx3-service-pending");
  await expect(pending).toContainText("The declared service and model information are in the SPDX 3.0.1 document");
  expect((state.saved as { service: unknown }).service).toEqual({
    name: "Acme Support Assistant",
    packageVersion: "2.3.0",
    downloadLocation: "https://support.acme.example/assistant",
    suppliedBy: { type: "Organization", name: "Acme Corp" },
    releaseTime: "2025-06-01T00:00:00Z",
    autonomyType: "no",
    dataFlows: [{ flow: "inbound", classification: "personal data" }],
    externalModels: [{ key: "example-translate", name: "Example Translate" }],
  });
  // The document's fields show the service as the publisher's declaration.
  await page.getByText("Show the document's fields").click();
  const fields = page.getByTestId("spdx3-service-fields");
  await expect(fields).toContainText("Publisher's declaration");
  await expect(fields.locator('tr[data-field="autonomyType"]')).toContainText("Involved");
  await expect(fields.locator('tr[data-field="dataFlows"]')).toContainText("Comes in: personal data");
  await expect(fields.locator('tr[data-field="primaryPurpose"]').first()).toContainText("Application");
  await expect(page.getByTestId("spdx3-external-model")).toContainText("External AI model: Example Translate");
  const axe = await new AxeBuilder({ page }).include('[data-testid="spdx3-band"]').include('[data-testid="spdx3-fields"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);
  // The band's re-scan opens the scan form, as the top bar's does.
  await pending.getByRole("button", { name: "Re-scan" }).click();
  await expect(page).toHaveURL(/#\/new/);
});

test("the model step asks input and output kinds, and folds the regulatory fields with a format check", async ({ page }) => {
  const state = await stub(page, { service: true });
  await page.route("**/file**", async (r) => {
    const name = new URL(r.request().url()).searchParams.get("name") ?? "";
    if (!name.endsWith(".template.json")) return r.fallback();
    const model = { ...TEMPLATE.model, inputModality: [], outputModality: [], trainingComputeFlops: "",
                    trainingComputeBasis: "", adversarialTesting: "" };
    const datasets = TEMPLATE.datasets.map((d) => ({ ...d, knownBias: [] }));
    return r.fulfill({ contentType: "application/json",
                       body: JSON.stringify({ ...TEMPLATE, model, datasets, service: BLANK_SERVICE }) });
  });
  await openModels(page);
  const flow = await openFlow(page);
  await flow.locator('[data-question="model.inputModality"]').getByRole("button", { name: "Text" }).click();
  await flow.locator('[data-question="model.outputModality"]').getByRole("button", { name: "Code" }).click();
  const reg = flow.locator("details").filter({ hasText: "For regulatory filings (optional)" });
  await expect(reg).not.toHaveAttribute("open", "");
  await reg.locator("summary").click();
  await expect(reg).toContainText("not legal advice");
  const flops = flow.locator('[data-question="model.trainingComputeFlops"]');
  await expect(flops).toContainText("Annex XI");
  await flops.locator("input").fill("about 1e24");
  await flops.locator("input").blur();
  await expect(flops).toContainText("Write a number greater than zero");
  await flops.locator("input").fill("3.2e24");
  await expect(flops).not.toContainText("Write a number greater than zero");
  await flow.locator('[data-question="model.adversarialTesting"]').getByRole("radio", { name: "Yes" }).click();
  // The dataset's known bias is asked with the main questions.
  await stepButton(flow, "Training data").click();
  await expect(flow.locator('[data-question="dataset.knownBias"]')).toBeVisible();
  await stepButton(flow, "Review").click();
  // No service, but these model values also reach the CycloneDX SBOM only from a new scan.
  await expect(flow.getByTestId("cdx-note")).toContainText("include them after a new scan");
  await flow.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  expect((state.saved as { model: unknown }).model).toMatchObject({
    inputModality: ["text"], outputModality: ["code"], trainingComputeFlops: "3.2e24", adversarialTesting: "yes",
  });
  expect((state.saved as { service?: unknown }).service).toBeUndefined();
});

test("model values saved after the scan, with no service, need a new scan and no service is named", async ({ page }) => {
  // pendingScan with no service in the document: the model's input and output
  // kinds or regulatory values were saved after the scan.
  await stub(page, { serviceState: "pendingScan" });
  await openModels(page);
  const pending = page.getByTestId("spdx3-service-pending");
  await expect(pending).toContainText("The saved declaration and the CycloneDX SBOM differ");
  await expect(pending).not.toContainText("declared service");
  await expect(pending.getByRole("button", { name: "Re-scan" })).toBeVisible();
});

test("an applied service adds no note to the band", async ({ page }) => {
  await stub(page, { serviceState: "applied" });
  await openModels(page);
  await expect(page.getByTestId("spdx3-band")).toBeVisible();
  await expect(page.getByTestId("spdx3-service-pending")).toHaveCount(0);
});

test("Models & datasets shows the declared service from the SBOM as the publisher's declaration", async ({ page }) => {
  await stub(page, {
    sbomService: true,
    conformance: {
      result: "pass",
      checks: [
        { id: "g7-slp-name", label: "System name", required: false, status: "pass", detail: "present (publisher's declaration, not verified by BomLens)",
          cluster: "slp", source: "declared" },
        { id: "g7-meta-signature", label: "Signature", required: false, status: "warn", detail: "no signature",
          cluster: "metadata", source: "declared" },
      ],
    },
  });
  await openModels(page);
  const card = page.getByTestId("declared-service");
  await expect(card).toContainText("Acme Support Assistant");
  await expect(card).toContainText("Publisher's declaration");
  await expect(card).toContainText("did not check it");
  await expect(card).toContainText("Acme Corp");
  await expect(card).toContainText("acme/model");
  await expect(card).toContainText("2 flows");
  await expect(page.getByTestId("declared-external-models")).toContainText("Example Translate");
  // A G7 element met by a declaration says whose word it is; one still open
  // says it needs one.
  await expect(page.locator("li").filter({ hasText: "System name" })).toContainText("Publisher's declaration");
  await expect(page.locator("li").filter({ hasText: "Signature" })).toContainText("Declaration needed");
  await expect(page.locator("li").filter({ hasText: "Signature" })).not.toContainText("Publisher's declaration");
  const axe = await new AxeBuilder({ page }).include('[data-testid="declared-service"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations).toEqual([]);
});
