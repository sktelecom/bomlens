// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

// A model described from its publisher's declaration alone: the New scan tile
// opens the questions instead of a scan, the answers are uploaded as the
// declaration, and the scan starts with its token. The scan itself is stubbed.

const MAP = readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8");

async function stub(page: Page, opts: { aiDeclare?: boolean; refuse?: string[] } = {}) {
  const state = { uploaded: null as unknown, scanQuery: "", checked: 0 };
  await page.route("**/ai-declaration-check**", (r) => {
    state.checked += 1;
    return opts.refuse
      ? r.fulfill({ status: 422, contentType: "application/json",
                    body: JSON.stringify({ error: "declaration refused", reasons: opts.refuse }) })
      : r.fulfill({ contentType: "application/json", body: JSON.stringify({ ok: true }) });
  });
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, aibom: true, spdx3: true, aiDeclare: opts.aiDeclare !== false }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/spdx3-map", (r) => r.fulfill({ contentType: "application/json", body: MAP }));
  await page.route("**/upload?kind=declaration", async (r) => {
    const body = r.request().postDataBuffer()?.toString("utf-8") ?? "";
    const json = body.slice(body.indexOf("{"), body.lastIndexOf("}") + 1);
    state.uploaded = JSON.parse(json);
    return r.fulfill({ contentType: "application/json", body: JSON.stringify({ token: "tok123", filename: "ai-declaration.json" }) });
  });
  await page.route("**/scan-stream**", (r) => {
    state.scanQuery = new URL(r.request().url()).search;
    const done = { ok: true, mode: "AIDECLARE", id: "acme_1.0", results: [], sbom: null, security: null, conformance: null };
    return r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` });
  });
  return state;
}

/** A step in the list on the left, by its name alone. */
const stepButton = (flow: ReturnType<Page["getByTestId"]>, name: string) =>
  flow.getByRole("navigation").getByRole("button", { name, exact: true });

async function pickTile(page: Page) {
  await page.goto("/#/new");
  await page.getByTestId("source-ai-declare").click();
  await page.fill("#project", "acme");
  await page.fill("#version", "1.0");
}

test("the tile opens the questions; finishing them uploads the declaration and starts the scan", async ({ page }) => {
  const state = await stub(page);
  await pickTile(page);
  await expect(page.getByTestId("ai-declare-hint")).toBeVisible();
  // The project name becomes the model's name.
  await expect(page.locator("#project-hint")).toContainText("becomes the model's name");
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow).toBeVisible();

  // Base models: first whether there is one, then added by id, checked as one.
  await expect(flow.getByRole("heading", { name: "Did this model start from another model?" })).toBeVisible();
  await expect(flow.getByLabel("Base model (HuggingFace id)")).toHaveCount(0);
  await flow.getByRole("radio", { name: "Started from a base model" }).click();
  await flow.getByLabel("Base model (HuggingFace id)").fill("not an id");
  await expect(flow.getByRole("button", { name: "Add", exact: true })).toBeDisabled();
  await flow.getByLabel("Base model (HuggingFace id)").fill("Qwen/Qwen2.5-0.5B");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  await expect(flow.locator('[data-base="Qwen/Qwen2.5-0.5B"]')).toBeVisible();
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Model: the author is asked (no SBOM author on the form), and the address
  // and supplier a hub would have given.
  await flow.locator('[data-question="document.createdBy"] input').first().fill("Acme AI Lab");
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await flow.locator('[data-question="model.downloadLocation"] input').fill("https://models.example.com/acme");
  await flow.locator('[data-question="model.suppliedBy"] input').first().fill("Acme");
  // The model's own licence, which the risk assessment judges it on.
  await expect(flow.locator('[data-question="model.license"]')).toContainText("Used for this model's risk verdict");
  await flow.locator('[data-question="model.license"] input').fill("apache-2.0");
  await flow.getByRole("button", { name: /^Next/ }).click();

  // Data: a hub dataset by id, whose address the scan reads.
  await flow.getByLabel("Dataset on HuggingFace (id)").fill("HuggingFaceH4/ultrachat_200k");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  const ds = flow.locator('[data-dataset="huggingface:HuggingFaceH4/ultrachat_200k"]');
  await expect(ds).toContainText("Read at scan");
  await expect(ds.locator('[data-question="dataset.downloadLocation"]')).toHaveCount(0);
  await ds.getByRole("radio", { name: "Training" }).click();
  await flow.getByRole("button", { name: "Review" }).click();
  await flow.getByRole("button", { name: "Start the scan" }).click();

  await expect.poll(() => state.scanQuery).toContain("source=ai-declare");
  expect(state.scanQuery).toContain("token=tok123");
  expect(state.checked).toBe(1);
  expect(state.uploaded).toMatchObject({
    schema: "bomlens-ai-declaration/1",
    document: { createdBy: [{ type: "Organization", name: "Acme AI Lab" }] },
    model: {
      releaseTime: "2025-04-15T00:00:00Z",
      downloadLocation: "https://models.example.com/acme",
      suppliedBy: { type: "Organization", name: "Acme" },
      license: "apache-2.0",
      baseModels: [{ ref: "Qwen/Qwen2.5-0.5B", revision: "" }],
    },
    datasets: [{ ref: "huggingface:HuggingFaceH4/ultrachat_200k", role: "trainedOn" }],
  });
});

test("cancelling the questions returns to the form", async ({ page }) => {
  await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  await page.getByTestId("ai-declaration").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByTestId("source-ai-declare")).toBeVisible();
});

test("the tile is locked when the server cannot describe a model from a declaration", async ({ page }) => {
  await stub(page, { aiDeclare: false });
  await page.goto("/#/new");
  await expect(page.getByTestId("source-ai-declare")).toHaveAttribute("aria-disabled", "true");
});

test("a declaration the server refuses is answered in the questions, with the answers kept", async ({ page }) => {
  const state = await stub(page, { refuse: ["datasets: huggingface:org/a is the same hub dataset as another declared one"] });
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await flow.getByRole("button", { name: /^Next/ }).click();
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await flow.getByRole("button", { name: "Review" }).click();
  await flow.getByRole("button", { name: "Start the scan" }).click();
  await expect(flow.getByRole("alert")).toContainText("same hub dataset");
  expect(state.uploaded).toBeNull();
  expect(state.scanQuery).toBe("");
  await stepButton(flow, "Model").click();
  await expect(flow.locator('[data-question="model.releaseTime"] input')).toHaveValue("2025-04-15");
});

test("the create-mode questions have no accessibility violations", async ({ page }) => {
  await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await flow.getByRole("radio", { name: "Started from a base model" }).click();
  await flow.getByLabel("Base model (HuggingFace id)").fill("org/base");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  await stepButton(flow, "Training data").click();
  await flow.getByLabel("Dataset on HuggingFace (id)").fill("org/ds");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  await stepButton(flow, "Base models").click();
  for (let i = 0; i < 5; i++) {
    const axe = await new AxeBuilder({ page }).include('[data-testid="ai-declaration"]')
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
    expect(axe.violations).toEqual([]);
    if (i < 4) await flow.getByRole("button", { name: /^Next/ }).click();
  }
});

test("re-scanning a declared model reopens the questions at the review, with its answers", async ({ page }) => {
  await stub(page);
  const saved = {
    schema: "bomlens-ai-declaration/1",
    model: { releaseTime: "2025-04-15T00:00:00Z", baseModels: [{ ref: "org/base", revision: "" }] },
    datasets: [{ ref: "huggingface:org/ds", role: "testedOn" }],
  };
  const detail = {
    ok: true, mode: null, id: "acme_1.0", security: null, conformance: null,
    results: [{ name: "acme_1.0_bom.json", size: 10 }, { name: "acme_1.0_ai-declaration.json", size: 10 }],
    sbom: { components: 1, componentType: "machine-learning-model",
            componentList: [{ name: "acme", version: "1.0", group: "", purl: "", type: "machine-learning-model", licenses: [] }] },
    scanConfig: { source: "ai-declare", target: "", project: "acme", version: "1.0" },
  };
  await page.route("**/scan?id=*", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(detail) }));
  // The declaration arrives late: the questions wait for it rather than opening empty.
  await page.route("**/file**", async (r) => {
    await new Promise((res) => setTimeout(res, 1500));
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(saved) });
  });
  await page.goto("/#/scan/acme_1.0");
  await page.getByRole("button", { name: "Re-scan" }).first().click();
  await expect(page.getByTestId("source-ai-declare")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await expect(flow.getByRole("heading", { name: "Review and save" })).toBeVisible();
  await flow.getByText("The declaration file that will be saved").click();
  await expect(flow.locator("pre")).toContainText('"org/base"');
  await expect(flow.locator("pre")).toContainText('"testedOn"');
  await expect(flow.locator("pre")).toContainText("2025-04-15T00:00:00Z");
});

test("removing an added dataset names it and keeps the keyboard in the step", async ({ page }) => {
  await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await stepButton(flow, "Training data").click();
  await flow.getByLabel("Dataset on HuggingFace (id)").fill("org/ds");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  await flow.getByLabel("Dataset on HuggingFace (id)").fill("ORG/DS");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  await expect(flow.locator("[data-dataset]")).toHaveCount(1);
  await flow.getByRole("button", { name: "Remove org/ds" }).click();
  await expect(flow.locator("[data-dataset]")).toHaveCount(0);
  await expect(flow.getByRole("heading", { name: "What data did you use?" })).toBeFocused();
});

test("leaving for another screen closes the questions", async ({ page }) => {
  await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  await expect(page.getByTestId("ai-declaration")).toBeVisible();
  await page.goto("/#/");
  await page.goto("/#/new");
  await expect(page.getByTestId("ai-declaration")).toHaveCount(0);
  await expect(page.getByTestId("source-ai-declare")).toBeVisible();
});

test("an id typed and not added is not lost: leaving the step adds it, and a bad one keeps the step", async ({ page }) => {
  const state = await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await flow.getByRole("radio", { name: "Started from a base model" }).click();
  await flow.getByLabel("Base model (HuggingFace id)").fill("not an id");
  await flow.getByRole("button", { name: /^Next/ }).click();
  await expect(flow.getByRole("heading", { name: "Did this model start from another model?" })).toBeVisible();
  await expect(flow).toContainText("you stayed on this step");
  await expect(flow.getByLabel("Base model (HuggingFace id)")).toBeFocused();
  // Typed, not added with the button: Next adds it.
  await flow.getByLabel("Base model (HuggingFace id)").fill("Qwen/Qwen2.5-0.5B");
  await flow.getByRole("button", { name: /^Next/ }).click();
  await expect(flow.getByRole("heading", { name: "Tell us about the model" })).toBeVisible();
  await flow.locator('[data-question="model.releaseTime"] input').fill("2025-04-15");
  await stepButton(flow, "Training data").click();
  // A hub dataset typed and not added is added on the way to the review.
  await flow.getByLabel("Dataset on HuggingFace (id)").fill("HuggingFaceH4/ultrachat_200k");
  await stepButton(flow, "Review").click();
  await expect(flow.locator('[data-summary="base"]')).toContainText("Qwen/Qwen2.5-0.5B");
  await expect(flow.locator('[data-summary="data"]')).toContainText("HuggingFaceH4/ultrachat_200k");
  await flow.getByRole("button", { name: "Start the scan" }).click();
  await expect.poll(() => state.scanQuery).toContain("source=ai-declare");
  expect(state.uploaded).toMatchObject({
    model: { baseModels: [{ ref: "Qwen/Qwen2.5-0.5B", revision: "" }] },
    datasets: [{ ref: "huggingface:HuggingFaceH4/ultrachat_200k" }],
  });
});

test("a model trained from scratch says so, and adapter weights without a base model are warned about", async ({ page }) => {
  const state = await stub(page);
  await pickTile(page);
  await page.getByTestId("run-scan").click();
  const flow = page.getByTestId("ai-declaration");
  await flow.getByRole("radio", { name: "Started from a base model" }).click();
  await flow.getByLabel("Base model (HuggingFace id)").fill("org/base");
  await flow.getByRole("button", { name: "Add", exact: true }).click();
  // Choosing "from scratch" drops the base model.
  await flow.getByRole("radio", { name: "Trained from scratch" }).click();
  await expect(flow.getByTestId("origin-scratch")).toBeVisible();
  await expect(flow.locator("[data-base]")).toHaveCount(0);
  await flow.getByRole("button", { name: /^Next/ }).click();
  const scope = flow.locator('[data-question="model.weightsScope"]');
  await scope.getByRole("radio", { name: "Adapter only" }).click();
  await expect(scope.getByRole("note")).toContainText("An adapter needs its base model's weights to run");
  await scope.getByRole("radio", { name: "Full weights" }).click();
  await expect(scope.getByRole("note")).toHaveCount(0);
  await scope.getByRole("radio", { name: "Adapter only" }).click();
  await stepButton(flow, "Review").click();
  await expect(flow.locator('[data-summary="base"]')).toContainText("Trained from scratch");
  // A warning, not a blocker.
  await flow.getByRole("button", { name: "Start the scan" }).click();
  await expect.poll(() => state.scanQuery).toContain("source=ai-declare");
  expect((state.uploaded as { model: Record<string, unknown> }).model.baseModels).toBeUndefined();
});

test("the AI model hint names both documents it writes", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.getByTestId("source-ai-model").click();
  await expect(page.getByText("CycloneDX ML-BOM and an SPDX 3.0.1 AI document")).toBeVisible();
});
