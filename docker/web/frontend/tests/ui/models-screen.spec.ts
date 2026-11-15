// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

import { waitForSettled } from "./settle";

// The Models and datasets screen: the SPDX 3.0.1 band, a box per model and per
// declared service, the datasets table, the model-card disclaimer, and the
// load, error and empty states. The backend is stubbed.

const ID = "model_1.0";
const prop = (name: string, value: string) => ({ name, value });
const LONG = "huggingface.co/very-long-organisation-name/an-extremely-long-model-name-that-must-wrap-and-not-be-cut-with-ellipsis/and-then-a-second-long-path-segment-that-forces-another-line-to-start";

const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  metadata: {
    component: {
      type: "machine-learning-model",
      "bom-ref": "m",
      name: "acme/robust-model",
      version: "1.0",
      description: "A model for tests.",
      licenses: [{ license: { id: "Apache-2.0" } }],
      properties: [
        prop("bomlens:assessment:overall", "review"),
        prop("bomlens:assessment:license", "ok"),
        prop("bomlens:assessment:security", "review"),
        prop("bomlens:assessment:reason", "Local scan found a pickle opcode"),
      ],
      modelCard: { modelParameters: { task: "fill-mask", architectureFamily: "bert", datasets: [{ type: "dataset", name: "org/data" }] } },
      externalReferences: [{ type: "website", url: `https://${LONG}` }],
    },
  },
  components: [
    {
      type: "data",
      "bom-ref": "dataset:huggingface/org/data",
      name: "org/data",
      version: "abc",
      licenses: [{ license: { id: "CC-BY-NC-4.0" } }],
      properties: [prop("bomlens:dataset:collectedBy", "huggingface"), prop("bomlens:assessment:overall", "caution")],
    },
  ],
  services: [
    {
      "bom-ref": "svc",
      name: "Chat API",
      version: "2",
      provider: { name: "Acme" },
      properties: [prop("bomlens:origin", "declared-input"), prop("bomlens:service:kind", "application")],
    },
  ],
  dependencies: [{ ref: "m", dependsOn: ["dataset:huggingface/org/data"] }, { ref: "svc", dependsOn: ["m"] }],
};

const G7 = ["metadata", "models"].flatMap((cluster) => [
  { id: `g7-${cluster}-a`, label: `Element ${cluster} A`, required: false, status: "warn", detail: "missing", cluster, source: "auto", missing: ["acme/robust-model"], evidence: ["card"], regulations: [{ framework: "EU AI Act", short: "EU AI Act", short_ko: "EU AI Act", ref: "Annex IV" }] },
  { id: `g7-${cluster}-b`, label: `Element ${cluster} B`, required: false, status: "pass", detail: "present", cluster, source: "auto" },
]);

const DONE = {
  ok: true,
  mode: "AIBOM",
  id: ID,
  scanConfig: { project: "model", version: "1.0", source: "ai" },
  results: [{ name: `${ID}_bom.json`, size: 200 }],
  security: null,
  conformance: { result: "pass", format: "CycloneDX", checks: G7, pipelineStepsFailed: [] },
  spdx3: { draft: true, counts: { filled: 5, optional: 3, judgment: 1, missingRequired: 2 } },
  sbom: {
    components: 1,
    componentType: "machine-learning-model",
    componentList: [{ name: "acme/robust-model", version: "1.0", group: "", purl: "", type: "machine-learning-model", licenses: ["Apache-2.0"] }],
  },
};

async function stub(page: Page, opts: { sbom?: unknown; failFirst?: boolean } = {}) {
  let fails = opts.failFirst ? 1 : 0;
  await page.route("**/capabilities", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdx3: true }) }));
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${ID}`, (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }));
  await page.route("**/file**", (r) => {
    if (fails > 0) {
      fails -= 1;
      return r.fulfill({ status: 500, body: "x" });
    }
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.sbom ?? SBOM) });
  });
}

async function open(page: Page, lang: "en" | "ko" = "en", theme: "light" | "dark" = "light") {
  await page.addInitScript(
    ([l, th]) => {
      localStorage.setItem("sbom.lang", l);
      localStorage.setItem("i18nextLng", l);
      localStorage.setItem("sbom.theme", th);
    },
    [lang, theme],
  );
  await page.goto(`/?ui=next#/scan/${ID}/models`);
  await page.getByTestId("result-meta").waitFor();
}

test("shows the band, the model box, the dataset table and the disclaimer", async ({ page }) => {
  await stub(page);
  await open(page);
  await expect(page.getByTestId("spdx3-band")).toContainText("Draft");
  await expect(page.getByTestId("spdx3-band")).toContainText("Fill in empty fields");
  const card = page.getByTestId("model-card");
  await expect(card).toContainText("acme/robust-model");
  await expect(card).toContainText("Apache-2.0");
  await expect(card.getByText("fill-mask")).toBeVisible();
  await expect(card.getByText("Needs review").first()).toBeVisible();
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("org/data");
  await expect(rows.first()).toContainText("CC-BY-NC-4.0");
  await expect(page.getByText("not legal advice", { exact: false }).first()).toBeVisible();
});

test("a declared service has its own box", async ({ page }) => {
  await stub(page);
  await open(page);
  const svc = page.getByTestId("declared-service");
  await expect(svc).toContainText("Chat API");
  await expect(svc).toContainText("Acme");
});

test("the G7 checks sit in one box whose head holds the title; groups start folded", async ({ page }) => {
  await stub(page);
  await open(page);
  const box = page.getByTestId("g7-disclosure");
  await expect(box.getByRole("heading", { level: 2 })).toContainText("discloses");
  const groups = box.locator("details.bl-cf-group");
  await expect(groups).toHaveCount(2);
  for (const g of await groups.all()) await expect(g).not.toHaveAttribute("open", "");
  // A row's how-to-fix line shows once the row is opened.
  const row = box.locator("details.bl-cf-group").first();
  await row.locator("summary").first().click();
  await expect(box.locator(".bl-cf-sub").first()).toBeHidden();
  await row.locator("details").first().locator("summary").click();
  await expect(row.locator(".bl-cf-sub").first()).toBeVisible();
});

test("a long reference address wraps and keeps its icon with the last characters", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await stub(page);
  await open(page);
  const link = page.locator("a.bl-md-link").first();
  const box = await link.boundingBox();
  expect(box!.height).toBeGreaterThan(30);
  // The icon and the last characters are one unbroken piece on one line.
  const spans = await link.locator(".bl-md-tail").evaluate((e) => {
    const r = [...e.getClientRects()];
    return Math.max(...r.map((x) => x.bottom)) - Math.min(...r.map((x) => x.top));
  });
  expect(spans).toBeLessThan(24);
  await expect(link).toHaveAttribute("title", `https://${LONG}`);
});

test("a failed load says so and Retry loads it again", async ({ page }) => {
  await stub(page, { failFirst: true });
  await open(page);
  const err = page.getByTestId("error-state");
  await expect(err).toBeVisible();
  await err.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByTestId("model-card")).toBeVisible();
});

test("a BOM with no model and no dataset shows the empty state", async ({ page }) => {
  await stub(page, { sbom: { bomFormat: "CycloneDX", specVersion: "1.7", metadata: {}, components: [] } });
  await open(page);
  await expect(page.getByTestId("empty-state")).toBeVisible();
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`names wrap and nothing is cut or scrolls sideways at ${width}px, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await stub(page);
      await open(page, lang);
      await expect(page.getByTestId("model-card")).toBeVisible();
      const cut = await page.evaluate(() =>
        [...document.querySelectorAll(".bl-md *")]
          .filter((e) => getComputedStyle(e).textOverflow === "ellipsis")
          .map((e) => `${e.tagName}.${e.className} ${(e.textContent ?? "").slice(0, 40)}`),
      );
      expect(cut).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
    });
  }
  for (const theme of ["light", "dark"] as const) {
    test(`the screen clears axe, ${lang} ${theme}`, async ({ page }) => {
      await stub(page);
      await open(page, lang, theme);
      await expect(page.getByTestId("model-card")).toBeVisible();
      await waitForSettled(page.locator("main"));
      const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(res.violations).toEqual([]);
    });
  }
}
