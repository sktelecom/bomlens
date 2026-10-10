// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// The datasets table shows the sources the pipeline traced from a dataset's
// card as rows of their own, indented under the dataset they came from, with
// the same grade and licence columns. Sources the card names in words are kept
// verbatim and marked for checking; a scan that traced nothing looks as before.

async function stub(page: Page, done: unknown, sbom: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(done)}\n\n` }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(sbom) }),
  );
}

const DONE = {
  ok: true,
  mode: "AIBOM",
  id: "model_1.0",
  results: [{ name: "model_1.0_bom.json", size: 200 }],
  security: null,
  conformance: null,
  sbom: {
    components: 1,
    componentType: "machine-learning-model",
    componentList: [
      { name: "acme/model", version: "1", group: "", purl: "", type: "machine-learning-model", licenses: ["Apache-2.0"] },
    ],
  },
};

const prop = (name: string, value: string) => ({ name, value });

function sbomWith(dataProps: { mix: { name: string; value: string }[]; nc?: boolean }) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    metadata: {
      component: {
        type: "machine-learning-model",
        "bom-ref": "m",
        name: "acme/model",
        licenses: [{ license: { id: "Apache-2.0" } }],
        modelCard: { modelParameters: { datasets: [{ type: "dataset", name: "org/mix" }] } },
      },
    },
    components: [
      {
        type: "data",
        "bom-ref": "dataset:huggingface/org/mix",
        name: "org/mix",
        licenses: [{ license: { name: "odc-by" } }],
        properties: [prop("bomlens:dataset:collectedBy", "huggingface"), ...dataProps.mix,
          prop("bomlens:assessment:overall", dataProps.nc ? "caution" : "ok")],
      },
      ...(dataProps.nc
        ? [
            {
              type: "data",
              "bom-ref": "dataset:huggingface/org/nc",
              name: "org/nc",
              licenses: [{ license: { id: "CC-BY-NC-4.0" } }],
              properties: [
                prop("bomlens:dataset:collectedBy", "huggingface"),
                prop("bomlens:dataset:depth", "1"),
                prop("bomlens:dataset:sourceDataset", "original"),
                prop("bomlens:assessment:overall", "caution"),
              ],
            },
          ]
        : []),
    ],
    dependencies: [
      { ref: "m", dependsOn: ["dataset:huggingface/org/mix"] },
      { ref: "dataset:huggingface/org/mix", dependsOn: dataProps.nc ? ["dataset:huggingface/org/nc"] : [] },
    ],
  };
}

async function openModels(page: Page) {
  await page.goto("/#/new");
  await page.fill("#project", "model");
  await page.fill("#version", "1.0");
  await page.getByTestId("run-scan").click();
  await page.getByRole("navigation").locator('a[href$="/models"]').first().click();
}

test("a traced source sits under its dataset with its own grade and licence", async ({ page }) => {
  await stub(
    page,
    DONE,
    sbomWith({
      nc: true,
      mix: [
        prop("bomlens:dataset:depth", "0"),
        prop("bomlens:dataset:sourceDataset", "extended|org/nc"),
        prop("bomlens:dataset:derivedFrom", "extended dataset:huggingface/org/nc"),
        prop("bomlens:dataset:sourceDataset:unverified", "Wikipedia dump 2023-01"),
      ],
    }),
  );
  await openModels(page);
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toContainText("org/mix");
  await expect(rows.nth(0)).toContainText("1 source");
  await expect(rows.nth(1)).toContainText("org/nc");
  await expect(rows.nth(1)).toContainText("CC-BY-NC-4.0");
  await expect(rows.nth(1)).toContainText("extended");
  // The words source is marked for checking; the traced source is not.
  await expect(rows.nth(0).getByText("needs checking")).toHaveCount(1);
  await expect(rows.nth(1).getByText("needs checking")).toHaveCount(0);
  const indent = await rows.nth(1).locator("td").first().evaluate((el) => getComputedStyle(el).paddingLeft);
  const rootIndent = await rows.nth(0).locator("td").first().evaluate((el) => getComputedStyle(el).paddingLeft);
  expect(parseFloat(indent)).toBeGreaterThan(parseFloat(rootIndent));
});

test("a scan that traced nothing shows the card's sources as before", async ({ page }) => {
  await stub(page, DONE, sbomWith({ mix: [prop("bomlens:dataset:sourceDataset", "extended|org/nc")] }));
  await openModels(page);
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText("extended|org/nc");
  await expect(page.getByText("needs checking")).toHaveCount(0);
});

test("a source two datasets share has a row under each, the second marked as listed above", async ({ page }) => {
  const sbom = sbomWith({
    nc: true,
    mix: [
      prop("bomlens:dataset:depth", "0"),
      prop("bomlens:dataset:derivedFrom", "extended dataset:huggingface/org/nc"),
    ],
  });
  sbom.components.push({
    type: "data",
    "bom-ref": "dataset:huggingface/org/second",
    name: "org/second",
    licenses: [{ license: { id: "MIT" } }],
    properties: [
      prop("bomlens:dataset:depth", "0"),
      prop("bomlens:dataset:derivedFrom", "listed dataset:huggingface/org/nc"),
      prop("bomlens:assessment:overall", "caution"),
    ],
  });
  await stub(page, DONE, sbom);
  await openModels(page);
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(4);
  await expect(rows.nth(2)).toContainText("org/second");
  await expect(rows.nth(3)).toContainText("org/nc");
  await expect(rows.nth(3)).toContainText("listed above");
  await expect(rows.nth(1)).not.toContainText("listed above");
});
