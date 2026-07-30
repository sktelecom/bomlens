// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

/**
 * The submitted-SBOM section: for a scan whose input was someone else's SBOM,
 * what that document said before it was converted to CycloneDX. Like the source
 * tree it has no @visual baseline, so these assertions are its only guard.
 */

const INPUT = {
  format: "SPDX",
  specVersion: "2.3",
  documentId: "https://acme.example/spdxdocs/supplier-app",
  documentName: "supplier-app-2.3.1",
  created: "2026-01-02T03:04:05Z",
  tools: ["syft-1.18.1"],
  authors: [],
  supplier: "Supplier Inc.",
  rootComponent: {
    name: "supplier-app",
    version: "",
    type: "",
    purl: "",
    licenses: ["CC0-1.0"],
  },
  componentCount: 2,
  originalName: "supplier.spdx.json",
  originalBytes: 8192,
};

const DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "supplier_1.0",
  results: [
    { name: "supplier_1.0_bom.json", size: 1234 },
    { name: "supplier_1.0_input.json", size: 400 },
  ],
  security: null,
  conformance: null,
  sbom: { components: 2, componentList: [] },
};

async function runAnalyze(page: Page, input: unknown = INPUT) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n`,
    }),
  );
  await page.route("**/file**", (r) =>
    input === null
      ? r.fulfill({ status: 404, body: "" })
      : r.fulfill({
          contentType: "application/json",
          body: JSON.stringify(input),
        }),
  );

  await page.goto("/#/new");
  await page.fill("#project", "supplier");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
  await page
    .getByRole("navigation")
    .locator('a[href$="/inputSbom"]')
    .first()
    .click();
}

test("the submitted document's own identity is on screen", async ({ page }) => {
  await runAnalyze(page);

  await expect(page.getByText("supplier.spdx.json")).toBeVisible();
  // The format the supplier wrote in — not the CycloneDX everything else shows.
  await expect(page.getByText("SPDX 2.3")).toBeVisible();
  await expect(page.getByText("syft-1.18.1")).toBeVisible();
  await expect(page.getByText("Supplier Inc.")).toBeVisible();
  await expect(page.getByText("2026-01-02T03:04:05Z")).toBeVisible();
  await expect(page.getByText("2 entries")).toBeVisible();
});

test("fields the supplier left out are omitted, not shown blank", async ({
  page,
}) => {
  await runAnalyze(page, {
    format: "CycloneDX",
    specVersion: "1.6",
    componentCount: 5,
    originalName: "bare.cdx.json",
  });
  await expect(page.getByText("CycloneDX 1.6")).toBeVisible();
  // No tool, supplier or timestamp was recorded, so those rows are absent
  // rather than printed empty or guessed at.
  await expect(page.getByText("Produced by")).toHaveCount(0);
  await expect(page.getByText("Supplier", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Created", { exact: true })).toHaveCount(0);
});

test("the section points at the components list instead of repeating it", async ({
  page,
}) => {
  await runAnalyze(page);
  const link = page.getByRole("link", { name: "Components", exact: true }).last();
  await expect(link).toHaveAttribute("href", /components/);
});

test("a failed load offers a retry rather than an empty section", async ({
  page,
}) => {
  await runAnalyze(page, null);
  await expect(
    page.getByText("Could not load the details of the submitted SBOM."),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: /Retry/i })).toBeVisible();
});

test("a source scan never offers the submitted-SBOM section", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({
      contentType: "text/event-stream",
      body: `event: done\ndata: ${JSON.stringify({
        ...DONE,
        mode: "SOURCE",
        results: [{ name: "supplier_1.0_bom.json", size: 1234 }],
      })}\n\n`,
    }),
  );
  await page.goto("/#/new");
  await page.fill("#project", "supplier");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
  await expect(
    page.getByRole("navigation").locator('a[href$="/inputSbom"]'),
  ).toHaveCount(0);
});
