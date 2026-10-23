// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

/**
 * Product supplier (--supplier on the CLI, PRODUCT_SUPPLIER on the container):
 * the organisation that supplies the product, written to
 * metadata.component.supplier as "Name <url-or-email>". Offered wherever the
 * SBOM author is (every scan except ANALYZE, which keeps the received SBOM's
 * supplier). The backend is stubbed.
 */

const LABEL = "Product supplier";

const DONE = {
  ok: true,
  mode: "ANALYZE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

async function stub(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/upload**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ token: "tok123", filename: "demo.json" }) }),
  );
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

async function selectSbomUpload(page: Page) {
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /SBOM upload/i }).click();
  await page.locator("#file").setInputFiles({
    name: "demo.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"bomFormat":"CycloneDX"}'),
  });
}

test("product supplier field sits after the SBOM author and stays accessible", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByText("Output format").click();
  const field = page.getByLabel(LABEL);
  await expect(field).toBeVisible();
  await expect(field).toHaveAttribute("aria-describedby", "product-supplier-hint");
  // Rendered right after the SBOM author field.
  const ids = await page
    .locator("#sbom-author, #product-supplier")
    .evaluateAll((els) => els.map((e) => e.id));
  expect(ids).toEqual(["sbom-author", "product-supplier"]);

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

test("product supplier field is labelled in Korean", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("sbom.lang", "ko"));
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByText("출력 형식").click();
  await expect(page.getByLabel("제품 공급자")).toBeVisible();
});

test("product supplier field is hidden for an SBOM upload (ANALYZE)", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await selectSbomUpload(page);
  await page.getByText("Output format").click();
  await expect(page.getByLabel(LABEL)).toHaveCount(0);
});

test("running with a product supplier sends it trimmed on the scan request", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByText("Output format").click();
  await page.getByLabel(LABEL).fill("  ACME Corp <https://acme.example>  ");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("supplier")).toBe("ACME Corp <https://acme.example>");
});

test("running without a product supplier sends an empty value", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("supplier")).toBe("");
});

test("a product supplier typed before switching to SBOM upload is not sent", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByText("Output format").click();
  await page.getByLabel(LABEL).fill("Should not reach ANALYZE <a@b.example>");

  await selectSbomUpload(page);
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("supplier")).toBe("");
});

test("Re-scan restores the product supplier from the scan's config", async ({ page }) => {
  const done = {
    ok: true,
    mode: "SOURCE",
    id: "demo_2.1",
    results: [{ name: "demo_2.1_bom.json", size: 100 }],
    security: null,
    conformance: null,
    sbom: { components: 0, componentList: [] },
    scanConfig: {
      source: "git-url",
      target: "https://github.com/acme/demo",
      project: "demo",
      version: "2.1",
      notice: true,
      security: false,
      deepLicense: false,
      identifyVendored: false,
      sbomAuthor: "SK Telecom Co., Ltd.",
      supplier: "ACME Corp <sbom@acme.example>",
    },
  };
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify([
      { id: "demo_2.1", project: "demo", version: "2.1", components: 0, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
    ]) }),
  );
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({
      bomFormat: "CycloneDX",
      metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
      components: [],
      dependencies: [],
    }) }),
  );
  await page.goto("/?ui=next#/scan/demo_2.1");
  await page.getByRole("button", { name: "Re-scan" }).click();
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("#/new");
  // A seeded value opens the Output format group on its own.
  await expect(page.locator("#product-supplier")).toHaveValue("ACME Corp <sbom@acme.example>");
  await expect(page.locator("#sbom-author")).toHaveValue("SK Telecom Co., Ltd.");
});
