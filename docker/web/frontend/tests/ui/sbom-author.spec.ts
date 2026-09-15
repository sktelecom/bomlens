// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

/**
 * SBOM author (--sbom-author on the CLI, SBOM_AUTHOR on the container): the
 * organisation or person running the scan, recorded on metadata.authors.
 * Offered for any scan except ANALYZE (a supplier SBOM we only convert; we did
 * not author it, see entrypoint.sh's docmeta dispatch). The backend is
 * stubbed; server.py's own env/sibling-arg wiring is covered by
 * tests/test-web-ui.sh and tests/test-windows.sh.
 */

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

test("SBOM author field is offered for a source scan", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByText("Advanced scan options").click();
  await expect(page.getByLabel("SBOM author (optional)")).toBeVisible();
});

test("SBOM author field is hidden for an SBOM upload (ANALYZE)", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await selectSbomUpload(page);
  // Other advanced options remain (deep CVE, byte-stable, …), so the
  // disclosure itself still renders, just not this field.
  await page.getByText("Advanced scan options").click();
  await expect(page.getByLabel("SBOM author (optional)")).toHaveCount(0);
});

test("running with an SBOM author sends it on the scan request", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByText("Advanced scan options").click();
  await page.getByLabel("SBOM author (optional)").fill("SK Telecom Co., Ltd.");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("sbom_author")).toBe("SK Telecom Co., Ltd.");
});

test("running without an SBOM author sends an empty value", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");

  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("sbom_author")).toBe("");
});

test("an SBOM author typed before switching to SBOM upload is not sent (field hidden, value dropped)", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByText("Advanced scan options").click();
  await page.getByLabel("SBOM author (optional)").fill("Should not reach ANALYZE");

  await selectSbomUpload(page);
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  const url = (await scanReq).url();
  expect(new URL(url).searchParams.get("sbom_author")).toBe("");
});
