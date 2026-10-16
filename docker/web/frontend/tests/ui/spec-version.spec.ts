// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

/**
 * CycloneDX version (--spec-version on the CLI, CYCLONEDX_SPEC_VERSION on the
 * container): 1.6 by default, 1.7 on request. Offered for any scan except
 * ANALYZE, the same rule as the SBOM author. The backend is stubbed;
 * server.py's allowlist and env wiring is covered by tests/test-web-ui.sh.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
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

async function fillIdentity(page: Page) {
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
}

async function specVersionSent(page: Page) {
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  return new URL((await scanReq).url()).searchParams.get("spec_version");
}

test("the CycloneDX version defaults to 1.6 and is sent on the scan request", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await fillIdentity(page);
  await page.getByText("Output format").click();
  await expect(page.getByLabel("CycloneDX version")).toHaveValue("1.6");
  expect(await specVersionSent(page)).toBe("1.6");
});

test("choosing CycloneDX 1.7 sends spec_version=1.7", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await fillIdentity(page);
  await page.getByText("Output format").click();
  await page.getByLabel("CycloneDX version").selectOption("1.7");
  expect(await specVersionSent(page)).toBe("1.7");
});

test("the CycloneDX version is hidden and not sent for an SBOM upload (ANALYZE)", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await fillIdentity(page);
  await page.getByText("Output format").click();
  await page.getByLabel("CycloneDX version").selectOption("1.7");
  await page.getByRole("button", { name: /SBOM upload/i }).click();
  await page.locator("#file").setInputFiles({
    name: "demo.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"bomFormat":"CycloneDX"}'),
  });
  await expect(page.getByLabel("CycloneDX version")).toHaveCount(0);
  expect(await specVersionSent(page)).toBe("");
});
