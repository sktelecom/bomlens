// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// A source scan can name paths to leave out. The field is offered for source
// inputs only, and its lines go out as one `exclude` value on the scan request.

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

async function openForm(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
  await page.goto("/#/new");
  await page.getByRole("button", { name: "GitHub URL" }).click();
  await page.fill("#target", "https://github.com/acme/demo.git");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
}

test("the lines typed in the form go out as one exclude value", async ({ page }) => {
  await openForm(page);
  await page.fill("#exclude", "vendor/legacy\n\n  test/fixtures  ");
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  expect(new URL((await scanReq).url()).searchParams.get("exclude")).toBe("vendor/legacy\ntest/fixtures");
});

test("the field is not offered for a Docker image", async ({ page }) => {
  await openForm(page);
  await page.getByRole("button", { name: "Docker image" }).click();
  await expect(page.locator("#exclude")).toHaveCount(0);
});
