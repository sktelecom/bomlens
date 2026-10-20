// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// A GitHub URL scan can name a branch, tag or commit. The field is offered only
// for that source, and its value goes out as git_ref on the scan request.

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: 0, componentList: [] },
};

async function openGitForm(page: Page) {
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

async function refSent(page: Page) {
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  return new URL((await scanReq).url()).searchParams.get("git_ref");
}

test("the tag typed in the form goes out as git_ref", async ({ page }) => {
  await openGitForm(page);
  await page.fill("#gitRef", "v1.2.0");
  expect(await refSent(page)).toBe("v1.2.0");
});

test("an empty field sends an empty git_ref", async ({ page }) => {
  await openGitForm(page);
  expect(await refSent(page)).toBe("");
});

test("the field is not offered for the current folder", async ({ page }) => {
  await openGitForm(page);
  await page.getByRole("button", { name: /Current folder/i }).click();
  await expect(page.locator("#gitRef")).toHaveCount(0);
});
