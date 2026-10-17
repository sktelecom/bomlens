// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// "Read a lock file instead of building": on by default for a source scan, sent
// as detection=auto, and turned off with the toggle, which sends detection=build.
// It is not offered where there is no source tree to read (an SBOM upload).

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
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
}

async function detectionSent(page: Page) {
  const scanReq = page.waitForRequest((req) => req.url().includes("/scan-stream"));
  await page.getByRole("button", { name: /Run scan/i }).click();
  return new URL((await scanReq).url()).searchParams.get("detection");
}

async function openForm(page: Page) {
  await stub(page);
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
}

test("a source scan reads a lock file by default and says auto on the request", async ({ page }) => {
  await openForm(page);
  await page.getByText("Result quality").click();
  await expect(page.getByRole("switch", { name: "Read a lock file instead of building" })).toBeChecked();
  expect(await detectionSent(page)).toBe("auto");
});

test("turning it off sends build", async ({ page }) => {
  await openForm(page);
  await page.getByText("Result quality").click();
  await page.getByRole("switch", { name: "Read a lock file instead of building" }).click();
  expect(await detectionSent(page)).toBe("build");
});

test("it is not offered for an SBOM upload", async ({ page }) => {
  await openForm(page);
  await page.getByRole("button", { name: /SBOM upload/i }).click();
  // Open the group when there is one, so a closed group cannot hide the switch.
  const group = page.getByText("Result quality");
  if ((await group.count()) > 0) await group.click();
  await expect(page.getByRole("switch", { name: "Read a lock file instead of building" })).toHaveCount(0);
});
