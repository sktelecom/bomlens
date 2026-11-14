// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// Stub the backend API so the UI renders deterministically (no Docker / network).
type Caps = { firmware: boolean; scanoss: boolean; docker: boolean };

async function stub(page: Page, caps: Caps, done?: unknown) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(caps) }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  if (done) {
    await page.route("**/scan-stream**", (r) =>
      r.fulfill({
        contentType: "text/event-stream",
        body: `event: done\ndata: ${JSON.stringify(done)}\n\n`,
      }),
    );
  }
}

// deps.dev opt-in fields (releasesBehind/lastReleased) present on lodash, absent
// on the offline-only outdated component (jinja2) — the UI must not break either way.
const OUTDATED_DONE = {
  ok: true,
  mode: "SOURCE",
  id: "testapp_1.0",
  results: [{ name: "testapp_1.0_bom.json", size: 1234 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    outdatedCount: 2,
    componentList: [
      { name: "lodash", version: "4.17.10", group: "", purl: "pkg:npm/lodash", type: "library", licenses: ["MIT"], outdated: "true", latestVersion: "4.17.21", releasesBehind: 11, lastReleased: "2021-02-20" },
      { name: "jinja2", version: "3.0.0", group: "", purl: "pkg:pypi/jinja2", type: "library", licenses: ["BSD-3-Clause"], outdated: "true", latestVersion: "3.0.3" },
      { name: "express", version: "4.18.2", group: "", purl: "pkg:npm/express", type: "library", licenses: ["MIT"], outdated: "false" },
    ],
  },
};

async function fillAndRun(page: Page) {
  await page.fill("#project", "testapp");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("Overview lists the outdated components and opens Components filtered to them", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, OUTDATED_DONE);
  await page.goto("/#/new");
  await fillAndRun(page);
  // The row carries the count and says what it counts in words (color is not the only signal).
  const row = page.getByTestId("needs-attention").getByRole("link", { name: "2 outdated components" });
  await expect(row).toBeVisible();
  await expect(row).toHaveAttribute("href", /#\/scan\/[^/]+\/components\?outdated=1$/);
  await row.click();
  await page.getByRole("button", { name: /^Filters/ }).click();
  await expect(page.getByRole("checkbox", { name: "Outdated" })).toBeChecked();
  await page.keyboard.press("Escape");
  await expect(page.getByText("express", { exact: true })).toHaveCount(0);
});

test("outdated badge + latest version render; filter narrows the table", async ({ page }) => {
  await stub(page, { firmware: false, scanoss: false, docker: true }, OUTDATED_DONE);
  await page.goto("/#/new");
  await fillAndRun(page);
  await page.getByRole("link", { name: /^Components/ }).first().click();

  // Both outdated components carry the "Outdated" badge with a "latest: X" hint.
  await expect(page.getByText("latest: 4.17.21").first()).toBeVisible();
  await expect(page.getByText("latest: 3.0.3").first()).toBeVisible();

  // The Outdated filter keeps only the two outdated rows (express drops out).
  await page.getByRole("button", { name: /^Filters/ }).click();
  await page.getByRole("checkbox", { name: "Outdated" }).check();
  await page.keyboard.press("Escape");
  await expect(page.getByText("lodash", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("jinja2", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("express", { exact: true })).toHaveCount(0);
});
