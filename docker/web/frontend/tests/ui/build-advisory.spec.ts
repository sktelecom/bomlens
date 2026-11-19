// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// A Maven or Gradle folder shows a notice before the scan when /project-info
// reports a low engine memory or another running scan.

async function stub(page: Page, extra: object) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/project-info**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        version: "",
        versionFrom: "",
        hasManifest: true,
        subProjects: [],
        buildTools: { maven: true, gradle: false },
        otherScanRunning: false,
        ...extra,
      }),
    }),
  );
}

test("low engine memory and a running scan are shown before the scan", async ({ page }) => {
  await stub(page, { engineMemoryLowGb: 3, otherScanRunning: true });
  await page.goto("/#/new");
  const notice = page.getByTestId("build-advisory");
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("about 3 GB of memory");
  await expect(notice).toContainText("Another scan is running now");
});

test("nothing is shown when the engine has enough memory", async ({ page }) => {
  await stub(page, {});
  await page.goto("/#/new");
  await page.fill("#project", "demo");
  await expect(page.getByTestId("build-advisory")).toHaveCount(0);
});
