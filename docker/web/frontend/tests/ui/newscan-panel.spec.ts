// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

// The settings panel keeps its run button on screen with every group open, and
// marks each option that sends data off the machine with the same label.

async function stub(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: true, docker: true, reachability: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
}

test("run button stays inside the viewport with every group open", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 720 });
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  for (const name of ["Result quality", "Output format", "External transfer (optional)"]) {
    await page.getByText(name).click();
  }
  const run = page.getByTestId("run-scan");
  await expect(run).toBeInViewport({ ratio: 1 });
  // The groups scroll inside the panel; the page itself does not grow.
  const overflow = await page.evaluate(
    () => document.documentElement.scrollHeight - window.innerHeight,
  );
  expect(overflow).toBeLessThan(300);
});

test("options that send data out carry the same mark", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByText("Result quality").click();
  await page.getByText("External transfer (optional)").click();
  const marks = page.getByTestId("external-mark");
  await expect(marks).toHaveCount(2);
  const lookup = page.locator("label", { hasText: "Detect copied-in open source" });
  await expect(lookup.getByTestId("external-mark")).toBeVisible();
  const upload = page.locator("label", { hasText: "Upload to a server" });
  await expect(upload.getByTestId("external-mark")).toBeVisible();
});

test("conformance, license, author and version sit under Output format", async ({ page }) => {
  await stub(page);
  await page.goto("/#/new");
  await page.locator("#project").waitFor();
  await page.getByText("Output format").click();
  await expect(page.locator("#outbound-license")).toBeVisible();
  await expect(page.locator("#sbom-author")).toBeVisible();
  await expect(page.locator("#spec-version")).toBeVisible();
  await expect(page.locator("#conformance-profile")).toBeVisible();
});
