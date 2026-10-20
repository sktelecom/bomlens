// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";

import { DONE, FIRMWARE_DONE, SBOM } from "./fixtures";
import { waitForSettled } from "./settle";
import { seedThemeLang } from "./visual";

// The result screen's header is one meta line (project, version, scan type, time)
// over the section title, the summary is a one-line strip, and the Overview names
// the items worth looking at first with their source and time. The Recent list
// keeps its at-risk filter as a chip above the table.

const GENERATED_AT = 1700000000;

async function openScan(page: Page, done: Record<string, unknown> & { id: string }, hash = "") {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: false }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: done.id,
          project: String(done.id).split("_")[0],
          version: String(done.id).split("_")[1],
          components: 3,
          maxSeverity: "CRITICAL",
          isAiScan: false,
          generatedAt: GENERATED_AT,
        },
      ]),
    }),
  );
  await page.route(`**/scan?id=${done.id}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto(`/?ui=next#/scan/${done.id}${hash}`);
  await page.locator("main h1").first().waitFor();
  await waitForSettled(page.locator("main"));
}

test("the header is one meta line over the section title, with no status badge on a clean scan", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openScan(page, { ...DONE, sbom: { ...DONE.sbom, componentType: "application" } });

  const meta = page.getByTestId("result-meta");
  await expect(meta).toContainText("demo");
  await expect(meta).toContainText("1.0");
  await expect(page.getByTestId("result-kind")).toHaveText("Source");
  await expect(meta.locator("time")).toHaveAttribute("datetime", new Date(GENERATED_AT * 1000).toISOString());
  await expect(meta.locator("time")).toContainText("2023");
  // The title sits below the meta line, and the badge only shows for a scan
  // that did not simply complete.
  const [metaBox, titleBox] = await Promise.all([meta.boundingBox(), page.locator("main h1").boundingBox()]);
  expect(titleBox!.y).toBeGreaterThan(metaBox!.y);
  await expect(page.getByRole("status")).toHaveCount(0);
  await expect(page.getByText("Scan complete")).toHaveCount(0);
  // The whole header stays compact: under the old 90px of title, badge and subtitle.
  const header = await meta.locator("xpath=..").boundingBox();
  expect(header!.height).toBeLessThan(80);
});

test("a scan that finished with failed steps carries a text badge", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openScan(page, {
    ...DONE,
    sbom: { ...DONE.sbom, componentType: "application", pipelineStepsFailed: ["license-scan"] },
  });
  await expect(page.getByRole("status")).toHaveText("Some steps failed");
});

test("the summary strip stays on compact lines at 1024px", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await seedThemeLang(page, "light", "en");
  await openScan(page, FIRMWARE_DONE);
  const strip = page.getByRole("list", { name: "Scan summary" });
  const items = strip.getByRole("listitem");
  const count = await items.count();
  expect(count).toBeGreaterThanOrEqual(3);
  // Each entry is a single line: no entry wraps its own words.
  for (let i = 0; i < count; i += 1) {
    const box = await items.nth(i).boundingBox();
    expect(box!.height, `summary entry ${i} stays one line`).toBeLessThan(48);
  }
  // And the strip is far shorter than the five tall cards it replaced (~130px each row).
  const stripBox = await strip.boundingBox();
  expect(stripBox!.height).toBeLessThan(110);
  // An entry still opens its section.
  await strip.getByRole("link", { name: /Vulnerabilities/ }).click();
  await expect(page.locator("main h1")).toHaveText("Vulnerabilities");
});

test("the Overview names up to three items to check first, with source and scan time", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openScan(page, FIRMWARE_DONE);

  const block = page.getByTestId("first-checks");
  await expect(block).toBeVisible();
  await expect(block).toContainText("Items to check first");
  // Worded as a reference order, never as a verdict.
  await expect(block).toContainText("reference order");
  await expect(block).toContainText("not a ranking of importance or a verdict");

  const rows = block.getByRole("listitem");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("Known exploited vulnerabilities (CISA KEV)");
  await expect(rows.nth(0)).toContainText("Source: vulnerability results");
  await expect(rows.nth(0)).toContainText("as of scan time");
  await expect(rows.nth(0)).toContainText("2023");
  await expect(rows.nth(1)).toContainText("Critical or High with a fixed version");
  // 6,945 findings but only 5 rows listed: the count says what it was taken over.
  await expect(rows.nth(1)).toContainText("counted among the 5 of 6,945 findings listed");
  await expect(rows.nth(2)).toContainText("Required conformance items to fill in");
  await expect(rows.nth(2)).toContainText("Source: this scan's conformance check");

  // The fixable row opens the table on the worst severity it counted.
  await rows.nth(1).getByRole("link").click();
  await expect(page.locator("main h1")).toHaveText("Vulnerabilities");
  expect(page.url()).toContain("severity=CRITICAL");
});

test("the Overview leaves the first-checks block out when nothing applies", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openScan(page, {
    ...DONE,
    security: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, UNKNOWN: 0, TOTAL: 1, vulnerabilities: [{ id: "CVE-1", severity: "MEDIUM", pkg: "zlib", installed: "1", fixed: "", title: "t" }] },
  });
  await expect(page.getByTestId("first-checks")).toHaveCount(0);
});

test("the needs-attention card is the same neutral card for a source and an AI scan", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openScan(page, DONE);
  const card = page.getByTestId("needs-attention");
  await expect(card).toBeVisible();
  // A thin left bar carries the role colour; the fill stays the card surface.
  const style = await card.evaluate((el) => {
    const cs = getComputedStyle(el);
    return { bar: cs.borderLeftWidth, bg: cs.backgroundColor, cardBg: getComputedStyle(document.body).backgroundColor };
  });
  expect(style.bar).toBe("3px");
  expect(style.bg).not.toBe("rgba(0, 0, 0, 0)");
});

test("the Recent list keeps the at-risk filter as a chip above the table", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { id: "a_1.0", project: "a", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: GENERATED_AT },
        { id: "b_1.0", project: "b", version: "1.0", components: 3, maxSeverity: "LOW", isAiScan: false, generatedAt: GENERATED_AT + 1 },
      ]),
    }),
  );
  await page.goto("/?ui=next");
  await page.getByRole("heading", { name: "Scan management" }).waitFor();

  const chip = page.getByRole("button", { name: /^At risk/ });
  await expect(chip).toHaveAttribute("aria-pressed", "false");
  await expect(chip).toContainText("1");
  // Totals read as text, not as cards or controls.
  await expect(page.getByText("Total scans 2")).toBeVisible();
  await expect(page.getByText("Projects 2")).toBeVisible();

  await chip.click();
  await expect(chip).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("link", { name: /a @1.0/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /b @1.0/ })).toHaveCount(0);
  await chip.click();
  await expect(page.getByRole("link", { name: /b @1.0/ })).toBeVisible();
});
