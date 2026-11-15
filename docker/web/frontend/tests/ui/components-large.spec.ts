// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

/**
 * A firmware scan holds 60,118 components. The table renders them in chunks of
 * 100 rows (one <tbody> each) and recycles the chunks far from the window into
 * a spacer of their measured height, so the whole list scrolls as one page
 * while the DOM stays a window onto it. This runs a synthetic list of 60,000
 * and checks the window stays small, the last row is reachable, a filter and a
 * sort finish in a few seconds, and the head sticks under the top bar.
 */

const N = 60_000;
const id = (i: number) => String(i).padStart(5, "0");
const componentList = Array.from({ length: N }, (_, i) => ({
  name: `pkg-${id(i)}`,
  version: `1.${i % 10}.0`,
  group: i % 4 === 0 ? "org.example" : "",
  purl: `pkg:generic/pkg-${id(i)}@1.${i % 10}.0`,
  type: i % 3 === 0 ? "library" : "file",
  licenses: i % 5 === 0 ? ["MIT", "Apache-2.0"] : ["MIT"],
  ...(i % 50 === 0 ? { maxSeverity: "HIGH", vulnCount: 2 } : {}),
  ...(i % 2 ? { scope: "transitive" } : { scope: "direct" }),
}));

const DONE = {
  ok: true,
  mode: "FIRMWARE",
  id: "big_1.0",
  results: [{ name: "big_1.0_bom.json", size: 100 }],
  security: null,
  conformance: null,
  sbom: { components: N, componentList },
};

async function openBig(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([{ id: "big_1.0", project: "big", version: "1.0", components: N, maxSeverity: null, isAiScan: false, componentType: "firmware", generatedAt: 1700000000 }]),
    }),
  );
  await page.route("**/scan?id=big_1.0", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }));
  await page.goto("/#/scan/big_1.0/components");
  await page.getByText("pkg-00000").first().waitFor({ timeout: 30_000 });
}

const liveRows = (page: Page) => page.locator("main table tbody[data-live='true'] button[aria-expanded]").count();
const spacers = (page: Page) => page.locator("main table tbody[data-live='false']").count();

/** Real rows on screen right now (a spacer or the top chunk, far above, does not count). */
const rowsInView = (page: Page) =>
  page
    .locator("main table tbody[data-live='true'] button[aria-expanded]")
    .evaluateAll((els) => els.filter((e) => { const r = e.getBoundingClientRect(); return r.bottom > 112 && r.top < window.innerHeight; }).length);

test("60,000 components: a window of rows in the DOM, the rest as spacers, the last row reachable", async ({ page }) => {
  const started = Date.now();
  await openBig(page);
  const firstPaint = Date.now() - started;
  test.info().annotations.push({ type: "first paint ms", description: String(firstPaint) });

  const live = await liveRows(page);
  expect(live).toBeGreaterThan(0);
  expect(live, "a few chunks of 100, never the list").toBeLessThanOrEqual(400);
  expect(await spacers(page)).toBeGreaterThan(500);
  // 600 chunks in all: one tbody each.
  expect(await page.locator("main table tbody[data-chunk]").count()).toBe(600);

  // The page is as tall as the list (spacers hold the unrendered rows' height).
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  expect(height).toBeGreaterThan(N * 30);

  // Jump to the end: the last component materialises, the first chunk is recycled.
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect(page.getByText("pkg-59999", { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect.poll(() => liveRows(page), { timeout: 10_000 }).toBeLessThanOrEqual(400);
  await expect(page.getByText("pkg-00000", { exact: true })).toHaveCount(0);

  // The head still sticks under the top bar, far down the list.
  const top = await page.evaluate(() => document.querySelector("main table thead")!.getBoundingClientRect().top);
  expect(Math.round(top)).toBe(56);
});

test("60,000 components: a filter and a sort finish in a few seconds and reset the window", async ({ page }) => {
  await openBig(page);
  const search = page.getByRole("searchbox", { name: "Search components" });

  const t0 = Date.now();
  await search.fill("pkg-0123");
  await expect(page.getByText("10 of 60,000 components")).toBeVisible({ timeout: 15_000 });
  test.info().annotations.push({ type: "filter ms", description: String(Date.now() - t0) });
  expect(Date.now() - t0).toBeLessThan(8_000);
  expect(await liveRows(page)).toBe(10);

  await page.getByRole("button", { name: "Remove filter: \"pkg-0123\"" }).click();
  await expect(page.getByText("pkg-00000").first()).toBeVisible();

  const t1 = Date.now();
  await page.locator("main table").getByRole("button", { name: "Name", exact: true }).click();
  await page.locator("main table").getByRole("button", { name: "Name", exact: true }).click();
  await expect(page.locator("main table thead th").first()).toHaveAttribute("aria-sort", "descending");
  await expect(page.getByText("pkg-59999", { exact: true })).toBeVisible({ timeout: 15_000 });
  test.info().annotations.push({ type: "sort ms", description: String(Date.now() - t1) });
  expect(Date.now() - t1).toBeLessThan(15_000);
  expect(await liveRows(page)).toBeLessThanOrEqual(400);
});

test("60,000 components: a row opened far down stays open while its chunk scrolls", async ({ page }) => {
  await openBig(page);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight / 2));
  // The top chunk stays live for a moment above the window, so pick a row that is on screen.
  await expect.poll(() => rowsInView(page), { timeout: 15_000 }).toBeGreaterThan(3);
  const label = await page
    .locator("main table tbody[data-live='true'] button[aria-expanded]")
    .evaluateAll((els) => els.find((e) => { const r = e.getBoundingClientRect(); return r.top > 200 && r.bottom < window.innerHeight - 50; })?.getAttribute("aria-label") ?? "");
  expect(label).not.toBe("");
  const row = page.getByRole("button", { name: label, exact: true });
  await row.click();
  await expect(row).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("main table tr[id^='cd-']")).toHaveCount(1);
  // Scrolling to the top and back keeps the open row's chunk live, so its detail never vanishes.
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect(page.getByText("pkg-00000").first()).toBeVisible();
  await expect(page.locator("main table tr[id^='cd-']")).toHaveCount(1);
  await expect(row).toHaveAttribute("aria-expanded", "true");
});

test("60,000 components: sorting from the middle of the list leaves rows on screen, not an empty table", async ({ page }) => {
  await openBig(page);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight / 2));
  await expect.poll(() => rowsInView(page), { timeout: 15_000 }).toBeGreaterThan(5);
  const before = await page.evaluate(() => window.scrollY);
  expect(before).toBeGreaterThan(1000);
  // The head sticks under the top bar, so it can be pressed from here.
  await page.locator("main table").getByRole("button", { name: "Name", exact: true }).click();
  await page.locator("main table").getByRole("button", { name: "Name", exact: true }).click();
  await expect(page.locator("main table thead th").first()).toHaveAttribute("aria-sort", "descending");
  // The window stays where it was and must show the new order's rows there.
  await page.waitForTimeout(1000);
  expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(1000);
  await expect.poll(() => rowsInView(page), { timeout: 15_000 }).toBeGreaterThan(5);
});
