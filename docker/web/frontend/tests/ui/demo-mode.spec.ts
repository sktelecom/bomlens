// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import type { ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

import { DATA_BASE, DEMO_DATA, serveDemoData, startDemoBundle } from "./demo-bundle";

// The read-only demo is a different build of the app (a banner, no scanning),
// so it is checked as its own target: built once, served from the committed
// capture. A visitor may open it on a phone from an article link, so the page
// must not scroll sideways at 390px, and the banner must pass the same axe
// rules as the rest of the app.

const PORT = Number(process.env.DEMO_MODE_PORT ?? 4175);
const ORIGIN = `http://localhost:${PORT}`;

let preview: ChildProcess | undefined;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(240_000);
  preview = await startDemoBundle("dist-demo-mode", PORT);
});

test.afterAll(() => {
  preview?.kill();
});

const SCANS = [
  "SpringBootDemo_1.0.0",
  "FlaskDataService_3.2.0",
  "NginxRuntimeImage_1.24-alpine",
  "RaspberryPiOsLite_2026-06-18",
  "BertBaseUncased_1.0",
];
const SECTIONS = ["", "/components", "/vulnerabilities", "/licenses", "/dependencies", "/conformance", "/artifacts"];

test("no screen scrolls sideways at 390px", async ({ page }) => {
  test.setTimeout(240_000);
  await page.setViewportSize({ width: 390, height: 844 });
  await serveDemoData(page);
  const over: string[] = [];
  for (const hash of ["#/", ...SCANS.flatMap((id) => SECTIONS.map((s) => `#/scan/${id}${s}`))]) {
    await page.goto(`${ORIGIN}/${hash}`);
    await page.locator("main h1").first().waitFor();
    await page.waitForLoadState("networkidle");
    const excess = await page.evaluate(() => {
      const main = document.querySelector("main");
      return Math.max(
        document.documentElement.scrollWidth - window.innerWidth,
        main ? main.scrollWidth - main.clientWidth : 0,
      );
    });
    if (excess > 0) over.push(`${hash} (+${excess}px)`);
  }
  expect(over).toEqual([]);
});

test("the banner and the scan list pass axe in the demo", async ({ page }) => {
  await serveDemoData(page);
  await page.goto(`${ORIGIN}/#/`);
  await page.getByTestId("demo-banner").waitFor();
  await page.waitForLoadState("networkidle");
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(results.violations).toEqual([]);
  // The banner's title is not a heading: the page's first heading is its h1.
  expect(await page.locator("h1, h2, h3, h4, h5, h6").first().evaluate((h) => h.tagName)).toBe("H1");
  // The notice opens the page content: its title line, then its text.
  const banner = page.getByTestId("demo-banner");
  await expect(page.locator("main").getByTestId("demo-banner")).toHaveCount(1);
  const [title, body] = await Promise.all([
    banner.getByText("Read-only demo").boundingBox(),
    banner.getByText(/^Results of a real scan/).boundingBox(),
  ]);
  expect(title!.y).toBeLessThan(body!.y);
  // The demo cannot scan, so nothing offers New scan.
  await expect(page.getByRole("link", { name: "New scan" })).toHaveCount(0);
  await expect(page.getByTestId("recent-new-scan")).toHaveCount(0);
});

test("the navigation reaches the bottom of the window, at the top and scrolled to the end", async ({ page }) => {
  await serveDemoData(page);
  await page.setViewportSize({ width: 1280, height: 600 });
  await page.goto(`${ORIGIN}/#/scan/SpringBootDemo_1.0.0/vulnerabilities`);
  await page.getByTestId("result-meta").waitFor();
  const bottom = async () => {
    const box = await page.locator(".bl-pane").boundingBox();
    return Math.round(box!.y + box!.height);
  };
  expect(await bottom()).toBe(600);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  expect(await bottom()).toBe(600);
});

test("the demo's scan list is read-only: no actions column, no delete menu, dates, and a start strip", async ({ page }) => {
  await serveDemoData(page);
  await page.goto(`${ORIGIN}/#/`);
  await page.getByTestId("demo-banner").waitFor();
  await expect(page.getByRole("table")).toBeVisible();

  // Nothing can be deleted or scanned: no row menu, no extra column, no output-folder note.
  await expect(page.getByRole("button", { name: /^More actions for/ })).toHaveCount(0);
  await expect(page.getByRole("columnheader")).toHaveCount(5);
  await expect(page.getByRole("columnheader", { name: "Actions" })).toHaveCount(0);
  await expect(page.getByText("~/sbom-output")).toHaveCount(0);

  // The scans were captured once, so they show the date they were made.
  await expect(page.locator("table time").first()).toHaveText(/\d{4}/);

  // Three scans to start with, and the project scanned twice to compare.
  const strip = page.getByTestId("demo-start-here");
  await expect(strip).toBeVisible();
  await expect(strip.getByRole("link")).toHaveCount(4);
  await expect(page.getByTestId("demo-compare-link")).toHaveAttribute("href", /#\/scan\//);

  // Reading still works: sorting, search and the at-risk toggle.
  await page.getByRole("columnheader", { name: "Components" }).getByRole("button").click();
  await expect(page.getByRole("columnheader", { name: "Components" })).toHaveAttribute("aria-sort", "descending");
  await page.getByRole("searchbox").fill("nginx");
  await expect(page.getByRole("table").getByRole("link")).toHaveCount(1);
  await expect(page.getByText("1 of 6")).toBeVisible();
});

test("a very long project name in the demo's start strip cannot push the page sideways", async ({ page }) => {
  await serveDemoData(page);
  const long = "Extremely-long-demo-project-name-".repeat(8);
  await page.route(`**${DATA_BASE}/scans.json`, async (route) => {
    const list = JSON.parse(readFileSync(join(DEMO_DATA, "scans.json"), "utf8")) as { project: string }[];
    list.forEach((s) => (s.project = long));
    await route.fulfill({ json: list });
  });
  await page.setViewportSize({ width: 1024, height: 800 });
  await page.goto(`${ORIGIN}/#/`);
  await page.getByTestId("demo-start-here").waitFor();
  const excess = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(excess).toBeLessThanOrEqual(0);
});
