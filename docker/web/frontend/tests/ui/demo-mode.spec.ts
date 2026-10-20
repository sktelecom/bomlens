// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import type { ChildProcess } from "node:child_process";
import { expect, test } from "@playwright/test";

import { serveDemoData, startDemoBundle } from "./demo-bundle";

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
});
