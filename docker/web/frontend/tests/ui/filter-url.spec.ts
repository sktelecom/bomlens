// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

/**
 * A narrowed view is a place, not a gesture: filtering a table puts the filter
 * in the URL, so the view survives a reload and can be handed to someone else
 * as a link. What is asserted here is the round trip in both directions — state
 * reaching the URL, and a URL reaching the state — plus the fact that the
 * filter really narrowed the table rather than only filling its input.
 *
 * The hash is replaced rather than pushed, so a search box does not turn every
 * keystroke into a history entry. That is why the assertions poll the hash
 * instead of waiting for a navigation.
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_3.0",
  results: [{ name: "demo_3.0_bom.json", size: 100 }],
  conformance: null,
  security: {
    total: 2,
    counts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0 },
    vulnerabilities: [
      {
        id: "CVE-2024-1111",
        severity: "CRITICAL",
        pkg: "openssl",
        installed: "3.0.0",
        fixed: "3.0.1",
        cvss: 9.8,
      },
      {
        id: "CVE-2024-2222",
        severity: "HIGH",
        pkg: "zlib",
        installed: "1.2.11",
        fixed: "1.2.12",
        cvss: 7.5,
      },
    ],
  },
  sbom: {
    components: 2,
    componentList: [
      {
        name: "openssl",
        version: "3.0.0",
        type: "library",
        licenses: ["Apache-2.0"],
        purl: "pkg:generic/openssl@3.0.0",
        vulnCount: 1,
        maxSeverity: "CRITICAL",
        direct: true,
      },
      {
        name: "zlib",
        version: "1.2.11",
        type: "library",
        licenses: ["Zlib"],
        purl: "pkg:generic/zlib@1.2.11",
        vulnCount: 1,
        maxSeverity: "HIGH",
        direct: false,
      },
    ],
  },
};

async function openAt(page: Page, hash: string) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan?id=demo_3.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.goto(`/?ui=next#${hash}`);
  await page.getByTestId("result-meta").waitFor();
}

const hashOf = (page: Page) => page.evaluate(() => window.location.hash);

test("filtering the components table puts the filter in the URL", async ({ page }) => {
  await openAt(page, "/scan/demo_3.0/components");
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toBeVisible();

  await page.getByRole("textbox", { name: "Search name, license, type…" }).fill("openssl");

  await expect.poll(() => hashOf(page)).toBe("#/scan/demo_3.0/components?q=openssl");
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toHaveCount(0);
});

test("a filtered view survives a reload", async ({ page }) => {
  await openAt(page, "/scan/demo_3.0/components");
  await page.getByRole("textbox", { name: "Search name, license, type…" }).fill("openssl");
  await expect.poll(() => hashOf(page)).toContain("q=openssl");

  await page.reload();
  await page.getByTestId("result-meta").waitFor();

  await expect(page.getByRole("textbox", { name: "Search name, license, type…" })).toHaveValue(
    "openssl",
  );
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toHaveCount(0);
});

test("a link into a filtered view opens it filtered", async ({ page }) => {
  // What a colleague receives: the URL alone, with no prior state in the tab.
  await openAt(page, "/scan/demo_3.0/vulnerabilities?severity=CRITICAL");

  await expect(page.getByText("CVE-2024-1111")).toBeVisible();
  await expect(page.getByText("CVE-2024-2222")).toHaveCount(0);
});

test("clearing a filter takes it back out of the URL", async ({ page }) => {
  await openAt(page, "/scan/demo_3.0/components?q=openssl");
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toHaveCount(0);

  await page.getByRole("textbox", { name: "Search name, license, type…" }).fill("");

  await expect.poll(() => hashOf(page)).toBe("#/scan/demo_3.0/components");
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toBeVisible();
});

test("sorting is carried too", async ({ page }) => {
  await openAt(page, "/scan/demo_3.0/components");
  await page.getByRole("button", { name: "Name" }).click();

  await expect.poll(() => hashOf(page)).toBe("#/scan/demo_3.0/components?dir=asc&sort=name");

  await page.reload();
  await page.getByTestId("result-meta").waitFor();
  await expect(page.locator("th").filter({ hasText: "Name" })).toHaveAttribute(
    "aria-sort",
    "ascending",
  );
});

test("a hand-edited query does not break the section", async ({ page }) => {
  // Someone truncates or mangles the link; the section still opens, unfiltered.
  await openAt(page, "/scan/demo_3.0/components?sort=nonsense&dir=sideways&q=");

  await expect(page.getByRole("cell", { name: "openssl", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toBeVisible();
});
