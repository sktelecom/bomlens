// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The investigation loop between the two result tables: a CVE's expanded detail
 * opens Components filtered to its package, and a component's expanded detail
 * opens Vulnerabilities filtered to that component. Both reuse the seed
 * mechanism the Overview jump cards use, so what is asserted here is the
 * routing and the seeded filter — the section the user lands on, and the term
 * sitting in its search box.
 *
 * The links sit in the expanded detail, not on the row's own cells, because
 * each row is itself the toggle control and axe rejects a control nested in a
 * control (nested-interactive).
 */

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_2.1",
  results: [{ name: "demo_2.1_bom.json", size: 100 }],
  conformance: null,
  security: {
    total: 2,
    counts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0 },
    vulnerabilities: [
      {
        id: "CVE-2024-0001",
        severity: "CRITICAL",
        pkg: "openssl",
        installed: "3.0.0",
        fixed: "3.0.1",
        cvss: 9.8,
      },
      {
        id: "CVE-2024-0002",
        severity: "HIGH",
        pkg: "zlib",
        installed: "1.2.11",
        fixed: null,
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
        group: "",
        purl: "pkg:generic/openssl@3.0.0",
        type: "library",
        licenses: ["Apache-2.0"],
        maxSeverity: "CRITICAL",
        vulnCount: 1,
      },
      {
        name: "zlib",
        version: "1.2.11",
        group: "",
        purl: "pkg:generic/zlib@1.2.11",
        type: "library",
        licenses: ["Zlib"],
        maxSeverity: "HIGH",
        vulnCount: 1,
      },
    ],
  },
};

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "2.1" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "o" },
    { "bom-ref": "z", name: "zlib", version: "1.2.11", type: "library", purl: "z" },
  ],
  dependencies: [],
};

async function openScan(page: Page, section: string) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, docker: true }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.route("**/scan?id=demo_2.1", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto(`/?ui=next#/scan/demo_2.1/${section}`);
  await page.getByTestId("result-meta").waitFor();
}

test("a CVE's detail opens Components filtered to its package", async ({ page }) => {
  await openScan(page, "vulnerabilities");
  await expect(page.getByText("CVE-2024-0001")).toBeVisible();

  await page.getByRole("button", { name: "Show vulnerability details" }).first().click();
  await page.getByRole("button", { name: "View openssl in Components" }).click();

  await expect
    .poll(() => page.evaluate(() => window.location.hash))
    // The term rides in the URL, which is what makes the filtered view
    // shareable and survive a reload.
    .toBe("#/scan/demo_2.1/components?q=openssl");
  await expect(
    page.getByRole("textbox", { name: "Search name, license, type…" }),
  ).toHaveValue("openssl");
  // The filter actually narrowed the table, not just the input.
  await expect(page.getByRole("cell", { name: "zlib", exact: true })).toHaveCount(0);
});

test("a component's detail opens Vulnerabilities filtered to it", async ({
  page,
}) => {
  await openScan(page, "components");
  await expect(page.getByRole("cell", { name: "openssl", exact: true })).toBeVisible();

  // Rows carry role="button" (they are the expand toggle), so the second one is
  // zlib's; its detail holds the link into Vulnerabilities.
  await page.getByRole("button", { name: "Show component details" }).nth(1).click();
  await page.getByRole("button", { name: "View vulnerabilities for zlib" }).click();

  await expect
    .poll(() => page.evaluate(() => window.location.hash))
    .toBe("#/scan/demo_2.1/vulnerabilities?q=zlib");
  await expect(
    page.getByRole("textbox", { name: "Search CVE, component, title" }),
  ).toHaveValue("zlib");
  await expect(page.getByText("CVE-2024-0002")).toBeVisible();
  await expect(page.getByText("CVE-2024-0001")).toHaveCount(0);
});

test("the round trip lands back on the component it started from", async ({
  page,
}) => {
  await openScan(page, "components");
  await page.getByRole("button", { name: "Show component details" }).first().click();
  await page.getByRole("button", { name: "View vulnerabilities for openssl" }).click();
  await expect(page.getByText("CVE-2024-0001")).toBeVisible();

  await page.getByRole("button", { name: "Show vulnerability details" }).first().click();
  await page.getByRole("button", { name: "View openssl in Components" }).click();
  await expect(
    page.getByRole("textbox", { name: "Search name, license, type…" }),
  ).toHaveValue("openssl");
  await expect(page.getByRole("cell", { name: "openssl", exact: true })).toBeVisible();
});

test("the cross-links are reachable and accessible", async ({ page }) => {
  await openScan(page, "vulnerabilities");
  await page.getByRole("button", { name: "Show vulnerability details" }).first().click();
  const link = page.getByRole("button", { name: "View openssl in Components" });

  // Keyboard-reachable, with a visible focus ring class applied.
  await link.focus();
  await expect(link).toBeFocused();
  await waitForSettled(page.locator("main"));

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});
