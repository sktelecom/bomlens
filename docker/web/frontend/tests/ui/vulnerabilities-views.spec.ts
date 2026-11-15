// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { waitForSettled } from "./settle";
import { hashOf, ID, openerOf, openVulns, rowOf } from "./vulnerabilities-helpers";
import { seedThemeLang } from "./visual";

/**
 * How the Vulnerabilities rows are read without changing what is in them: the
 * upgrade bundles, the preset views, the by-package layout, the row density and
 * the optional columns. All of it travels in the URL or in local storage.
 * The URL assertions poll the hash (it is replaced, not pushed).
 */

const base = `#/scan/${ID}/vulnerabilities`;
const ids = (page: import("@playwright/test").Page, id: string) => openerOf(page, id);

test.describe("upgrade bundles", () => {
  test("a collapsed box says how many packages and CVEs it covers, and opens to one line per package", async ({ page }) => {
    await openVulns(page);
    const box = page.getByTestId("upgrade-bundles");
    await expect(box).toBeVisible();
    await expect(box.getByRole("heading", { level: 2 })).toHaveText("Upgrading 2 packages resolves 7 CVEs");
    // Collapsed: the lines are not shown until the box is opened.
    await expect(box.getByRole("listitem").first()).toBeHidden();
    await box.getByRole("heading", { level: 2 }).click();
    const urllib3 = box.getByRole("listitem").filter({ hasText: "urllib3" });
    await expect(urllib3).toContainText("Upgrade to 2.8.0 to resolve 5 (2.5.0 alone: 1, 2.6.0 alone: 3)");
    // A package whose CVEs share one fixed version keeps the plain wording.
    await expect(box.getByRole("listitem").filter({ hasText: "qs" })).toContainText("Upgrade to 6.16.0 to resolve 2");
    // One CVE is not a bundle.
    await expect(box.getByRole("listitem").filter({ hasText: "lodash" })).toHaveCount(0);
  });

  test("choosing a package narrows the table to it", async ({ page }) => {
    await openVulns(page);
    const box = page.getByTestId("upgrade-bundles");
    await box.getByRole("heading", { level: 2 }).click();
    await box.getByRole("button", { name: "qs" }).click();
    await expect(page.getByLabel("Search CVE, component, title")).toHaveValue("qs");
    await expect(ids(page, "CVE-2024-4101")).toBeVisible();
    await expect(ids(page, "CVE-2024-4001")).toHaveCount(0);
    await expect.poll(() => hashOf(page)).toBe(`${base}?q=qs`);
  });

  test("the box lists the five worst packages and counts the rest, and a KEV bundle says so", async ({ page }) => {
    const many = Array.from({ length: 14 }, (_, i) => {
      const pkg = `pkg${String(i).padStart(2, "0")}`;
      return [
        { id: `CVE-2025-${i}1`, severity: i === 0 ? "CRITICAL" : "HIGH", pkg, installed: "1.0", fixed: "2.0", title: `${pkg} one`, kev: i === 0 },
        { id: `CVE-2025-${i}2`, severity: "HIGH", pkg, installed: "1.0", fixed: "2.0", title: `${pkg} two` },
      ];
    }).flat();
    const { security } = await import("./vulnerabilities-helpers");
    await openVulns(page, "", { security: security(many) });
    const box = page.getByTestId("upgrade-bundles");
    await box.getByRole("heading", { level: 2 }).click();
    await expect(box.getByRole("listitem")).toHaveCount(5);
    await expect(box).toContainText("and 9 more bundle(s) below");
    await expect(box.getByRole("listitem").first()).toContainText("KEV");
  });

  test("the box is for the list: the by-package layout has the same facts in its package rows", async ({ page }) => {
    await openVulns(page, "group=package");
    await expect(page.getByTestId("upgrade-bundles")).toHaveCount(0);
    await expect(page.getByTestId("vuln-package-row").filter({ hasText: "urllib3" })).toContainText("Upgrade to 2.8.0 to resolve 5");
  });
});

test.describe("preset views", () => {
  test("a segment for each view, with its count once in the accessible name", async ({ page }) => {
    await openVulns(page);
    const views = page.getByRole("list", { name: "Preset views" });
    await expect(views.getByRole("button")).toHaveText(["All10 (10)", "Fix available8 (8)", "No fix yet2 (2)", "Known exploited1 (1)", "Critical and High6 (6)"]);
    for (const name of ["All (10)", "Fix available (8)", "No fix yet (2)", "Known exploited (1)", "Critical and High (6)"]) {
      await expect(views.getByRole("button", { name, exact: true })).toBeVisible();
    }
    await expect(views.getByRole("button", { name: "All (10)", exact: true })).toHaveAttribute("aria-pressed", "true");
  });

  test("a link into a view opens it, with the segment pressed and the table narrowed", async ({ page }) => {
    await openVulns(page, "view=fixable");
    await expect(page.getByRole("button", { name: "Fix available (8)", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(ids(page, "CVE-2024-4001")).toBeVisible();
    // No fixed version: out of this view.
    await expect(ids(page, "CVE-2024-4006")).toHaveCount(0);
    await expect(ids(page, "CVE-2024-4301")).toHaveCount(0);
    await expect(page.getByText("8 of 10 shown")).toBeVisible();
  });

  test("the no-fix view holds only the rows with no published fix", async ({ page }) => {
    await openVulns(page, "view=unfixed");
    await expect(page.getByRole("button", { name: "No fix yet (2)", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(ids(page, "CVE-2024-4006")).toBeVisible();
    await expect(ids(page, "CVE-2024-4001")).toHaveCount(0);
  });

  test("choosing a view puts it in the URL and survives a reload", async ({ page }) => {
    await openVulns(page);
    await page.getByRole("button", { name: "Critical and High (6)", exact: true }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?view=critical-high`);
    await expect(ids(page, "CVE-2024-4003")).toHaveCount(0); // Medium
    await expect(ids(page, "CVE-2024-4001")).toBeVisible();

    await page.reload();
    await page.getByTestId("result-meta").waitFor();
    await expect(page.getByRole("button", { name: "Critical and High (6)", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(ids(page, "CVE-2024-4003")).toHaveCount(0);

    await page.getByRole("button", { name: "All (10)", exact: true }).click();
    await expect.poll(() => hashOf(page)).toBe(base);
    await expect(ids(page, "CVE-2024-4003")).toBeVisible();
  });

  test("a view with no rows is disabled, unless it is the one on screen", async ({ page }) => {
    const { security } = await import("./vulnerabilities-helpers");
    await openVulns(page, "", { security: security([{ id: "CVE-1", severity: "HIGH", pkg: "a", installed: "1", fixed: "2", title: "t" }]) });
    await expect(page.getByRole("button", { name: "No fix yet (0)", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Known exploited (0)", exact: true })).toBeDisabled();
    // A shared link into an empty view can still be left again.
    await page.evaluate((hash) => { window.location.hash = hash; }, `${base}?view=unfixed`);
    const active = page.getByRole("button", { name: "No fix yet (0)", exact: true });
    await expect(active).toBeEnabled();
    await expect(active).toHaveAttribute("aria-pressed", "true");
  });

  test("the known-exploited view holds only the exploited rows", async ({ page }) => {
    await openVulns(page);
    await page.getByRole("button", { name: "Known exploited (1)", exact: true }).click();
    await expect(ids(page, "CVE-2024-4201")).toBeVisible();
    await expect(ids(page, "CVE-2024-4001")).toHaveCount(0);
  });

  test("a view narrows together with the severity filter", async ({ page }) => {
    await openVulns(page, "view=fixable&severity=HIGH");
    await expect(ids(page, "CVE-2024-4002")).toBeVisible();
    await expect(ids(page, "CVE-2024-4001")).toHaveCount(0); // Critical
    await expect(ids(page, "CVE-2024-4003")).toHaveCount(0); // Medium
  });

  test("an unknown view in a hand-edited link opens the whole table", async ({ page }) => {
    await openVulns(page, "view=vibes&group=nope");
    await expect(ids(page, "CVE-2024-4301")).toBeVisible();
    await expect(ids(page, "CVE-2024-4001")).toBeVisible();
  });

  test("Critical and High with a fix has no segment of its own: the Critical and High segment plus a removable filter", async ({ page }) => {
    await openVulns(page, "view=fixable-severe");
    await expect(page.getByRole("button", { name: "Critical and High (6)", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("button", { name: /^Critical and High with a fix/ })).toHaveCount(0);
    await page.getByRole("button", { name: "Remove filter: Critical and High with a fix" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?view=critical-high`);
  });
});

test.describe("per-package layout", () => {
  test("one header row per package, opened to its CVEs, and the layout is in the URL", async ({ page }) => {
    await openVulns(page);
    await page.getByRole("button", { name: "View" }).click();
    await page.getByRole("menuitemradio", { name: "By package" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?group=package`);

    const rows = page.getByTestId("vuln-package-row");
    await expect(rows).toHaveCount(4);
    // Four packages is a short list, so every package starts open.
    await expect(ids(page, "CVE-2024-4001")).toBeVisible();
    const urllib3 = rows.filter({ hasText: "urllib3" });
    await expect(urllib3).toContainText("6 CVEs");
    await expect(urllib3).toContainText("Upgrade to 2.8.0 to resolve 5 (2.5.0 alone: 1, 2.6.0 alone: 3)");
    await expect(urllib3).toContainText("1 without a fix");
    await expect(rows.filter({ hasText: "zlib" })).toContainText("No fixed version yet");
    await expect(rows.filter({ hasText: "lodash" })).toContainText("KEV");

    await expect(ids(page, "CVE-2024-4006")).toBeVisible();
    await urllib3.getByRole("button").click();
    await expect(ids(page, "CVE-2024-4001")).toHaveCount(0);
    await expect(urllib3.getByRole("button")).toHaveAttribute("aria-expanded", "false");
    await urllib3.getByRole("button").click();
    await expect(ids(page, "CVE-2024-4001")).toBeVisible();
  });

  test("a shared link carries layout and view together, and the View menu goes back to the list", async ({ page }) => {
    await openVulns(page, "group=package&view=fixable");
    const rows = page.getByTestId("vuln-package-row");
    // zlib has no fixed version, so the fixable view leaves it out.
    await expect(rows).toHaveCount(3);
    await expect(rows.filter({ hasText: "zlib" })).toHaveCount(0);
    await page.getByRole("button", { name: "View" }).click();
    await expect(page.getByRole("menuitemradio", { name: "By package" })).toHaveAttribute("aria-checked", "true");
    await page.getByRole("menuitemradio", { name: "List" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?view=fixable`);
    await expect(page.getByTestId("vuln-package-row")).toHaveCount(0);
  });

  test("a single package on screen is shown open", async ({ page }) => {
    await openVulns(page, "group=package&q=zlib");
    await expect(page.getByTestId("vuln-package-row")).toHaveCount(1);
    await expect(ids(page, "CVE-2024-4301")).toBeVisible();
  });

  test("the bundle box's \"View by package\" switches the layout", async ({ page }) => {
    await openVulns(page);
    const box = page.getByTestId("upgrade-bundles");
    await box.getByRole("heading", { level: 2 }).click();
    await box.getByRole("button", { name: "View by package" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?group=package`);
  });
});

test.describe("row density", () => {
  const height = (page: import("@playwright/test").Page, id: string) =>
    rowOf(page, id).evaluate((el) => el.getBoundingClientRect().height);

  test("rows are 62px comfortable and 52px compact, and the choice is the one the Components table uses", async ({ page }) => {
    await openVulns(page);
    await expect(ids(page, "CVE-2024-4101")).toBeVisible();
    expect(await height(page, "CVE-2024-4101")).toBeGreaterThanOrEqual(61.5);
    expect(await height(page, "CVE-2024-4101")).toBeLessThan(63);

    await page.getByRole("button", { name: "View" }).click();
    await page.getByRole("menuitemradio", { name: "Compact" }).click();
    expect(await page.evaluate(() => localStorage.getItem("sbom.table.density"))).toBe("compact");
    expect(await height(page, "CVE-2024-4101")).toBeGreaterThanOrEqual(51.5);
    expect(await height(page, "CVE-2024-4101")).toBeLessThan(53);

    await page.reload();
    await page.getByTestId("result-meta").waitFor();
    expect(await height(page, "CVE-2024-4101")).toBeLessThan(53);
    await page.getByRole("button", { name: "View" }).click();
    await expect(page.getByRole("menuitemradio", { name: "Compact" })).toHaveAttribute("aria-checked", "true");
  });

  test("a density chosen on the Components table applies here", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("sbom.table.density", "compact"));
    await openVulns(page);
    expect(await height(page, "CVE-2024-4101")).toBeLessThan(53);
  });
});

test.describe("optional columns", () => {
  const withScores = VULNS_WITH_SCORES();

  test("EPSS and the NVD rating are offered only when the report carries them", async ({ page }) => {
    await openVulns(page);
    await expect(page.getByRole("columnheader", { name: "EPSS" })).toHaveCount(0);
    await page.getByRole("button", { name: "View" }).click();
    await expect(page.getByRole("menuitemcheckbox", { name: /EPSS|NVD/ })).toHaveCount(0);
  });

  test("a column is on as soon as any row has a value, and the View menu turns each off and remembers it", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openVulns(page, "", { security: withScores });
    await expect(page.getByRole("columnheader", { name: "EPSS" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "NVD severity" })).toBeVisible();
    await expect(rowOf(page, "CVE-2024-4001")).toContainText("97.2%");

    await page.getByRole("button", { name: "View" }).click();
    const nvd = page.getByRole("menuitemcheckbox", { name: /NVD severity/ });
    await expect(nvd).toContainText("2 of 3 rows have a value");
    await nvd.click();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("columnheader", { name: "NVD severity" })).toHaveCount(0);
    await page.reload();
    await page.getByTestId("result-meta").waitFor();
    await expect(page.getByRole("columnheader", { name: "NVD severity" })).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem("sbom.vulns.columns"))).toBe('{"nvd":false}');
  });

  test("narrow windows keep both columns and scroll the table sideways inside its box", async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 900 });
    await openVulns(page, "", { security: withScores });
    await expect(page.getByRole("columnheader", { name: "EPSS" })).toBeVisible();
    const [sw, cw] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    expect(sw).toBeLessThanOrEqual(cw);
  });

  test("a sort in the URL that names a hidden column shows that column", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("sbom.vulns.columns", '{"epss":false,"nvd":false}'));
    await openVulns(page, "sort=epss&dir=asc", { security: withScores });
    await expect(page.getByRole("columnheader", { name: "EPSS" })).toHaveAttribute("aria-sort", "ascending");
    await expect(page.getByRole("columnheader", { name: "NVD severity" })).toHaveCount(0);
  });
});

function VULNS_WITH_SCORES() {
  const rows = [
    { id: "CVE-2024-4001", severity: "CRITICAL", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0", title: "urllib3 flaw one", cvss: 9.8, epss: 0.972, nvdSeverity: "CRITICAL" },
    { id: "CVE-2024-4002", severity: "HIGH", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0", title: "urllib3 flaw two", cvss: 7.5, epss: 0.004, nvdSeverity: "HIGH" },
    { id: "CVE-2024-4003", severity: "MEDIUM", pkg: "qs", installed: "1.0", fixed: "1.1", title: "qs flaw", cvss: 5.3, epss: 0.1 },
  ];
  return {
    CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, UNKNOWN: 0, TOTAL: 3, vulnerabilities: rows,
  };
}

// The controls sit on tinted and selected surfaces, which is where the contrast
// bugs of this UI have been: check both themes and both languages with the
// bundle box open, the segments, the chips and the package rows on screen.
for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`views, bundle box and package rows pass axe: ${theme}/${lang}`, async ({ page }) => {
      await seedThemeLang(page, theme, lang);
      await openVulns(page, "severity=HIGH");
      const box = page.getByTestId("upgrade-bundles");
      await box.locator("summary").click();
      await waitForSettled(page.locator("main"));
      let axe = await new AxeBuilder({ page }).include("main").withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(axe.violations).toEqual([]);

      await page.goto(`/?ui=next${base}?group=package&view=fixable`);
      await page.getByTestId("result-meta").waitFor();
      await expect(page.getByTestId("vuln-package-row").first()).toBeVisible();
      await waitForSettled(page.locator("main"));
      axe = await new AxeBuilder({ page }).include("main").withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(axe.violations).toEqual([]);
    });
  }
}
