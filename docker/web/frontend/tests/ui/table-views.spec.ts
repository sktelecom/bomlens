// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";
import { seedThemeLang } from "./visual";

/**
 * Reading the result tables differently without changing what is in them:
 * one line per package for the upgrade bundles, preset views and a per-package
 * layout that travel in the URL, a row density that is remembered, and a
 * dependency view that opens as the tree when the graph would be a tangle.
 *
 * The URL assertions poll the hash (it is replaced, not pushed). Density is
 * measured on real rows, because "32px" and "40px" are the claim.
 */

const ID = "views_1.0";

// urllib3: fixed at 2.5.0 (1 CVE), 2.6.0 (2 more) and 2.8.0 (2 more), one with
// no fix. Upgrading to 2.8.0 therefore resolves 5, to 2.6.0 resolves 3.
const VULNS = [
  { id: "CVE-2024-4001", severity: "CRITICAL", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0" },
  { id: "CVE-2024-4002", severity: "HIGH", pkg: "urllib3", installed: "2.1.0", fixed: "2.8.0" },
  { id: "CVE-2024-4003", severity: "MEDIUM", pkg: "urllib3", installed: "2.1.0", fixed: "2.6.0" },
  { id: "CVE-2024-4004", severity: "LOW", pkg: "urllib3", installed: "2.1.0", fixed: "2.6.0" },
  { id: "CVE-2024-4005", severity: "HIGH", pkg: "urllib3", installed: "2.1.0", fixed: "2.5.0" },
  { id: "CVE-2024-4006", severity: "LOW", pkg: "urllib3", installed: "2.1.0", fixed: "" },
  { id: "CVE-2024-4101", severity: "HIGH", pkg: "qs", installed: "6.15.3", fixed: "6.16.0" },
  { id: "CVE-2024-4102", severity: "MEDIUM", pkg: "qs", installed: "6.15.3", fixed: "6.16.0" },
  { id: "CVE-2024-4201", severity: "HIGH", pkg: "lodash", installed: "4.17.20", fixed: "4.17.21", kev: true },
  { id: "CVE-2024-4301", severity: "CRITICAL", pkg: "zlib", installed: "1.2.11", fixed: "" },
];

const COMPONENTS = ["urllib3", "qs", "lodash", "zlib"].map((name) => ({
  name,
  version: "1.0.0",
  group: "",
  type: "library",
  licenses: ["MIT"],
  purl: `pkg:generic/${name}@1.0.0`,
}));

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: ID,
  results: [{ name: `${ID}_bom.json`, size: 100 }],
  conformance: null,
  security: {
    CRITICAL: 2, HIGH: 4, MEDIUM: 2, LOW: 2, UNKNOWN: 0, TOTAL: VULNS.length,
    vulnerabilities: VULNS,
  },
  sbom: { components: COMPONENTS.length, componentList: COMPONENTS },
};

/** A CycloneDX document with `leaves` packages under 12 direct dependencies,
 *  so the graph is deep and wide enough that a fit lands well under zoom 1. */
function sbomWith(total: number) {
  const components = Array.from({ length: total }, (_, i) => ({
    "bom-ref": `n${i}`,
    name: `pkg-${i}`,
    version: "1.0.0",
    type: "library",
    purl: `pkg:npm/pkg-${i}@1.0.0`,
  }));
  const direct = 12;
  const dependencies = [
    { ref: "root", dependsOn: components.slice(0, direct).map((c) => c["bom-ref"]) },
    ...components.slice(0, direct).map((c, i) => ({
      ref: c["bom-ref"],
      dependsOn: components
        .slice(direct)
        .filter((_, j) => j % direct === i)
        .map((x) => x["bom-ref"]),
    })),
  ];
  return {
    bomFormat: "CycloneDX",
    metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
    components,
    dependencies,
  };
}

async function open(page: Page, hash: string, sbom: unknown = sbomWith(8)) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${ID}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(sbom) }),
  );
  await page.goto(`/?ui=next#/scan/${ID}/${hash}`);
  await page.getByRole("navigation").first().waitFor();
}

const hashOf = (page: Page) => page.evaluate(() => window.location.hash);
const base = `#/scan/${ID}/vulnerabilities`;

test.describe("upgrade bundles", () => {
  test("a package with several fix versions is one line with the lower targets beside it", async ({ page }) => {
    await open(page, "vulnerabilities");
    const lines = page.getByRole("button", { name: /^Upgrade urllib3 to / });
    await expect(lines).toHaveCount(1);
    await expect(lines).toHaveAccessibleName(
      "Upgrade urllib3 to 2.8.0 to resolve 5 CVEs (2.5.0 alone: 1, 2.6.0 alone: 3)",
    );
    // A package whose CVEs share one fixed version keeps the plain wording.
    await expect(
      page.getByRole("button", { name: "Upgrade qs to 6.16.0 to resolve 2 CVEs" }),
    ).toBeVisible();
    // One CVE is not a bundle.
    await expect(page.getByRole("button", { name: /^Upgrade lodash/ })).toHaveCount(0);
  });

  test("clicking a bundle narrows the table to that package", async ({ page }) => {
    await open(page, "vulnerabilities");
    await page.getByRole("button", { name: /^Upgrade qs to / }).click();
    await expect(page.getByText("CVE-2024-4101")).toBeVisible();
    await expect(page.getByText("CVE-2024-4001")).toHaveCount(0);
  });
});

test.describe("preset views", () => {
  test("a link into a view opens it, with the chip pressed and the table narrowed", async ({ page }) => {
    await open(page, "vulnerabilities?view=fixable");
    await expect(page.getByRole("button", { name: /^Fix available/ })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByText("CVE-2024-4001")).toBeVisible();
    // No fixed version: out of this view.
    await expect(page.getByText("CVE-2024-4006")).toHaveCount(0);
    await expect(page.getByText("CVE-2024-4301")).toHaveCount(0);
  });

  test("choosing a view puts it in the URL and survives a reload", async ({ page }) => {
    await open(page, "vulnerabilities");
    await page.getByRole("button", { name: /^Critical and High/ }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?view=critical-high`);
    await expect(page.getByText("CVE-2024-4003")).toHaveCount(0); // Medium
    await expect(page.getByText("CVE-2024-4001")).toBeVisible();

    await page.reload();
    await page.getByRole("navigation").first().waitFor();
    await expect(page.getByRole("button", { name: /^Critical and High/ })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByText("CVE-2024-4003")).toHaveCount(0);

    await page.getByRole("button", { name: /^All/ }).click();
    await expect.poll(() => hashOf(page)).toBe(base);
    await expect(page.getByText("CVE-2024-4003")).toBeVisible();
  });

  test("the known-exploited view holds only the exploited rows", async ({ page }) => {
    await open(page, "vulnerabilities");
    await page.getByRole("button", { name: /^Known exploited/ }).click();
    await expect(page.getByText("CVE-2024-4201")).toBeVisible();
    await expect(page.getByText("CVE-2024-4001")).toHaveCount(0);
  });

  test("a view narrows together with the severity filter", async ({ page }) => {
    await open(page, "vulnerabilities?view=fixable&severity=HIGH");
    await expect(page.getByText("CVE-2024-4002")).toBeVisible();
    await expect(page.getByText("CVE-2024-4001")).toHaveCount(0); // Critical
    await expect(page.getByText("CVE-2024-4003")).toHaveCount(0); // Medium
  });

  test("an unknown view in a hand-edited link opens the whole table", async ({ page }) => {
    await open(page, "vulnerabilities?view=vibes&group=nope");
    await expect(page.getByText("CVE-2024-4301")).toBeVisible();
    await expect(page.getByText("CVE-2024-4001")).toBeVisible();
  });
});

test.describe("per-package layout", () => {
  test("one header row per package, opened to its CVEs, and the layout is in the URL", async ({ page }) => {
    await open(page, "vulnerabilities");
    await page.getByRole("button", { name: "By package" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?group=package`);

    const rows = page.getByTestId("vuln-package-row");
    await expect(rows).toHaveCount(4);
    // Closed to start with: the CVE rows are not in the table yet.
    await expect(page.getByText("CVE-2024-4001")).toHaveCount(0);
    const urllib3 = rows.filter({ hasText: "urllib3" });
    await expect(urllib3).toContainText("6 CVEs");
    await expect(urllib3).toContainText("Upgrade to 2.8.0 to resolve 5 (2.5.0 alone: 1, 2.6.0 alone: 3)");
    await expect(urllib3).toContainText("1 without a fix");
    await expect(rows.filter({ hasText: "zlib" })).toContainText("No fixed version yet");

    await urllib3.click();
    await expect(page.getByText("CVE-2024-4001")).toBeVisible();
    await expect(page.getByText("CVE-2024-4006")).toBeVisible();
    await urllib3.click();
    await expect(page.getByText("CVE-2024-4001")).toHaveCount(0);
  });

  test("a shared link carries layout and view together", async ({ page }) => {
    await open(page, "vulnerabilities?group=package&view=fixable");
    const rows = page.getByTestId("vuln-package-row");
    // zlib has no fixed version, so the fixable view leaves it out.
    await expect(rows).toHaveCount(3);
    await expect(rows.filter({ hasText: "zlib" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "By package" })).toHaveAttribute("aria-pressed", "true");
    // Back to the list: the layout leaves the URL, the view stays.
    await page.getByRole("button", { name: "List" }).click();
    await expect.poll(() => hashOf(page)).toBe(`${base}?view=fixable`);
    await expect(page.getByTestId("vuln-package-row")).toHaveCount(0);
  });

  test("a single package on screen is shown open", async ({ page }) => {
    await open(page, "vulnerabilities?group=package&q=zlib");
    await expect(page.getByTestId("vuln-package-row")).toHaveCount(1);
    await expect(page.getByText("CVE-2024-4301")).toBeVisible();
  });
});

test.describe("row density", () => {
  const firstRowHeight = (page: Page, label: RegExp) =>
    page
      .locator("tbody tr[role='button']")
      .filter({ hasText: label })
      .first()
      .evaluate((el) => el.getBoundingClientRect().height);

  test("components rows are 32px compact and 40px comfortable, and the choice is remembered", async ({ page }) => {
    await open(page, "components");
    await expect(page.getByRole("cell", { name: "urllib3", exact: true })).toBeVisible();
    const toggle = page.getByTestId("density-toggle");
    await expect(toggle.getByRole("button", { name: "Comfortable" })).toHaveAttribute("aria-pressed", "true");
    expect(await firstRowHeight(page, /urllib3/)).toBeGreaterThanOrEqual(39.5); // sub-pixel layout can give 39.99998
    expect(await firstRowHeight(page, /urllib3/)).toBeLessThan(42);

    await toggle.getByRole("button", { name: "Compact" }).click();
    await expect(toggle.getByRole("button", { name: "Compact" })).toHaveAttribute("aria-pressed", "true");
    expect(await firstRowHeight(page, /urllib3/)).toBeGreaterThanOrEqual(31.5);
    expect(await firstRowHeight(page, /urllib3/)).toBeLessThan(34);

    await page.reload();
    await page.getByRole("navigation").first().waitFor();
    await expect(page.getByTestId("density-toggle").getByRole("button", { name: "Compact" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(await firstRowHeight(page, /urllib3/)).toBeLessThan(34);
  });

  test("the vulnerabilities table has the same two steps and shares the choice", async ({ page }) => {
    await open(page, "components");
    await page.getByTestId("density-toggle").getByRole("button", { name: "Compact" }).click();
    await page.getByRole("link", { name: /^Vulnerabilities/ }).first().click();

    const toggle = page.getByTestId("density-toggle");
    await expect(toggle.getByRole("button", { name: "Compact" })).toHaveAttribute("aria-pressed", "true");
    const compact = await firstRowHeight(page, /CVE-2024-4101/);
    expect(compact).toBeGreaterThanOrEqual(31.5);
    expect(compact).toBeLessThan(34);

    await toggle.getByRole("button", { name: "Comfortable" }).click();
    const comfortable = await firstRowHeight(page, /CVE-2024-4101/);
    expect(comfortable).toBeGreaterThanOrEqual(39.5);
    expect(comfortable).toBeLessThan(42);
  });

  test("a corrupt stored value reads as the default", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("sbom.table.density", "spacious"));
    await open(page, "components");
    await expect(
      page.getByTestId("density-toggle").getByRole("button", { name: "Comfortable" }),
    ).toHaveAttribute("aria-pressed", "true");
  });
});

test.describe("dependency graph default", () => {
  const graph = (page: Page) => page.locator("[data-zoom]");
  const zoomOf = async (page: Page) => Number(await graph(page).getAttribute("data-zoom"));

  test("a small graph opens as the graph", async ({ page }) => {
    await open(page, "dependencies", sbomWith(8));
    await graph(page).waitFor({ timeout: 15000 });
    await expect(page.getByTestId("deps-view-graph")).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("deps-auto-tree-note")).toHaveCount(0);
  });

  test("a graph past the threshold opens as the tree, says why, and the graph is still one click away", async ({ page }) => {
    await open(page, "dependencies", sbomWith(200));
    await expect(page.getByTestId("deps-view-tree")).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("deps-auto-tree-note")).toContainText("201 packages");
    await expect(page.locator("[data-zoom]")).toHaveCount(0);

    await page.getByTestId("deps-view-graph").click();
    await expect(page.getByTestId("deps-view-graph")).toHaveAttribute("aria-pressed", "true");
    await graph(page).waitFor({ timeout: 15000 });
    // The reader's own pick replaces the note.
    await expect(page.getByTestId("deps-auto-tree-note")).toHaveCount(0);
  });

  test("the threshold counts graph nodes: 150 still opens the graph, 151 the tree", async ({ page }) => {
    // The scanned root is a node too, so 149 components make 150 nodes.
    await open(page, "dependencies", sbomWith(149));
    await graph(page).waitFor({ timeout: 15000 });
    await expect(page.getByTestId("deps-view-graph")).toHaveAttribute("aria-pressed", "true");

    await page.unrouteAll();
    await open(page, "dependencies", sbomWith(150));
    await page.reload();
    await expect(page.getByTestId("deps-view-tree")).toHaveAttribute("aria-pressed", "true");
  });

  test("labels take the label size token, 12px", async ({ page }) => {
    await open(page, "dependencies", sbomWith(8));
    await graph(page).waitFor({ timeout: 15000 });
    await expect(graph(page)).toHaveAttribute("data-label-px", "12");
  });

  test("the legend is a group of chips, not one long sentence", async ({ page }) => {
    await open(page, "dependencies", sbomWith(8));
    await graph(page).waitFor({ timeout: 15000 });
    const items = page.getByTestId("deps-legend").getByRole("listitem");
    await expect(items).toHaveCount(7);
    await expect(items.filter({ hasText: "Scanned component" })).toHaveCount(1);
    for (const text of await items.allTextContents()) expect(text.length).toBeLessThan(45);
  });

  test("the first view is the whole graph, not a zoomed-in corner, and zoom is not reset by other actions", async ({ page }) => {
    await open(page, "dependencies", sbomWith(120));
    await graph(page).waitFor({ timeout: 15000 });
    // Starts at 1 until the canvas has loaded and fitted itself.
    await expect(graph(page)).toHaveAttribute("data-zoom", /^0\./);
    const initial = await zoomOf(page);
    // A graph this size cannot fit at 1:1. The old first view snapped to 1 and
    // anchored the top-left, which cut nodes off.
    expect(initial).toBeLessThan(0.9);

    // The first view is what "Fit to view" produces.
    await page.getByRole("button", { name: "Fit to view" }).click();
    await expect.poll(() => zoomOf(page)).toBeCloseTo(initial, 2);

    // Zoom in, then do things that must not touch zoom: search, then clear it.
    await page.getByRole("button", { name: "Zoom in" }).click();
    await expect.poll(() => zoomOf(page)).toBeGreaterThan(initial);
    const zoomed = await zoomOf(page);
    await page.getByPlaceholder("Search packages…").fill("pkg-3");
    await page.getByPlaceholder("Search packages…").fill("");
    await expect.poll(() => zoomOf(page)).toBeCloseTo(zoomed, 2);
  });
});

// The new controls sit on tinted and selected surfaces, which is where the
// contrast bugs of this UI have been: check both themes and both languages
// with the bundle card, the chips and the open package group on screen.
for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`view chips, bundle card and package groups pass axe — ${theme}/${lang}`, async ({ page }) => {
      await seedThemeLang(page, theme, lang);
      await open(page, "vulnerabilities?group=package&view=fixable");
      await page.getByTestId("vuln-package-row").first().click();
      await expect(page.getByTestId("upgrade-bundles")).toBeVisible();
      await waitForSettled(page.locator("main"));
      const axe = await new AxeBuilder({ page })
        .include("main")
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(axe.violations).toEqual([]);
    });

    test(`graph legend chips and density switch pass axe — ${theme}/${lang}`, async ({ page }) => {
      await seedThemeLang(page, theme, lang);
      await open(page, "dependencies", sbomWith(8));
      await page.locator("[data-label-px]").waitFor({ timeout: 15000 });
      await waitForSettled(page.locator("main"));
      let axe = await new AxeBuilder({ page })
        .include("main")
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(axe.violations).toEqual([]);

      await page.getByRole("link", { name: /^(Components|컴포넌트)/ }).first().click();
      await expect(page.getByTestId("density-toggle")).toBeVisible();
      await waitForSettled(page.locator("main"));
      axe = await new AxeBuilder({ page })
        .include("main")
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(axe.violations).toEqual([]);
    });
  }
}
