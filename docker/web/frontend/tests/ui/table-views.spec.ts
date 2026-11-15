// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";
import { seedThemeLang } from "./visual";

/**
 * Reading the result tables differently without changing what is in them:
 * a row density that is remembered and a dependency view that opens as the tree
 * when the graph would be a tangle. (The Vulnerabilities views are in
 * vulnerabilities-views.spec.ts.)
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
  await page.getByTestId("result-meta").waitFor();
}


test.describe("row density", () => {
  // The Components rows are plain rows with an expand button inside.
  const componentRowHeight = (page: Page, name: string) =>
    page
      .locator("main table tbody tr")
      .filter({ has: page.getByRole("button", { name: `Show component details: ${name}`, exact: true }) })
      .first()
      .evaluate((el) => el.getBoundingClientRect().height);
  const viewMenu = (page: Page) => page.getByRole("button", { name: "View", exact: true });

  test("components rows are shorter compact than comfortable, and the choice is remembered", async ({ page }) => {
    await open(page, "components");
    await expect(page.getByRole("button", { name: "Show component details: urllib3", exact: true })).toBeVisible();
    await viewMenu(page).click();
    await expect(page.getByRole("menuitemradio", { name: "Comfortable" })).toHaveAttribute("aria-checked", "true");
    await page.keyboard.press("Escape");
    const comfortable = await componentRowHeight(page, "urllib3");
    expect(comfortable).toBeGreaterThanOrEqual(36);
    expect(comfortable).toBeLessThan(46);

    await viewMenu(page).click();
    await page.getByRole("menuitemradio", { name: "Compact" }).click();
    await page.keyboard.press("Escape");
    const compact = await componentRowHeight(page, "urllib3");
    expect(compact).toBeGreaterThanOrEqual(28);
    expect(compact).toBeLessThan(comfortable);

    await page.reload();
    await page.getByTestId("result-meta").waitFor();
    await viewMenu(page).click();
    await expect(page.getByRole("menuitemradio", { name: "Compact" })).toHaveAttribute("aria-checked", "true");
    await page.keyboard.press("Escape");
    expect(await componentRowHeight(page, "urllib3")).toBe(compact);
  });

  test("a corrupt stored value reads as the default", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("sbom.table.density", "spacious"));
    await open(page, "components");
    await viewMenu(page).click();
    await expect(page.getByRole("menuitemradio", { name: "Comfortable" })).toHaveAttribute("aria-checked", "true");
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

  test("the threshold counts graph nodes: 60 still opens the graph, 61 the tree", async ({ page }) => {
    // The scanned root is a node too, so 59 components make 60 nodes.
    await open(page, "dependencies", sbomWith(59));
    await graph(page).waitFor({ timeout: 15000 });
    await expect(page.getByTestId("deps-view-graph")).toHaveAttribute("aria-pressed", "true");

    await page.unrouteAll();
    await open(page, "dependencies", sbomWith(60));
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
    await expect(items).toHaveCount(8);
    await expect(items.filter({ hasText: "Scanned component" })).toHaveCount(1);
    // How to read the canvas is one line under it, not more chips.
    await expect(page.getByTestId("deps-hints")).toContainText("Keyboard: use Tree");
    for (const text of await items.allTextContents()) expect(text.length).toBeLessThan(45);
  });

  test("the first view is the whole graph, not a zoomed-in corner, and zoom is not reset by other actions", async ({ page }) => {
    await open(page, "dependencies", sbomWith(59));
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
// contrast bugs of this UI have been: check both themes and both languages.
for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`graph legend chips and the components toolbar pass axe: ${theme}/${lang}`, async ({ page }) => {
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
      await expect(page.getByRole("button", { name: /^(View|보기)$/ })).toBeVisible();
      await waitForSettled(page.locator("main"));
      axe = await new AxeBuilder({ page })
        .include("main")
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(axe.violations).toEqual([]);
    });
  }
}
