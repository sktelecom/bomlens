// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The Dependencies screen: a Primer tree or a Cytoscape graph over the SBOM's
 * dependency relationships. The backend is stubbed, so each control is checked
 * against what the screen shows afterwards.
 */

const ID = "demo_1.0";

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: ID,
  results: [{ name: "demo_1.0_bom.json", size: 2048 }],
  security: null,
  conformance: null,
  sbom: {
    components: 5,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", type: "library", licenses: ["Apache-2.0"], purl: "pkg:generic/openssl@3.0.0", vulnCount: 2, maxSeverity: "CRITICAL" },
      { name: "zlib", version: "1.2.11", group: "", type: "library", licenses: ["Zlib"], purl: "pkg:generic/zlib@1.2.11", vulnCount: 1, maxSeverity: "HIGH" },
      { name: "libloop-a", version: "1.0", group: "", type: "library", licenses: [], purl: "pkg:generic/libloop-a@1.0" },
      { name: "libloop-b", version: "1.0", group: "", type: "library", licenses: [], purl: "pkg:generic/libloop-b@1.0" },
      { name: "multi-license", version: "2.0", group: "", type: "library", licenses: ["MIT", "ISC", "BSD-3-Clause", "Zlib"], purl: "pkg:generic/multi-license@2.0" },
    ],
  },
};

const SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
  components: [
    { "bom-ref": "o", name: "openssl", version: "3.0.0", type: "library", purl: "pkg:generic/openssl@3.0.0", licenses: [{ license: { id: "Apache-2.0" } }] },
    { "bom-ref": "z", name: "zlib", version: "1.2.11", type: "library", purl: "pkg:generic/zlib@1.2.11", licenses: [{ license: { id: "Zlib" } }] },
    { "bom-ref": "a", name: "libloop-a", version: "1.0", type: "library", purl: "pkg:generic/libloop-a@1.0" },
    { "bom-ref": "b", name: "libloop-b", version: "1.0", type: "library", purl: "pkg:generic/libloop-b@1.0" },
    {
      "bom-ref": "m",
      name: "multi-license",
      version: "2.0",
      type: "library",
      purl: "pkg:generic/multi-license@2.0",
      licenses: [{ license: { id: "MIT" } }, { license: { id: "ISC" } }, { license: { id: "BSD-3-Clause" } }, { license: { id: "Zlib" } }],
    },
  ],
  dependencies: [
    { ref: "root", dependsOn: ["o", "a", "m"] },
    { ref: "o", dependsOn: ["z"] },
    { ref: "a", dependsOn: ["b"] },
    { ref: "b", dependsOn: ["a"] },
  ],
};

const FLAT_SBOM = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
  components: SBOM.components,
};

const NO_COMPONENTS_SBOM = { bomFormat: "CycloneDX", metadata: { component: { name: "demo", version: "1.0" } }, components: [] };

/** A graph of `total` packages under 12 direct dependencies. */
function sbomWith(total: number) {
  const components = Array.from({ length: total }, (_, i) => ({
    "bom-ref": `n${i}`,
    name: `pkg-${i}`,
    version: "1.0.0",
    type: "library",
    purl: `pkg:npm/pkg-${i}@1.0.0`,
  }));
  const direct = 12;
  return {
    bomFormat: "CycloneDX",
    metadata: { component: { "bom-ref": "root", name: "demo", version: "1.0" } },
    components,
    dependencies: [
      { ref: "root", dependsOn: components.slice(0, direct).map((c) => c["bom-ref"]) },
      ...components.slice(0, direct).map((c, i) => ({
        ref: c["bom-ref"],
        dependsOn: components
          .slice(direct)
          .filter((_, j) => j % direct === i)
          .map((x) => x["bom-ref"]),
      })),
    ],
  };
}

interface Options {
  sbom?: unknown;
  lang?: "en" | "ko";
  theme?: "light" | "dark";
  /** Answer every request for the SBOM file with an error until `ctl.fail` is cleared. */
  ctl?: { fail: boolean };
  slow?: boolean;
}

async function openScreen(page: Page, hashQuery = "", opts: Options = {}) {
  const { sbom = SBOM, lang = "en", theme = "light", ctl, slow = false } = opts;
  await page.addInitScript(
    ([l, th]) => {
      localStorage.setItem("sbom.lang", l);
      localStorage.setItem("i18nextLng", l);
      localStorage.setItem("sbom.theme", th);
    },
    [lang, theme],
  );
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${ID}`, (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }));
  await page.route("**/file**", async (r) => {
    if (slow) await new Promise((res) => setTimeout(res, 800));
    if (ctl?.fail) return r.fulfill({ status: 500, body: "nope" });
    return r.fulfill({ contentType: "application/json", body: JSON.stringify(sbom) });
  });
  await page.goto(`/?ui=next#/scan/${ID}/dependencies${hashQuery}`);
  await page.getByTestId("result-meta").waitFor();
}

const tree = (page: Page) => page.getByRole("tree");
const treeItem = (page: Page, name: string) => page.getByRole("treeitem", { name, exact: true });
const canvas = (page: Page) => page.locator("[data-zoom]");
const zoomOf = async (page: Page) => Number(await canvas(page).getAttribute("data-zoom"));

test("a small graph opens as the graph with the legend, hints and a canvas", async ({ page }) => {
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  await expect(page.getByRole("img", { name: /Dependency graph/ })).toBeVisible();
  await expect(page.getByTestId("deps-view-graph")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("deps-view-tree")).not.toHaveAttribute("aria-pressed", "true");
  const legend = page.getByRole("list", { name: "Legend" });
  await expect(legend.getByRole("listitem")).toHaveText(["Scanned component", "Direct", "Transitive", "Vulnerable", "Critical", "High", "Medium", "Low"]);
  await expect(page.getByTestId("deps-hints")).toContainText("Arrow: package to its dependency");
  await expect(page.getByTestId("deps-hints")).toContainText("Hover to trace, click for details");
  await expect(page.getByTestId("deps-hints")).toContainText("Keyboard: use Tree");
});

test("graph buttons zoom, fit and save a PNG named for the scan", async ({ page }) => {
  // A graph this size cannot fit at 1:1, so the first view is below the zoom cap.
  await openScreen(page, "", { sbom: sbomWith(59) });
  await canvas(page).waitFor({ timeout: 15000 });
  // Starts at 1 until the canvas has loaded and fitted itself.
  await expect(canvas(page)).toHaveAttribute("data-zoom", /^0\./);
  const initial = await zoomOf(page);
  await page.getByRole("button", { name: "Zoom in", exact: true }).click();
  await expect.poll(() => zoomOf(page)).toBeGreaterThan(initial);
  await page.getByRole("button", { name: "Zoom out", exact: true }).click();
  await expect.poll(() => zoomOf(page)).toBeCloseTo(initial, 1);
  await page.getByRole("button", { name: "Zoom in", exact: true }).click();
  await page.getByRole("button", { name: "Fit to view", exact: true }).click();
  await expect.poll(() => zoomOf(page)).toBeCloseTo(initial, 2);

  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Save as PNG", exact: true }).click();
  expect((await download).suggestedFilename()).toBe("demo_1.0_dependency-graph.png");
});

test("clicking a graph node opens its detail, and the close button hides it", async ({ page }) => {
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  const box = await canvas(page).boundingBox();
  expect(box).not.toBeNull();
  const detail = page.getByTestId("deps-detail");
  // The canvas is not in the DOM, so click along a grid until a node answers.
  const cols = Math.floor((box!.width - 24) / 30) + 1;
  let step = 0;
  await expect
    .poll(
      async () => {
        const x = 24 + (step % cols) * 30;
        const y = 24 + Math.floor(step / cols) * 12;
        step += 1;
        await canvas(page).click({ position: { x, y: Math.min(y, box!.height - 2) }, force: true });
        return detail.isVisible();
      },
      { timeout: 30000, intervals: [0] },
    )
    .toBe(true);
  await expect(detail.getByRole("heading", { level: 2 })).not.toHaveText("");
  await detail.getByRole("button", { name: "Close" }).click();
  await expect(detail).toHaveCount(0);
});

test("Tree shows direct dependencies open, the vulnerable, cycle and licence markers", async ({ page }) => {
  await openScreen(page);
  await page.getByRole("button", { name: "Tree", exact: true }).click();
  await expect(tree(page)).toBeVisible();
  await expect(page.getByTestId("deps-view-tree")).toHaveAttribute("aria-pressed", "true");

  const openssl = treeItem(page, "openssl 3.0.0");
  await expect(openssl).toHaveAttribute("aria-level", "1");
  await expect(openssl).toHaveAttribute("aria-expanded", "true");
  // A top-level row has no visible "Direct" label; the word is in its description
  // together with severity and licences, and the box head counts them.
  await expect(openssl).toHaveAccessibleDescription(/Direct.*Critical.*Apache-2\.0/);
  await expect(openssl.getByText("Critical", { exact: true })).toBeVisible();
  await expect(openssl.getByText("Apache-2.0", { exact: true })).toBeVisible();
  // Its child is shown at level 2 and is not direct.
  const zlib = treeItem(page, "zlib 1.2.11");
  await expect(zlib).toHaveAttribute("aria-level", "2");
  await expect(zlib.getByText("High", { exact: true })).toBeVisible();
  await expect(zlib).not.toHaveAccessibleDescription(/Direct/);
  await expect(page.getByRole("heading", { name: "Packages" })).toBeVisible();
  await expect(page.getByTestId("deps-split")).toHaveText("3 direct, 2 transitive");

  // Two licences and a count for the rest; the rest are in the tooltip.
  const multi = treeItem(page, "multi-license 2.0");
  await expect(multi.getByText("MIT", { exact: true })).toBeVisible();
  await expect(multi.getByText("ISC", { exact: true })).toBeVisible();
  await expect(multi.getByText("+2", { exact: true })).toHaveAttribute("title", "BSD-3-Clause, Zlib");

  // A cycle is marked and has no expander. Its first visit is open under
  // libloop-a; open libloop-b to reach the repeat.
  const loopA = treeItem(page, "libloop-a 1.0");
  await expect(loopA).toHaveAttribute("aria-expanded", "true");
  const loopB = treeItem(page, "libloop-b 1.0");
  await loopB.focus();
  await page.keyboard.press("ArrowRight");
  const repeat = loopB.getByRole("treeitem", { name: "libloop-a 1.0", exact: true });
  await expect(repeat).toHaveCount(1);
  await expect(repeat).toContainText("cycle");
  await expect(repeat).not.toHaveAttribute("aria-expanded", /.*/);
});

test("the tree moves under the arrow keys, expands, collapses and jumps to the ends", async ({ page }) => {
  await openScreen(page);
  await page.getByRole("button", { name: "Tree", exact: true }).click();
  const items = page.getByRole("treeitem");
  const openssl = treeItem(page, "openssl 3.0.0");
  await openssl.focus();
  await expect(openssl).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(treeItem(page, "zlib 1.2.11")).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(openssl).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(openssl).toHaveAttribute("aria-expanded", "false");
  await expect(treeItem(page, "zlib 1.2.11")).toHaveCount(0);
  await page.keyboard.press("Enter");
  await expect(openssl).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("End");
  await expect(items.last()).toBeFocused();
  await page.keyboard.press("Home");
  await expect(items.first()).toBeFocused();
  // One tab stop for the whole tree.
  const stops = await page.getByRole("treeitem").evaluateAll((els) => els.filter((e) => e.getAttribute("tabindex") === "0").length);
  expect(stops).toBe(1);
});

test("search keeps the cursor in the box, expands to the match and Enter moves to it", async ({ page }) => {
  await openScreen(page);
  await page.getByRole("button", { name: "Tree", exact: true }).click();
  const search = page.getByRole("textbox", { name: "Search packages…" });
  await treeItem(page, "openssl 3.0.0").focus();
  await page.keyboard.press("ArrowLeft");
  await expect(treeItem(page, "zlib 1.2.11")).toHaveCount(0);

  await search.fill("zlib");
  await expect(treeItem(page, "zlib 1.2.11")).toBeVisible();
  await expect(search).toBeFocused();
  await expect(page.getByTestId("deps-search-status")).toHaveText("Press Enter to move to the match.");
  await expect(treeItem(page, "zlib 1.2.11")).toHaveAttribute("aria-current", "true");
  await search.press("Enter");
  await expect(treeItem(page, "zlib 1.2.11")).toBeFocused();

  await search.fill("no-such-package");
  await expect(page.getByTestId("deps-search-status")).toHaveText("No package matches this search.");
  await search.fill("");
  await expect(page.getByTestId("deps-search-status")).toHaveText("");
});

test("the graph search lights up the matching nodes and leaves the cursor in the box", async ({ page }) => {
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  const search = page.getByRole("textbox", { name: "Search packages…" });
  await search.fill("zlib");
  await expect.poll(() => canvas(page).getAttribute("data-matches")).toBe("1");
  await expect(search).toBeFocused();
  await search.fill("libloop");
  await expect.poll(() => canvas(page).getAttribute("data-matches")).toBe("2");
  await search.fill("");
  await expect.poll(() => canvas(page).getAttribute("data-matches")).toBeNull();
});

test("a jump from another section opens the tree on the row and focuses it", async ({ page }) => {
  await openScreen(page, "?q=zlib&version=1.2.11");
  await expect(tree(page)).toBeVisible();
  await expect(page.getByTestId("deps-view-tree")).toHaveAttribute("aria-pressed", "true");
  await expect(treeItem(page, "zlib 1.2.11")).toBeFocused();
  await expect(page.getByTestId("deps-auto-tree-note")).toHaveCount(0);
});

test("a jump to a package under a collapsed branch opens its ancestors", async ({ page }) => {
  await openScreen(page, "?q=libloop-b");
  await expect(treeItem(page, "libloop-b 1.0")).toBeFocused();
  await expect(treeItem(page, "libloop-a 1.0").first()).toHaveAttribute("aria-expanded", "true");
});

test("the view switch changes the view both ways", async ({ page }) => {
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  await page.getByTestId("deps-view-tree").click();
  await expect(canvas(page)).toHaveCount(0);
  await page.getByTestId("deps-view-graph").click();
  await canvas(page).waitFor({ timeout: 15000 });
});

test("a large graph opens as the tree with the reason, and the graph stays one click away", async ({ page }) => {
  await openScreen(page, "", { sbom: sbomWith(200) });
  await expect(tree(page)).toBeVisible();
  await expect(page.getByTestId("deps-auto-tree-note")).toContainText("201 packages");
  await page.getByTestId("deps-view-graph").click();
  await canvas(page).waitFor({ timeout: 15000 });
  await expect(page.getByTestId("deps-auto-tree-note")).toHaveCount(0);
});

test("a graph over the cap says so and points at the tree", async ({ page }) => {
  await openScreen(page, "", { sbom: sbomWith(1600) });
  await page.getByTestId("deps-view-graph").click();
  await expect(page.getByTestId("deps-too-large")).toContainText("The graph has 1,601 nodes (over 1,500); use the tree view instead.");
  await expect(canvas(page)).toHaveCount(0);
});

test("an SBOM without relationships says so in the graph and lists flat in the tree", async ({ page }) => {
  await openScreen(page, "", { sbom: FLAT_SBOM });
  await expect(page.getByTestId("deps-empty")).toContainText("No dependency relationships were recorded.");
  await page.getByTestId("deps-view-tree").click();
  await expect(page.getByTestId("deps-flat-note")).toHaveText("This SBOM has no dependency graph; showing a flat component list.");
  await expect(page.getByRole("treeitem")).toHaveCount(5);
  await expect(page.getByRole("treeitem", { name: "openssl 3.0.0" })).toHaveAttribute("aria-level", "1");
});

test("an SBOM with no packages says so in the tree", async ({ page }) => {
  await openScreen(page, "", { sbom: NO_COMPONENTS_SBOM });
  await page.getByTestId("deps-view-tree").click();
  await expect(page.getByTestId("deps-empty")).toContainText("No dependency relationships were recorded.");
});

test("a failed SBOM load shows the error and Retry loads it again", async ({ page }) => {
  const ctl = { fail: true };
  await openScreen(page, "", { ctl });
  const error = page.getByTestId("deps-error");
  await expect(error).toContainText("Could not load the SBOM for the dependency view.");
  ctl.fail = false;
  await error.getByRole("button", { name: "Retry" }).click();
  await canvas(page).waitFor({ timeout: 15000 });
  await expect(error).toHaveCount(0);
});

test("a slow SBOM load shows the loading state first", async ({ page }) => {
  await openScreen(page, "", { slow: true });
  await expect(page.getByTestId("deps-loading")).toContainText("Loading dependencies…");
  await canvas(page).waitFor({ timeout: 15000 });
});

test("a graph canvas that fails to load shows the error, and Retry draws it once the chunk loads", async ({ page }) => {
  const chunk = /cytoscape[^/]*\.js/;
  await page.route(chunk, (r) => r.abort());
  await openScreen(page);
  const error = page.getByTestId("deps-error");
  await expect(error).toContainText("The dependency graph could not be rendered.");
  await page.unroute(chunk);
  await error.getByRole("button", { name: "Retry" }).click();
  await canvas(page).waitFor({ timeout: 15000 });
  await expect(error).toHaveCount(0);
  // The view switch stays through the error, so the reader can also leave for the tree.
  await page.getByTestId("deps-view-tree").click();
  await expect(tree(page)).toBeVisible();
});

test("the selected view segment and the focus ring come from Primer variables", async ({ page }) => {
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  await page.mouse.move(0, 0);
  const graphBtn = page.getByTestId("deps-view-graph");
  const treeBtn = page.getByTestId("deps-view-tree");
  // Primer draws the selected segment with a heavier label (the fill sits on an
  // inner layer, so the button's own background is transparent in both states).
  const weight = (l: ReturnType<Page["getByTestId"]>) =>
    l.evaluate((el) => Number(getComputedStyle(el.firstElementChild ?? el).fontWeight));
  await expect.poll(async () => (await weight(graphBtn)) > (await weight(treeBtn))).toBe(true);
  const ring = await page.evaluate(() => {
    const probe = document.createElement("div");
    probe.style.color = "var(--focus-outlineColor)";
    document.body.appendChild(probe);
    const c = getComputedStyle(probe).color;
    probe.remove();
    return c;
  });
  // Tab onto the unselected segment: it takes the focus outline, and its fill
  // does not turn into the selected one.
  await page.getByRole("textbox", { name: "Search packages…" }).focus();
  await page.keyboard.press("Shift+Tab");
  await expect(treeBtn).toBeFocused();
  const focused = await treeBtn.evaluate((el) => {
    const cs = getComputedStyle(el);
    return { outline: cs.outlineColor, width: cs.outlineWidth, style: cs.outlineStyle };
  });
  expect(focused.outline).toBe(ring);
  expect(focused.style).not.toBe("none");
  expect(await weight(treeBtn)).toBeLessThan(await weight(graphBtn));
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`tree rows wrap and nothing is clipped at ${width}px (${lang})`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await openScreen(page, "", { lang, sbom: SBOM });
      await page.getByTestId("deps-view-tree").click();
      await expect(tree(page)).toBeVisible();
      const report = await page.evaluate(() => {
        const out: string[] = [];
        const root = document.querySelector('[role="tree"]');
        root?.querySelectorAll("*").forEach((el) => {
          const cs = getComputedStyle(el);
          if (cs.textOverflow === "ellipsis") out.push(`ellipsis on ${el.className}`);
          if (!/isually/i.test(String(el.className)) && el.scrollWidth > el.clientWidth + 1 && cs.overflowX === "hidden" && el.clientWidth > 0) out.push(`clipped ${el.className}`);
        });
        const docOver = document.documentElement.scrollWidth - window.innerWidth;
        if (docOver > 0) out.push(`page scrolls sideways by ${docOver}`);
        return out;
      });
      expect(report).toEqual([]);
    });
  }
}

test("nothing scrolls sideways at 390px in the tree or the graph", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openScreen(page);
  await canvas(page).waitFor({ timeout: 15000 });
  const over = () =>
    page.evaluate(() => {
      const main = document.querySelector("main");
      return Math.max(document.documentElement.scrollWidth - window.innerWidth, main ? main.scrollWidth - main.clientWidth : 0);
    });
  await expect.poll(over).toBeLessThanOrEqual(0);
  await page.getByTestId("deps-view-tree").click();
  await expect(tree(page)).toBeVisible();
  await expect.poll(over).toBeLessThanOrEqual(0);
});

for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    for (const view of ["graph", "tree"] as const) {
      test(`axe is clean: ${view} ${theme} ${lang}`, async ({ page }) => {
        await openScreen(page, "", { lang, theme });
        if (view === "graph") {
          await canvas(page).waitFor({ timeout: 15000 });
        } else {
          await page.getByTestId("deps-view-tree").click();
          await expect(tree(page)).toBeVisible();
        }
        await page.mouse.move(0, 0);
        await waitForSettled(page.locator("main"));
        const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
        expect(results.violations).toEqual([]);
      });
    }
  }
}
