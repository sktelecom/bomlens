// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

import { AI_DONE, AI_SBOM, DONE as SOURCE_DONE, SBOM as SOURCE_SBOM } from "./fixtures";
import { waitForSettled } from "./settle";
import { COMBOS, seedThemeLang } from "./visual";

// Findings an adversarial pass turned up that the existing checks did not cover.
// The accessibility scan ran on one result screen in light mode only, so a badge
// under the AA contrast floor and a tree with no tree semantics both went
// unnoticed, and a canvas colour that never parsed could not be seen at all.

/** Recent-scan rows: one AI scan, which is the only kind drawn in brand colour. */
const SCANS = [
  { id: "modelx_1.0", project: "modelx", version: "1.0", components: 3, maxSeverity: "", isAiScan: true, generatedAt: 1700000000 },
  { id: "demo_1.0", project: "demo", version: "1.0", components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: 1700000001 },
];

const DONE = {
  ok: true,
  mode: "SOURCE",
  id: "demo_1.0",
  results: [{ name: "demo_1.0_bom.json", size: 2048 }],
  security: null,
  conformance: null,
  sbom: {
    components: 3,
    componentList: [
      { name: "flask", version: "3.0.0", group: "", purl: "pkg:pypi/flask", type: "library", licenses: ["BSD-3-Clause"], scope: "direct" },
      { name: "jinja2", version: "3.1.6", group: "", purl: "pkg:pypi/jinja2", type: "library", licenses: ["BSD-3-Clause"], scope: "transitive" },
      { name: "markupsafe", version: "3.0.3", group: "", purl: "pkg:pypi/markupsafe", type: "library", licenses: ["BSD-3-Clause"], scope: "transitive" },
    ],
  },
};

/** A BOM whose dependency graph gives the tree something to expand. */
const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  metadata: { component: { type: "application", name: "demo", version: "1.0", "bom-ref": "root" } },
  components: [
    { type: "library", name: "flask", version: "3.0.0", "bom-ref": "pkg:pypi/flask@3.0.0", purl: "pkg:pypi/flask@3.0.0", licenses: [{ license: { id: "BSD-3-Clause" } }] },
    { type: "library", name: "jinja2", version: "3.1.6", "bom-ref": "pkg:pypi/jinja2@3.1.6", purl: "pkg:pypi/jinja2@3.1.6", licenses: [{ license: { id: "BSD-3-Clause" } }] },
    { type: "library", name: "markupsafe", version: "3.0.3", "bom-ref": "pkg:pypi/markupsafe@3.0.3", purl: "pkg:pypi/markupsafe@3.0.3", licenses: [{ license: { id: "BSD-3-Clause" } }] },
  ],
  dependencies: [
    { ref: "root", dependsOn: ["pkg:pypi/flask@3.0.0"] },
    { ref: "pkg:pypi/flask@3.0.0", dependsOn: ["pkg:pypi/jinja2@3.1.6"] },
    { ref: "pkg:pypi/jinja2@3.1.6", dependsOn: ["pkg:pypi/markupsafe@3.0.3"] },
  ],
};

async function openDependencies(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan?id=demo_1.0", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.goto("/?ui=next#/scan/demo_1.0/dependencies");
  await page.getByRole("navigation").first().waitFor();
}

test("risk tokens stay in the channel form the graph converts", async ({ page }) => {
  // The graph reads --risk-* and hands them to a canvas renderer that needs a
  // real colour. They store RGB channels ("234 88 12") for Tailwind's
  // rgb(var(--x) / <alpha>) composition; code that assumed hex produced an
  // unparseable value and every severity ring fell back to black. Nothing in the
  // canvas is inspectable afterwards, so the contract is pinned here instead.
  await openDependencies(page);

  const shape = await page.evaluate(() => {
    const css = getComputedStyle(document.documentElement);
    return ["--risk-critical", "--risk-high", "--risk-medium", "--risk-low", "--risk-info"].map(
      (name) => {
        const raw = css.getPropertyValue(name).trim();
        return {
          name,
          channels: /^\d+\s+\d+\s+\d+$/.test(raw),
          valid: CSS.supports("color", `rgb(${raw.replace(/\s+/g, ", ")})`),
          // What the pre-fix code passed through: bare channels are not a colour.
          rawIsColour: CSS.supports("color", raw),
        };
      },
    );
  });

  for (const token of shape) {
    expect(token.channels, `${token.name} stores space-separated RGB channels`).toBe(true);
    expect(token.valid, `${token.name} wrapped in rgb() is a colour`).toBe(true);
    expect(token.rawIsColour, `${token.name} raw is NOT a colour on its own`).toBe(false);
  }
});

for (const theme of ["light", "dark"] as const) {
  test(`the recent-scan list clears the contrast floor — ${theme}`, async ({ page }) => {
    // The AI badge used the brand red that is also a solid fill, and a fill has
    // to stay dark for its white label. On the surface the badge composites to —
    // a 10% brand tint over the card — it scored 3.87 light and 3.57 dark.
    //
    // Nothing caught it because the accessibility check ran on one result screen
    // in light mode, and the list it did open had no rows: with no backend there
    // are no scans, so there was no badge to measure. The list has to be seeded
    // with an AI scan for the brand branch to render at all.
    await seedThemeLang(page, theme, "en");
    await page.route("**/capabilities", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
    );
    await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
    await page.route("**/scans", (r) =>
      r.fulfill({ contentType: "application/json", body: JSON.stringify(SCANS) }),
    );
    await page.goto("/?ui=next");
    await page.getByRole("banner").waitFor();
    await expect(page.locator("td").getByText("AI model", { exact: true })).toBeVisible();
    // The section fades in; measuring mid-animation folds opacity into the
    // contrast and gives a number that is neither the start nor the end state.
    await waitForSettled(page.locator("main"));

    const axe = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(axe.violations).toEqual([]);
  });
}

// Artifacts and Licenses were never scanned. Both carried text under the AA
// floor: the artifact cards' filename line and the download-all link (brand red
// as text, 4.4:1 light and 4.19:1 dark), and the count that sits ON a licence
// distribution bar, read against the fill rather than the page.
const ARTIFACT_DONE = {
  ...DONE,
  results: [
    { name: "demo_1.0_bom.json", size: 2048 },
    { name: "demo_1.0_risk-report.html", size: 7100 },
    { name: "demo_1.0_risk-report.md", size: 1900 },
    { name: "demo_1.0_NOTICE.txt", size: 1200 },
  ],
  sbom: {
    ...DONE.sbom,
    componentList: [
      ...DONE.sbom.componentList,
      { name: "mpl-thing", version: "1.0", group: "", purl: "pkg:pypi/mpl-thing", type: "library", licenses: ["MPL-2.0"], scope: "direct" },
      { name: "gpl-thing", version: "1.0", group: "", purl: "pkg:pypi/gpl-thing", type: "library", licenses: ["GPL-3.0-only"], scope: "direct" },
    ],
  },
};

for (const section of ["artifacts", "licenses"] as const) {
  for (const theme of ["light", "dark"] as const) {
    test(`the ${section} section clears the contrast floor, ${theme}`, async ({ page }) => {
      await seedThemeLang(page, theme, "en");
      await page.route("**/capabilities", (r) =>
        r.fulfill({
          contentType: "application/json",
          body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: false }),
        }),
      );
      await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
      await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
      await page.route("**/scan?id=demo_1.0", (r) =>
        r.fulfill({ contentType: "application/json", body: JSON.stringify(ARTIFACT_DONE) }),
      );
      await page.goto(`/?ui=next#/scan/demo_1.0/${section}`);
      await page.getByRole("navigation").first().waitFor();
      await waitForSettled(page.locator("main"));

      const axe = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(axe.violations).toEqual([]);
    });
  }
}

test("the dependency tree carries tree semantics and moves under the arrow keys", async ({ page }) => {
  // The graph view tells keyboard users to switch here, so this view has to be
  // navigable. It used to offer a row of identically-named Expand buttons, no
  // role, no level and no expanded state.
  await openDependencies(page);
  await page.getByTestId("deps-view-tree").click();

  const tree = page.getByRole("tree");
  await expect(tree).toBeVisible();

  const items = page.getByRole("treeitem");
  await expect(items.first()).toBeVisible();
  // Depth is exposed, not left to indentation.
  await expect(items.first()).toHaveAttribute("aria-level", "1");
  // A row with children says whether it is open; a leaf says nothing.
  await expect(items.first()).toHaveAttribute("aria-expanded", "true");

  // One tab stop for the whole tree, then the arrow keys move within it.
  await items.first().focus();
  await expect(items.first()).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(items.nth(1)).toBeFocused();
  await page.keyboard.press("ArrowUp");
  await expect(items.first()).toBeFocused();

  // Left collapses the open row, and the subtree goes with it.
  const before = await items.count();
  await page.keyboard.press("ArrowLeft");
  await expect(items.first()).toHaveAttribute("aria-expanded", "false");
  expect(await page.getByRole("treeitem").count()).toBeLessThan(before);

  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

for (const lang of ["en", "ko"] as const) {
  test(`<html lang> follows the UI language from the first render (${lang})`, async ({ page }) => {
    // A screen reader picks its voice from this attribute (WCAG 3.1.1); the
    // static default in index.html must never outlive the first render.
    await seedThemeLang(page, "light", lang);
    await openDependencies(page);
    await expect(page.locator("html")).toHaveAttribute("lang", lang);
  });
}

// ---------------------------------------------------------------------------
// Every rail section x theme x language. The checks above cover a handful of
// sections in one theme; a regression in any other section, in dark mode or in
// Korean, would pass CI unnoticed. Each section is rendered from the shared
// stub data so it draws real content, then scanned with the same WCAG tags.

/** A source scan that has a dependency graph, a source tree and a conformance report. */
const FULL_DONE = {
  ...SOURCE_DONE,
  conformance: {
    result: "pass",
    format: "CycloneDX",
    checks: [
      { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
      { id: "license", label: "License coverage (recommended)", required: false, status: "warn", detail: "33%" },
    ],
  },
  results: [
    ...SOURCE_DONE.results,
    { name: "demo_1.0_risk-report.html", size: 7100 },
    { name: "demo_1.0_NOTICE.txt", size: 1200 },
  ],
};

const SCANCODE = {
  files: [
    { path: "src", type: "directory" },
    { path: "src/main.c", type: "file", detected_license_expression_spdx: "Apache-2.0" },
    { path: "LICENSE", type: "file" },
  ],
};

type Kind = "source" | "ai";

const SECTIONS: Array<{ kind: Kind; section: string }> = [
  { kind: "source", section: "overview" },
  { kind: "source", section: "components" },
  { kind: "source", section: "dependencies" },
  { kind: "source", section: "sourceTree" },
  { kind: "source", section: "vulnerabilities" },
  { kind: "source", section: "licenses" },
  { kind: "source", section: "conformance" },
  { kind: "source", section: "artifacts" },
  { kind: "ai", section: "overview" },
  { kind: "ai", section: "models" },
  { kind: "ai", section: "conformance" },
];

/**
 * Combinations known to violate today, keyed `kind/section/theme/lang`, value =
 * the reason. They run under test.fail so CI documents the current state and
 * flips red the moment one is fixed (remove the entry then). Never widen this
 * list to silence a new regression.
 */
const KNOWN_VIOLATIONS: Record<string, string> = {
  "source/conformance/light/en": "color-contrast: success badge (text-success on bg-success-surface) in the light theme",
  "source/conformance/light/ko": "color-contrast: success badge (text-success on bg-success-surface) in the light theme",
  "ai/conformance/light/en": "color-contrast: info badge (text-risk-info-fg) inside dimmed (opacity-60) check cards, light theme",
  "ai/conformance/light/ko": "color-contrast: info badge (text-risk-info-fg) inside dimmed (opacity-60) check cards, light theme",
};

async function openSection(page: Page, kind: Kind, section: string) {
  const done = kind === "ai" ? AI_DONE : FULL_DONE;
  const sbom = kind === "ai" ? AI_SBOM : SOURCE_SBOM;
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: false }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${done.id}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  await page.route("**/file**", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify(r.request().url().includes("scancode") ? SCANCODE : sbom),
    }),
  );
  await page.goto(`/?ui=next#/scan/${done.id}/${section}`);
  await page.getByRole("navigation").first().waitFor();
  await page.locator("main h1").first().waitFor();
  await waitForSettled(page.locator("main"));
}

for (const { kind, section } of SECTIONS) {
  for (const { theme, lang } of COMBOS) {
    const key = `${kind}/${section}/${theme}/${lang}`;
    test(`axe: ${key}`, async ({ page }) => {
      if (KNOWN_VIOLATIONS[key]) test.fail(true, KNOWN_VIOLATIONS[key]);
      await seedThemeLang(page, theme, lang);
      await openSection(page, kind, section);
      // Guard against scanning an empty or fallback screen: the rail link for
      // this section must be the active one.
      // Overview has no section suffix in its route, so match it by exclusion.
      const active = page.locator('nav a[aria-current="page"]');
      await expect(active).toHaveCount(1);
      if (section !== "overview") await expect(active).toHaveAttribute("href", new RegExp(`/${section}$`));
      const axe = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(
        axe.violations.map((v) => `${v.id}: ${v.nodes.length} (${v.nodes[0]?.target.join(" ")})`),
      ).toEqual([]);
    });
  }
}

test("a skip link lets keyboard users bypass the rail", async ({ page }) => {
  // WCAG 2.4.1: the first Tab stop should jump past the repeated navigation to
  // the main content. There is no such link yet, so this is expected to fail.
  test.fail(true, "no skip-to-content link exists in the shell yet");
  await seedThemeLang(page, "light", "en");
  await openSection(page, "source", "overview");
  await page.keyboard.press("Tab");
  const first = page.locator(":focus");
  await expect(first).toHaveAttribute("href", /^#/);
  const target = await first.getAttribute("href");
  await expect(page.locator(target ?? "#main")).toHaveCount(1);
});
