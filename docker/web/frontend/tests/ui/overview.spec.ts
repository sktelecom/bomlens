// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { AI_DONE, DONE, FIRMWARE_DONE, SBOM } from "./fixtures";
import { waitForSettled } from "./settle";
import { seedThemeLang, type Lang, type Theme } from "./visual";

// The Overview screen: a title with what was scanned, banners about how far to
// trust the result, then two columns. Main: the AI summary, "Items to check
// first" with "Needs attention" in one box, the Yocto note, the comparison with
// the previous scan and the riskiest components. Side: the severity and license
// axes and the scan summary list. Every row keeps the filter of the section it
// opens.

const GENERATED_AT = 1700000000;

type Scan = Record<string, unknown> & { id: string };

interface Options {
  /** Other scans in the Recent list, and their results by id. */
  others?: Array<{ list: Record<string, unknown>; done: Scan }>;
  /** Hold the previous scan's detail back for this long (ms). */
  prevDelay?: number;
}

async function open(page: Page, done: Scan, opts: Options = {}, section = "", theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: false }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  const [project, version] = String(done.id).split("_");
  const list = [
    { id: done.id, project, version, components: 3, maxSeverity: "CRITICAL", isAiScan: false, generatedAt: GENERATED_AT },
    ...(opts.others ?? []).map((o) => o.list),
  ];
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(list) }));
  await page.route(`**/scan?id=${done.id}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }),
  );
  for (const o of opts.others ?? []) {
    await page.route(`**/scan?id=${o.done.id}`, async (r) => {
      if (opts.prevDelay) await new Promise((x) => setTimeout(x, opts.prevDelay));
      await r.fulfill({ contentType: "application/json", body: JSON.stringify(o.done) });
    });
  }
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }));
  await page.goto(`/#/scan/${done.id}${section}`);
  await page.locator("main h1").first().waitFor();
  await waitForSettled(page.locator("main"));
}

const sbomWith = (over: Record<string, unknown>) => ({ ...DONE.sbom, ...over });

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

test("the Overview is two columns on a wide window and one column on a narrow one", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, DONE);
  const first = await page.getByTestId("first-checks").boundingBox();
  const sev = await page.getByTestId("severity-panel").boundingBox();
  expect(sev!.x).toBeGreaterThan(first!.x + first!.width - 1);
  // Side column is the narrow one (about 340px), the main column the wide one.
  expect(sev!.width).toBeLessThan(first!.width);
  expect(sev!.width).toBeGreaterThan(300);
  expect(sev!.width).toBeLessThan(380);
  // Both columns start at the same height.
  expect(Math.abs(sev!.y - first!.y)).toBeLessThan(2);

  await page.setViewportSize({ width: 1024, height: 900 });
  const f2 = await page.getByTestId("first-checks").boundingBox();
  const s2 = await page.getByTestId("severity-panel").boundingBox();
  // One column: the side column's boxes come under the main column's.
  expect(s2!.y).toBeGreaterThan(f2!.y + f2!.height - 1);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("the title, the input source and the download button sit in the page header", async ({ page }) => {
  await open(page, {
    ...DONE,
    id: "demo_1.0",
    scanConfig: { source: "current-dir", sourceLabel: "/work/demo", project: "demo", version: "1.0" },
    sbom: sbomWith({ detection: "static", detectionSource: "package-lock.json" }),
  });
  await expect(page.locator("main h1")).toContainText("demo");
  const prov = page.getByTestId("provenance");
  await expect(prov).toContainText("/work/demo");
  await expect(page.getByTestId("detection")).toHaveText("Read from the lock file (package-lock.json), no build");
  // Both lines are part of the header, above the first box.
  const [h, box] = await Promise.all([prov.boundingBox(), page.getByTestId("first-checks").boundingBox()]);
  expect(h!.y).toBeLessThan(box!.y);
  const download = page.getByRole("link", { name: "Download all (ZIP)" });
  await expect(download).toHaveAttribute("href", /\/download-all\?id=demo_1\.0$/);
});

// ---------------------------------------------------------------------------
// First checks and needs attention (one box)
// ---------------------------------------------------------------------------

test("every needs-attention row keeps the filter of the section it opens", async ({ page }) => {
  // A High finding without a fix keeps the Critical-and-High row in the list.
  await open(page, {
    ...DONE,
    security: {
      ...DONE.security,
      vulnerabilities: DONE.security.vulnerabilities.map((v) => (v.severity === "HIGH" ? { ...v, fixed: "" } : v)),
    },
    sbom: sbomWith({ maliciousCount: 1, eolCount: 3, atRiskCount: 1, outdatedCount: 2 }),
  });
  const box = page.getByTestId("first-checks");
  const rows = box.getByTestId("needs-attention");
  await expect(rows.getByRole("link", { name: /known-malicious package/ })).toHaveAttribute("href", /#\/scan\/demo_1\.0\/components$/);
  await expect(rows.getByRole("link", { name: /critical or high vulnerabilities/ })).toHaveAttribute(
    "href",
    /#\/scan\/demo_1\.0\/vulnerabilities\?view=critical-high$/,
  );
  const eol = rows.getByRole("link", { name: /3 components past end of life/ });
  await expect(eol).toHaveAttribute("href", /#\/scan\/demo_1\.0\/components\?eol=1$/);
  await expect(eol).toContainText("1 also vulnerable");
  await expect(rows.getByRole("link", { name: "2 outdated components" })).toHaveAttribute(
    "href",
    /#\/scan\/demo_1\.0\/components\?outdated=1$/,
  );

  // Following the Critical and High row lands on that preset, not the whole list.
  await rows.getByRole("link", { name: /critical or high vulnerabilities/ }).click();
  await expect(page.locator("main h1")).toHaveText("Vulnerabilities");
  expect(page.url()).toContain("view=critical-high");
});

test("the first-checks box has the same plain border on every edge", async ({ page }) => {
  await open(page, { ...DONE, sbom: sbomWith({ outdatedCount: 1 }) });
  const box = page.getByTestId("first-checks");
  const edges = await box.evaluate((el) => {
    const cs = getComputedStyle(el);
    return ["Top", "Right", "Bottom", "Left"].map((e) => [cs.getPropertyValue(`border-${e.toLowerCase()}-width`), cs.getPropertyValue(`border-${e.toLowerCase()}-style`), cs.getPropertyValue(`border-${e.toLowerCase()}-color`)].join(" "));
  });
  // No thick or coloured edge on one side: all four borders are identical.
  expect(new Set(edges).size).toBe(1);
  expect(edges[0]).toMatch(/^1px solid /);
  // The "Needs attention" sub-heading is a real heading under the box title.
  await expect(box.getByRole("heading", { level: 3, name: "Needs attention" })).toBeVisible();
});

test("the box is left out when no row applies", async ({ page }) => {
  await open(page, {
    ...DONE,
    security: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, UNKNOWN: 0, TOTAL: 1, vulnerabilities: [{ id: "CVE-1", severity: "MEDIUM", pkg: "zlib", installed: "1", fixed: "", title: "t" }] },
  });
  await expect(page.getByTestId("first-checks")).toHaveCount(0);
  await expect(page.getByTestId("needs-attention")).toHaveCount(0);
});

test("with no first check the box is titled Needs attention", async ({ page }) => {
  await open(page, {
    ...DONE,
    security: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, UNKNOWN: 0, TOTAL: 1, vulnerabilities: [{ id: "CVE-1", severity: "MEDIUM", pkg: "zlib", installed: "1", fixed: "", title: "t" }] },
    sbom: sbomWith({ outdatedCount: 1 }),
  });
  const box = page.getByTestId("first-checks");
  await expect(box.getByRole("heading", { name: "Needs attention" })).toBeVisible();
  await expect(box.getByText("Items to check first")).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// Notices
// ---------------------------------------------------------------------------

test("one notice is one banner with its own text", async ({ page }) => {
  await open(page, { ...DONE, sbom: sbomWith({ versionPinning: "unpinned" }) });
  const banner = page.getByTestId("version-pinning");
  await expect(banner).toBeVisible();
  await expect(banner).toContainText("Versions were resolved at scan time");
  await expect(page.getByTestId("merged-info")).toHaveCount(0);
  await expect(page.getByTestId("merged-warning")).toHaveCount(0);
});

test("notices of one kind share one banner, with the full text of each under Details", async ({ page }) => {
  await open(page, {
    ...DONE,
    scanWarnings: ["[WARN] first warning", "[WARN] second warning"],
    sbom: sbomWith({
      pipelineStepsFailed: ["enrich-eol"],
      pipelineStepsFailedMore: 2,
      suggestIdentifyVendored: true,
      sbomToolDegraded: "oom",
      versionPinning: "unpinned",
    }),
    scanoss: { status: "no-match" },
  });
  const warn = page.getByTestId("merged-warning");
  await expect(warn).toBeVisible();
  // Folded by default: the title and the count, nothing else.
  await expect(warn).toContainText("4 notices");
  await expect(warn.getByRole("listitem")).toHaveCount(0);
  await warn.getByText("Details", { exact: true }).click();
  // One line per notice, named and explained in a short sentence.
  await expect(warn.locator("ul.bl-ov-bullets > li")).toHaveCount(4);
  await expect(warn).toContainText("Some enrichment data may be missing");
  await expect(warn).toContainText("Transitive dependencies were not resolved");
  // The full text of each is in the fold, hidden until it is opened.
  const pipeline = page.getByTestId("pipeline-steps-failed");
  await expect(pipeline).toBeVisible();
  await expect(pipeline).toContainText("end-of-life data enrichment");
  await expect(pipeline).toContainText("2 more");
  await expect(page.getByTestId("scan-warnings")).toContainText("first warning");
  await expect(page.getByTestId("scan-warnings")).not.toContainText("[WARN]");

  const info = page.getByTestId("merged-info");
  await expect(info).toBeVisible();
  await info.getByText("Details", { exact: true }).click();
  await expect(info).toContainText("Versions may differ from what you installed");
  await expect(info).toContainText("No open source copied into the source was found");
});

test("the firmware scope notice says how much of the image was not opened", async ({ page }) => {
  await open(page, FIRMWARE_DONE);
  const fw = page.getByTestId("firmware-scope");
  await expect(fw).toBeVisible();
  await expect(fw).toContainText("12%");
  await expect(fw).toContainText("3.0 MB");
});

test("a notice for a supplied SBOM asks the supplier, and the firmware note is not shown for it", async ({ page }) => {
  await open(page, {
    ...DONE,
    results: [...DONE.results, { name: "demo_1.0_input.json", size: 10 }],
    sbom: sbomWith({ pipelineStepsFailed: ["enrich-eol"], firmwareScope: FIRMWARE_DONE.sbom.firmwareScope }),
  });
  await expect(page.getByTestId("pipeline-steps-failed")).toContainText("Ask the supplier");
  await expect(page.getByTestId("firmware-scope")).toHaveCount(0);
});

test("a scan with no components warns, and a failed scan never shares a banner", async ({ page }) => {
  await open(page, {
    ...DONE,
    ok: false,
    errorMessage: "[ERROR] the scanner stopped",
    security: null,
    sbom: { components: 0, componentList: [], sbomToolDegraded: "network" },
    scanWarnings: ["[WARN] one"],
  });
  const failed = page.getByRole("alert");
  await expect(failed).toContainText("The scan didn't finish");
  await expect(failed).toContainText("[ERROR] the scanner stopped");
  // The failure is its own banner; the warnings gather below it.
  await expect(page.getByTestId("merged-warning")).toBeVisible();
  await expect(page.getByTestId("merged-warning")).not.toContainText("the scanner stopped");
  await page.getByTestId("merged-warning").getByText("Details", { exact: true }).click();
  await expect(page.getByTestId("zero-components")).toContainText("cdxgen");
});

test("a refused declaration file lists its reasons and offers the refused SBOM", async ({ page }) => {
  await open(page, {
    ...DONE,
    ok: false,
    security: null,
    declarationRefused: {
      file: "demo_1.0_bom.refused.json",
      reasons: ["sbom-declared.cdx.json: component foo has no version", "sbom-declared.cdx.json: duplicate bom-ref bar"],
    },
  });
  const card = page.getByTestId("declaration-refused");
  await expect(card).toBeVisible();
  await expect(card).toContainText("The declaration file was refused");
  await expect(card).toContainText("component foo has no version");
  await expect(card).toContainText("duplicate bom-ref bar");
  await expect(card).toContainText("Fix the declaration file");
  const view = card.getByRole("link", { name: /View the refused SBOM/ });
  await expect(view).toHaveAttribute("href", /file\?id=demo_1\.0&name=demo_1\.0_bom\.refused\.json|demo_1\.0_bom\.refused\.json/);
  await expect(view).toHaveAttribute("target", "_blank");
  const dl = card.getByRole("link", { name: "Download" });
  await expect(dl).toHaveAttribute("download", "demo_1.0_bom.refused.json");
  await expect(card.getByRole("button", { name: "Report a problem" })).toBeVisible();
});

// ---------------------------------------------------------------------------
// Comparison with the previous scan
// ---------------------------------------------------------------------------

const PREV: Scan = {
  ...DONE,
  id: "demo_0.9",
  security: {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, UNKNOWN: 0, TOTAL: 1,
    vulnerabilities: [{ id: "CVE-2024-0003", severity: "LOW", pkg: "curl", installed: "7.80.0", fixed: "7.81.0", title: "minor" }],
  },
  sbom: {
    components: 2,
    componentList: [
      { name: "zlib", version: "1.1.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"] },
      { name: "curl", version: "7.80.0", group: "", purl: "pkg:generic/curl@7.80.0", type: "library", licenses: ["MIT"] },
    ],
  },
};
const PREV_LIST = { id: "demo_0.9", project: "demo", version: "0.9", components: 2, maxSeverity: "LOW", isAiScan: false, generatedAt: 1000 };

test("the comparison names the previous scan, the severity trend and a loading state", async ({ page }) => {
  await open(page, DONE, { others: [{ list: PREV_LIST, done: PREV }], prevDelay: 1200 });
  const box = page.getByTestId("comparison");
  await expect(box.getByRole("heading", { name: "vs demo 0.9" })).toBeVisible();
  await expect(box).toContainText("+1 components");
  await expect(box).toContainText("Worst severity");
  await expect(box.getByText("Higher", { exact: true })).toBeVisible();
  // The specifics load in a second pass, and say so while they do.
  await expect(page.getByTestId("diff-loading")).toHaveText("Computing changes…");
  await expect(page.getByTestId("comp-change-summary")).toHaveText("2 new · 1 removed · 1 updated");
  await expect(page.getByTestId("diff-loading")).toHaveCount(0);
});

test("a resolved CVE opens in the previous scan, a new one in this scan", async ({ page }) => {
  await open(page, DONE, { others: [{ list: PREV_LIST, done: PREV }] });
  await page.getByTestId("vuln-change-summary").click();
  const details = page.getByTestId("vuln-change-details");
  await expect(details.getByRole("link", { name: /^CVE-2024-0001\s+openssl/ })).toHaveAttribute(
    "href",
    /#\/scan\/demo_1\.0\/vulnerabilities\?q=CVE-2024-0001$/,
  );
  const resolved = details.getByRole("link", { name: /^CVE-2024-0003\s+curl/ });
  await expect(resolved).toHaveAttribute("href", /#\/scan\/demo_0\.9\/vulnerabilities\?q=CVE-2024-0003$/);
  await expect(resolved).toContainText("Opens in demo 0.9");
});

test("a long change list stops at eight rows and says how many more", async ({ page }) => {
  const many = Array.from({ length: 12 }, (_, i) => ({
    name: `lib${String(i).padStart(2, "0")}`, version: "1.0", group: "", purl: `pkg:generic/lib${i}@1.0`, type: "library", licenses: ["MIT"],
  }));
  await open(page, { ...DONE, sbom: sbomWith({ components: 12, componentList: many }) }, { others: [{ list: PREV_LIST, done: PREV }] });
  await page.getByTestId("comp-change-summary").click();
  const details = page.getByTestId("comp-change-details");
  // Twelve added, capped at eight with the rest counted; each name filters Components.
  await expect(details.getByRole("link", { name: /^lib0\d\s+1\.0$/ })).toHaveCount(8);
  await expect(details).toContainText("4 more");
  await expect(details.getByRole("link", { name: /^lib00\s+1\.0$/ })).toHaveAttribute("href", /components\?q=lib00$/);
  await expect(page.getByTestId("comp-diff-all-link")).toHaveAttribute("href", /#\/scan\/demo_1\.0\/components$/);
});

test("a component list cut on the server says the comparison is partial", async ({ page }) => {
  await open(page, { ...DONE, sbom: sbomWith({ truncated: true }) }, { others: [{ list: PREV_LIST, done: PREV }] });
  await expect(page.getByTestId("comparison")).toContainText("Based on the components shown for each scan");
});

test("there is no comparison for a project scanned once", async ({ page }) => {
  await open(page, DONE);
  await expect(page.getByTestId("comparison")).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// Riskiest components and the two axes
// ---------------------------------------------------------------------------

test("the riskiest components link to their vulnerabilities", async ({ page }) => {
  await open(page, DONE);
  const box = page.getByTestId("top-risk");
  await expect(box).toContainText("1 of 1 with vulnerabilities");
  const row = box.getByRole("link", { name: /openssl/ });
  await expect(row).toHaveAttribute("href", /#\/scan\/demo_1\.0\/vulnerabilities\?q=openssl$/);
  await expect(row).toContainText("Critical");
  await expect(box.getByRole("link", { name: "All components" })).toHaveAttribute("href", /#\/scan\/demo_1\.0\/components$/);
});

test("the severity cells link to that severity and a cell with no findings is disabled", async ({ page }) => {
  await open(page, DONE);
  const panel = page.getByTestId("severity-panel");
  await expect(panel).toContainText("Click a severity to filter");
  // The bar only displays the split; it is not a control.
  const bar = panel.getByRole("img");
  await expect(bar).toHaveAttribute("aria-label", /Critical 1, High 1, Medium 0, Low 0, Unknown 0/);
  await expect(bar.getByRole("link")).toHaveCount(0);
  const high = panel.getByRole("link", { name: "High 1" });
  await expect(high).toHaveAttribute("href", /#\/scan\/demo_1\.0\/vulnerabilities\?severity=HIGH$/);
  // Shape marker plus the word: colour is never the only signal.
  await expect(high.locator("svg[data-marker]")).toHaveCount(1);
  await expect(panel.getByRole("link", { name: "Medium 0" })).toHaveCount(0);
  const none = panel.locator('[role="link"][aria-disabled="true"]');
  await expect(none).toHaveCount(3);
  await expect(none.first()).toContainText("Medium");
  await high.click();
  await expect(page.locator("main h1")).toHaveText("Vulnerabilities");
  expect(page.url()).toContain("severity=HIGH");
});

test("a scan with no findings says so instead of drawing a bar", async ({ page }) => {
  await open(page, {
    ...DONE,
    security: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 0, vulnerabilities: [], uncheckedCount: 4 },
  });
  const panel = page.getByTestId("severity-panel");
  await expect(panel).toContainText("4");
  await expect(panel.getByRole("img")).toHaveCount(0);
  await expect(panel.getByText("Click a severity to filter")).toHaveCount(0);
});

test("the license bar and its legend both open Licenses filtered to the class", async ({ page }) => {
  await open(page, DONE);
  const panel = page.getByTestId("license-panel");
  await expect(panel).toContainText("Click a class to filter");
  const seg = panel.getByRole("group").getByRole("link", { name: "Strong copyleft 1" });
  const chip = panel.getByRole("link", { name: /^Strong copyleft\s+1$/ }).last();
  for (const link of [seg, chip]) {
    await expect(link).toHaveAttribute("href", /#\/scan\/demo_1\.0\/licenses\?tier=strong-copyleft$/);
  }
  // The tooltip says what the class means, and that it is guidance.
  await expect(chip).toHaveAttribute("title", /not legal advice|guidance/i);
  await chip.click();
  await expect(page.locator("main h1")).toHaveText("Licenses");
  expect(page.url()).toContain("tier=strong-copyleft");
});

for (const theme of ["light", "dark"] as const) {
  test(`Tab focus on a license segment is drawn inside the bar (${theme})`, async ({ page }) => {
    await open(page, DONE, {}, "", theme);
    const seg = page.getByTestId("license-panel").getByRole("group").getByRole("link").first();
    await seg.focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab");
    await expect(seg).toBeFocused();
    const ring = await seg.evaluate((el) => {
      const cs = getComputedStyle(el);
      const bar = el.parentElement!.getBoundingClientRect();
      const r = el.getBoundingClientRect();
      return { width: cs.outlineWidth, style: cs.outlineStyle, offset: parseFloat(cs.outlineOffset), top: r.top - bar.top, bottom: bar.bottom - r.bottom };
    });
    // A visible ring pulled inward, so the bar's clipped edge cannot cut it off.
    expect(ring.style).toBe("solid");
    expect(parseFloat(ring.width)).toBeGreaterThanOrEqual(2);
    expect(ring.offset).toBeLessThan(0);
  });
}

test("the license bar keeps a 2px gap in the page colour between segments", async ({ page }) => {
  await open(page, DONE);
  const bar = page.getByTestId("license-panel").getByRole("group");
  const gap = await bar.evaluate((el) => {
    const cs = getComputedStyle(el);
    return { gap: cs.columnGap, bg: cs.backgroundColor };
  });
  expect(gap.gap).toBe("2px");
  const page_bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(gap.bg).toBe(page_bg);
});

for (const [theme, expected] of [["light", "rgb(136, 136, 144)"], ["dark", "rgb(118, 118, 126)"]] as const) {
  test(`the Permissive segment uses the report's colour (${theme})`, async ({ page }) => {
    await open(page, DONE, {}, "", theme);
    const seg = page.getByTestId("license-panel").getByRole("group").getByRole("link", { name: /^Permissive/ });
    const bg = await seg.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(bg).toBe(expected);
  });
}

// ---------------------------------------------------------------------------
// Scan summary: only what the navigation counts leave out
// ---------------------------------------------------------------------------

test("the scan summary box lists only what the navigation counts leave out", async ({ page }) => {
  await open(page, { ...DONE, security: { ...DONE.security, uncheckedCount: 7 }, sbom: sbomWith({ directCount: 2, transitiveCount: 1 }) });
  const box = page.getByTestId("sections");
  await expect(box.getByRole("heading", { name: "Scan summary" })).toBeVisible();
  // One row, with the read-out the Vulnerabilities count leaves out. The
  // visible text is the link's name; no figure is repeated from the navigation.
  const rows = box.getByRole("listitem");
  await expect(rows).toHaveCount(1);
  const link = rows.getByRole("link");
  await expect(link).toHaveAccessibleName(/Vulnerabilities\s+7 not checked/);
  await expect(link).toHaveAttribute("href", /#\/scan\/demo_1\.0\/vulnerabilities$/);
  await expect(box).not.toContainText("Components");
  await expect(box).not.toContainText("Artifacts");
  // The counts that are not repeated are in the navigation.
  await expect(page.getByTestId("nav-count-components")).toHaveText("3");
  await expect(page.getByTestId("nav-count-vulnerabilities")).toHaveText("2");
  await expect(page.getByTestId("nav-count-artifacts")).toHaveText("2");
  await expect(page.getByTestId("nav-count-dependencies")).toContainText("2/1");
  await link.click();
  await expect(page.locator("main h1")).toHaveText("Vulnerabilities");
});

test("the dependency row appears only when no relationships were recorded", async ({ page }) => {
  await open(page, { ...DONE, sbom: sbomWith({ directCount: 0, transitiveCount: 0 }) });
  await expect(page.getByTestId("sections").getByRole("link", { name: /Dependencies/ })).toContainText("no relationships recorded");
});

test("the scan summary box is left out when the counts say it all", async ({ page }) => {
  await open(page, { ...DONE, sbom: sbomWith({ directCount: 2, transitiveCount: 1 }) });
  await expect(page.getByTestId("sections")).toHaveCount(0);
});

test("Yocto adds its note", async ({ page }) => {
  await open(page, { ...FIRMWARE_DONE, yoctoVex: { fixed: 12255, notAffected: 63, unresolved: 2 } });
  const vex = page.getByTestId("yocto-vex");
  await expect(vex).toContainText("Already handled during the build");
  await expect(vex).toContainText("2 still need attention");
});

// ---------------------------------------------------------------------------
// AI scan
// ---------------------------------------------------------------------------

test("an AI scan leads with its summary", async ({ page }) => {
  await open(page, AI_DONE);
  const card = page.getByTestId("ai-summary");
  await expect(card).toBeVisible();
  await expect(card.getByRole("heading", { name: "AI model SBOM" })).toBeVisible();
  await expect(card.getByRole("link", { name: /^View model/ })).toHaveAttribute("href", /#\/scan\/model_1\.0\/models$/);
  await expect(card.getByRole("link", { name: /conformance/i })).toHaveAttribute("href", /#\/scan\/model_1\.0\/conformance$/);
  // The model count is in the navigation.
  await expect(page.getByTestId("nav-count-models")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Korean
// ---------------------------------------------------------------------------

test("in Korean the text is Korean and the severity words stay English", async ({ page }) => {
  await open(page, DONE, {}, "", "light", "ko");
  const sev = page.getByTestId("severity-panel");
  await expect(sev.getByRole("heading", { name: "심각도 분포" })).toBeVisible();
  await expect(sev).toContainText("Critical");
  await expect(page.getByTestId("first-checks")).toContainText("먼저 확인할 항목");
  await expect(page.getByRole("link", { name: "전체 다운로드 (ZIP)" })).toBeVisible();
});

// ---------------------------------------------------------------------------
// Accessibility
// ---------------------------------------------------------------------------

const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

for (const theme of ["light", "dark"] as const) {
  test(`the Overview has no accessibility violations: a full scan (${theme})`, async ({ page }) => {
    await open(
      page,
      {
        ...DONE,
        scanWarnings: ["[WARN] one"],
        sbom: sbomWith({ eolCount: 2, atRiskCount: 1, outdatedCount: 1, versionPinning: "unpinned", pipelineStepsFailed: ["enrich-eol"] }),
      },
      { others: [{ list: PREV_LIST, done: PREV }] },
      "",
      theme,
    );
    await expect(page.getByTestId("comp-change-summary")).toContainText("·");
    await page.getByTestId("comp-change-summary").click();
    await page.getByTestId("merged-warning").getByText("Details", { exact: true }).click();
    await waitForSettled(page.locator("main"));
    const axe = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
    expect(axe.violations).toEqual([]);
  });

  test(`the Overview has no accessibility violations: a failed scan and an AI scan (${theme})`, async ({ page }) => {
    await open(page, { ...DONE, ok: false, errorMessage: "[ERROR] stopped", security: null }, {}, "", theme);
    let axe = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
    expect(axe.violations).toEqual([]);
    await page.goto("about:blank");
    await open(page, AI_DONE, {}, "", theme);
    await expect(page.getByTestId("ai-summary")).toBeVisible();
    axe = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
    expect(axe.violations).toEqual([]);
  });
}
