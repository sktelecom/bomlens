// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The Conformance screen: a summary box, kind tabs with a search, boxes of folded
 * groups with one row per check, the regulatory crosswalk and the report
 * downloads. The backend is stubbed, so each control is checked against what it
 * writes to the URL and what the screen shows afterwards.
 */

const ID = "demo_1.0";

const CHECKS = [
  { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
  { id: "hash", label: "SHA-512 checksum coverage", labelKo: "SHA-512 체크섬 포함률", required: false, status: "warn", detail: "0% (0/39)", detailKo: "0% (0/39)",
    regulations: [{ framework: "BSI TR-03183-2", short: "BSI TR-03183-2", short_ko: "BSI TR-03183-2", ref: "Section 5.2.2" }] },
  { id: "cisa-producer", label: "Component producer", required: false, status: "warn", detail: "32/40 component(s)", cluster: "cisa-component", source: "auto",
    missing: ["flask", "click", "flask"], regulations: [{ framework: "CISA 2026", short: "CISA 2026", short_ko: "CISA 2026", ref: "Component Producer" }],
    guidance: { snippet: '{"publisher": "Example"}', docUrl: "https://example.test/guide" } },
  { id: "cisa-signature", label: "SBOM author signature", required: false, status: "warn", detail: "not present in the SBOM", cluster: "cisa-metadata", source: "na",
    reviewGuide: { how: "Verify the detached signature and record that you did.", howKo: "분리된 서명을 검증하고 기록합니다." } },
  { id: "cisa-timestamp", label: "SBOM timestamp", required: false, status: "pass", detail: "present", cluster: "cisa-metadata", source: "auto", evidence: ["2026-11-12T08:53:00Z"] },
  { id: "cisa-relationships", label: "Relationships", required: false, status: "warn", detail: "no parts to relate", cluster: "cisa-practices", source: "na", naKind: "not-applicable" },
  { id: "cisa-version", label: "Component version", required: false, status: "pass", detail: "39/40", cluster: "cisa-component", source: "auto",
    explained: [{ name: "own-lib", reason: "own-code" }] },
];

const CROSSWALK = {
  frameworks: [
    { id: "bsi", title: "BSI TR-03183-2", source: "Regulation (EU) 2024/2847", present: 11, gap: 2, failed: 0, review: 1, total: 14,
      elements: [{ label: "Component name", status: "pass", refs: ["5.2.2"] }, { label: "Hash value", status: "warn", refs: [] }] },
  ],
};

const RESULTS = [
  { name: "demo_1.0_conformance.html", size: 3000 },
  { name: "demo_1.0_conformance.md", size: 900 },
  { name: "demo_1.0_conformance.json", size: 800 },
];

const CONFORMANCE = {
  result: "pass",
  format: "CycloneDX",
  checks: CHECKS,
  regulatoryCrosswalk: CROSSWALK,
  pipelineStepsFailed: [],
  licenseCoverage: { declared: 39, total: 39, pct: 100 },
};

const done = (conformance: unknown, extra: Record<string, unknown> = {}) => ({
  ok: true,
  mode: "SOURCE",
  id: ID,
  results: RESULTS,
  security: null,
  conformance,
  sbom: { components: 1, componentList: [{ name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"] }] },
  ...extra,
});

async function stub(page: Page, body: unknown = done(CONFORMANCE)) {
  await page.route("**/capabilities", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }));
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${ID}`, (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(body) }));
}

async function openScreen(page: Page, lang: "en" | "ko" = "en", theme: "light" | "dark" = "light", query = "") {
  await page.addInitScript(
    ([l, th]) => {
      localStorage.setItem("sbom.lang", l);
      localStorage.setItem("i18nextLng", l);
      localStorage.setItem("sbom.theme", th);
    },
    [lang, theme],
  );
  await page.goto(`/?ui=next#/scan/${ID}/conformance${query}`);
  await page.getByTestId("result-meta").waitFor();
  await waitForSettled(page.locator("main"));
}

const hash = (page: Page) => new URL(page.url()).hash;
// The count is part of the name, so a tab is found by name and count.
const tab = (page: Page, name: string, count: number) => page.getByRole("button", { name: `${name} (${count})`, exact: true });

test("opens on what can be fixed, with the counts of all four kinds", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Conformance check");
  await expect(page.getByRole("heading", { level: 2, name: "CycloneDX" })).toBeVisible();
  await expect(page.getByText("Pass", { exact: true })).toBeVisible();
  await expect(page.getByText("No mandatory check failed")).toBeVisible();
  // A healthy license figure is not repeated in the summary.
  await expect(page.getByTestId("conformance-license-coverage")).toHaveCount(0);
  await expect(tab(page, "All", 7)).toHaveAttribute("aria-pressed", "false");
  await expect(tab(page, "Can be fixed", 2)).toHaveAttribute("aria-pressed", "true");
  for (const [name, count] of [["Needs a person", 1], ["Not applicable", 1], ["Met", 3]] as const) {
    await expect(tab(page, name, count)).toBeVisible();
  }
  await expect(page.getByText("Showing 2 of 7 checks.")).toBeVisible();
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance`);
});

test("a tab writes kind to the URL and All returns to the full list", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await tab(page, "Met", 3).click();
  await expect(tab(page, "Met", 3)).toHaveAttribute("aria-pressed", "true");
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance?kind=pass`);
  await expect(page.getByText("Showing 3 of 7 checks.")).toBeVisible();
  // Pressing the chosen tab again keeps it; All is the way back.
  await tab(page, "Met", 3).click();
  await expect(tab(page, "Met", 3)).toHaveAttribute("aria-pressed", "true");
  await tab(page, "All", 7).click();
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance?kind=all`);
  await expect(page.getByText("Showing all 7 checks.")).toBeVisible();
  // Back to the screen's own start leaves the URL bare.
  await tab(page, "Can be fixed", 2).click();
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance`);
});

test("a link with kind and q opens that view; a bad kind falls back to the start", async ({ page }) => {
  await stub(page);
  await openScreen(page, "en", "light", "?kind=pass&q=timestamp");
  await expect(tab(page, "Met", 3)).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("searchbox", { name: "Search requirements and references" })).toHaveValue("timestamp");
  await expect(page.getByText("Showing 2 of 7 checks.")).toBeVisible();
  await page.goto(`/?ui=next#/scan/${ID}/conformance?kind=bogus`);
  await page.reload();
  await page.getByTestId("result-meta").waitFor();
  await expect(tab(page, "Can be fixed", 2)).toHaveAttribute("aria-pressed", "true");
});

test("the search takes every word, in any field, and rides in the URL", async ({ page }) => {
  await stub(page);
  await openScreen(page, "en", "light", "?kind=all");
  const search = page.getByRole("searchbox", { name: "Search requirements and references" });
  await search.fill("bsi 5.2.2");
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance?kind=all&q=bsi+5.2.2`);
  await expect(page.getByText("Showing 1 of 7 checks.")).toBeVisible();
  await expect(page.getByText("SHA-512 checksum coverage")).toBeVisible();
  await search.fill("");
  await expect.poll(() => hash(page)).toBe(`#/scan/${ID}/conformance?kind=all`);
});

test("a search that a tab narrows says so and offers all kinds", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  await page.getByRole("searchbox", { name: "Search requirements and references" }).fill("timestamp");
  // The two timestamp checks are met, so under "Can be fixed" nothing matches.
  await expect(page.getByRole("heading", { level: 2, name: "No check matches this filter." })).toBeVisible();
  await expect(page.getByText("2 more match this search under another filter.")).toBeVisible();
  await page.getByRole("button", { name: "Search all kinds" }).click();
  await expect(page.getByText("Showing 2 of 7 checks.")).toBeVisible();
  await expect(page.getByText("SBOM timestamp", { exact: true })).toBeVisible();
});

test("a tab with no checks is disabled", async ({ page }) => {
  const checks = CHECKS.filter((c) => c.source !== "na");
  await stub(page, done({ ...CONFORMANCE, checks }));
  await openScreen(page);
  await expect(tab(page, "Needs a person", 0)).toBeDisabled();
  await expect(tab(page, "Not applicable", 0)).toBeDisabled();
});

test("a row shows its summary and the fix, and opens to its detail", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const row = page.locator('[data-check="cisa-producer"]');
  // Unfiltered groups open on what can be fixed; the fix sits under the name.
  await expect(row).toBeVisible();
  await expect(row).toContainText("Component producer");
  await expect(row).toContainText("32/40 components");
  await expect(row.getByText("Advisory", { exact: true })).toBeAttached();
  await expect(row.getByText("Missing from:")).toBeHidden();
  // The references stay on the folded row.
  await expect(row.getByText("CISA 2026 Component Producer")).toBeVisible();
  await row.locator("summary").first().click();
  await expect(row.getByText("CISA 2026 Component Producer")).toBeVisible();
  await expect(row.getByText("Missing from:")).toBeVisible();
  // A repeated name is one chip with a count.
  await expect(row.locator("code").filter({ hasText: "flask ×2" })).toBeVisible();
  await expect(row.locator("code").filter({ hasText: "click" })).toBeVisible();
  await expect(row.getByRole("link", { name: "Learn more" })).toHaveAttribute("href", "https://example.test/guide");
  const example = row.getByText("Show example");
  await expect(row.locator("pre")).toBeHidden();
  await example.click();
  await expect(row.locator("pre")).toContainText('"publisher": "Example"');
  await row.locator("summary").first().click();
  await expect(row.getByText("Missing from:")).toBeHidden();
});

test("the format box folds from its heading button and keeps the heading", async ({ page }) => {
  await stub(page);
  await openScreen(page, "en", "light", "?kind=all");
  const head = page.getByRole("heading", { level: 2, name: "Format conformance" });
  const toggle = head.getByRole("button");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator('[data-check="timestamp"]')).toBeVisible();
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(page.locator('[data-check="timestamp"]')).toBeHidden();
});

test("a row can be opened and closed from the keyboard", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const row = page.locator('[data-check="cisa-producer"]');
  await row.locator("summary").first().focus();
  await page.keyboard.press("Enter");
  await expect(row.getByText("Missing from:")).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(row.getByText("Missing from:")).toBeHidden();
});

test("met rows show what satisfied them and the supplier's explanation", async ({ page }) => {
  await stub(page);
  await openScreen(page, "en", "light", "?kind=pass");
  const stamp = page.locator('[data-check="cisa-timestamp"]');
  await stamp.locator("summary").click();
  await expect(stamp.getByText("Met with:")).toBeVisible();
  await expect(stamp.locator("code")).toHaveText("2026-11-12T08:53:00Z");
  const version = page.locator('[data-check="cisa-version"]');
  await version.locator("summary").click();
  await expect(version.getByText("Explained by the supplier:")).toBeVisible();
  await expect(version.locator("code")).toContainText("own-lib");
});

test("what a person has to establish shows in the row, in the page language", async ({ page }) => {
  await stub(page);
  await openScreen(page, "ko", "light", "?kind=review");
  const row = page.locator('[data-check="cisa-signature"]');
  await row.locator("summary").click();
  await expect(row.getByText("분리된 서명을 검증하고 기록합니다.")).toBeVisible();
});

test("the crosswalk is always shown, folds open to its requirements and carries the disclaimer", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const box = page.getByTestId("crosswalk");
  await expect(box).toBeVisible();
  await expect(box.getByRole("heading", { level: 2, name: "Regulatory crosswalk" })).toBeVisible();
  await expect(box.getByRole("table")).toBeVisible();
  await expect(box.getByRole("columnheader", { name: "Present" })).toBeVisible();
  await expect(box).toContainText("A documentation-preparation aid");
  await box.getByText("BSI TR-03183-2", { exact: true }).click();
  await expect(box.getByRole("listitem")).toHaveCount(2);
  await expect(box.getByText("Component name")).toBeVisible();
});

test("report buttons sit in the page header and download the readable files", async ({ page }) => {
  await stub(page);
  await openScreen(page);
  const html = page.getByRole("link", { name: "Report (HTML)" });
  await expect(html).toHaveAttribute("href", `/file?id=${ID}&name=demo_1.0_conformance.html`);
  await expect(html).toHaveAttribute("download", "demo_1.0_conformance.html");
  await expect(page.getByRole("link", { name: "Report (MD)" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Report \(JSON\)/ })).toHaveCount(0);
  await html.evaluate((a) => a.addEventListener("click", (e) => e.preventDefault()));
  await html.click();
  await expect(page.getByText("Download started")).toBeVisible();
  // They live with the title, above the summary.
  const head = await page.getByRole("heading", { level: 1 }).boundingBox();
  const btn = await html.boundingBox();
  expect(Math.abs((btn?.y ?? 0) - (head?.y ?? 0))).toBeLessThan(60);
});

test("no report files, no report buttons", async ({ page }) => {
  await stub(page, done(CONFORMANCE, { results: [] }));
  await openScreen(page);
  await expect(page.getByRole("link", { name: /^Report/ })).toHaveCount(0);
});

test("a failing report says so in the summary", async ({ page }) => {
  await stub(page, done({ ...CONFORMANCE, result: "fail", checks: [{ ...CHECKS[0], status: "fail", detail: "missing" }, ...CHECKS.slice(1)] }));
  await openScreen(page);
  await expect(page.getByText("Fail", { exact: true })).toBeVisible();
  await expect(page.getByText("1 mandatory check failed")).toBeVisible();
});

test("failed pipeline steps and a submission judged as firmware are named", async ({ page }) => {
  await stub(
    page,
    done({
      ...CONFORMANCE,
      pipelineStepsFailed: ["enrich-cpe", "some-future-step"],
      pipelineStepsFailedMore: 2,
      submissionJudgedAs: "FIRMWARE",
    }),
  );
  await openScreen(page);
  const note = page.getByTestId("conformance-pipeline-steps-failed");
  await expect(note).toContainText("CPE identifier enrichment");
  await expect(note).toContainText("some-future-step");
  await expect(note).toContainText("2 more");
  await expect(page.getByTestId("conformance-judged-as")).toContainText("bomlens:scanMode=FIRMWARE");
});

test("a pass with no license anywhere is downgraded and warned about", async ({ page }) => {
  await stub(page, done({ ...CONFORMANCE, licenseCoverage: { declared: 0, total: 5, pct: 0 } }));
  await openScreen(page);
  await expect(page.getByText("Pass, see the note below")).toBeVisible();
  await expect(page.getByTestId("conformance-no-licenses")).toContainText("No component declares a license");
});

// ---------------------------------------------------------------------------
// Layout and accessibility
// ---------------------------------------------------------------------------

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`the screen fits without clipping at ${width}px, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await stub(page);
      await openScreen(page, lang, "light", "?kind=all");
      await page.evaluate(() => document.querySelectorAll("main details").forEach((d) => ((d as HTMLDetailsElement).open = true)));
      const overflow = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        clipped: [...document.querySelectorAll("main li *, main h2, main .bl-cf-head *")].filter((e) => {
          const s = getComputedStyle(e);
          return s.textOverflow === "ellipsis" || (e.scrollWidth > e.clientWidth + 1 && s.overflow !== "visible" && e.clientWidth > 2 && !e.closest(".bl-cf-xscroll"));
        }).length,
      }));
      expect(overflow.page).toBeLessThanOrEqual(0);
      expect(overflow.clipped).toBe(0);
      // Labels in a row head (Required, source) stay inside the row.
      const spill = await page.evaluate(() =>
        [...document.querySelectorAll("main .bl-cf-rowhead")].filter((h) => {
          const r = h.getBoundingClientRect();
          return [...h.children].some((c) => c.getBoundingClientRect().right > r.right + 1);
        }).length,
      );
      expect(spill).toBe(0);
    });
  }
}

test("nothing scrolls sideways at 390px; the crosswalk scrolls in its own box", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await stub(page);
  await openScreen(page, "en", "light", "?kind=all");
  await page.evaluate(() => document.querySelectorAll("main details").forEach((d) => ((d as HTMLDetailsElement).open = true)));
  const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  const offenders = await page.evaluate(() =>
    [...document.querySelectorAll("body *")]
      .filter((e) => e.getBoundingClientRect().right > document.documentElement.clientWidth + 1 && !e.closest(".bl-cf-xscroll"))
      .slice(0, 8)
      .map((e) => `${e.tagName}.${e.getAttribute("class") ?? ""} ${Math.round(e.getBoundingClientRect().left)}-${Math.round(e.getBoundingClientRect().right)}`),
  );
  expect(offenders).toEqual([]);
  expect(wide).toBeLessThanOrEqual(0);
  const inner = await page.locator(".bl-cf-xscroll").evaluate((e) => e.scrollWidth > e.clientWidth);
  expect(inner).toBe(true);
});

test("from 1536px the summary is a column beside the checks", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 });
  await stub(page);
  await openScreen(page);
  const side = await page.locator(".bl-cf-side").boundingBox();
  const main = await page.locator(".bl-cf-main").boundingBox();
  expect(side!.x).toBeGreaterThan(main!.x + main!.width - 1);
  expect(Math.round(side!.width)).toBe(352);
});

for (const lang of ["en", "ko"] as const) {
  for (const theme of ["light", "dark"] as const) {
    test(`the screen clears axe with every row open, ${lang} ${theme}`, async ({ page }) => {
      await stub(page);
      await openScreen(page, lang, theme, "?kind=all");
      const run = () => new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect((await run()).violations).toEqual([]);
      await page.evaluate(() => document.querySelectorAll("main details").forEach((d) => ((d as HTMLDetailsElement).open = true)));
      await waitForSettled(page.locator("main"));
      expect((await run()).violations).toEqual([]);
    });
  }
}
