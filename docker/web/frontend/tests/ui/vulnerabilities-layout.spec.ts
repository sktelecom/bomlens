// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

import { openVulns, rowOf, security, type Vuln } from "./vulnerabilities-helpers";

/**
 * What the table looks like, measured rather than eyeballed: row heights, the
 * second line of a row (whole items only, no dot left hanging), the sticky head,
 * no scrolling inside the table, the one package separator, a truncated list,
 * and a table of thousands of rows.
 */

const VULNS_FOR_BOX: Vuln[] = [
  { id: "CVE-1", severity: "HIGH", pkg: "a", installed: "1", fixed: "2", title: "t1" },
  { id: "CVE-2", severity: "HIGH", pkg: "a", installed: "1", fixed: "2", title: "t2" },
];

const LONG = "A very long vulnerability title that goes on and on to prove that the first line is cut with an ellipsis instead of pushing the layout around the page edge";

const STRESS: Vuln[] = [
  {
    id: "CVE-2024-9001",
    severity: "CRITICAL",
    pkg: "org.apache.tomcat.embed:tomcat-embed-core",
    installed: "10.1.31",
    fixed: "11.0.3, 10.1.35, 9.0.99",
    title: LONG,
    cvss: 10,
    kev: true,
    aliases: ["GHSA-83qj-6fr2-vhqg", "GHSA-aaaa-bbbb-cccc", "CVE-2020-99999", "OSV-2021-12345", "GHSA-dddd-eeee-ffff"],
  },
  { id: "CVE-2024-9002", severity: "HIGH", pkg: "org.springframework.boot:spring-boot-starter-actuator-autoconfigure-extra", installed: "3.1.0-SNAPSHOT-20240101", fixed: "3.1.1", title: "Long package name", cvss: 7.5, aliases: ["GHSA-1111-2222-3333"] },
  { id: "CVE-2024-9003", severity: "MEDIUM", pkg: "zlib", installed: "1.2.11", fixed: "", title: "", cvss: 5, aliases: ["GHSA-4444-5555-6666", "GHSA-7777-8888-9999"] },
  { id: "CVE-2024-9004", severity: "LOW", pkg: "left-pad", installed: "1.0.0", fixed: "1.0.1", title: "Short", cvss: 2 },
];

const lineMeasures = (page: Page) =>
  page.evaluate(() => {
    return [...document.querySelectorAll<HTMLElement>(".bl-v-line2")].map((line) => {
      const box = line.querySelector<HTMLElement>(".bl-v-aliases");
      let fragments = 0;
      let hiddenAliases = 0;
      if (box) {
        const br = box.getBoundingClientRect();
        for (const c of box.children) {
          const cr = c.getBoundingClientRect();
          if (cr.top >= br.bottom - 1) hiddenAliases += 1;
          else if (cr.right > br.right + 0.5 || cr.bottom > br.bottom + 1) fragments += 1;
        }
      }
      const id = line.querySelector<HTMLElement>(".bl-v-id");
      const lr = line.getBoundingClientRect();
      const idBox = id?.getBoundingClientRect();
      const idShown = id ? idBox!.width > 0 && idBox!.bottom <= lr.bottom + 1 && idBox!.right <= lr.right + 0.5 && id.scrollWidth <= id.clientWidth + 1 : true;
      const cut = [...line.querySelectorAll<HTMLElement>(".bl-coord span")].filter((e) => e.scrollWidth > e.clientWidth + 1).length;
      return { fragments, hiddenAliases, idShown, cut };
    });
  });

for (const width of [900, 1024, 1280, 1440]) {
  for (const lang of ["en", "ko"] as const) {
    test(`a row's CVE id is always shown, aliases are whole or left out, nothing is cut (${width}px, ${lang})`, async ({ page }) => {
      await page.addInitScript((l) => localStorage.setItem("sbom.lang", l), lang);
      await page.setViewportSize({ width, height: 900 });
      await openVulns(page, "", { security: security(STRESS) });
      await expect(page.getByRole("row").filter({ has: page.locator('[data-open-id="CVE-2024-9001"]') })).toBeVisible();
      const m = await lineMeasures(page);
      expect(m).toHaveLength(STRESS.length);
      for (const row of m) {
        expect(row.idShown, "the CVE id is never hidden or cut").toBe(true);
        expect(row.fragments, "no alias is drawn partly").toBe(0);
        expect(row.cut, "no part of the package is shortened").toBe(0);
      }
      // At the narrowest widths the five aliases cannot all fit: the ones that do not are left out whole.
      if (width <= 1024) expect(m[0].hiddenAliases).toBeGreaterThan(0);
    });
  }
}

test("at the narrowest column a long Maven coordinate and GHSA aliases still leave the CVE id", async ({ page }) => {
  await page.setViewportSize({ width: 900, height: 900 });
  const rows: Vuln[] = [
    {
      id: "CVE-2024-9100",
      severity: "HIGH",
      pkg: "org.apache.tomcat.embed.very.long.namespace.segment:tomcat-embed-core-with-a-long-artifact-name",
      installed: "10.1.31-SNAPSHOT-20240101",
      fixed: "10.1.35",
      title: "Narrowest column",
      aliases: ["GHSA-83qj-6fr2-vhqg", "GHSA-aaaa-bbbb-cccc"],
    },
  ];
  await openVulns(page, "", { security: security(rows) });
  const row = rowOf(page, "CVE-2024-9100");
  await expect(row.locator(".bl-v-id")).toBeVisible();
  const col = await row.locator(".bl-v-cell").evaluate((e) => e.getBoundingClientRect().width);
  expect(col).toBeGreaterThanOrEqual(355);
  const m = await lineMeasures(page);
  expect(m[0].idShown).toBe(true);
  expect(m[0].cut).toBe(0);
  const title = await row.locator(".bl-v-line2").getAttribute("title");
  expect(title).toContain("CVE-2024-9100");
  expect(title).toContain("GHSA-aaaa-bbbb-cccc");
});

test("the tooltip of the second line lists every id, including the ones left out", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await openVulns(page, "", { security: security(STRESS) });
  const line = rowOf(page, "CVE-2024-9001").locator(".bl-v-line2");
  const title = await line.getAttribute("title");
  for (const a of ["CVE-2024-9001", "GHSA-83qj-6fr2-vhqg", "GHSA-aaaa-bbbb-cccc", "CVE-2020-99999", "OSV-2021-12345", "GHSA-dddd-eeee-ffff"]) expect(title).toContain(a);
});

test("a row with no title shows its id once, as the first line", async ({ page }) => {
  await openVulns(page, "", { security: security(STRESS) });
  const row = rowOf(page, "CVE-2024-9003");
  await expect(row.locator(".bl-v-title")).toHaveText("CVE-2024-9003");
  await expect(row.locator(".bl-v-line2 .bl-v-id")).toHaveCount(0);
});

test("the package is written 'group / name', one separator style everywhere, and is wrapped rather than shortened at 1024px", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await openVulns(page, "", { security: security(STRESS) });
  const coord = rowOf(page, "CVE-2024-9001").locator(".bl-coord");
  await expect(coord).toHaveText("org.apache.tomcat.embed / tomcat-embed-core");
  await expect(coord).toHaveAttribute("title", "org.apache.tomcat.embed:tomcat-embed-core");
  // Every part of the coordinate is whole: no ellipsis, nothing clipped.
  for (const id of ["CVE-2024-9001", "CVE-2024-9002"]) {
    const clipped = await rowOf(page, id).locator(".bl-coord, .bl-coord span").evaluateAll((els) => els.filter((e) => getComputedStyle(e).textOverflow === "ellipsis" || e.scrollWidth > e.clientWidth + 1).length);
    expect(clipped).toBe(0);
  }
  await expect(page.locator("tbody .bl-v-line2").first()).not.toContainText("org.apache.tomcat.embed:tomcat");
  await expect(rowOf(page, "CVE-2024-9004").locator(".bl-coord")).toHaveText("left-pad");
});

test("a folded box's summary shows a keyboard focus ring", async ({ page }) => {
  await openVulns(page, "", { security: security(VULNS_FOR_BOX, { kernelCount: 3 }) });
  for (const sel of ['[data-testid="upgrade-bundles"] > summary', '[data-testid="kernel-advisories-notice"] > summary']) {
    const el = page.locator(sel);
    await el.focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab");
    await expect(el).toBeFocused();
    expect(await el.evaluate((e) => getComputedStyle(e).outlineStyle)).not.toBe("none");
    expect(await el.evaluate((e) => parseFloat(getComputedStyle(e).outlineWidth))).toBeGreaterThanOrEqual(2);
  }
});

test("a long unchecked list is capped and scrolls inside its box", async ({ page }) => {
  const many = Array.from({ length: 500 }, (_, i) => ({ name: `comp-${i}`, version: "1", reason: "no-identifier" }));
  await openVulns(page, "", { security: security([], { uncheckedCount: 500, uncheckedComponents: many }) });
  const box = page.getByTestId("unchecked-components");
  await box.getByText("Show the components").click();
  const scroller = box.locator(".bl-v-covscroll");
  const h = await scroller.evaluate((e) => e.getBoundingClientRect().height);
  expect(h).toBeLessThanOrEqual(321);
  expect(await scroller.evaluate((e) => e.scrollHeight > e.clientHeight)).toBe(true);
});

test("fixed versions are one per line, all shown, and the branch the installed version can reach is marked", async ({ page }) => {
  await openVulns(page, "", { security: security(STRESS) });
  const versions = rowOf(page, "CVE-2024-9001").locator(".bl-fixed > span");
  await expect(versions).toHaveCount(3);
  const tops = await versions.evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().top)));
  expect(new Set(tops).size, "each version on its own line").toBe(3);
  await expect(rowOf(page, "CVE-2024-9001").locator(".bl-fixed-mine")).toHaveText("10.1.35 (fixed version for the installed branch)");
  await expect(rowOf(page, "CVE-2024-9003").getByText("-", { exact: true })).toHaveCount(1);
});

test("the head sticks 56px from the top of the window, and nothing inside the table scrolls", async ({ page }) => {
  const many = Array.from({ length: 60 }, (_, i) => ({
    id: `CVE-2025-${1000 + i}`,
    severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
    pkg: `pkg-${i}`,
    installed: "1.0.0",
    fixed: "1.0.1",
    title: `Finding number ${i}`,
    cvss: 5,
  }));
  await page.setViewportSize({ width: 1280, height: 800 });
  await openVulns(page, "", { security: security(many) });
  await expect(rowOf(page, "CVE-2025-1030")).toBeAttached();
  await page.evaluate(() => window.scrollTo(0, 900));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(800);
  const top = await page.locator("main thead").evaluate((e) => e.getBoundingClientRect().top);
  expect(top).toBeGreaterThanOrEqual(55.5);
  expect(top).toBeLessThanOrEqual(56.5);
  const inner = await page.evaluate(() => {
    const scrollers: string[] = [];
    document.querySelectorAll(".bl-v-table, .bl-v-table *").forEach((e) => {
      const el = e as HTMLElement;
      const cs = getComputedStyle(el);
      if ((cs.overflowY === "auto" || cs.overflowY === "scroll") && el.scrollHeight > el.clientHeight + 1) scrollers.push(el.className);
    });
    return scrollers;
  });
  expect(inner, "no vertical scroll inside the table").toEqual([]);
});

test("no page-level horizontal scroll at 1024, 1280 and 1440", async ({ page }) => {
  for (const w of [1024, 1280, 1440]) {
    await page.setViewportSize({ width: w, height: 800 });
    await openVulns(page, "", { security: security(STRESS) });
    const [sw, cw] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    expect(sw, `${w}px`).toBeLessThanOrEqual(cw);
    await page.unrouteAll();
  }
});

test.describe("a list that was cut off", () => {
  test("says how many findings are listed of how many, once", async ({ page }) => {
    await openVulns(page, "", { security: { ...security(STRESS), TOTAL: 7686 } });
    const note = page.getByTestId("vuln-truncated");
    await expect(note).toBeVisible();
    await expect(note).toContainText("Not every finding is listed");
    await expect(note).toContainText("This list holds 4 of the 7,686 findings in the security report.");
  });

  test("is silent when every finding is listed", async ({ page }) => {
    await openVulns(page, "", { security: security(STRESS) });
    await expect(page.getByTestId("vuln-truncated")).toHaveCount(0);
  });

  test("is said in Korean too", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("sbom.lang", "ko"));
    await openVulns(page, "", { security: { ...security(STRESS), TOTAL: 7686 } });
    await expect(page.getByTestId("vuln-truncated")).toContainText("7,686건 중 4건만");
  });
});

test("a table of thousands of rows draws every row and stays usable", async ({ page }) => {
  test.setTimeout(120_000);
  const rows = Array.from({ length: 4000 }, (_, i) => ({
    id: `CVE-2025-${10000 + i}`,
    severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
    pkg: `lib${i % 400}`,
    installed: "1.0.0",
    fixed: i % 5 ? "1.0.1" : "",
    title: `Finding number ${i}`,
    cvss: (i % 100) / 10,
  }));
  const t0 = Date.now();
  await openVulns(page, "", { security: security(rows) });
  await expect(page.locator("main tbody tr")).toHaveCount(4000, { timeout: 60_000 });
  const drawn = Date.now() - t0;
  // Typing in the search narrows the table without rebuilding every row.
  const t1 = Date.now();
  await page.getByLabel("Search CVE, component, title").fill("lib7 ");
  await expect(page.locator("main tbody tr")).not.toHaveCount(4000);
  const searched = Date.now() - t1;
  // Opening a row's panel does not redraw the others.
  await page.getByLabel("Search CVE, component, title").fill("");
  await expect(page.locator("main tbody tr")).toHaveCount(4000);
  const t2 = Date.now();
  await page.locator('[data-open-id="CVE-2025-10500"]').click();
  await expect(page.getByRole("dialog")).toBeVisible();
  const opened = Date.now() - t2;
  console.log(`4000 rows: drawn ${drawn} ms, search ${searched} ms, panel ${opened} ms`);
  expect(drawn).toBeLessThan(45_000);
  expect(opened).toBeLessThan(10_000);
});
