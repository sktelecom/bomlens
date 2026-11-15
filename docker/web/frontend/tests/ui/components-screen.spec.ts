// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Locator, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The Components screen: every control, state and URL key the table has, the
 * layout promises (the name is never cut, the table is as wide as the page,
 * nothing scrolls inside it, the head sticks under the top bar) and axe.
 */

/** Like waitForSettled, but for the whole subtree: a menu's overlay fades in, and its rows with it. */
async function settleTree(locator: Locator) {
  await locator.evaluate(async (el) => {
    await Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => undefined)));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}

type Item = Record<string, unknown>;
const mk = (o: Item): Item => ({ name: "x", version: "1.0", group: "", purl: "", type: "library", licenses: ["MIT"], ...o });

const ITEMS: Item[] = [
  mk({ name: "openssl", version: "3.0.0", purl: "pkg:generic/openssl@3.0.0", licenses: ["Apache-2.0", "OpenSSL"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 3, source: "https://example.test/openssl", copyright: "Copyright OpenSSL authors" }),
  mk({ name: "zlib", version: "1.2.0", purl: "pkg:generic/zlib@1.2.0", licenses: ["Zlib"], scope: "transitive" }),
  mk({ name: "logback-classic", group: "ch.qos.logback", version: "1.5.11", purl: "pkg:maven/ch.qos.logback/logback-classic@1.5.11", licenses: ["EPL-1.0", "LGPL-2.1-only", "MIT"], scope: "transitive", maxSeverity: "MEDIUM", vulnCount: 6 }),
  mk({ name: "declared-own", group: "com.acme", version: "2.0", purl: "pkg:maven/com.acme/declared-own@2.0", declaredOrigin: "first-party", scope: "direct", type: "application" }),
  mk({ name: "declared-third", version: "1.0", purl: "pkg:npm/declared-third@1.0", declaredOrigin: "third-party", licenses: [] }),
  mk({ name: "vendored-lib", purl: "pkg:generic/vendored-lib@1.0", vendored: true, matchConfidence: "92%", licenses: ["GPL-2.0-only"] }),
  mk({ name: "evil-pkg", version: "1.0.0", purl: "pkg:npm/evil-pkg@1.0.0", malicious: true, maliciousId: "MAL-2026-1", maliciousSource: "osv.dev@2026-07-28" }),
  mk({ name: "libpresent.so", version: "", purl: "", presenceOnly: true, licenses: [] }),
  mk({ name: "eol-dated", purl: "pkg:npm/eol-dated@1.0", eol: "true", eolDate: "2025-06-30", scope: "transitive", maxSeverity: "HIGH", vulnCount: 12 }),
  mk({ name: "outdated-latest", purl: "pkg:npm/outdated-latest@1.0", outdated: "true", latestVersion: "3.4.5", releasesBehind: 4, lastReleased: "2026-03-01", scope: "direct" }),
  mk({ name: "unclear-license", purl: "pkg:npm/unclear-license@1.0", licenses: ["LicenseRef-weird"] }),
];

function scan(items: Item[], extra: Record<string, unknown> = {}, security = true) {
  return {
    ok: true,
    mode: "SOURCE",
    id: "comp_1.0",
    results: [{ name: "comp_1.0_bom.json", size: 100 }],
    security: security
      ? {
          CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 1,
          vulnerabilities: [{ id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", title: "overflow" }],
        }
      : null,
    conformance: null,
    sbom: { components: items.length, componentList: items, ...extra },
  };
}

async function open(
  page: Page,
  done: ReturnType<typeof scan>,
  o: { query?: string; lang?: "en" | "ko"; theme?: "light" | "dark"; width?: number; storage?: Record<string, string> } = {},
) {
  const { query = "", lang = "en", theme = "light", width, storage = {} } = o;
  if (width) await page.setViewportSize({ width, height: 900 });
  await page.addInitScript(
    ([l, t, extra]) => {
      localStorage.setItem("sbom.lang", l as string);
      localStorage.setItem("sbom.theme", t as string);
      for (const [k, v] of Object.entries(extra as Record<string, string>)) localStorage.setItem(k, v);
    },
    [lang, theme, storage] as const,
  );
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { id: "comp_1.0", project: "comp", version: "1.0", components: done.sbom.components, maxSeverity: null, isAiScan: false, componentType: "application", generatedAt: 1700000000 },
      ]),
    }),
  );
  await page.route("**/scan?id=comp_1.0", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }));
  await page.route("**/file**", (r) => r.fulfill({ status: 404, body: "nf" }));
  await page.goto(`/#/scan/comp_1.0/components${query}`);
  await page.locator("main h1").first().waitFor();
}

const table = (page: Page) => page.locator("main table");
/** Names of the rows in table order (the disclosure buttons carry them). */
const rowNames = (page: Page) =>
  table(page)
    .locator("tbody button[aria-expanded]")
    .evaluateAll((els) => els.map((e) => (e.getAttribute("aria-label") ?? "").split(": ").slice(1).join(": ")));
const hash = (page: Page) => page.evaluate(() => window.location.hash);

test.describe("controls", () => {
  test("search matches the name, the group, the version, the type and the license, and rides in the URL", async ({ page }) => {
    await open(page, scan(ITEMS));
    const search = page.getByRole("searchbox", { name: "Search components" });
    for (const [term, expected] of [
      ["openssl", ["openssl"]],
      ["ch.qos", ["ch.qos.logback/logback-classic"]],
      ["1.5.11", ["ch.qos.logback/logback-classic"]],
      ["application", ["com.acme/declared-own"]],
      ["zlib", ["zlib"]],
    ] as const) {
      await search.fill(term);
      expect(await rowNames(page)).toEqual(expected);
    }
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components?q=zlib");
    // Cleared by its chip.
    await page.getByRole("button", { name: 'Remove filter: "zlib"' }).click();
    await expect(search).toHaveValue("");
    expect((await rowNames(page)).length).toBe(ITEMS.length);
  });

  test("type and license menus show counts, filter, and clear from their chip or by choosing again", async ({ page }) => {
    await open(page, scan(ITEMS));
    await page.getByRole("button", { name: /^Type:/ }).click();
    await page.getByRole("menuitemradio", { name: "application 1" }).click();
    expect(await rowNames(page)).toEqual(["com.acme/declared-own"]);
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components?type=application");
    await expect(page.getByText("1 of 11 components")).toBeVisible();
    await page.getByRole("button", { name: "Remove filter: Type: application" }).click();
    expect((await rowNames(page)).length).toBe(ITEMS.length);

    await page.getByRole("button", { name: /^License:/ }).click();
    await page.getByRole("menuitemradio", { name: /^Zlib/ }).click();
    expect(await rowNames(page)).toEqual(["zlib"]);
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components?license=Zlib");
    await page.getByRole("button", { name: /^License:/ }).click();
    await page.getByRole("menuitemradio", { name: /^Zlib/ }).click();
    expect((await rowNames(page)).length).toBe(ITEMS.length);
  });

  test("the type menu needs two types; the license menu stays for a selected license", async ({ page }) => {
    const one = [mk({ name: "a" }), mk({ name: "b" })];
    await open(page, scan(one), { query: "?license=MIT" });
    await expect(page.getByRole("button", { name: /^Type:/ })).toHaveCount(0);
    // One license, but it is the selected one, so it stays clearable.
    await expect(page.getByRole("button", { name: /^License: MIT/ })).toBeVisible();
  });

  const FLAGS: [string, string, string][] = [
    ["Has vulnerabilities", "vulns", "zlib"],
    ["Direct only", "direct", "zlib"],
    ["Needs review", "review", "zlib"],
    ["End of life", "eol", "zlib"],
    ["Outdated", "outdated", "zlib"],
    ["License to decide", "licensecheck", "zlib"],
  ];
  for (const [label, key, absent] of FLAGS) {
    test(`filter "${label}" sets ?${key}=1, narrows, shows its chip and clears`, async ({ page }) => {
      await open(page, scan(ITEMS));
      await page.getByRole("button", { name: /^Filters/ }).click();
      await page.getByRole("menuitemcheckbox", { name: label }).click();
      await page.keyboard.press("Escape");
      await expect.poll(() => hash(page)).toBe(`#/scan/comp_1.0/components?${key}=1`);
      expect(await rowNames(page)).not.toContain(absent);
      await expect(page.getByRole("button", { name: `Remove filter: ${label}` })).toBeVisible();
      await expect(page.getByRole("button", { name: /^Filters/ })).toContainText("1");
      await page.getByRole("button", { name: "Clear filters" }).click();
      expect((await rowNames(page)).length).toBe(ITEMS.length);
      await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components");
    });
  }

  test("the Filters menu stays open while several filters are changed, and Escape closes it", async ({ page }) => {
    await open(page, scan(ITEMS));
    await page.getByRole("button", { name: /^Filters/ }).click();
    await page.getByRole("menuitemcheckbox", { name: "Has vulnerabilities" }).click();
    await page.getByRole("menuitemcheckbox", { name: "Direct only" }).click();
    await expect(page.getByRole("menuitemcheckbox", { name: "Direct only" })).toHaveAttribute("aria-checked", "true");
    expect(await rowNames(page)).toEqual(["openssl"]);
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components?direct=1&vulns=1");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Filters/ })).toBeFocused();
  });

  test("the Filters menu and the Scope and Risk columns are offered only when the scan has data for them", async ({ page }) => {
    const plain = [mk({ name: "a" }), mk({ name: "b" })];
    await open(page, scan(plain, {}, false));
    await expect(page.getByRole("button", { name: /^Filters/ })).toHaveCount(0);
    await expect(table(page).getByRole("button", { name: "Scope", exact: true })).toHaveCount(0);
    await expect(table(page).getByRole("button", { name: "Risk", exact: true })).toHaveCount(0);
  });

  test("a link with several filters and a sort restores all of them", async ({ page }) => {
    await open(page, scan(ITEMS), { query: "?vulns=1&direct=1&sort=risk&dir=desc&q=o" });
    await expect(page.getByRole("searchbox", { name: "Search components" })).toHaveValue("o");
    await expect(page.getByRole("button", { name: /^Filters/ })).toContainText("2");
    expect(await rowNames(page)).toEqual(["openssl"]);
    await expect(table(page).getByRole("columnheader", { name: "Risk" })).toHaveAttribute("aria-sort", "descending");
  });

  test("sorting: no sort by default, a new column ascends, again descends, and the Risk and Scope rules hold", async ({ page }) => {
    await open(page, scan(ITEMS));
    const heads = table(page).getByRole("columnheader");
    const nameHead = heads.filter({ hasText: "Name" });
    await expect(nameHead).toHaveAttribute("aria-sort", "none");
    expect((await rowNames(page))[0]).toBe("openssl");

    await table(page).getByRole("button", { name: "Name", exact: true }).click();
    await expect(nameHead).toHaveAttribute("aria-sort", "ascending");
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/components?dir=asc&sort=name");
    expect((await rowNames(page))[0]).toBe("ch.qos.logback/logback-classic");
    await table(page).getByRole("button", { name: "Name", exact: true }).click();
    await expect(nameHead).toHaveAttribute("aria-sort", "descending");
    expect((await rowNames(page))[0]).toBe("zlib");

    // Risk, worst first (a new column ascends, so two clicks): severity, then the count.
    await table(page).getByRole("button", { name: "Risk", exact: true }).click();
    await table(page).getByRole("button", { name: "Risk", exact: true }).click();
    expect((await rowNames(page)).slice(0, 3)).toEqual(["openssl", "eol-dated", "ch.qos.logback/logback-classic"]);

    // Scope, direct first: direct, then transitive, then none.
    await table(page).getByRole("button", { name: "Scope", exact: true }).click();
    await table(page).getByRole("button", { name: "Scope", exact: true }).click();
    const byScope = await rowNames(page);
    expect(byScope.slice(0, 3).sort()).toEqual(["com.acme/declared-own", "openssl", "outdated-latest"]);
  });

  test("the View menu sets the row height and hides columns, and both are remembered", async ({ page }) => {
    await open(page, scan(ITEMS));
    const rowHeight = () => table(page).locator("tbody tr").first().evaluate((e) => e.getBoundingClientRect().height);
    await page.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.getByRole("menuitemradio", { name: "Comfortable" })).toHaveAttribute("aria-checked", "true");
    await page.keyboard.press("Escape");
    const comfortable = await rowHeight();

    await page.getByRole("button", { name: "View", exact: true }).click();
    await page.getByRole("menuitemradio", { name: "Compact" }).click();
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => localStorage.getItem("sbom.table.density"))).toBe("compact");
    expect(await rowHeight()).toBeLessThan(comfortable);

    await page.getByRole("button", { name: "View", exact: true }).click();
    await page.getByRole("menuitemcheckbox", { name: "Version" }).click();
    await page.keyboard.press("Escape");
    await expect(table(page).getByRole("columnheader", { name: "Version" })).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem("sbom.components.hiddenColumns"))).toContain("version");

    await page.reload();
    await page.locator("main h1").first().waitFor();
    await expect(table(page).getByRole("columnheader", { name: "Version" })).toHaveCount(0);
    await page.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.getByRole("menuitemradio", { name: "Compact" })).toHaveAttribute("aria-checked", "true");
    await expect(page.getByRole("menuitemcheckbox", { name: "Version" })).toHaveAttribute("aria-checked", "false");
    await page.getByRole("menuitemcheckbox", { name: "Version" }).click();
    await page.keyboard.press("Escape");
    await expect(table(page).getByRole("columnheader", { name: "Version" })).toBeVisible();
  });

  test("the Type column starts hidden when every row has one type, and a stored choice wins", async ({ page }) => {
    const oneType = ITEMS.map((c) => ({ ...c, type: "library" }));
    await open(page, scan(oneType));
    await expect(table(page).getByRole("columnheader", { name: "Type" })).toHaveCount(0);
    await page.getByRole("button", { name: "View", exact: true }).click();
    await expect(page.getByRole("menuitemcheckbox", { name: "Type" })).toHaveAttribute("aria-checked", "false");
  });

  test("a single-type scan hides Type at render time and stores only what the reader chose", async ({ page }) => {
    const oneType = ITEMS.map((c) => ({ ...c, type: "library" }));
    await open(page, scan(oneType));
    await expect(table(page).getByRole("columnheader", { name: "Type" })).toHaveCount(0);
    // Nothing is stored for the automatic hiding.
    expect(await page.evaluate(() => localStorage.getItem("sbom.components.hiddenColumns"))).toBeNull();
    // Hiding Version stores Version only, not the automatic Type.
    await page.getByRole("button", { name: "View", exact: true }).click();
    await page.getByRole("menuitemcheckbox", { name: "Version" }).click();
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => localStorage.getItem("sbom.components.hiddenColumns"))).toBe('["version"]');
    await page.reload();
    await page.locator("main h1").first().waitFor();
    await expect(table(page).getByRole("columnheader", { name: "Type" })).toHaveCount(0);
    // Showing Type is the reader's choice and is remembered.
    await page.getByRole("button", { name: "View", exact: true }).click();
    await page.getByRole("menuitemcheckbox", { name: "Type" }).click();
    await page.keyboard.press("Escape");
    await expect(table(page).getByRole("columnheader", { name: "Type" })).toBeVisible();
    await page.reload();
    await page.locator("main h1").first().waitFor();
    await expect(table(page).getByRole("columnheader", { name: "Type" })).toBeVisible();
  });

  test("storage that cannot be read does not break the screen", async ({ page }) => {
    await page.addInitScript(() => {
      const original = Storage.prototype.getItem;
      Storage.prototype.getItem = function (key: string) {
        if (key.startsWith("sbom.components")) throw new Error("blocked");
        return original.call(this, key);
      };
    });
    await open(page, scan(ITEMS.map((c) => ({ ...c, type: "library" }))));
    await expect(table(page)).toBeVisible();
  });

  test("the license shown is the most concerning one and the rest are named by the +N", async ({ page }) => {
    await open(page, scan([mk({ name: "mixed", licenses: ["MIT", "GPL-3.0-only", "Apache-2.0"] })]));
    const row = table(page).locator("tbody tr").first();
    await expect(row.getByText("GPL-3.0-only", { exact: true })).toBeVisible();
    await expect(row.getByText("MIT", { exact: true })).toHaveCount(0);
    await expect(row.getByRole("img", { name: "MIT, GPL-3.0-only, Apache-2.0" })).toHaveText("+2 more");
  });

  test("an open row is one band: every cell carries the open background", async ({ page }) => {
    await open(page, scan(ITEMS));
    await table(page).getByRole("button", { name: "Show component details: openssl" }).click();
    const bgs = await table(page).locator("tbody tr[data-open='true'] > *").evaluateAll((els) => els.map((e) => getComputedStyle(e).backgroundColor));
    expect(bgs.length).toBeGreaterThan(3);
    expect(new Set(bgs).size).toBe(1);
  });

  test("the export carries the filter and the sort, in the order shown", async ({ page }) => {
    await open(page, scan(ITEMS), { query: "?sort=name&dir=desc&vulns=1" });
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Export CSV" }).click()]);
    const chunks: Buffer[] = [];
    for await (const c of await download.createReadStream()) chunks.push(c as Buffer);
    const lines = Buffer.concat(chunks).toString("utf8").replace(/^﻿/, "").split("\r\n");
    expect(lines[0]).toBe("Name,Version,Type,Licenses,Scope,Vulnerabilities,Max severity,Package URL");
    expect(lines.slice(1).map((l) => l.split(",")[0])).toEqual(["openssl", "eol-dated", "logback-classic"]);
    expect(download.suggestedFilename()).toMatch(/^comp_1\.0-components-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  test("nothing matching is said in words, the export is off and the count reads 0", async ({ page }) => {
    await open(page, scan(ITEMS), { query: "?q=zzzz" });
    await expect(page.getByRole("button", { name: "Export CSV" })).toBeDisabled();
    await expect(page.getByRole("heading", { name: "No matching rows." })).toBeVisible();
    await expect(page.getByText("0 of 11 components")).toBeVisible();
  });
});

test.describe("rows", () => {
  test("labels for declared, vendored, malicious, no-version, end of life and outdated components", async ({ page }) => {
    await open(page, scan(ITEMS));
    const declared = page.getByTestId("declared-origin");
    await expect(declared).toHaveCount(2);
    await expect(declared.nth(0)).toHaveText("first-party");
    await expect(declared.nth(1)).toHaveText("third-party");
    await expect(page.getByText("vendored", { exact: true })).toHaveAttribute("title", /match 92%/);
    await expect(page.getByText("Malicious package")).toHaveAttribute("title", /MAL-2026-1, osv\.dev@2026-07-28/);
    await expect(page.getByText("no version")).toHaveAttribute("title", /ELF structure/);
    await expect(page.getByText("End of life since 2025-06-30")).toBeVisible();
    await expect(page.getByText("Outdated · latest: 3.4.5")).toBeVisible();
    await expect(page.getByText("No license declared").first()).toBeVisible();
    // Three licenses: the first one and "+2 more", with all of them in the tooltip.
    await expect(page.getByText("+2 more")).toHaveAttribute("title", "EPL-1.0, LGPL-2.1-only, MIT");
    await expect(page.getByText("+2 more")).toHaveAttribute("aria-label", "EPL-1.0, LGPL-2.1-only, MIT");
  });

  test("with the End of life filter on, the second line leaves out the words the filter already says", async ({ page }) => {
    await open(page, scan(ITEMS), { query: "?eol=1" });
    await expect(page.getByText("since 2025-06-30", { exact: true })).toBeVisible();
    await expect(page.getByText("End of life since 2025-06-30")).toHaveCount(0);
  });

  test("a row opens from the keyboard, one at a time, and the detail holds everything the old row did", async ({ page }) => {
    await open(page, scan(ITEMS));
    const first = table(page).getByRole("button", { name: "Show component details: openssl" });
    await first.focus();
    await expect(first).toHaveAttribute("aria-expanded", "false");
    await page.keyboard.press("Enter");
    await expect(first).toHaveAttribute("aria-expanded", "true");
    const detail = table(page).locator("tr[id^='cd-']");
    await expect(detail).toHaveCount(1);
    await expect(detail).toContainText("pkg:generic/openssl@3.0.0");
    await expect(detail.getByRole("link", { name: "https://example.test/openssl" })).toHaveAttribute("target", "_blank");
    await expect(detail).toContainText("Copyright OpenSSL authors");
    await expect(detail).toContainText("Apache-2.0, OpenSSL");
    await expect(detail).toContainText("Critical");
    await expect(detail.getByRole("link", { name: "View vulnerabilities for openssl" })).toBeVisible();
    await expect(detail.getByRole("link", { name: "View openssl in Dependencies" })).toBeVisible();

    // Opening another closes this one; Space also toggles.
    const second = table(page).getByRole("button", { name: "Show component details: zlib" });
    await second.focus();
    await page.keyboard.press(" ");
    await expect(second).toHaveAttribute("aria-expanded", "true");
    await expect(first).toHaveAttribute("aria-expanded", "false");
    await expect(detail).toHaveCount(1);
    await page.keyboard.press("Enter");
    await expect(detail).toHaveCount(0);

    // A click anywhere on the row opens it too.
    await table(page).locator("tbody tr").filter({ hasText: "1.2.0" }).first().locator("td").first().click();
    await expect(detail).toHaveCount(1);
  });

  test("the detail of an end-of-life or outdated row names the support state and the currency", async ({ page }) => {
    await open(page, scan(ITEMS));
    await table(page).getByRole("button", { name: "Show component details: eol-dated" }).click();
    const detail = table(page).locator("tr[id^='cd-']");
    await expect(detail).toContainText("Support");
    await expect(detail).toContainText("End of life (2025-06-30)");
    await table(page).getByRole("button", { name: "Show component details: outdated-latest" }).click();
    await expect(detail).toContainText("Version currency");
    await expect(detail).toContainText("latest: 3.4.5 · 4 releases behind · released 2026-03-01");
  });

  test("the vulnerabilities link goes through the shell, filtered to the name", async ({ page }) => {
    await open(page, scan(ITEMS));
    await table(page).getByRole("button", { name: "Show component details: openssl" }).click();
    await page.getByRole("link", { name: "View vulnerabilities for openssl" }).click();
    await expect.poll(() => hash(page)).toBe("#/scan/comp_1.0/vulnerabilities?q=openssl");
  });

  test("with no security result there is no vulnerabilities link; the dependencies link stays", async ({ page }) => {
    const items = ITEMS.map((c) => {
      const copy = { ...c };
      delete copy.maxSeverity;
      delete copy.vulnCount;
      return copy;
    });
    await open(page, scan(items, {}, false));
    await table(page).getByRole("button", { name: "Show component details: openssl" }).click();
    await expect(page.getByRole("link", { name: /View vulnerabilities for/ })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "View openssl in Dependencies" })).toBeVisible();
  });
});

test.describe("states", () => {
  test("zero components is an empty state, not a table", async ({ page }) => {
    await open(page, scan([]));
    const empty = page.getByTestId("components-empty");
    await expect(empty.getByRole("heading", { name: "No components were detected." })).toBeVisible();
    await expect(empty).toContainText("The scan finished without identifying a single component.");
    await expect(table(page)).toHaveCount(0);
    expect((await new AxeBuilder({ page }).include("main").analyze()).violations).toEqual([]);
  });

  test("a truncated list says how many rows are shown", async ({ page }) => {
    await open(page, scan(ITEMS, { truncated: true, components: 5000 }));
    await expect(page.getByText("11 of 5,000 components · first 11 rows shown")).toBeVisible();
  });
});

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440]) {
    test(`layout at ${width}px (${lang}): names whole, table as wide as the page, nothing scrolls inside, head sticks at 56px`, async ({ page }) => {
      const many = Array.from({ length: 80 }, (_, i) =>
        mk({
          name: i % 7 === 0 ? `a-very-long-artifact-name-that-keeps-going-for-a-while-${i}` : `pkg-${i}`,
          group: i % 3 === 0 ? "org.example.some.rather.long.group.identifier" : "",
          version: i % 5 === 0 ? "1.2.3-SNAPSHOT-build.20260101.123456" : "1.0",
          purl: `pkg:maven/x/pkg-${i}@1.0`,
          type: i % 2 ? "library" : "framework",
          licenses: i % 4 === 0 ? ["Apache-2.0", "MIT", "BSD-3-Clause"] : ["MIT"],
          scope: i % 2 ? "direct" : "transitive",
          maxSeverity: i % 6 === 0 ? "HIGH" : undefined,
          vulnCount: i % 6 === 0 ? 12 : undefined,
          eol: i % 9 === 0 ? "true" : undefined,
          eolDate: i % 9 === 0 ? "2025-06-30" : undefined,
        }),
      );
      await open(page, scan(many), { lang, width });
      await expect(table(page)).toBeVisible();
      await waitForSettled(page.locator("main"));

      const m = await page.evaluate(() => {
        const box = document.querySelector<HTMLElement>(".bl-comp-scroll")!;
        const bar = document.querySelector<HTMLElement>(".bl-filterbar")!;
        // The name is wrapped text inside the disclosure button, inside the row header cell: neither may
        // overflow, and no element on the way is set to cut with an ellipsis.
        const names = [...document.querySelectorAll<HTMLElement>(".bl-comp-name")];
        const cut = names.filter((n) => {
          const btn = n.closest<HTMLElement>(".bl-comp-disclose")!;
          const cell = n.closest<HTMLElement>("th")!;
          let ellipsis = false;
          for (let e: HTMLElement | null = n; e && e !== cell.parentElement; e = e.parentElement) {
            if (getComputedStyle(e).textOverflow === "ellipsis") ellipsis = true;
          }
          return ellipsis || btn.scrollWidth > btn.clientWidth + 1 || cell.scrollWidth > cell.clientWidth + 1;
        }).length;
        // Any ancestor between the table and the page that scrolls on its own.
        let scrolls = 0;
        for (let el: HTMLElement | null = box; el && el !== document.documentElement; el = el.parentElement) {
          const s = getComputedStyle(el);
          if ((s.overflowY === "auto" || s.overflowY === "scroll") && el.scrollHeight > el.clientHeight) scrolls++;
        }
        // Outside the name, no word is split and no license is cut: every other cell fits its content on one line.
        const squeezed = [...document.querySelectorAll<HTMLElement>("main table tbody td")].filter((td) => {
          if (td.querySelector(".bl-comp-ver")) return false;
          const label = td.querySelector<HTMLElement>(".bl-comp-liclabel");
          return td.scrollWidth > td.clientWidth + 1 || (label !== null && label.scrollWidth > label.clientWidth + 1) || [...td.querySelectorAll<HTMLElement>("span")].some((sp) => sp.getBoundingClientRect().height > 30);
        }).length;
        const r = box.getBoundingClientRect();
        const b = bar.getBoundingClientRect();
        return {
          pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          names: names.length,
          cut,
          scrolls,
          boxLeft: r.left,
          boxRight: r.right,
          barLeft: b.left,
          barRight: b.right,
          clipped: box.scrollWidth - box.clientWidth,
          squeezed,
        };
      });
      expect(m.pageOverflow).toBe(0);
      expect(m.names).toBeGreaterThan(5);
      expect(m.cut, "no component name is cut or ellipsised").toBe(0);
      expect(m.scrolls, "nothing between the table and the page scrolls").toBe(0);
      expect(Math.abs(m.boxLeft - m.barLeft)).toBeLessThan(1.5);
      expect(Math.abs(m.boxRight - m.barRight)).toBeLessThan(1.5);
      expect(m.squeezed, "no cell outside the name is squeezed, split or cut").toBe(0);
      expect(m.clipped, "no column is clipped at the table's edge").toBeLessThanOrEqual(1);

      // Scroll the page: the head stays 56px from the top.
      await page.mouse.move(400, 500);
      await page.mouse.wheel(0, 900);
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(300);
      const top = await page.evaluate(() => document.querySelector("main table thead")!.getBoundingClientRect().top);
      expect(Math.round(top)).toBe(56);
    });
  }
}

test("the name column is the widest", async ({ page }) => {
  await open(page, scan(ITEMS), { width: 1280 });
  const w = await page.evaluate(() => {
    const ths = [...document.querySelectorAll<HTMLElement>("main table thead th")].map((e) => e.getBoundingClientRect().width);
    return { name: ths[0], rest: ths.slice(1) };
  });
  for (const other of w.rest) expect(w.name).toBeGreaterThan(other);
});

for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`axe: the table, its menus and an open row (${theme}/${lang})`, async ({ page }) => {
      await open(page, scan(ITEMS), { theme, lang });
      await expect(table(page)).toBeVisible();
      await waitForSettled(page.locator("main"));
      const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];
      expect((await new AxeBuilder({ page }).withTags(tags).analyze()).violations).toEqual([]);

      await table(page).locator("tbody button[aria-expanded]").first().click();
      await waitForSettled(page.locator("main"));
      expect((await new AxeBuilder({ page }).withTags(tags).analyze()).violations).toEqual([]);

      for (const trigger of lang === "en" ? ["Filters", "View"] : ["필터", "보기"]) {
        await page.getByRole("button", { name: trigger }).first().click();
        await expect(page.getByRole("menu")).toBeVisible();
        await settleTree(page.locator('[data-component="ActionMenu.Overlay"]'));
        expect((await new AxeBuilder({ page }).withTags(tags).analyze()).violations).toEqual([]);
        await page.keyboard.press("Escape");
      }
    });
  }
}

test("the toolbar is reachable by Tab, in reading order", async ({ page }) => {
  await open(page, scan(ITEMS));
  await page.getByRole("searchbox", { name: "Search components" }).focus();
  const order: string[] = [];
  for (let i = 0; i < 7; i++) {
    await page.keyboard.press("Tab");
    order.push(await page.evaluate(() => (document.activeElement?.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 24)));
  }
  const at = (prefix: string) => order.findIndex((t) => t.startsWith(prefix));
  expect(at("Type")).toBeGreaterThanOrEqual(0);
  expect(at("Type")).toBeLessThan(at("License"));
  expect(at("License")).toBeLessThan(at("Filters"));
  expect(at("Filters")).toBeLessThan(at("View"));
  expect(at("View")).toBeLessThan(at("Export CSV"));
});
