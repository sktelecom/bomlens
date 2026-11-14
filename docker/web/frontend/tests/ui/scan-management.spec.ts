// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";
import { seedThemeLang } from "./visual";

/**
 * Scan management (the home list): sorting, filtering, the row menu, the delete
 * confirmation, the empty states, long names and the comparison to the previous
 * scan of a project. The backend is stubbed, and DELETE calls are counted, so
 * "cancel deletes nothing" is asserted against the network.
 */

const NOW = Math.floor(Date.now() / 1000);
const DAY = 86_400;

interface Stub {
  id: string;
  project: string;
  version: string;
  components: number;
  maxSeverity: string | null;
  isAiScan: boolean;
  componentType: string;
  inputSource?: string | null;
  generatedAt: number;
  refused?: boolean;
}

function scan(id: string, project: string, version: string, components: number, maxSeverity: string | null, ageDays: number, extra: Partial<Stub> = {}): Stub {
  return { id, project, version, components, maxSeverity, isAiScan: false, componentType: "application", generatedAt: NOW - ageDays * DAY, ...extra };
}

/** Eight scans, one of each kind, ages 1..8 days (alpha is the newest). */
const LONG = "Raspberry-Pi-OS-Lite-arm64-2026-06-18-raspios-trixie-arm64-lite.img.xz";
const SCANS: Stub[] = [
  scan("alpha_1", "alpha", "1.0", 50, "HIGH", 1),
  scan("bravo_1", "bravo", "2.0", 7, "CRITICAL", 2, { componentType: "container" }),
  scan("charlie_1", "charlie", "3.0", 900, "LOW", 3, { componentType: "firmware" }),
  scan("delta_1", "delta", "4.0", 3, null, 4, { isAiScan: true, componentType: "machine-learning-model" }),
  scan("echo_1", "echo", "5.0", 120, "MEDIUM", 5),
  scan("foxtrot_1", "foxtrot", "6.0", 12, "UNKNOWN", 6),
  scan("golf_1", "golf", "7.0", 30, "CRITICAL", 7, { inputSource: "sbom-upload" }),
  scan("long_1", LONG, "2026-06-18", 60118, "CRITICAL", 8, { componentType: "firmware" }),
];

async function stub(page: Page, scans: Stub[] | (() => Stub[]), opts: { deleteStatus?: number } = {}) {
  const deletes: string[] = [];
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(typeof scans === "function" ? scans() : scans) }),
  );
  await page.route("**/scan-delete**", (r) => {
    deletes.push(new URL(r.request().url()).searchParams.get("id") ?? "");
    return r.fulfill({ status: opts.deleteStatus ?? 200, contentType: "application/json", body: "{}" });
  });
  return deletes;
}

/** Every animation on the page has finished: an overlay fades in, and axe weighs a half-faded colour. */
async function settleAll(page: Page) {
  await page.evaluate(async () => {
    await Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined)));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}

async function open(page: Page, lang: "en" | "ko" = "en", theme: "light" | "dark" = "light") {
  await seedThemeLang(page, theme, lang);
  await page.goto("/?ui=next#/");
  await page.locator("main h1").first().waitFor();
}

/** The scan-name links of the table, top to bottom (project names; versions are separate). */
async function order(page: Page): Promise<string[]> {
  const links = page.getByRole("table").getByRole("link");
  return (await links.allTextContents()).map((t) => t.replace(/\s+@.*$/, "").trim());
}

const SORTS: { column: string; asc: string[]; desc: string[] }[] = [
  {
    column: "Scan",
    asc: ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "long_1"],
    desc: ["long_1", "golf", "foxtrot", "echo", "delta", "charlie", "bravo", "alpha"],
  },
  {
    column: "Generated",
    asc: ["long_1", "golf", "foxtrot", "echo", "delta", "charlie", "bravo", "alpha"],
    desc: ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "long_1"],
  },
  {
    column: "Components",
    asc: ["delta", "bravo", "foxtrot", "golf", "alpha", "echo", "charlie", "long_1"],
    desc: ["long_1", "charlie", "echo", "alpha", "golf", "foxtrot", "bravo", "delta"],
  },
  {
    column: "Top severity",
    // none, unknown, low, medium, high, critical (newest first inside a grade)
    asc: ["delta", "foxtrot", "charlie", "echo", "alpha", "bravo", "golf", "long_1"],
    desc: ["bravo", "golf", "long_1", "alpha", "echo", "charlie", "foxtrot", "delta"],
  },
];

test.describe("sorting", () => {
  test.beforeEach(async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
  });

  test("the list opens newest first with Generated marked descending", async ({ page }) => {
    const header = page.getByRole("columnheader", { name: "Generated" });
    await expect(header).toHaveAttribute("aria-sort", "descending");
    for (const other of ["Scan", "Components", "Top severity"]) {
      await expect(page.getByRole("columnheader", { name: other })).toHaveAttribute("aria-sort", "none");
    }
    // Type and the actions column are not sortable.
    await expect(page.getByRole("columnheader", { name: "Type" })).not.toHaveAttribute("aria-sort", /.+/);
    expect((await order(page))[0]).toBe("alpha");
  });

  for (const { column, asc, desc } of SORTS) {
    test(`sorting by ${column} runs both ways and says so in aria-sort`, async ({ page }) => {
      const header = page.getByRole("columnheader", { name: column });
      const button = header.getByRole("button", { name: column });
      const names = async () => {
        const all = await order(page);
        // The long firmware name is shortened; match it by its start.
        return all.map((n) => (n.startsWith("Raspberry") ? "long_1" : n));
      };
      // A new column starts descending.
      if (column === "Generated") {
        // Already the active column: the first click flips it to ascending.
        await button.click();
        await expect(header).toHaveAttribute("aria-sort", "ascending");
        expect(await names()).toEqual(asc);
        await button.click();
        await expect(header).toHaveAttribute("aria-sort", "descending");
        expect(await names()).toEqual(desc);
        return;
      }
      await button.click();
      await expect(header).toHaveAttribute("aria-sort", "descending");
      expect(await names()).toEqual(desc);
      await button.click();
      await expect(header).toHaveAttribute("aria-sort", "ascending");
      expect(await names()).toEqual(asc);
      // Only the sorted column is marked.
      await expect(page.getByRole("columnheader", { name: "Generated" })).toHaveAttribute("aria-sort", "none");
    });
  }

  test("a column header can be sorted from the keyboard", async ({ page }) => {
    const button = page.getByRole("columnheader", { name: "Components" }).getByRole("button");
    await button.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("columnheader", { name: "Components" })).toHaveAttribute("aria-sort", "descending");
    await page.keyboard.press("Space");
    await expect(page.getByRole("columnheader", { name: "Components" })).toHaveAttribute("aria-sort", "ascending");
    await expect(button).toBeFocused();
  });
});

test.describe("filters", () => {
  test.beforeEach(async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
  });

  test("search matches the project and the version, ignoring case", async ({ page }) => {
    const search = page.getByRole("searchbox", { name: "Search scans…" });
    await search.fill("BRAVO");
    expect(await order(page)).toEqual(["bravo"]);
    await expect(page.getByText("1 of 8")).toBeVisible();
    await search.fill("3.0");
    expect(await order(page)).toEqual(["charlie"]);
    await search.fill("");
    expect(await order(page)).toHaveLength(8);
    await expect(page.getByText("of 8", { exact: false })).toHaveCount(0);
  });

  test("the at-risk toggle keeps Critical and High, with its count on the button", async ({ page }) => {
    const toggle = page.getByRole("button", { name: /^At risk/ });
    await expect(toggle).toContainText("4");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect((await order(page)).map((n) => (n.startsWith("Raspberry") ? "long_1" : n))).toEqual(["alpha", "bravo", "golf", "long_1"]);
    await toggle.click();
    expect(await order(page)).toHaveLength(8);
  });

  test("the type menu lists the types present with counts, and choosing the chosen one clears it", async ({ page }) => {
    const menu = page.getByRole("button", { name: /^Type:/ });
    await expect(menu).toContainText("All types");
    await menu.click();
    const list = page.getByRole("menu", { name: "Type" });
    await expect(list.getByRole("menuitemradio")).toHaveText([/All types/, /Source\s*3/, /Container\s*1/, /Firmware\s*2/, /AI model\s*1/, /SBOM\s*1/]);
    await list.getByRole("menuitemradio", { name: /^Firmware/ }).click();
    await expect(menu).toContainText("Firmware");
    expect((await order(page)).map((n) => (n.startsWith("Raspberry") ? "long_1" : n))).toEqual(["charlie", "long_1"]);
    // Choosing the chosen type again clears it.
    await menu.click();
    await page.getByRole("menu", { name: "Type" }).getByRole("menuitemradio", { name: /^Firmware/ }).click();
    await expect(menu).toContainText("All types");
    expect(await order(page)).toHaveLength(8);
  });

  test("filters combine, show as removable chips, and clear together", async ({ page }) => {
    await page.getByRole("button", { name: /^At risk/ }).click();
    await page.getByRole("button", { name: /^Type:/ }).click();
    await page.getByRole("menuitemradio", { name: /^Firmware/ }).click();
    expect((await order(page)).map((n) => (n.startsWith("Raspberry") ? "long_1" : n))).toEqual(["long_1"]);
    await expect(page.getByText("1 of 8")).toBeVisible();

    const chips = page.getByRole("group", { name: "Active filters" });
    await expect(chips.getByRole("button", { name: "Remove filter: At risk" })).toBeVisible();
    await expect(chips.getByRole("button", { name: "Remove filter: Firmware" })).toBeVisible();

    // Removing one chip leaves the other in force.
    await chips.getByRole("button", { name: "Remove filter: At risk" }).click();
    await expect(page.getByRole("button", { name: /^At risk/ })).toHaveAttribute("aria-pressed", "false");
    expect(await order(page)).toHaveLength(2);

    await page.getByRole("searchbox").fill("charlie");
    expect(await order(page)).toEqual(["charlie"]);
    await expect(chips.getByRole("button", { name: /Remove filter: .charlie./ })).toBeVisible();
    await chips.getByRole("button", { name: "Clear filters" }).click();
    expect(await order(page)).toHaveLength(8);
    await expect(page.getByRole("searchbox")).toHaveValue("");
    await expect(page.getByRole("button", { name: /^Type:/ })).toContainText("All types");
    await expect(chips.getByRole("button")).toHaveCount(0);
  });

  test("filters and sorting work together", async ({ page }) => {
    await page.getByRole("button", { name: /^At risk/ }).click();
    await page.getByRole("columnheader", { name: "Components" }).getByRole("button").click();
    expect((await order(page)).map((n) => (n.startsWith("Raspberry") ? "long_1" : n))).toEqual(["long_1", "alpha", "golf", "bravo"]);
  });

  test("the totals count every scan and every project, whatever the filter", async ({ page }) => {
    await expect(page.getByText("Total scans 8")).toBeVisible();
    await expect(page.getByText("Projects 8")).toBeVisible();
    await page.getByRole("searchbox").fill("alpha");
    await expect(page.getByText("Total scans 8")).toBeVisible();
  });

  test("a filter that matches nothing says so and offers the way back", async ({ page }) => {
    await page.getByRole("searchbox").fill("no such scan");
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "No scans match the filter." })).toBeVisible();
    await expect(page.getByText("Try a different search or type.")).toBeVisible();
    // The heading already says nothing matches, so the "0 of 8" count is not repeated.
    await expect(page.getByText("0 of 8")).toHaveCount(0);
    // The filter chip stays on screen, and the way back sits in the box itself.
    await expect(page.getByRole("button", { name: /^Remove filter:/ })).toBeVisible();
    await page.getByRole("heading", { name: "No scans match the filter." }).locator("xpath=ancestor::div[contains(@class,'bl-box')]").getByRole("button", { name: "Clear filters" }).click();
    await expect(page.getByRole("table")).toBeVisible();
    expect(await order(page)).toHaveLength(8);
  });

  test("only one type present means no type menu, and no at-risk toggle without risk", async ({ page }) => {
    const calm = [scan("a_1", "a", "1", 1, "LOW", 1), scan("b_1", "b", "1", 1, "MEDIUM", 2)];
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await stub(page, calm);
    await page.reload();
    await page.locator("main h1").first().waitFor();
    await expect(page.getByRole("button", { name: /^Type:/ })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^At risk/ })).toHaveCount(0);
    await expect(page.getByRole("searchbox")).toBeVisible();
  });
});

test.describe("empty list", () => {
  test("offers the start options and no table", async ({ page }) => {
    await stub(page, []);
    await open(page);
    await expect(page.getByRole("heading", { name: "Generate your first SBOM" })).toBeVisible();
    const main = page.getByRole("main");
    await expect(main.getByRole("link", { name: "New scan" })).toHaveCount(1);
    await expect(main.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
    await expect(page.getByTestId("empty-demo-link")).toHaveAttribute("target", "_blank");
    for (const out of ["SBOM (CycloneDX)", "Open-source notice", "Security report"]) {
      await expect(main.getByText(out, { exact: true })).toBeVisible();
    }
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("searchbox")).toHaveCount(0);
    await expect(page.getByTestId("recent-new-scan")).toHaveCount(0);
  });

  test("a list that fails to load shows the same first-run screen", async ({ page }) => {
    await page.route("**/capabilities", (r) => r.fulfill({ contentType: "application/json", body: "{}" }));
    await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
    await page.route("**/scans", (r) => r.fulfill({ status: 500, body: "boom" }));
    await open(page);
    await expect(page.getByRole("heading", { name: "Generate your first SBOM" })).toBeVisible();
  });
});

test.describe("header and footer", () => {
  test("a filled list leads with New scan in the header and ends with the output folder", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    await expect(page.getByRole("heading", { level: 1, name: "Scan management" })).toBeVisible();
    await expect(page.getByTestId("recent-new-scan")).toHaveAttribute("href", "#/new");
    await expect(page.getByText("~/sbom-output")).toBeVisible();
    await expect(page.getByText("Delete a file and it leaves this list too.")).toBeVisible();
    await expect(page).toHaveTitle(/Scan management/);
  });
});

test.describe("rows", () => {
  test("a scan name opens that scan", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    await expect(page.getByRole("link", { name: "alpha @1.0" })).toHaveAttribute("href", "#/scan/alpha_1");
  });

  test("relative times, with the exact time as the tooltip", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    const time = page.getByRole("row", { name: /alpha/ }).locator("time");
    await expect(time).toHaveText("yesterday");
    await expect(time).toHaveAttribute("title", /\d/);
    await expect(time).toHaveAttribute("datetime", /^\d{4}-\d{2}-\d{2}T/);
  });

  test("a long name is cut in the middle, with the full name in the tooltip and for screen readers", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    const link = page.getByRole("link", { name: `${LONG} @2026-06-18`, exact: true });
    await expect(link).toHaveAttribute("title", `${LONG} @2026-06-18`);
    const shown = await link.locator("span[aria-hidden]").textContent();
    expect(shown).toContain("…");
    expect(shown!.length).toBeLessThanOrEqual(40);
    expect(shown!.startsWith("Raspberry")).toBe(true);
    expect(shown!.endsWith("lite.img.xz")).toBe(true);
    // The version is never pushed out.
    await expect(link).toContainText("@2026-06-18");
    // Every name carries both parts in its tooltip.
    await expect(page.getByRole("link", { name: "alpha @1.0" })).toHaveAttribute("title", "alpha @1.0");
  });

  test("an AI scan carries the model icon in its type label", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    await expect(page.getByRole("row", { name: /delta/ }).getByText("AI model", { exact: true })).toBeVisible();
    await expect(page.getByRole("row", { name: /delta/ }).locator("svg")).not.toHaveCount(0);
    // No severity shows a dash, not a grade.
    await expect(page.getByRole("row", { name: /delta/ }).getByText("—")).toBeVisible();
  });
});

test.describe("comparison with the previous scan", () => {
  const PAIR: Stub[] = [
    scan("api_3", "api", "3.0", 13, "CRITICAL", 1),
    scan("api_2", "api", "2.0", 20, "HIGH", 2),
    scan("api_1", "api", "1.0", 10, "HIGH", 3),
    scan("solo_1", "solo", "1.0", 5, "LOW", 4),
    scan("refused_1", "api", "9.9", 0, null, 0.5, { refused: true, isAiScan: true, componentType: "machine-learning-model" }),
  ];

  test("shows the change in components and the direction of the worst severity", async ({ page }) => {
    await stub(page, PAIR);
    await open(page);
    const newest = page.getByRole("row", { name: /api @3\.0/ });
    await expect(newest).toContainText("13");
    await expect(newest.getByText("-7")).toBeVisible();
    await expect(newest.getByText("Worse than the previous scan")).toBeAttached();
    await expect(newest.getByTitle("Worse than the previous scan")).toBeVisible();

    const middle = page.getByRole("row", { name: /api @2\.0/ });
    await expect(middle.getByText("+10")).toBeVisible();
    // High to High: the grade did not move, so there is no arrow.
    await expect(middle.getByText(/than the previous scan/)).toHaveCount(0);

    // The first scan of a project, and a project scanned once, compare to nothing.
    for (const name of [/api @1\.0/, /solo @1\.0/]) {
      const row = page.getByRole("row", { name });
      await expect(row).not.toContainText("+");
      await expect(row.getByText(/than the previous scan/)).toHaveCount(0);
      await expect(row.getByTitle("Change since the previous scan of this project")).toHaveCount(0);
    }
  });

  test("a refused declaration is flagged and never used as a baseline", async ({ page }) => {
    await stub(page, PAIR);
    await open(page);
    const refused = page.getByRole("row", { name: /api @9\.9/ });
    await expect(refused.getByText("Declaration refused")).toBeVisible();
    await expect(refused.getByText("Declaration refused")).toHaveAttribute("title", /declaration file was refused/);
    await expect(refused).not.toContainText("+");
    // It does not turn api 3.0 into a comparison against 0 components.
    await expect(page.getByRole("row", { name: /api @3\.0/ })).toContainText("-7");
  });
});

test.describe("row menu and delete", () => {
  test("every row has its own named menu button, and the menu holds Delete", async ({ page }) => {
    await stub(page, SCANS);
    await open(page);
    const kebab = page.getByRole("button", { name: "More actions for alpha 1.0" });
    await expect(kebab).toBeVisible();
    await expect(page.getByRole("button", { name: /^More actions for/ })).toHaveCount(8);
    await kebab.click();
    await expect(page.getByRole("menuitem", { name: "Delete" })).toBeVisible();
  });

  test("the menu works from the keyboard and Escape returns focus to its button", async ({ page }) => {
    const deletes = await stub(page, SCANS);
    await open(page);
    const kebab = page.getByRole("button", { name: "More actions for bravo 2.0" });
    await kebab.focus();
    await page.keyboard.press("Enter");
    const item = page.getByRole("menuitem", { name: "Delete" });
    await expect(item).toBeVisible();
    await expect(item).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(item).toHaveCount(0);
    await expect(kebab).toBeFocused();
    expect(deletes).toEqual([]);

    // ArrowDown also opens it.
    await page.keyboard.press("ArrowDown");
    await expect(page.getByRole("menuitem", { name: "Delete" })).toBeVisible();
    await page.keyboard.press("Enter");
    // Enter on Delete opens the confirmation, naming the scan.
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("bravo 2.0");
    expect(deletes).toEqual([]);
  });

  test("the confirmation focuses Cancel; cancelling sends nothing and hands focus back to the row's menu button", async ({ page }) => {
    const deletes = await stub(page, SCANS);
    await open(page);
    const kebab = page.getByRole("button", { name: "More actions for bravo 2.0" });
    await kebab.click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("cannot be undone");
    await expect(page.getByRole("button", { name: "Cancel" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    expect(deletes).toEqual([]);
    await expect(kebab).toBeFocused();
    expect(await order(page)).toHaveLength(8);
  });

  test("confirming deletes that scan only, refreshes the list and says so", async ({ page }) => {
    let list = SCANS;
    const deletes = await stub(page, () => list);
    await open(page);
    await page.getByRole("button", { name: "More actions for bravo 2.0" }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    list = SCANS.filter((s) => s.id !== "bravo_1");
    await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
    await expect.poll(() => deletes).toEqual(["bravo_1"]);
    await expect(page.getByText("Scan deleted")).toBeVisible();
    await expect(page.getByRole("link", { name: "bravo @2.0" })).toHaveCount(0);
    expect(await order(page)).toHaveLength(7);
  });

  test("a refused delete says so and keeps the row", async ({ page }) => {
    await stub(page, SCANS, { deleteStatus: 500 });
    await open(page);
    await page.getByRole("button", { name: "More actions for bravo 2.0" }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
    await expect(page.getByText("The scan could not be deleted. Try again.")).toBeVisible();
    await expect(page.getByRole("link", { name: "bravo @2.0" })).toBeVisible();
  });
});

test.describe("layout", () => {
  for (const width of [1024, 1280, 1440]) {
    test(`the page does not scroll sideways at ${width}px, even with the longest name`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await stub(page, SCANS);
      await open(page);
      await expect(page.getByRole("table")).toBeVisible();
      const excess = await page.evaluate(() => {
        const main = document.querySelector("main")!;
        const table = document.querySelector("table")!;
        const box = table.getBoundingClientRect();
        return {
          page: document.documentElement.scrollWidth - window.innerWidth,
          main: main.scrollWidth - main.clientWidth,
          tableRight: box.right - main.getBoundingClientRect().right,
        };
      });
      expect(excess.page).toBeLessThanOrEqual(0);
      expect(excess.main).toBeLessThanOrEqual(0);
      expect(excess.tableRight).toBeLessThanOrEqual(1);
    });
  }

  test("at 390px the table gives way to stacked rows that keep every fact", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await stub(page, SCANS);
    await open(page);
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("listitem").filter({ hasText: "alpha" }).first()).toContainText("50 components");
    await expect(page.getByRole("button", { name: "More actions for alpha 1.0" })).toBeVisible();
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(over).toBeLessThanOrEqual(0);
  });

  test("Korean fits the same way", async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 900 });
    await stub(page, SCANS);
    await open(page, "ko");
    await expect(page.getByRole("heading", { level: 1, name: "스캔 관리" })).toBeVisible();
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(over).toBeLessThanOrEqual(0);
  });
});

for (const theme of ["light", "dark"] as const) {
  for (const lang of ["en", "ko"] as const) {
    test(`the list, its menus and the delete prompt pass axe: ${theme}/${lang}`, async ({ page }) => {
      await stub(page, SCANS);
      await open(page, lang, theme);
      await expect(page.getByRole("table")).toBeVisible();
      await waitForSettled(page.locator("main"));
      const scan = () =>
        new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect((await scan()).violations).toEqual([]);

      // With a filter on and the type menu open.
      await page.getByRole("button", { name: /^(At risk|위험)/ }).click();
      await page.getByRole("button", { name: /^(Type|유형):/ }).click();
      await expect(page.getByRole("menu")).toBeVisible();
      await settleAll(page);
      expect((await scan()).violations).toEqual([]);
      await page.keyboard.press("Escape");

      // And with the row menu and the prompt open.
      await page.getByRole("button", { name: /^(More actions for|.* 작업 더 보기)/ }).first().click();
      await expect(page.getByRole("menuitem")).toBeVisible();
      await settleAll(page);
      expect((await scan()).violations).toEqual([]);
      await page.getByRole("menuitem").click();
      await waitForSettled(page.getByRole("dialog"));
      expect((await scan()).violations).toEqual([]);
    });
  }
}

test("the empty and the filtered-empty screens pass axe", async ({ page }) => {
  await stub(page, []);
  await open(page);
  await waitForSettled(page.locator("main"));
  expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze()).violations).toEqual([]);
  await page.unrouteAll({ behavior: "ignoreErrors" });
  await stub(page, SCANS);
  await page.reload();
  await page.getByRole("searchbox").fill("zzzz");
  await expect(page.getByRole("heading", { name: "No scans match the filter." })).toBeVisible();
  expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze()).violations).toEqual([]);
});

test.describe("list details", () => {
  test.beforeEach(async ({ page }) => {
    await stub(page, [...SCANS, scan("pair_1", "alpha", "0.9", 40, "MEDIUM", 20)]);
    await open(page);
  });

  test("the at-risk toggle is clearly different when pressed (fill, not only the outline)", async ({ page }) => {
    const toggle = page.getByRole("button", { name: /^At risk/ });
    const paint = () =>
      toggle.evaluate((el) => {
        const cs = getComputedStyle(el);
        return { bg: cs.backgroundColor, border: cs.borderTopColor };
      });
    const off = await paint();
    await toggle.click();
    await page.mouse.move(0, 0);
    const on = await paint();
    expect(on.bg).not.toBe(off.bg);
    expect(on.border).not.toBe(off.border);
  });

  test("every row is one line high, the long firmware name included", async ({ page }) => {
    const heights = await page.locator("tbody tr").evaluateAll((rows) => rows.map((r) => Math.round(r.getBoundingClientRect().height)));
    expect(new Set(heights).size).toBe(1);
    const link = page.getByRole("link", { name: `${LONG} @2026-06-18`, exact: true });
    const box = await link.boundingBox();
    expect(box!.height).toBeLessThan(30);
    // Version sits on the same line, in the muted colour.
    const version = link.locator("span").last();
    const [nameBox, versionBox] = await Promise.all([link.locator("span").first().boundingBox(), version.boundingBox()]);
    expect(Math.abs(nameBox!.y - versionBox!.y)).toBeLessThan(6);
    const colours = await Promise.all([link.locator("span").first(), version].map((l) => l.evaluate((e) => getComputedStyle(e).color)));
    expect(colours[0]).not.toBe(colours[1]);
  });

  test("component counts share one right edge, with or without a change beside them", async ({ page }) => {
    // alpha 1.0 has a change (+10 against 0.9); bravo has none.
    const right = async (name: RegExp) =>
      page.getByRole("row", { name }).locator(".bl-compcell").evaluate((el) => {
        const range = document.createRange();
        range.selectNodeContents(el.firstChild!);
        return Math.round(range.getBoundingClientRect().right);
      });
    expect(await right(/alpha @1\.0/)).toBe(await right(/bravo @2\.0/));
    await expect(page.getByRole("row", { name: /alpha @1\.0/ })).toContainText("+10");
  });

  test("the trend arrow is an up or down arrow with a name and a tooltip, not red", async ({ page }) => {
    const row = page.getByRole("row", { name: /alpha @1\.0/ });
    const arrow = row.getByTitle("Worse than the previous scan");
    await expect(arrow).toBeVisible();
    await expect(arrow.locator("svg")).toHaveCount(1);
    const colour = await arrow.evaluate((e) => getComputedStyle(e).color);
    const danger = await page.evaluate(() => {
      const probe = document.createElement("span");
      probe.style.color = "var(--fgColor-danger)";
      document.body.appendChild(probe);
      const c = getComputedStyle(probe).color;
      probe.remove();
      return c;
    });
    expect(colour).not.toBe(danger);
  });

  test("every type label carries an icon", async ({ page }) => {
    const labels = page.locator("tbody tr td:nth-child(2) [class*=Label]");
    const n = await labels.count();
    expect(n).toBeGreaterThan(4);
    for (let i = 0; i < n; i++) await expect(labels.nth(i).locator("svg")).toHaveCount(1);
  });

  test("the totals are two counts set apart by a separator", async ({ page }) => {
    const totals = page.locator(".bl-totals");
    await expect(totals).toContainText("Total scans 9");
    await expect(totals).toContainText("·");
    await expect(totals).toContainText("Projects 8");
  });

  test("the delete prompt names the scan in bold", async ({ page }) => {
    await page.getByRole("button", { name: "More actions for bravo 2.0" }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    await expect(page.getByRole("dialog").locator("strong")).toHaveText("bravo 2.0");
  });

  test("after a confirmed delete focus lands on the list heading", async ({ page }) => {
    await page.getByRole("button", { name: "More actions for bravo 2.0" }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
    await expect(page.getByText("Scan deleted")).toBeVisible();
    await expect(page.locator("main h1")).toBeFocused();
  });
});

test("a refused declaration is not drawn in the Critical colour", async ({ page }) => {
  await stub(page, [scan("c_1", "c", "1", 1, "CRITICAL", 1), scan("r_1", "r", "1", 0, null, 0.5, { refused: true })]);
  await open(page);
  const colour = (loc: ReturnType<Page["getByText"]>) => loc.evaluate((e) => getComputedStyle(e).color);
  expect(await colour(page.getByText("Declaration refused"))).not.toBe(await colour(page.getByText("Critical", { exact: true })));
});
