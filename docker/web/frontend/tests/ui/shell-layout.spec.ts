// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

import { DONE, SBOM } from "./fixtures";
import { seedThemeLang, type Lang } from "./visual";

/**
 * The app frame: the top bar, the left navigation and the path to the open
 * scan, measured across the desktop widths the UI is built for. The page
 * itself scrolls, so a sticky element under the top bar sticks at 56px.
 */

const ID = "SpringBootDemo_1.1.0";
const SCAN = { ...DONE, id: ID, results: [{ name: `${ID}_bom.json`, size: 100 }] };
const LISTED = {
  id: ID,
  project: "SpringBootDemo",
  version: "1.1.0",
  components: 3,
  maxSeverity: "CRITICAL",
  isAiScan: false,
  componentType: "application",
  inputSource: null,
  generatedAt: 1700000000,
};

async function stub(
  page: Page,
  opts: { scans?: object[]; scansDelay?: number; scan?: object; scanDelay?: number; deleteStatus?: number } = {},
) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ firmware: false, scanoss: false, docker: true, externalLookup: true, version: "1.14.5" }),
    }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", async (r) => {
    if (opts.scansDelay) await new Promise((res) => setTimeout(res, opts.scansDelay));
    await r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.scans ?? [LISTED]) });
  });
  await page.route(`**/scan?id=${ID}`, async (r) => {
    if (opts.scanDelay) await new Promise((res) => setTimeout(res, opts.scanDelay));
    await r.fulfill({ contentType: "application/json", body: JSON.stringify(opts.scan ?? SCAN) });
  });
  await page.route("**/file**", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }),
  );
  await page.route("**/scan-delete**", (r) => r.fulfill({ status: opts.deleteStatus ?? 200, body: "" }));
}

const SCREENS: Array<[string, string]> = [
  ["scan management", "#/"],
  ["new scan", "#/new"],
  ["external lookup", "#/lookup"],
  ["overview", `#/scan/${ID}`],
  ["components", `#/scan/${ID}/components`],
  ["vulnerabilities", `#/scan/${ID}/vulnerabilities`],
  ["artifacts", `#/scan/${ID}/artifacts`],
];

for (const width of [1024, 1280, 1440]) {
  for (const lang of ["ko", "en"] as Lang[]) {
    test(`no screen scrolls sideways at ${width}px, ${lang}`, async ({ page }) => {
      await page.setViewportSize({ width, height: width === 1440 ? 900 : 800 });
      await seedThemeLang(page, "light", lang);
      await stub(page);
      const over: string[] = [];
      for (const [name, hash] of SCREENS) {
        await page.goto(`/?ui=next${hash}`);
        await page.locator("main h1").first().waitFor();
        if (hash.startsWith("#/scan/")) await page.getByTestId("result-meta").waitFor();
        const sw = await page.evaluate(() => document.documentElement.scrollWidth);
        if (sw > width) over.push(`${name}: ${sw}`);
      }
      expect(over).toEqual([]);
    });
  }
}

test("the top bar is 56px and stays at the top while the page scrolls", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 600 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}/components`);
  await page.getByTestId("result-meta").waitFor();
  // Make sure the page is tall enough to scroll, whatever the section holds.
  await page.locator("main").evaluate((el) => {
    const pad = document.createElement("div");
    pad.style.height = "2000px";
    el.appendChild(pad);
  });
  const header = page.getByRole("banner");
  expect((await header.boundingBox())!.height).toBe(56);
  await page.evaluate(() => window.scrollTo(0, 800));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  expect((await header.boundingBox())!.y).toBe(0);
  // The navigation sticks right under it.
  const pane = page.locator(".bl-pane");
  expect((await pane.boundingBox())!.y).toBe(56);
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
});

test("the path and the title name the scan by project and version, not its id", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  // The scan list answers after the scan itself: the name must still come
  // from the list, never fall back to the id on the first render.
  await stub(page, { scansDelay: 600 });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();

  const path = page.getByTestId("topbar-path");
  await expect(path).toHaveText("/SpringBootDemo 1.1.0");
  await expect(path.getByRole("link")).toHaveAttribute("href", `#/scan/${ID}`);
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
  await expect(page.getByText(ID, { exact: true })).toHaveCount(0);

  // On a section the title is the section and the meta line names the scan.
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: /^Components/ }).click();
  await expect(page.locator("main h1")).toHaveText("Components");
  await expect(page.getByTestId("result-meta")).toContainText("SpringBootDemo 1.1.0");
  await expect(path).toHaveText("/SpringBootDemo 1.1.0");
});

test("a failed scan is named the same way", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { scan: { ...SCAN, ok: false } });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await expect(page.getByRole("status").filter({ hasText: "Scan failed" })).toBeVisible();
  await expect(page.getByTestId("topbar-path")).toHaveText("/SpringBootDemo 1.1.0");
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
});

test("a scan missing from the list is named from the settings it ran with", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, {
    scans: [],
    scan: { ...SCAN, scanConfig: { source: "cwd", project: "SpringBootDemo", version: "1.1.0" } },
  });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await expect(page.getByTestId("topbar-path")).toHaveText("/SpringBootDemo 1.1.0");
});

test("a deep link shows a loading state, not the scan list, while the scan loads", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { scanDelay: 1500 });
  await page.goto(`/?ui=next#/scan/${ID}/components`);
  await expect(page.getByTestId("scan-opening")).toHaveText("Opening the scan…");
  await expect(page.getByRole("heading", { name: "Scan management" })).toHaveCount(0);
  await expect(page.locator("main h1")).toHaveText("Components");
  await expect(page.getByTestId("scan-opening")).toHaveCount(0);
});

test("every screen has the navigation, with the current page marked", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  const nav = page.getByRole("navigation", { name: "Main" });
  for (const [hash, current] of [
    ["#/", "Scan management"],
    ["#/new", "New scan"],
    ["#/lookup", null],
  ] as const) {
    await page.goto(`/?ui=next${hash}`);
    await page.locator("main h1").first().waitFor();
    await expect(nav.getByRole("link", { name: "Scan management" })).toHaveAttribute("href", "#/");
    await expect(nav.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
    await expect(nav.locator('[aria-current="page"]')).toHaveCount(current ? 1 : 0);
    if (current) await expect(nav.getByRole("link", { name: current })).toHaveAttribute("aria-current", "page");
    // External lookup has no navigation entry; its top-bar button is marked.
    const lookup = page.getByTestId("external-lookup-link");
    if (hash === "#/lookup") await expect(lookup).toHaveAttribute("aria-current", "page");
    else await expect(lookup).not.toHaveAttribute("aria-current", "page");
    // No scan open: no section links, a hint instead.
    await expect(nav.getByRole("link", { name: /^Overview/ })).toHaveCount(0);
    await expect(nav).toContainText("Open a scan to see its sections here.");
  }
});

test("the navigation starts as icons at 1024px and the toggle expands it", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}/components`);
  await page.getByTestId("result-meta").waitFor();
  const nav = page.getByRole("navigation", { name: "Main" });
  // Icon links keep their names (and the current page) for assistive tech.
  await expect(nav.getByRole("link", { name: "Components" })).toHaveAttribute("aria-current", "page");
  await expect(nav.getByText("Inventory")).toHaveCount(0);
  await page.getByRole("button", { name: "Expand sidebar" }).click();
  await expect(nav.getByText("Inventory")).toBeVisible();
  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect(nav.getByText("Inventory")).toHaveCount(0);
});

test("the language moves into the help menu on a compact top bar", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto("/?ui=next#/new");
  await page.locator("#project").waitFor();
  await expect(page.getByRole("radiogroup", { name: "Language" })).toHaveCount(0);
  await page.getByTestId("help-menu").click();
  await page.getByRole("menuitemradio", { name: "한국어" }).click();
  await expect(page.getByRole("navigation", { name: "주 메뉴" })).toBeVisible();
});

test("the language and theme switches in the top bar", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto("/?ui=next#/new");
  await page.locator("#project").waitFor();
  await page.getByRole("button", { name: "한국어" }).click();
  await expect(page.getByRole("link", { name: "새 스캔" }).first()).toBeVisible();
  await page.getByRole("button", { name: "English" }).click();
  await expect(page.getByRole("link", { name: "New scan" }).first()).toBeVisible();

  await page.getByRole("button", { name: "Switch to dark" }).click();
  await expect(page.locator("html")).toHaveClass(/\bdark\b/);
  await expect(page.locator("html")).toHaveAttribute("data-color-mode", "dark");
  await page.getByRole("button", { name: "Switch to light" }).click();
  await expect(page.locator("html")).not.toHaveClass(/\bdark\b/);
});

test("deleting from the Recent menu says so when the server refuses", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { deleteStatus: 500 });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByRole("button", { name: "Recent scans" }).click();
  await page.getByRole("button", { name: "Delete this scan" }).click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText("The scan could not be deleted. Try again.")).toBeVisible();
  await expect(page.getByText("Scan deleted")).toHaveCount(0);
  // Still on the scan.
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
});

test("the logo links home, except on the home screen itself", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto("/?ui=next#/");
  await page.locator("main h1").first().waitFor();
  const banner = page.getByRole("banner");
  await expect(banner.getByRole("img", { name: "BomLens" })).toBeVisible();
  await expect(banner.getByRole("link", { name: "BomLens" })).toHaveCount(0);
  // The home screen has its own New scan button; the top bar does not repeat it.
  await expect(banner.getByRole("link", { name: "New scan" })).toHaveCount(0);
  await expect(page.getByRole("main").getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
  // Nor does it on New scan itself.
  await page.goto("/?ui=next#/new");
  await page.locator("#project").waitFor();
  await expect(banner.getByRole("link", { name: "BomLens" })).toHaveAttribute("href", "#/");
  await expect(banner.getByRole("link", { name: "New scan" })).toHaveCount(0);
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await expect(banner.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "#/new");
});

test("the Recent menu says when there are no scans yet", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { scans: [] });
  await page.goto("/?ui=next#/new");
  await page.locator("#project").waitFor();
  await page.getByRole("button", { name: "Recent scans" }).click();
  await expect(page.getByText("No recent scans yet")).toBeVisible();
  await expect(page.getByRole("link", { name: "View all scans" })).toHaveAttribute("href", "#/");
});

test("global search says when nothing matches", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  // With External lookup off there is no lookup row to offer instead.
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByTestId("global-search").fill("zzzz-nothing");
  await expect(page.getByRole("listbox")).toContainText("No matches");
});

test("a section the scan does not have opens the Overview", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  // Models & datasets exists only for an AI scan.
  await page.goto(`/?ui=next#/scan/${ID}/models`);
  await page.getByTestId("result-meta").waitFor();
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
  await expect(
    page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: /^Overview/ }),
  ).toHaveAttribute("aria-current", "page");
});

test("a section change starts the new section at its title, with focus on it", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 600 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}/components`);
  await page.getByTestId("result-meta").waitFor();
  // A long section, read down to its end.
  await page.locator("main").evaluate((el) => {
    const pad = document.createElement("div");
    pad.style.height = "3000px";
    el.appendChild(pad);
  });
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(1000);
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: /^Vulnerabilities/ }).click();
  const title = page.locator("main h1");
  await expect(title).toHaveText("Vulnerabilities");
  await expect(title).toBeFocused();
  await expect(title).toBeInViewport();
  // Not under the sticky top bar either.
  expect((await title.boundingBox())!.y).toBeGreaterThanOrEqual(56);
});

test("a late answer for a scan left behind does not replace the scan now open", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { scanDelay: 1500 });
  const OTHER = "flask_2.0";
  await page.route(`**/scan?id=${OTHER}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ ...SCAN, id: OTHER }) }),
  );
  await page.route("**/scans", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify([LISTED, { ...LISTED, id: OTHER, project: "flask", version: "2.0" }]),
    }),
  );
  const lateAnswer = page.waitForResponse((r) => r.url().includes(`scan?id=${ID}`));
  await page.goto(`/?ui=next#/scan/${ID}`);
  await expect(page.getByTestId("scan-opening")).toBeVisible();
  await page.evaluate((id) => (window.location.hash = `#/scan/${id}`), OTHER);
  await expect(page.locator("main h1")).toHaveText("flask 2.0");
  // The first scan's answer arrives now; once the app has handled it (two
  // frames after the response), the screen is still on flask.
  await lateAnswer;
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  await expect(page.locator("main h1")).toHaveText("flask 2.0");
  await expect(page.getByTestId("topbar-path")).toHaveText("/flask 2.0");
});

test("a slow scan list does not hold the scan back; it renames it when it lands", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, {
    scansDelay: 6000,
    scan: { ...SCAN, scanConfig: { source: "cwd", project: "Configured", version: "9" } },
  });
  await page.goto(`/?ui=next#/scan/${ID}`);
  // Drawn after the 3 s wait, named from its settings.
  await expect(page.getByTestId("result-meta")).toBeVisible({ timeout: 4500 });
  await expect(page.getByTestId("topbar-path")).toHaveText("/Configured 9");
  // The list arrives and names it as stored.
  await expect(page.getByTestId("topbar-path")).toHaveText("/SpringBootDemo 1.1.0", { timeout: 8000 });
});

test("the Recent menu marks the open scan", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByRole("button", { name: "Recent scans" }).click();
  // The entry is named with its worst severity, not by the shape alone.
  // (A no-break space joins name and version; the hidden severity text is
  // its own box, so name computation may put a space before its comma.)
  const entry = page.getByRole("link", { name: /^SpringBootDemo\s1\.1\.0\s?, Critical$/ });
  await expect(entry).toHaveAttribute("aria-current", "page");
  // No title attribute to read the same name a second time.
  await expect(entry).not.toHaveAttribute("title", /.+/);
  // "View all scans" is an action row below the scans, and the menu holds no
  // link named like the navigation's "Scan management".
  const all = page.getByRole("link", { name: "View all scans" });
  await expect(all).toHaveAttribute("href", "#/");
  expect((await all.boundingBox())!.y).toBeGreaterThan((await entry.boundingBox())!.y);
  await expect(page.getByRole("link", { name: "Scan management" })).toHaveCount(1);
});

test("global search shows the grade, the component name and a clear button", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  const box = page.getByTestId("global-search");
  await box.fill("CVE-2024-0001");
  const option = page.getByRole("listbox").getByRole("option", { name: /^Critical CVE-2024-0001/ });
  await expect(option).toContainText("Critical");
  await expect(option.locator("[title]").last()).toHaveText("openssl");
  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(box).toHaveValue("");
  await expect(box).toBeFocused();
  await expect(page.getByRole("button", { name: "Clear search" })).toHaveCount(0);
});

test("the compact Re-scan button keeps its explanation", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page, { scan: { ...SCAN, scanConfig: { source: "cwd", project: "SpringBootDemo", version: "1.1.0" } } });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await expect(page.getByRole("button", { name: "Re-scan" })).toHaveAccessibleDescription(
    "Scan the same target again with these settings prefilled",
  );
});

test("the meta line counts the components", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}`);
  await expect(page.getByTestId("result-components")).toHaveText(`Components ${DONE.sbom.components}`);
});

test("the artifact viewer is wide enough for a report", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}/artifacts`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByRole("main").getByRole("button", { name: "View" }).first().click();
  const box = await page.getByRole("dialog").boundingBox();
  // min(1200px, 95vw) wide, 80vh tall.
  expect(Math.round(box!.width)).toBe(1200);
  expect(Math.round(box!.height)).toBe(640);
});

test("going back to the open scan while another loads drops the loading state", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  const SLOW = "slow_1.0";
  await page.route(`**/scan?id=${SLOW}`, async (r) => {
    await new Promise((res) => setTimeout(res, 3000));
    await r.fulfill({ contentType: "application/json", body: JSON.stringify({ ...SCAN, id: SLOW }) });
  });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.evaluate((id) => (window.location.hash = `#/scan/${id}`), SLOW);
  await expect(page.getByTestId("scan-opening")).toBeVisible();
  await page.evaluate((id) => (window.location.hash = `#/scan/${id}`), ID);
  await expect(page.getByTestId("scan-opening")).toHaveCount(0);
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
});

test("a capped search group ends with a row that opens the section filtered", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  const many = Array.from({ length: 8 }, (_, i) => ({
    name: `libalpha${i}`, version: "1.0", group: "", purl: `pkg:npm/libalpha${i}@1.0`, type: "library", licenses: [],
  }));
  await stub(page, { scan: { ...SCAN, sbom: { ...SCAN.sbom, components: 8, componentList: many } } });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByTestId("global-search").fill("libalpha");
  const listbox = page.getByRole("listbox");
  await expect(listbox.getByRole("option", { name: /^libalpha/ })).toHaveCount(5);
  await listbox.getByRole("option", { name: "View all components (8)" }).click();
  await expect(page.locator("main h1")).toHaveText("Components");
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe(`#/scan/${ID}/components?q=libalpha`);
});

test("the browser tab names the screen, the scan and the app", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto("/?ui=next#/");
  await expect(page).toHaveTitle("Scan management · BomLens");
  await page.goto("/?ui=next#/new");
  await expect(page).toHaveTitle("New scan · BomLens");
  await page.goto(`/?ui=next#/scan/${ID}/vulnerabilities`);
  await expect(page).toHaveTitle("Vulnerabilities · SpringBootDemo 1.1.0 · BomLens");
  await page.getByRole("button", { name: /한국어/ }).click();
  await expect(page).toHaveTitle("취약점 · SpringBootDemo 1.1.0 · BomLens");
});

const LONG_GROUP = "org.springframework.boot.autoconfigure.web.servlet.error";
const LONG_NAME = "spring-boot-starter-web-with-a-very-long-artifact-name-that-cannot-fit-the-row";

test("search rows never scroll sideways and keep ids whole", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await seedThemeLang(page, "light", "en");
  const vulns = ["CVE-2024-0001", "CVE-2024-0002"].map((id) => ({
    id, severity: "CRITICAL", pkg: `${LONG_GROUP}:${LONG_NAME}`, installed: "1", fixed: "2", title: "t",
  }));
  await stub(page, {
    scan: {
      ...SCAN,
      security: { ...SCAN.security, vulnerabilities: vulns },
      sbom: {
        ...SCAN.sbom,
        componentList: [{ name: LONG_NAME, version: "1.0", group: LONG_GROUP, purl: "pkg:maven/x/y@1", type: "library", licenses: [] }],
      },
    },
  });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByTestId("global-search").fill("spring-boot-starter");
  const listbox = page.getByRole("listbox");
  await expect(listbox).toBeVisible();
  // No sideways scroll in the list, and it is as wide as asked: min(560px, 100vw - 32px).
  const m = await listbox.evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth }));
  expect(m.sw).toBeLessThanOrEqual(m.cw);
  expect(Math.round((await listbox.boundingBox())!.width)).toBe(560);
  // The two CVE ids are whole and different: neither is clipped.
  const ids = page.locator(".bl-searchpop-id.bl-searchpop-mono");
  await expect(ids).toHaveText(["CVE-2024-0001", "CVE-2024-0002"]);
  const clipped = await ids.evaluateAll((els) => els.filter((e) => e.scrollWidth > e.clientWidth).length);
  expect(clipped).toBe(0);
  // The coordinate shortens with an ellipsis, shows "group / name", and the full
  // value stays in the tooltip and in the option's accessible name.
  const coord = listbox.getByRole("option", { name: new RegExp(`^${LONG_GROUP}\\s/\\s${LONG_NAME}`) }).locator(".bl-searchpop-coord");
  await expect(coord).toHaveAttribute("title", `${LONG_GROUP} / ${LONG_NAME}`);
  await expect(coord).toContainText(`${LONG_GROUP} / ${LONG_NAME}`);
  await expect(page.getByRole("option", { name: new RegExp(`CVE-2024-0001.*${LONG_NAME}`) })).toBeVisible();
});

test("both capped groups end with their own labelled row, visible without scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await seedThemeLang(page, "light", "en");
  const comps = Array.from({ length: 8 }, (_, i) => ({
    name: `libbeta${i}`, version: "1.0", group: "org.beta", purl: `pkg:maven/org.beta/libbeta${i}@1.0`, type: "library", licenses: [],
  }));
  const vulns = Array.from({ length: 8 }, (_, i) => ({
    id: `CVE-2024-10${i}`, severity: "HIGH", pkg: `org.beta:libbeta${i}`, installed: "1", fixed: "2", title: "t",
  }));
  await stub(page, {
    scan: { ...SCAN, security: { ...SCAN.security, vulnerabilities: vulns }, sbom: { ...SCAN.sbom, components: 8, componentList: comps } },
  });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  await page.getByTestId("global-search").fill("libbeta");
  const listbox = page.getByRole("listbox");
  const rows = listbox.getByRole("option", { name: /^View all/ });
  await expect(rows).toHaveText(["View all components (8)", "View all vulnerabilities (8)"]);
  await expect(rows.nth(0)).toBeInViewport();
  await expect(rows.nth(1)).toBeInViewport();
  // A group with an owner reads "group / name".
  await expect(listbox.getByRole("option", { name: /^org\.beta\s\/\slibbeta0/ })).toBeVisible();
  const m = await listbox.evaluate((el) => ({ sh: el.scrollHeight, ch: el.clientHeight }));
  expect(m.sh).toBeLessThanOrEqual(m.ch + 1);
  await rows.nth(1).click();
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe(`#/scan/${ID}/vulnerabilities?q=libbeta`);
});

test("the current page is marked by a selected fill, on the top bar and the collapsed navigation", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/lookup`);
  await page.locator("main h1").first().waitFor();
  const bg = (loc: ReturnType<Page["locator"]>) => loc.evaluate((el) => getComputedStyle(el).backgroundColor);
  const lookup = page.getByTestId("external-lookup-link");
  await expect(lookup).toHaveAttribute("data-variant", "invisible");
  expect(await bg(lookup)).not.toBe("rgba(0, 0, 0, 0)");
  expect(await bg(page.getByRole("button", { name: "Recent scans" }))).toBe("rgba(0, 0, 0, 0)");

  await page.goto(`/?ui=next#/scan/${ID}/components`);
  await page.getByTestId("result-meta").waitFor();
  const nav = page.getByRole("navigation", { name: "Main" });
  const current = nav.getByRole("link", { name: "Components" });
  await expect(current).toHaveAttribute("aria-current", "page");
  await expect(current).toHaveAttribute("data-variant", "invisible");
  expect(await bg(current)).not.toBe("rgba(0, 0, 0, 0)");
  expect(await bg(nav.getByRole("link", { name: "Vulnerabilities" }))).toBe("rgba(0, 0, 0, 0)");
  // One rule per group boundary: four groups (inventory, security, compliance, outputs).
  await expect(page.locator(".bl-pane-icons-rule")).toHaveCount(4);
});

test("the expanded navigation draws one rule between its blocks, never two in a row", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.goto(`/?ui=next#/scan/${ID}`);
  await page.getByTestId("result-meta").waitFor();
  const adjacent = await page.getByRole("navigation", { name: "Main" }).evaluate((nav) => {
    const items = [...nav.querySelectorAll("li, hr")];
    const isRule = (e: Element) => e.getAttribute("role") === "separator" || e.tagName === "HR" || e.className.toString().includes("Divider");
    let n = 0;
    for (let i = 1; i < items.length; i++) if (isRule(items[i]) && isRule(items[i - 1])) n++;
    return { n, rules: items.filter(isRule).length };
  });
  expect(adjacent.n).toBe(0);
  expect(adjacent.rules).toBeGreaterThan(0);
});

test("the navigation shows placeholders while a scan opens or runs, then its sections", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page, { scanDelay: 1200 });
  await page.goto(`/?ui=next#/scan/${ID}`);
  await expect(page.getByTestId("nav-loading")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main" })).not.toContainText("Open a scan to see its sections here.");
  await expect(page.getByTestId("result-meta")).toBeVisible();
  await expect(page.getByTestId("nav-loading")).toHaveCount(0);
  // Idle with nothing open: the hint, not placeholders.
  await page.goto("/?ui=next#/new");
  await expect(page.getByRole("navigation", { name: "Main" })).toContainText("Open a scan to see its sections here.");
  await expect(page.getByTestId("nav-loading")).toHaveCount(0);
});

test("the scan list is requested once on a first visit, again when it may be stale", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  let listCalls = 0;
  const NOT_LISTED = "other_3.0";
  await page.route("**/scans", async (r) => {
    listCalls++;
    await r.fulfill({ contentType: "application/json", body: JSON.stringify([LISTED]) });
  });
  await page.route(`**/scan?id=${NOT_LISTED}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ ...SCAN, id: NOT_LISTED }) }),
  );
  await page.goto("/?ui=next#/");
  await page.locator("main h1").first().waitFor();
  await expect(page.getByRole("link", { name: /SpringBootDemo/ }).first()).toBeVisible();
  // Let capabilities arrive and the router run again before counting.
  await page.evaluate(() => new Promise((r) => setTimeout(r, 400)));
  expect(listCalls).toBe(1);

  // A scan the list does not have: asked again.
  await page.evaluate((id) => (window.location.hash = `#/scan/${id}`), NOT_LISTED);
  await expect(page.getByTestId("result-meta")).toBeVisible();
  expect(listCalls).toBe(2);
  // One the list has: reused, no new request.
  await page.evaluate((id) => (window.location.hash = `#/scan/${id}`), ID);
  await expect(page.locator("main h1")).toHaveText("SpringBootDemo 1.1.0");
  expect(listCalls).toBe(2);
  // Back to Scan management from a scan: asked again.
  await page.evaluate(() => (window.location.hash = "#/"));
  await expect(page.getByRole("heading", { name: "Scan management" })).toBeVisible();
  await expect.poll(() => listCalls).toBe(3);
});

test("the tab title follows a running scan, not the screen it started from", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await stub(page);
  await page.route("**/scan-stream**", async (r) => {
    await new Promise((res) => setTimeout(res, 4000));
    await r.abort();
  });
  await page.goto("/?ui=next#/new");
  await page.fill("#project", "live");
  await page.fill("#version", "2.0");
  await page.getByTestId("run-scan").click();
  await expect(page).toHaveTitle("live 2.0 · BomLens");
});
