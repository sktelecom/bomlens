import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Shell gates for the new UI behind `?ui=next`:
 *  - accessibility (axe) + visual regression for the idle "New scan" screen,
 *    across light/dark × en/ko;
 *  - a stubbed end-to-end scan that proves the result content moved from tabs
 *    into the left-rail sections (Phase 1), with scan-type/data adaptation.
 *
 * Theme and language are seeded into localStorage before the app boots so each
 * combination is deterministic. Visual snapshots are tagged @visual and run in
 * the pinned Playwright container so pixels are stable.
 */

type Theme = "light" | "dark";
type Lang = "en" | "ko";

async function openShell(page: Page, theme: Theme, lang: Lang) {
  await page.addInitScript(
    ([t, l]) => {
      localStorage.setItem("sbom.theme", t);
      localStorage.setItem("sbom.lang", l);
    },
    [theme, lang],
  );
  await page.goto("/?ui=next");
  await page.getByRole("navigation").first().waitFor();
}

const COMBOS: Array<{ theme: Theme; lang: Lang }> = [
  { theme: "light", lang: "en" },
  { theme: "dark", lang: "en" },
  { theme: "light", lang: "ko" },
  { theme: "dark", lang: "ko" },
];

for (const { theme, lang } of COMBOS) {
  test(`idle shell has no axe violations — ${theme}/${lang}`, async ({ page }) => {
    await openShell(page, theme, lang);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  });

  test(`idle shell matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await openShell(page, theme, lang);
    await expect(page).toHaveScreenshot(`shell-idle-${theme}-${lang}.png`, {
      fullPage: true,
      animations: "disabled",
    });
  });
}

// A finished scan with an SBOM, a ScanCode artifact and vulnerabilities — enough
// to exercise data-gated rail sections (Dependencies, Source tree) and counts.
const DONE = {
  ok: true,
  mode: "SOURCE",
  results: [
    { name: "demo_1.0_bom.json", size: 100 },
    { name: "demo_1.0_scancode.json", size: 50 },
  ],
  security: {
    CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 2,
    vulnerabilities: [
      { id: "CVE-2024-0001", severity: "CRITICAL", pkg: "openssl", installed: "3.0.0", fixed: "3.0.1", title: "buffer overflow", cvss: 9.8 },
      { id: "CVE-2024-0002", severity: "HIGH", pkg: "zlib", installed: "1.2.0", fixed: "1.2.1", title: "oob read", cvss: 7.5 },
    ],
  },
  conformance: null,
  sbom: {
    components: 2,
    componentList: [
      { name: "openssl", version: "3.0.0", group: "", purl: "pkg:github/openssl/openssl", type: "library", licenses: ["Apache-2.0"], scope: "direct", maxSeverity: "CRITICAL", vulnCount: 1 },
      { name: "zlib", version: "1.2.0", group: "", purl: "pkg:github/madler/zlib", type: "library", licenses: ["Zlib"], scope: "transitive" },
    ],
  },
};

async function stubAndRun(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scan-stream**", (r) =>
    r.fulfill({ contentType: "text/event-stream", body: `event: done\ndata: ${JSON.stringify(DONE)}\n\n` }),
  );
  await page.goto("/?ui=next");
  await page.fill("#project", "demo");
  await page.fill("#version", "1.0");
  await page.getByRole("button", { name: /Run scan/i }).click();
}

test("scan results render in the rail sections, adapted to scan type", async ({ page }) => {
  await stubAndRun(page);

  // Result sections appear in the rail; AI-only ones stay hidden for a SOURCE scan.
  await expect(page.getByRole("button", { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Components/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Vulnerabilities/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Dependencies/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Source tree/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Models & datasets/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /G7 conformance/ })).toHaveCount(0);

  // Overview leads; switching to Components shows the table content.
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByRole("button", { name: /^Components/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();

  // Vulnerabilities section shows the CVE rows.
  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  await expect(page.getByText("CVE-2024-0001").first()).toBeVisible();
});

test("Components table shows Scope/Risk and filters on the full set", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();

  // Scope + Risk columns render from the joined data.
  await expect(page.getByRole("button", { name: "Scope", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Risk", exact: true })).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toBeVisible();

  // "Has vulnerabilities" narrows to the component with a CVE (openssl only).
  await page.getByRole("button", { name: "Has vulnerabilities" }).click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);

  // Clearing it brings zlib back; "Direct only" then also excludes the transitive zlib.
  await page.getByRole("button", { name: "Has vulnerabilities" }).click();
  await page.getByRole("button", { name: "Direct only" }).click();
  await expect(page.getByText("zlib", { exact: true })).toHaveCount(0);
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
});

test("components section matches baseline — light/en @visual", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByText("openssl", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toHaveScreenshot("components-light-en.png", {
    animations: "disabled",
  });
});

test("results view has no axe violations", async ({ page }) => {
  await stubAndRun(page);
  await page.getByRole("button", { name: /^Components/ }).click();
  await expect(page.getByText("openssl", { exact: true }).first()).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
