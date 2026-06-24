import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * Phase 0 shell gates: accessibility (axe) and visual regression for the new
 * AppShell behind `?ui=next`, across light/dark × en/ko.
 *
 * Theme and language are seeded into localStorage before the app boots so each
 * combination is deterministic (no UI-toggle race). Visual snapshots are tagged
 * @visual and run in the pinned Playwright container so pixels are stable.
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
  // Wait for the rail to render (its accessible name is localized).
  await page.getByRole("navigation").first().waitFor();
}

const COMBOS: Array<{ theme: Theme; lang: Lang }> = [
  { theme: "light", lang: "en" },
  { theme: "dark", lang: "en" },
  { theme: "light", lang: "ko" },
  { theme: "dark", lang: "ko" },
];

for (const { theme, lang } of COMBOS) {
  test(`shell has no axe violations — ${theme}/${lang}`, async ({ page }) => {
    await openShell(page, theme, lang);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  });

  test(`shell matches baseline — ${theme}/${lang} @visual`, async ({ page }) => {
    await openShell(page, theme, lang);
    await expect(page).toHaveScreenshot(`shell-${theme}-${lang}.png`, {
      fullPage: true,
      animations: "disabled",
    });
  });
}

test("rail navigation switches the active section", async ({ page }) => {
  await openShell(page, "light", "en");
  const components = page.getByRole("button", { name: "Components" });
  await components.click();
  await expect(components).toHaveAttribute("aria-current", "page");
  // A non-AI scan must not expose the AI-only sections.
  await expect(page.getByRole("button", { name: "Models & datasets" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "G7 conformance" })).toHaveCount(0);
});
