// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { DONE } from "./fixtures";
import { waitForSettled } from "./settle";
import { seedThemeLang, type Lang, type Theme } from "./visual";

// The Licenses screen: the classification bar as the filter, the license
// distribution, conflicts with the outbound license, terms that need review and
// what each license asks of a redistributor.

type Item = Record<string, unknown>;
const mk = (o: Item): Item => ({ name: "x", version: "1.0", group: "", purl: "", type: "library", licenses: ["MIT"], ...o });

const WHY_STRONG =
  "Distributing a combined work requires the whole work to be offered under the copyleft license, which the declared permissive outbound license does not do.";
const WHY_WEAK =
  "File- or library-level reciprocity: changes to the dependency stay under its license, and static linking adds obligations. Distributing your own code under the permissive license is still fine.";

/** 25 filler licenses (permissive-looking refs fall to uncategorized) plus one of each interesting kind. */
const FILLER = Array.from({ length: 25 }, (_, i) =>
  mk({ name: `lib-${i}`, purl: `pkg:npm/lib-${i}@1.0`, licenses: [`LicenseRef-L${String(i).padStart(2, "0")}`], licenseConflict: "unknown", licenseConflictWhy: "The dependency's license was not recognised." }),
);
const LIST: Item[] = [
  mk({ name: "mit-a", group: "org.example", purl: "pkg:maven/org.example/mit-a@1.0", licenses: ["MIT"], licenseConflict: "compatible" }),
  mk({ name: "mit-b", purl: "pkg:npm/mit-b@1.0", licenses: ["MIT"], licenseConflict: "compatible" }),
  mk({ name: "mit-c", purl: "pkg:npm/mit-c@1.0", licenses: ["MIT"], licenseConflict: "compatible" }),
  mk({ name: "gpl-dep", purl: "pkg:npm/gpl-dep@1.0", licenses: ["GPL-3.0-only"], licenseConflict: "incompatible", licenseConflictWhy: WHY_STRONG }),
  mk({ name: "lgpl-a", purl: "pkg:npm/lgpl-a@1.0", licenses: ["LGPL-2.1-only"], licenseConflict: "conditional", licenseConflictWhy: WHY_WEAK }),
  mk({ name: "lgpl-b", purl: "pkg:npm/lgpl-b@1.0", licenses: ["LGPL-2.1-only"], licenseConflict: "conditional", licenseConflictWhy: WHY_WEAK }),
  mk({ name: "dual", purl: "pkg:npm/dual@1.0", licenses: ["MIT OR Apache-2.0"], licenseConflict: "compatible" }),
  mk({ name: "llama", purl: "pkg:huggingface/llama@1", type: "machine-learning-model", licenses: ["LLaMA-3.1"], licenseReview: "behavioral-use" }),
  mk({ name: "nc-data", purl: "pkg:huggingface/nc-data@1", type: "data", licenses: ["CC-BY-NC-4.0"], licenseReview: "non-commercial" }),
  mk({ name: "no-license", purl: "pkg:npm/no-license@1.0", licenses: [] }),
  ...FILLER,
];

const doneWith = (list: Item[], over: Record<string, unknown> = {}) => ({
  ...DONE,
  sbom: { ...DONE.sbom, components: list.length, outboundLicense: "Apache-2.0", componentList: list, ...over },
});

async function open(page: Page, done: Record<string, unknown> & { id: string }, hash = "/licenses", theme: Theme = "light", lang: Lang = "en") {
  await seedThemeLang(page, theme, lang);
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true, spdxExport: false }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${done.id}`, (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(done) }));
  await page.goto(`/#/scan/${done.id}${hash}`);
  await page.locator("main h1").first().waitFor();
  await page.locator("main section, main [data-testid=licenses-empty]").first().waitFor();
  await waitForSettled(page.locator("main"));
  await page.mouse.move(0, 0);
}

const main = (page: Page) => page.locator("main");
/** The legend pill of a class (the bar segment carries the same name). */
const pill = (page: Page, name: string) => page.getByTestId("license-classes").locator("button.bl-tierchip", { hasText: name });
const dist = (page: Page) => page.getByRole("list", { name: /^(Licenses|라이선스)$/ });

test("the screen shows the class box, the conflicts, the distribution, review and obligations", async ({ page }) => {
  await open(page, doneWith(LIST));
  await expect(main(page).getByRole("heading", { level: 2, name: "Licenses", exact: true })).toBeVisible();
  await expect(main(page).getByRole("heading", { name: "Conflicts with your outbound license (Apache-2.0)" })).toBeVisible();
  await expect(main(page).getByRole("heading", { name: "License review needed" })).toBeVisible();
  await expect(main(page).getByRole("heading", { name: "What each license asks of you" })).toBeVisible();
  await expect(page.getByTestId("license-conflict-off")).toHaveCount(0);
  // The verdict is a word, worst first.
  const verdicts = main(page).getByTestId("license-conflicts").locator(".prc-Label-Label, [class*='Label']").filter({ hasText: /Cannot be met|Depends on how you ship|Cannot judge/ });
  await expect(verdicts.first()).toHaveText("Cannot be met");
  // One reason sentence for the two LGPL rows.
  await expect(main(page).getByText(/^File- or library-level reciprocity/)).toHaveCount(1);
});

test("the bar and the legend toggle the class filter, the URL follows, and every box narrows", async ({ page }) => {
  await open(page, doneWith(LIST));
  const classes = page.getByTestId("license-classes");
  const chip = pill(page, "Weak copyleft");
  const seg = classes.getByRole("group").getByRole("button", { name: "Weak copyleft 2" });
  await expect(chip).toHaveAttribute("aria-pressed", "false");

  await chip.click();
  await expect(page).toHaveURL(/tier=weak-copyleft/);
  await expect(chip).toHaveAttribute("aria-pressed", "true");
  await expect(seg).toHaveAttribute("aria-pressed", "true");
  // The bar keeps the whole scan's proportions: the other classes are still there.
  await expect(pill(page, "Permissive")).toBeVisible();
  // Distribution, conflicts and obligations narrow to the class; review has none left.
  await expect(dist(page).getByRole("listitem")).toHaveCount(1);
  await expect(dist(page).getByText("LGPL-2.1-only", { exact: true })).toBeVisible();
  await expect(main(page).getByText("gpl-dep")).toHaveCount(0);
  await expect(main(page).getByText("lgpl-a")).toBeVisible();
  await expect(page.getByTestId("license-review")).toHaveCount(0);
  await expect(page.getByTestId("license-obligations").getByText("LGPL-2.1-only", { exact: true })).toBeVisible();
  await expect(page.getByTestId("license-obligations").getByText("MIT", { exact: true })).toHaveCount(0);
  await expect(page.getByTestId("license-tier-note")).toContainText("Showing Weak copyleft only: 2 components.");
  // The note lives in the class box, under the legend, and is a polite live region.
  await expect(classes.getByTestId("license-tier-note")).toHaveAttribute("aria-live", "polite");

  // The bar segment toggles it off again.
  await seg.click();
  await expect(page).not.toHaveURL(/tier=/);
  await expect(chip).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("license-tier-note")).toBeEmpty();

  // Keyboard: Space on the chip selects, and the clear link in the note clears.
  await chip.focus();
  await page.keyboard.press("Space");
  await expect(chip).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("license-tier-note").getByRole("button", { name: "Clear filters" }).click();
  await expect(chip).toHaveAttribute("aria-pressed", "false");
  await expect(page).not.toHaveURL(/tier=/);
});

test("a link with a class opens filtered, and a class that does not exist says so", async ({ page }) => {
  await open(page, doneWith(LIST), "/licenses?tier=strong-copyleft");
  await expect(pill(page, "Strong copyleft")).toHaveAttribute("aria-pressed", "true");
  await expect(dist(page).getByRole("listitem")).toHaveCount(1);
  await expect(page.getByTestId("license-bad-tier")).toHaveCount(0);

  await page.goto(`/#/scan/${DONE.id}/licenses?tier=bogus`);
  const banner = page.getByTestId("license-bad-tier");
  await expect(banner).toContainText('The class "bogus" is not one of the six');
  // Nothing is filtered, and the address is left as it came.
  await expect(page).toHaveURL(/tier=bogus/);
  await expect(page.getByTestId("license-classes").locator("[aria-pressed=true]")).toHaveCount(0);
  await banner.getByRole("button", { name: "Clear filters" }).click();
  await expect(banner).toHaveCount(0);
  await expect(page).not.toHaveURL(/tier=/);
});

test("the distribution sorts by count or by name", async ({ page }) => {
  await open(page, doneWith(LIST));
  const names = () => dist(page).locator(".bl-licrow-name").allInnerTexts();
  expect((await names())[0]).toBe("MIT");
  await page.getByRole("button", { name: "By name" }).click();
  const byName = await names();
  const shown = byName.filter((n) => n !== "No license declared");
  expect(shown).toEqual([...shown].sort((a, b) => a.localeCompare(b)));
  await page.getByRole("button", { name: "By count" }).click();
  expect((await names())[0]).toBe("MIT");
});

test("a license row opens Components filtered to it, and the unlicensed row is not a link", async ({ page }) => {
  await open(page, doneWith(LIST));
  const row = dist(page).getByRole("link", { name: /^GPL-3.0-only,/ });
  await expect(row).toHaveAttribute("href", `#/scan/${DONE.id}/components?license=GPL-3.0-only`);
  await expect(dist(page).getByRole("link")).toHaveCount(20);
  await row.click();
  await expect(page.locator("main h1")).toHaveText("Components");
  await expect(page).toHaveURL(/license=GPL-3.0-only/);

  await page.goBack();
  await expect(main(page).getByText("No license declared")).toBeVisible();
  await expect(main(page).getByRole("link", { name: /No license declared/ })).toHaveCount(0);
});

test("a long list opens on the busiest twenty and folds", async ({ page }) => {
  await open(page, doneWith(LIST));
  const toggle = page.getByTestId("license-summary-toggle");
  await expect(toggle).toHaveText(/^Show all \d+ licenses$/);
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  const id = await toggle.getAttribute("aria-controls");
  const links = page.locator(`[id="${id}"]`).getByRole("link");
  await expect(links).toHaveCount(20);
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(toggle).toHaveText("Show fewer");
  expect(await links.count()).toBeGreaterThan(20);
  await toggle.click();
  await expect(links).toHaveCount(20);
});

test("obligations: chips, an expression with its alternatives, and a fold after eight", async ({ page }) => {
  await open(page, doneWith(LIST));
  const box = page.getByTestId("license-obligations");
  await box.getByTestId("license-obligations-toggle").click();
  const row = (id: string) => box.locator("li", { has: page.getByText(id, { exact: true }) }).first();
  await expect(row("GPL-3.0-only").getByText("Disclose source")).toBeVisible();
  await expect(row("LLaMA-3.1").getByText("Needs checking")).toBeVisible();
  await expect(row("MIT OR Apache-2.0")).toContainText("Choose one");
  await expect(box.getByText(/not a legal determination/)).toBeVisible();
  const toggle = box.getByTestId("license-obligations-toggle");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  const id = await toggle.getAttribute("aria-controls");
  const items = page.locator(`[id="${id}"] > li`);
  expect(await items.count()).toBeGreaterThan(8);
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(items).toHaveCount(8);
});

test("without an outbound license it says so, and offers the re-scan only where the form has the field", async ({ page }) => {
  const list = [mk({ name: "a", purl: "pkg:npm/a@1" })];
  const withConfig = (source: string) => ({ ...doneWith(list, { outboundLicense: undefined }), scanConfig: { source, project: "demo", version: "1.0" } });
  await open(page, withConfig("current-dir"));
  await expect(page.getByTestId("license-conflict-off")).toContainText("Outbound-license conflicts were not checked");
  await expect(main(page).getByText(/Conflicts with your outbound license/)).toHaveCount(0);
  await expect(main(page).getByText(/--license/)).toBeHidden();
  await main(page).getByText("Command line", { exact: true }).click();
  await expect(main(page).getByText(/--license/)).toBeVisible();

  const second = await page.context().newPage();
  await open(second, { ...withConfig("sbom-upload"), id: "up_1.0" });
  await expect(second.getByTestId("license-conflict-off")).toContainText("someone else produced");
  await expect(second.getByTestId("rescan-with-license")).toHaveCount(0);
});

test("a scan with no components shows the empty state", async ({ page }) => {
  await open(page, doneWith([]));
  await expect(page.getByTestId("licenses-empty")).toContainText("No licenses were detected.");
  await expect(page.getByTestId("license-classes")).toHaveCount(0);
});

const LONG = "org.very.long.group.name.that.keeps.going.and.going.and.going.on.and.on.example";
const WIDE = doneWith([
  mk({ name: "n".repeat(70), group: LONG, version: "1.2.3-SNAPSHOT-with-a-long-qualifier-0123456789", purl: "pkg:maven/x/y@1", licenses: ["LicenseRef-" + "scancode-very-long-identifier-".repeat(3)], licenseConflict: "incompatible", licenseConflictWhy: "Some reason." }),
  mk({ name: "plain", purl: "pkg:npm/plain@1", licenses: ["GPL-2.0-only"], licenseConflict: "conditional", licenseConflictWhy: WHY_WEAK }),
  mk({ name: "m", purl: "pkg:npm/m@1", licenses: ["MIT"], licenseConflict: "compatible" }),
]);

for (const lang of ["en", "ko"] as const) {
  for (const width of [1024, 1280, 1440, 1536]) {
    test(`layout at ${width}px (${lang}): nothing clipped, no ellipsis, no sideways scroll`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await open(page, WIDE, "/licenses", "light", lang);
      // The screen's own boxes; the shell's title line above them is not this screen.
      const bad = await page.locator("main").evaluate((root) => {
        const out: string[] = [];
        for (const el of Array.from(root.querySelectorAll<HTMLElement>("section *"))) {
          const cs = getComputedStyle(el);
          if (cs.textOverflow === "ellipsis") out.push(`ellipsis: ${el.tagName}.${el.className} ${el.outerHTML.slice(0, 120)}`);
          if (el.closest("svg") || el.closest(".bl-visually-hidden, [class*='VisuallyHidden']")) continue;
          const text = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent ?? "").trim());
          if (text && el.scrollWidth > el.clientWidth + 1 && cs.display !== "inline") out.push(`clipped: ${el.tagName}.${el.className}`);
        }
        const doc = document.documentElement;
        if (doc.scrollWidth > doc.clientWidth) out.push("page scrolls sideways");
        return out;
      });
      expect(bad).toEqual([]);
    });
  }
}

for (const lang of ["en", "ko"] as const) {
  for (const theme of ["light", "dark"] as const) {
    test(`axe finds nothing on Licenses (${theme}/${lang})`, async ({ page }) => {
      await open(page, doneWith(LIST), "/licenses", theme, lang);
      const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(res.violations).toEqual([]);
      // And with a class chosen.
      await page.getByTestId("license-classes").locator("button.bl-tierchip").nth(1).click();
      await waitForSettled(page.locator("main"));
      const res2 = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(res2.violations).toEqual([]);
    });
  }
}

test("a class the scan has no license in says so inside the class box", async ({ page }) => {
  await open(page, doneWith(LIST), "/licenses?tier=network-copyleft");
  const note = page.getByTestId("license-classes").getByTestId("license-tier-note");
  await expect(note).toContainText("This scan has no licenses in the Network copyleft class.");
  await expect(page.getByTestId("license-bad-tier")).toHaveCount(0);
  await note.getByRole("button", { name: "Clear filters" }).click();
  await expect(page).not.toHaveURL(/tier=/);
  await expect(dist(page).getByRole("listitem").first()).toBeVisible();
});

test("a long verdict group shows five rows and folds the rest, headings kept", async ({ page }) => {
  await open(page, doneWith(LIST));
  const toggle = page.getByTestId("license-conflict-toggle-unknown");
  await expect(toggle).toHaveText("Show all 25");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  const table = page.locator(`[id="${await toggle.getAttribute("aria-controls")}"]`);
  await expect(table.getByRole("row")).toHaveCount(6);
  await expect(table.getByRole("columnheader", { name: "Name" })).toBeVisible();
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(table.getByRole("row")).toHaveCount(26);
  // A group of five or fewer has no button.
  await expect(page.getByTestId("license-conflict-toggle-conditional")).toHaveCount(0);
  // Each table has its own name: the verdict and its reason.
  await expect(page.getByRole("table", { name: /^Cannot be met: / })).toHaveCount(1);
});

test("a reason with no translation is replaced by a notice in Korean, original in the tooltip", async ({ page }) => {
  const odd = "Something a newer scanner wrote.";
  const list = [mk({ name: "odd", purl: "pkg:npm/odd@1", licenses: ["GPL-3.0-only"], licenseConflict: "incompatible", licenseConflictWhy: odd })];
  await open(page, doneWith(list), "/licenses", "light", "ko");
  await expect(page.getByText(odd)).toHaveCount(0);
  await expect(page.locator(`[title="${odd}"]`)).toContainText("번역이 없습니다");
});

test("the unchecked-conflicts banner sits right under the title", async ({ page }) => {
  await open(page, doneWith([mk({ name: "a", purl: "pkg:npm/a@1" })], { outboundLicense: undefined }));
  const banner = page.getByTestId("license-conflict-off");
  const title = page.locator("main h1").first();
  const tb = (await title.boundingBox())!;
  const bb = (await banner.boundingBox())!;
  const cb = (await page.getByTestId("license-classes").boundingBox())!;
  expect(bb.y).toBeGreaterThan(tb.y);
  expect(bb.y).toBeLessThan(cb.y);
});

for (const theme of ["light", "dark"] as const) {
  test(`class buttons: keyboard focus is the focus outline, selection is the accent border, nothing but the bar fades (${theme})`, async ({ page }) => {
    await open(page, doneWith(LIST), "/licenses", theme);
    const look = (loc: ReturnType<Page["locator"]>) =>
      loc.evaluate((el) => {
        const cs = getComputedStyle(el);
        const probe = document.createElement("i");
        probe.style.cssText = "outline-color: var(--focus-outlineColor); border-color: var(--borderColor-accent-emphasis)";
        document.body.append(probe);
        const tokens = getComputedStyle(probe);
        const out = {
          outlineStyle: cs.outlineStyle,
          outlineWidth: cs.outlineWidth,
          outline: cs.outlineColor,
          border: cs.borderTopColor,
          opacity: cs.opacity,
          focusToken: tokens.outlineColor,
          accentToken: tokens.borderTopColor,
        };
        probe.remove();
        return out;
      });
    const pills = page.getByTestId("license-classes").locator("button.bl-tierchip");
    const bar = page.getByTestId("license-classes").locator(".bl-lic-bar > button");
    for (const target of [pills.first(), bar.first()]) {
      await target.focus();
      await page.keyboard.press("Shift+Tab");
      await page.keyboard.press("Tab");
      await expect(target).toBeFocused();
      const focused = await look(target);
      expect(focused.outlineStyle).toBe("solid");
      expect(focused.outline).toBe(focused.focusToken);
      await page.keyboard.press("Enter");
      await expect(target).toHaveAttribute("aria-pressed", "true");
      await page.keyboard.press("Tab");
      await page.mouse.move(0, 0);
      const selected = await look(target);
      expect(selected.outlineStyle === "none" || selected.outlineWidth === "0px").toBe(true);
      if (target === pills.first()) {
        expect(selected.border).toBe(selected.accentToken);
        expect(selected.border).not.toBe(focused.outline);
      }
      // Choosing again clears it for the next round.
      await target.click();
      await page.mouse.move(0, 0);
    }
    // Choose one class: the other pills stay at full strength; only the bar's segments fade.
    await pills.first().click();
    await page.mouse.move(0, 0);
    expect((await look(pills.nth(1))).opacity).toBe("1");
    expect(Number((await look(bar.nth(1))).opacity)).toBeGreaterThanOrEqual(0.4);
  });
}
