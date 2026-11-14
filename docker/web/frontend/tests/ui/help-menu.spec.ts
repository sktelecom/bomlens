// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { waitForSettled } from "./settle";

/**
 * The way out of the app: documentation, the demo, and which version is
 * running. Every other external link lived inside a scan form, so a reader who
 * wanted the docs had to already be starting a scan.
 *
 * The version comes from `capabilities`, which is empty on a local build. That
 * case is tested too: a build with no stamp says so rather than showing a blank
 * where a number belongs.
 */
async function open(page: Page, version: string | undefined) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        firmware: false,
        scanoss: false,
        docker: true,
        ...(version === undefined ? {} : { version }),
      }),
    }),
  );
  await page.route("**/results", (r) =>
    r.fulfill({ contentType: "application/json", body: "[]" }),
  );
  await page.goto("/?ui=next#/new");
  await page.locator("#project").waitFor();
}

test("the help menu opens with documentation and demo links", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();

  // A menu's entries are menu items, links underneath.
  const docs = page.getByRole("menuitem", { name: /Documentation/ });
  const demo = page.getByRole("menuitem", { name: /Live demo/ });
  await expect(docs).toBeVisible();
  await expect(demo).toBeVisible();
  // Opened away from the app: a scan in progress is not navigated out from.
  await expect(docs).toHaveAttribute("target", "_blank");
  await expect(docs).toHaveAttribute("rel", /noopener/);
  await expect(demo).toHaveAttribute("target", "_blank");
});

test("the menu reports the running version", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("app-version")).toHaveText("Version 1.10.5");
});

test("a build with no version stamp says so rather than showing a blank", async ({
  page,
}) => {
  await open(page, "");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("app-version")).toHaveText(
    "Version not stamped in this build",
  );
});

test("the menu closes on Escape and from the keyboard", async ({ page }) => {
  await open(page, "1.10.5");
  const trigger = page.getByTestId("help-menu");

  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("app-version")).toBeVisible();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");

  await page.keyboard.press("Escape");
  await expect(page.getByTestId("app-version")).toHaveCount(0);
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
});

test("the open menu has no axe violations", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("app-version")).toBeVisible();
  // The menu fades in; axe would read the text mid-fade.
  await waitForSettled(page.locator('[data-component="ActionMenu.Overlay"]'));
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});

test("the menu offers getting started, shortcuts and what changed", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("help-start")).toHaveAttribute("href", /\/start\/first-scan\/$/);
  await expect(page.getByTestId("help-shortcuts")).toBeVisible();
  await expect(page.getByTestId("help-whats-new")).toHaveAttribute(
    "href",
    "https://github.com/sktelecom/bomlens/releases/tag/v1.10.5",
  );
});

test("a build with no version stamp links the release list", async ({ page }) => {
  await open(page, "");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("help-whats-new")).toHaveAttribute(
    "href",
    "https://github.com/sktelecom/bomlens/releases",
  );
});

test("the shortcut list opens from the menu and closes with Escape", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();
  await page.getByTestId("help-shortcuts").click();
  const dialog = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId("shortcut-list").getByRole("listitem")).not.toHaveCount(0);
  // The dialog fades in; axe would read the text mid-fade.
  await waitForSettled(dialog);
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  // Focus returns to the control that opened it.
  await expect(page.getByTestId("help-menu")).toBeFocused();
});

test("? with the help menu open closes the menu and opens the list", async ({ page }) => {
  await open(page, "1.10.5");
  await page.getByTestId("help-menu").click();
  await expect(page.getByTestId("app-version")).toBeVisible();
  await page.keyboard.press("?");
  await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
  await expect(page.getByTestId("app-version")).toHaveCount(0);
});

test("the version is part of a menu item, so the keyboard reaches it", async ({ page }) => {
  await open(page, "1.10.5");
  const trigger = page.getByTestId("help-menu");
  await trigger.focus();
  await page.keyboard.press("Enter");
  const item = page.getByRole("menuitem", { name: /What's new/ });
  await expect(item).toBeVisible();
  // Opened from the keyboard, the menu puts focus on its first item.
  await expect(page.getByRole("menuitem").first()).toBeFocused();
  // Walk down with the arrow keys until the item that carries the version
  // has focus; it has to be reachable this way, not only by pointer.
  for (let i = 0; i < 8; i++) {
    if (await item.evaluate((el) => el === document.activeElement)) break;
    await page.keyboard.press("ArrowDown");
  }
  await expect(item).toBeFocused();
  await expect(item.getByTestId("app-version")).toHaveText("Version 1.10.5");
  // Links out say they open a new tab.
  await expect(page.getByRole("menuitem", { name: /Documentation/ })).toContainText("opens in a new tab");
});

test("? opens the shortcut list, but not while typing in a field", async ({ page }) => {
  await open(page, "1.10.5");
  await page.locator("#project").focus();
  await page.keyboard.press("?");
  await expect(page.locator("#project")).toHaveValue("?");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press("?");
  await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
});

test("the empty scan list offers the demo next to the first scan", async ({ page }) => {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.goto("/?ui=next#/");
  await expect(page.getByText("Generate your first SBOM")).toBeVisible();
  await expect(page.getByRole("link", { name: "New scan" }).first()).toBeVisible();
  const demo = page.getByTestId("empty-demo-link");
  await expect(demo).toHaveAttribute("href", /\/demo\/$/);
  await expect(demo).toHaveAttribute("target", "_blank");
});
