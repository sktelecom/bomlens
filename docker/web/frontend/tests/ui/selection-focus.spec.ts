// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Locator, type Page } from "@playwright/test";

import { DONE, SBOM } from "./fixtures";
import { waitForSettled } from "./settle";
import { seedThemeLang, type Theme } from "./visual";

/**
 * Selected and keyboard-focused are different looks.
 *
 * Both used to be the same dark ring with an offset, so a tile you had tabbed to
 * looked chosen and the chosen tile looked focused. Now a selection is a fill
 * plus a dark border (never a ring) and focus is the brand-red ring from --ring
 * (focus-visible only). These tests read computed styles, so they do not depend
 * on a screenshot baseline.
 */

const CAPS = { firmware: false, scanoss: false, docker: true, hostDir: "/work/acme" };

interface Look {
  border: string;
  borderStyle: string;
  cursor: string;
  background: string;
  shadow: string;
  opacity: string;
}

/** The properties that make up how a control looks in each state. */
async function look(el: Locator): Promise<Look> {
  return el.evaluate(async (node) => {
    // Colour and shadow transition over 150ms; read the end state, not a frame
    // of the fade.
    await Promise.all(node.getAnimations().map((a) => a.finished.catch(() => undefined)));
    const cs = getComputedStyle(node);
    return {
      border: cs.borderTopColor,
      borderStyle: cs.borderTopStyle,
      cursor: cs.cursor,
      background: cs.backgroundColor,
      shadow: cs.boxShadow,
      opacity: cs.opacity,
    };
  });
}

/** Computed rgb() of a token, resolved the way the page resolves it. */
async function tokenColour(page: Page, expr: string): Promise<string> {
  return page.evaluate((e) => {
    const probe = document.createElement("i");
    probe.style.color = e;
    document.body.appendChild(probe);
    const c = getComputedStyle(probe).color;
    probe.remove();
    return c;
  }, expr);
}

/** Move keyboard focus with Tab until `pick` matches the active element. */
async function tabTo(page: Page, pick: (el: Element) => boolean, max = 60) {
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    const hit = await page.evaluate(
      `(${pick.toString()})(document.activeElement)`,
    );
    if (hit) return;
  }
  throw new Error("focus never reached the target within " + max + " Tab presses");
}

async function stubNewScan(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(CAPS) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
}

for (const theme of ["light", "dark"] as Theme[]) {
  test(`new-scan tiles: default, hover, selected, focus and disabled all look different (${theme})`, async ({ page }) => {
    await seedThemeLang(page, theme, "en");
    await stubNewScan(page);
    await page.goto("/#/new");
    await page.locator("#project").waitFor();
    await page.mouse.move(0, 0);

    const selected = page.locator('[data-testid^="source-"][aria-pressed="true"]');
    await expect(selected).toHaveCount(1);
    const idle = page.locator('[data-testid^="source-"][aria-pressed="false"]:not([aria-disabled="true"])').first();
    // Firmware needs a capability the stub withholds, so its tile is the locked one.
    const locked = page.getByTestId("source-firmware-upload");
    await expect(locked).toHaveAttribute("aria-disabled", "true");

    const ring = await tokenColour(page, "hsl(var(--ring))");
    const foreground = await tokenColour(page, "hsl(var(--foreground))");

    // Rest states: no ring anywhere. Selected is a dark border on a filled tile.
    const idleLook = await look(idle);
    const selectedLook = await look(selected);
    const lockedLook = await look(locked);
    expect(idleLook.shadow).not.toContain(ring);
    expect(selectedLook.shadow, "a selected tile is not drawn with a ring").not.toContain(ring);
    expect(selectedLook.border).toBe(foreground);
    expect(selectedLook.background).not.toBe(idleLook.background);
    expect(idleLook.border).not.toBe(foreground);
    expect(lockedLook.shadow).not.toContain(ring);
    // The locked tile keeps its dashed border and is not clickable.
    await expect(locked).toHaveCSS("border-top-style", "dashed");
    await expect(locked).toHaveCSS("cursor", "not-allowed");

    // Hover: a hint of fill, still no ring, still not the selected look.
    await idle.hover();
    const hoverLook = await look(idle);
    expect(hoverLook.shadow).not.toContain(ring);
    expect(hoverLook.border).not.toBe(foreground);
    await page.mouse.move(0, 0);

    // Keyboard focus lands on the tiles in order. Tab to the first one, note
    // whether it is the selected one, then step to a second.
    await tabTo(page, (el) => (el.getAttribute("data-testid") ?? "").startsWith("source-"));
    const firstId = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));
    const first = page.getByTestId(firstId!);
    const firstPressed = (await first.getAttribute("aria-pressed")) === "true";
    const firstFocused = await look(first);
    expect(firstFocused.shadow, "focus draws the ring").toContain(ring);

    await page.keyboard.press("Tab");
    const secondId = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));
    expect(secondId).toMatch(/^source-/);
    const second = page.getByTestId(secondId!);
    const secondPressed = (await second.getAttribute("aria-pressed")) === "true";
    const secondFocused = await look(second);
    expect(secondFocused.shadow).toContain(ring);

    // One of the two is the selected tile, so we have it focused, and the other
    // is a plain tile that is only focused.
    const [focusedSelected, focusedPlain] =
      firstPressed || !secondPressed ? [firstFocused, secondFocused] : [secondFocused, firstFocused];
    if (firstPressed || secondPressed) {
      // Focused + selected keeps BOTH cues: the ring and the dark border/fill.
      expect(focusedSelected.shadow).toContain(ring);
      expect(focusedSelected.border).toBe(foreground);
      expect(focusedSelected.background).toBe(selectedLook.background);
    }
    // Focused but not selected: ring, and neither the dark border nor the fill.
    expect(focusedPlain.border).not.toBe(foreground);
    expect(focusedPlain.background).toBe(idleLook.background);

    // The five states are pairwise distinguishable by what is painted.
    const sig = (l: Look) =>
      `${l.border}|${l.borderStyle}|${l.cursor}|${l.background}|${l.shadow}|${l.opacity}`;
    const states = {
      default: sig(idleLook),
      hover: sig(hoverLook),
      selected: sig(selectedLook),
      focus: sig(focusedPlain),
      disabled: sig(lockedLook),
    };
    expect(new Set(Object.values(states)).size).toBe(Object.keys(states).length);
  });
}

async function openDependencies(page: Page) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${DONE.id}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(DONE) }),
  );
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }));
  await page.goto(`/?ui=next#/scan/${DONE.id}/dependencies`);
  await page.getByTestId("deps-view-graph").waitFor();
  await waitForSettled(page.locator("main"));
}

test("graph/tree switch: the chosen segment is solid, the tabbed-to segment has the ring", async ({ page }) => {
  await seedThemeLang(page, "light", "en");
  await openDependencies(page);
  await page.mouse.move(0, 0);

  const graph = page.getByTestId("deps-view-graph");
  const tree = page.getByTestId("deps-view-tree");
  const ring = await tokenColour(page, "hsl(var(--ring))");
  const primary = await tokenColour(page, "hsl(var(--primary))");

  await expect(graph).toHaveAttribute("aria-pressed", "true");
  const chosen = await look(graph);
  expect(chosen.background).toBe(primary);
  expect(chosen.shadow, "selection is a fill, not a ring").not.toContain(ring);
  const other = await look(tree);
  expect(other.background).not.toBe(primary);

  // Tab onto the unselected segment: the ring appears, the fill does not move.
  await tabTo(page, (el) => el.getAttribute("data-testid") === "deps-view-tree");
  const focused = await look(tree);
  expect(focused.shadow).toContain(ring);
  expect(focused.background).not.toBe(primary);
  // The chosen segment kept its fill and gained no ring while focus was elsewhere.
  const stillChosen = await look(graph);
  expect(stillChosen.background).toBe(primary);
  expect(stillChosen.shadow).not.toContain(ring);

  // Space selects it: now it is both chosen and focused, and shows both cues.
  await page.keyboard.press("Space");
  await expect(tree).toHaveAttribute("aria-pressed", "true");
  const both = await look(tree);
  expect(both.background).toBe(primary);
  expect(both.shadow).toContain(ring);
});
