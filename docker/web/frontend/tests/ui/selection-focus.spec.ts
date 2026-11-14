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
 * looked chosen and the chosen tile looked focused. Now a selection is a tinted
 * fill plus an accent border (never a ring) and focus is the outline from
 * --focus-outlineColor (focus-visible only). These tests read computed styles,
 * so they do not depend on a screenshot baseline.
 */

const CAPS = { firmware: false, scanoss: false, docker: true, hostDir: "/work/acme" };

interface Look {
  border: string;
  borderStyle: string;
  cursor: string;
  background: string;
  shadow: string;
  outline: string;
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
      outline: cs.outlineStyle === "none" || cs.outlineWidth === "0px" ? "none" : `${cs.outlineWidth} ${cs.outlineStyle} ${cs.outlineColor}`,
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

    // The tiles are one radio group: exactly one is checked.
    const selected = page.locator('[data-testid^="source-"][aria-checked="true"]');
    await expect(selected).toHaveCount(1);
    const idle = page.locator('[data-testid^="source-"][aria-checked="false"]:not([aria-disabled="true"])').first();
    // Firmware needs a capability the stub withholds, so its tile is the locked one.
    const locked = page.getByTestId("source-firmware-upload");
    await expect(locked).toHaveAttribute("aria-disabled", "true");

    const accent = await tokenColour(page, "var(--borderColor-accent-emphasis)");
    const ring = await tokenColour(page, "var(--focus-outlineColor)");

    // Rest states: no outline anywhere. Selected is an accent border on a tinted tile.
    const idleLook = await look(idle);
    const selectedLook = await look(selected);
    const lockedLook = await look(locked);
    expect(idleLook.outline).toBe("none");
    expect(selectedLook.outline, "a selected tile is not drawn with a ring").toBe("none");
    expect(selectedLook.border).toBe(accent);
    expect(selectedLook.background).not.toBe(idleLook.background);
    expect(idleLook.border).not.toBe(accent);
    expect(lockedLook.outline).toBe("none");
    // The locked tile keeps its dashed border and is not clickable.
    await expect(locked).toHaveCSS("border-top-style", "dashed");
    await expect(locked).toHaveCSS("cursor", "not-allowed");

    // Hover: a hint of fill, still no ring, still not the selected look.
    await idle.hover();
    const hoverLook = await look(idle);
    expect(hoverLook.outline).toBe("none");
    expect(hoverLook.border).not.toBe(accent);
    await page.mouse.move(0, 0);

    // The group is one tab stop, the selected tile: Tab lands on it, and the
    // next Tab leaves the tiles.
    await tabTo(page, (el) => (el.getAttribute("data-testid") ?? "").startsWith("source-"));
    const firstId = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));
    const first = page.getByTestId(firstId!);
    await expect(first).toHaveAttribute("aria-checked", "true");
    const focusedSelected = await look(first);
    expect(focusedSelected.outline, "focus draws the ring").toContain(ring);
    // Focused + selected keeps BOTH cues: the ring and the accent border/fill.
    expect(focusedSelected.border).toBe(accent);
    expect(focusedSelected.background).toBe(selectedLook.background);

    // Keyboard focus on a tile that is not selected (the keyboard was the last
    // input, so :focus-visible applies): ring, and neither the accent border nor the fill.
    await idle.focus();
    const focusedPlain = await look(idle);
    expect(focusedPlain.outline).toContain(ring);
    expect(focusedPlain.border).not.toBe(accent);
    expect(focusedPlain.background).toBe(idleLook.background);

    // The five states are pairwise distinguishable by what is painted.
    const sig = (l: Look) =>
      `${l.border}|${l.borderStyle}|${l.cursor}|${l.background}|${l.outline}|${l.opacity}`;
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
  const selectedFill = await tokenColour(page, "hsl(var(--selected))");

  await expect(graph).toHaveAttribute("aria-pressed", "true");
  const chosen = await look(graph);
  expect(chosen.background).toBe(selectedFill);
  expect(chosen.shadow, "selection is a fill, not a ring").not.toContain(ring);
  const other = await look(tree);
  expect(other.background).not.toBe(selectedFill);

  // Tab onto the unselected segment: the ring appears, the fill does not move.
  await tabTo(page, (el) => el.getAttribute("data-testid") === "deps-view-tree");
  const focused = await look(tree);
  expect(focused.shadow).toContain(ring);
  expect(focused.background).not.toBe(selectedFill);
  // The chosen segment kept its fill and gained no ring while focus was elsewhere.
  const stillChosen = await look(graph);
  expect(stillChosen.background).toBe(selectedFill);
  expect(stillChosen.shadow).not.toContain(ring);

  // Space selects it: now it is both chosen and focused, and shows both cues.
  await page.keyboard.press("Space");
  await expect(tree).toHaveAttribute("aria-pressed", "true");
  const both = await look(tree);
  expect(both.background).toBe(selectedFill);
  expect(both.shadow).toContain(ring);
});

// ---------------------------------------------------------------------------
// Filter chips: the removable component filter chips (Components). Same
// contract as the tiles above, asserted on computed styles, not screenshots:
//   - Tab onto a chip draws the brand ring, and that look is not the selected one
//   - choosing a chip gives it the selection cue (border or fill), never a ring
//   - once focus moves on, the selected chip keeps its cue and has no ring
//   - a chip that is not selected is never dimmed (computed opacity 1)
//   - a chip with nothing behind it (count 0) is the one deliberately faded state

const CHIP_DONE = {
  ...DONE,
};

async function openChipSection(page: Page, section: string) {
  await page.route("**/capabilities", (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify({ firmware: false, scanoss: false, docker: true }) }),
  );
  await page.route("**/results", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route("**/scans", (r) => r.fulfill({ contentType: "application/json", body: "[]" }));
  await page.route(`**/scan?id=${CHIP_DONE.id}`, (r) =>
    r.fulfill({ contentType: "application/json", body: JSON.stringify(CHIP_DONE) }),
  );
  await page.route("**/file**", (r) => r.fulfill({ contentType: "application/json", body: JSON.stringify(SBOM) }));
  await page.goto(`/?ui=next#/scan/${CHIP_DONE.id}/${section}`);
  await page.locator("main h1").first().waitFor();
  await waitForSettled(page.locator("main"));
  await page.mouse.move(0, 0);
}

/** Keyboard focus arrives from the previous stop, so :focus-visible applies. */
async function focusByKeyboard(page: Page, el: Locator) {
  await el.focus();
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Tab");
  await expect(el).toBeFocused();
}

// The Vulnerabilities severity buttons, the Licenses class buttons and the
// Conformance tabs are Primer-based and are checked in their own screen specs.

for (const theme of ["light", "dark"] as Theme[]) {
  // The Components filters are Primer buttons under the toolbar, one per active filter, that remove
  // it. They take the focus colour as an outline under the keyboard and are never faded.
  test(`component filter chips: outline only under the keyboard, never faded, Enter removes (${theme})`, async ({ page }) => {
    await seedThemeLang(page, theme, "en");
    await openChipSection(page, "components?vulns=1&direct=1");

    const focusColour = await tokenColour(page, "var(--focus-outlineColor)");
    const chips = page.getByRole("button", { name: /^Remove filter:/ });
    await expect(chips).toHaveCount(2);
    const outline = (el: Locator) =>
      el.evaluate((node) => {
        const cs = getComputedStyle(node);
        return { style: cs.outlineStyle, width: cs.outlineWidth, colour: cs.outlineColor, opacity: cs.opacity };
      });
    const first = chips.nth(0);
    await page.mouse.move(0, 0);
    const rest = await outline(first);
    expect(rest.opacity).toBe("1");
    expect(rest.style === "none" || rest.width === "0px", "a chip at rest has no outline").toBe(true);

    await focusByKeyboard(page, first);
    const focused = await outline(first);
    expect(focused.style).toBe("solid");
    expect(focused.width).not.toBe("0px");
    expect(focused.colour, "focus draws the outline in the focus colour").toBe(focusColour);
    expect((await outline(chips.nth(1))).style === "none" || (await outline(chips.nth(1))).width === "0px").toBe(true);

    await page.keyboard.press("Enter");
    await expect(chips).toHaveCount(1);
  });
}

// Text fields take focus on their own (autoFocus, a click), so their focus is
// Primer's own field focus: the field's outline in the focus colour
// (--focus-outlineColor, the navy accent), drawn on the field and not on the
// buttons' ring. A field at rest has no outline.
//
// This used to assert a foreground-coloured outline and "not the brand ring":
// the brand colour was red, and a red ring beside the red required marks read as
// an error. The accent is now navy (Primer's own focus colour for fields), so
// that premise is gone and the field takes the same focus colour as every other
// control.
for (const theme of ["light", "dark"] as Theme[]) {
  test(`a Tab-focused text field gets the navy focus outline, the same as other controls (${theme})`, async ({ page }) => {
    await seedThemeLang(page, theme, "en");
    await stubNewScan(page);
    await page.goto("/#/new");
    const field = page.locator("#version");
    await field.waitFor();
    await page.mouse.move(0, 0);

    const focusColour = await tokenColour(page, "var(--focus-outlineColor)");
    const wrapper = field.locator("xpath=ancestor::span[contains(@class,'TextInputBaseWrapper')][1]");
    const outline = (): Promise<{ style: string; width: string; colour: string }> =>
      wrapper.evaluate((node) => {
        const cs = getComputedStyle(node);
        return { style: cs.outlineStyle, width: cs.outlineWidth, colour: cs.outlineColor };
      });
    const rest = await outline();
    expect(rest.style === "none" || rest.width === "0px", "a field at rest has no outline").toBe(true);

    await focusByKeyboard(page, field);
    const focused = await outline();
    expect(focused.style).toBe("solid");
    expect(focused.width).not.toBe("0px");
    expect(focused.colour, "focus draws the outline in the focus colour").toBe(focusColour);
  });
}
