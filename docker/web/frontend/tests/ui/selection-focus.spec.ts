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
// Filter chips: severity (Vulnerabilities), licence tier (Licenses), check kind
// (Conformance) and the removable component filter chips (Components). Same
// contract as the tiles above, asserted on computed styles, not screenshots:
//   - Tab onto a chip draws the brand ring, and that look is not the selected one
//   - choosing a chip gives it the selection cue (border or fill), never a ring
//   - once focus moves on, the selected chip keeps its cue and has no ring
//   - a chip that is not selected is never dimmed (computed opacity 1)
//   - a chip with nothing behind it (count 0) is the one deliberately faded state

const CHIP_DONE = {
  ...DONE,
  conformance: {
    result: "warn",
    format: "CycloneDX",
    checks: [
      { id: "timestamp", label: "Timestamp present", required: true, status: "pass", detail: "1 found" },
      { id: "license", label: "License coverage (recommended)", required: false, status: "warn", detail: "33%" },
      // No automated source, so it counts as "needs review": a third enabled kind.
      { id: "coverage", label: "Coverage", required: false, status: "warn", detail: "needs a person", source: "na" },
    ],
  },
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

const sig = (l: Look) =>
  `${l.border}|${l.borderStyle}|${l.cursor}|${l.background}|${l.shadow}|${l.opacity}`;

/** Keyboard focus arrives from the previous stop, so :focus-visible applies. */
async function focusByKeyboard(page: Page, el: Locator) {
  await el.focus();
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Tab");
  await expect(el).toBeFocused();
}

const OUTLINE_CHIPS: Array<{ name: string; section: string; chips: string; disabled: boolean }> = [
  // Legend pills only: the bar segments above them carry an aria-label, the pills do not.
  { name: "severity chips", section: "vulnerabilities", chips: "main button[aria-pressed]:not([aria-label])", disabled: true },
  { name: "licence chips", section: "licenses", chips: "main button[aria-pressed]:not([aria-label])", disabled: false },
  { name: "conformance chips", section: "conformance", chips: "main button[aria-pressed]", disabled: true },
];

for (const theme of ["light", "dark"] as Theme[]) {
  for (const c of OUTLINE_CHIPS) {
    test(`${c.name}: selection is a border, focus is the ring, nothing is dimmed (${theme})`, async ({ page }) => {
      await seedThemeLang(page, theme, "en");
      await openChipSection(page, c.section);

      const ring = await tokenColour(page, "hsl(var(--ring))");
      const foreground = await tokenColour(page, "hsl(var(--foreground))");
      const enabled = page.locator(`${c.chips}:not([disabled])`);
      // The conformance panel opens with one kind already chosen. Tag the first
      // two UNselected chips so they can be followed after the selection moves.
      const unselected = page.locator(`${c.chips}[aria-pressed="false"]:not([disabled])`);
      expect(await unselected.count(), "needs two unselected chips to compare").toBeGreaterThanOrEqual(2);
      await unselected.nth(0).evaluate((n) => n.setAttribute("data-probe", "target"));
      await unselected.nth(1).evaluate((n) => n.setAttribute("data-probe", "other"));
      const target = page.locator('[data-probe="target"]');
      const other = page.locator('[data-probe="other"]');

      // Rest: no unselected chip is dimmed, has a ring or the selected border; a
      // chip that starts selected has the border and no ring.
      for (let i = 0; i < (await enabled.count()); i++) {
        const chip = enabled.nth(i);
        const pressed = (await chip.getAttribute("aria-pressed")) === "true";
        const l = await look(chip);
        expect(l.opacity, "no enabled chip is faded").toBe("1");
        expect(l.shadow).not.toContain(ring);
        if (pressed) expect(l.border).toBe(foreground);
        else expect(l.border).not.toBe(foreground);
      }
      const rest = await look(target);

      // Keyboard focus: ring appears, border and fill stay those of an unselected chip.
      await focusByKeyboard(page, target);
      const focused = await look(target);
      expect(focused.shadow, "focus draws the ring").toContain(ring);
      expect(focused.border).toBe(rest.border);
      expect(focused.background).toBe(rest.background);
      expect(focused.opacity).toBe("1");
      expect(sig(focused)).not.toBe(sig(rest));

      // Space selects it: chosen AND focused, so both cues show.
      await page.keyboard.press("Space");
      await expect(target).toHaveAttribute("aria-pressed", "true");
      const both = await look(target);
      expect(both.shadow).toContain(ring);
      expect(both.border).toBe(foreground);

      // Focus moves on: the border stays, the ring goes, and the selected look is
      // neither the rest look nor the focus look.
      await page.keyboard.press("Tab");
      await expect(target).not.toBeFocused();
      await page.mouse.move(0, 0);
      const selected = await look(target);
      expect(selected.border, "selection is a dark border").toBe(foreground);
      expect(selected.shadow, "selection is never a ring").not.toContain(ring);
      expect(selected.opacity).toBe("1");
      expect(new Set([sig(rest), sig(focused), sig(selected)]).size).toBe(3);

      // A sibling that is not selected is not dimmed because another chip is.
      const sibling = await look(other);
      expect(sibling.opacity, "unselected siblings do not fade when a chip is chosen").toBe("1");
      expect(sibling.border).not.toBe(foreground);
      expect(sig(sibling)).not.toBe(sig(selected));

      // A chip with nothing behind it is the one faded, unclickable state.
      if (c.disabled) {
        const off = page.locator(`${c.chips}:disabled`).first();
        await expect(off).toHaveCount(1);
        const offLook = await look(off);
        expect(Number(offLook.opacity)).toBeLessThan(1);
        expect(offLook.cursor).toBe("not-allowed");
        expect(offLook.shadow).not.toContain(ring);
        expect(new Set([sig(rest), sig(focused), sig(selected), sig(offLook)]).size).toBe(4);
      }
    });
  }

  test(`component filter chips: solid fill when on, ring only under the keyboard, never faded (${theme})`, async ({ page }) => {
    await seedThemeLang(page, theme, "en");
    await openChipSection(page, "components?vulns=1&direct=1");

    const ring = await tokenColour(page, "hsl(var(--ring))");
    const selectedFill = await tokenColour(page, "hsl(var(--selected))");
    // The density switch beside them is pressable too, but it is not a filter chip.
    const chips = page.locator('main :not([data-testid="density-toggle"]) > button[aria-pressed]');
    await expect(chips).toHaveCount(2);
    const first = chips.nth(0);
    const second = chips.nth(1);

    for (const chip of [first, second]) {
      await expect(chip).toHaveAttribute("aria-pressed", "true");
      const l = await look(chip);
      expect(l.background, "an active filter chip is a solid fill").toBe(selectedFill);
      expect(l.opacity).toBe("1");
      expect(l.shadow, "selection is not a ring").not.toContain(ring);
    }
    const rest = await look(first);

    await focusByKeyboard(page, first);
    const focused = await look(first);
    expect(focused.shadow, "focus draws the ring").toContain(ring);
    expect(focused.background, "focus does not move the fill").toBe(selectedFill);
    expect(sig(focused)).not.toBe(sig(rest));
    // The neighbour was not focused, so it carries the fill but no ring.
    const neighbour = await look(second);
    expect(neighbour.shadow).not.toContain(ring);
    expect(neighbour.background).toBe(selectedFill);

    await page.keyboard.press("Tab");
    await expect(first).not.toBeFocused();
    const after = await look(first);
    expect(after.shadow).not.toContain(ring);
    expect(after.background).toBe(selectedFill);
    expect(after.opacity).toBe("1");
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
