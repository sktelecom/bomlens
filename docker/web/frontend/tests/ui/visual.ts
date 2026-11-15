// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

/**
 * Shared pieces for the visual baselines, so every spec that captures a screen
 * captures it the same way. The baselines are produced and compared in one
 * pinned container at a 0-pixel tolerance, which only holds if the capture
 * conditions are identical everywhere: same theme/language seeding, same
 * settling, same neutral pointer.
 */

export type Theme = "light" | "dark";
export type Lang = "en" | "ko";

/** The four theme x language combinations every section is captured in. */
export const COMBOS: Array<{ theme: Theme; lang: Lang }> = [
  { theme: "light", lang: "en" },
  { theme: "dark", lang: "en" },
  { theme: "light", lang: "ko" },
  { theme: "dark", lang: "ko" },
];

/** Pin the theme and language before the app boots. */
export async function seedThemeLang(page: Page, theme: Theme, lang: Lang) {
  await page.addInitScript(
    ([t, l]) => {
      localStorage.setItem("sbom.theme", t);
      localStorage.setItem("sbom.lang", l);
    },
    [theme, lang],
  );
}

// The page scrolls (the top bar and the navigation stick), and `main` mounts
// with `animate-fade-in` (translateY(4px) -> 0). A non-zero scroll position or
// an unsettled transform shifts the whole tall section a few px, a
// deterministic-looking but flaky ~3% diff. Let the animations finish, reset
// the page scroll to the top, and wait two animation frames so layout has fully
// settled before the capture.
export async function waitForMainSettled(page: Page) {
  await page.locator("main").evaluate(async (el) => {
    await Promise.all(el.getAnimations().map((a) => a.finished.catch(() => undefined)));
    window.scrollTo(0, 0);
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}

/**
 * Capture the content canvas as `<name>-<theme>-<lang>.png`.
 *
 * Note what a passing snapshot does and does not prove: only what fits the
 * canvas is compared, so anything below the fold of a long section needs a
 * functional assertion of its own.
 */
export async function captureMain(
  page: Page,
  name: string,
  theme: Theme,
  lang: Lang,
) {
  await waitForMainSettled(page);
  await page.mouse.move(0, 0); // neutral pointer — avoid hover-state flake
  await expect(page.locator("main")).toHaveScreenshot(
    `${name}-${theme}-${lang}.png`,
    { animations: "disabled" },
  );
}
