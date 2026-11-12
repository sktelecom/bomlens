// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Light and dark theme, in one place.
 *
 * The `dark` class on <html> is the source of truth: the Tailwind tokens in
 * index.css switch on it, and the saved choice lives in localStorage under
 * `sbom.theme`. Primer reads its colours from three attributes instead
 * (`data-color-mode`, `data-light-theme`, `data-dark-theme`), so this module
 * writes them on the same element every time the class changes. Because they
 * sit on <html>, Primer overlays portalled to <body> get the same colours.
 *
 * `watchColorMode` mirrors the class even when something else flips it (a test
 * or a capture script that toggles the class directly), so the two can never
 * disagree.
 */

export type ThemeMode = "light" | "dark";

export const THEME_STORAGE_KEY = "sbom.theme";

/** The Primer themes the app loads (src/main.tsx imports only these two). */
export const PRIMER_LIGHT_THEME = "light";
export const PRIMER_DARK_THEME = "dark";

/** The element the theme is written on: a class list plus attributes. */
export interface ThemeRoot {
  classList: { contains(token: string): boolean; toggle(token: string, force?: boolean): boolean };
  getAttribute(name: string): string | null;
  setAttribute(name: string, value: string): void;
}

/** The saved choice if there is one (anything but "dark" reads as light), else the OS preference. */
export function initialTheme(saved: string | null, prefersDark: boolean): ThemeMode {
  if (saved) return saved === "dark" ? "dark" : "light";
  return prefersDark ? "dark" : "light";
}

/** The mode the root currently shows, read from the `dark` class. */
export function readTheme(root: ThemeRoot): ThemeMode {
  return root.classList.contains("dark") ? "dark" : "light";
}

/** Primer's colour mode for a theme (ThemeProvider takes day/night). */
export function primerColorMode(mode: ThemeMode): "day" | "night" {
  return mode === "dark" ? "night" : "day";
}

/** Write the Primer attributes so they match the `dark` class. Idempotent. */
export function syncColorMode(root: ThemeRoot): ThemeMode {
  const mode = readTheme(root);
  const set = (name: string, value: string) => {
    if (root.getAttribute(name) !== value) root.setAttribute(name, value);
  };
  set("data-color-mode", mode);
  set("data-light-theme", PRIMER_LIGHT_THEME);
  set("data-dark-theme", PRIMER_DARK_THEME);
  return mode;
}

/** Show a theme: the class and the Primer attributes together. */
export function applyTheme(root: ThemeRoot, mode: ThemeMode): void {
  root.classList.toggle("dark", mode === "dark");
  syncColorMode(root);
}

/** Show a theme and remember it. */
export function saveTheme(
  root: ThemeRoot,
  storage: Pick<Storage, "setItem">,
  mode: ThemeMode,
): void {
  applyTheme(root, mode);
  storage.setItem(THEME_STORAGE_KEY, mode);
}

/**
 * Keep the Primer attributes in step with the `dark` class and tell `onChange`
 * when the mode changes. Returns the unsubscribe function.
 */
export function watchColorMode(root: HTMLElement, onChange: (mode: ThemeMode) => void): () => void {
  let last = syncColorMode(root);
  const observer = new MutationObserver(() => {
    const mode = syncColorMode(root);
    if (mode !== last) {
      last = mode;
      onChange(mode);
    }
  });
  observer.observe(root, { attributes: true, attributeFilter: ["class"] });
  return () => observer.disconnect();
}
