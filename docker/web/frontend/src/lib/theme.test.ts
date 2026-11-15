// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  applyTheme,
  initialTheme,
  primerColorMode,
  readTheme,
  saveTheme,
  syncColorMode,
  THEME_STORAGE_KEY,
  watchColorMode,
  type ThemeRoot,
} from "./theme";

function fakeRoot(dark = false) {
  const classes = new Set<string>(dark ? ["dark"] : []);
  const attrs = new Map<string, string>();
  const root: ThemeRoot = {
    classList: {
      contains: (c) => classes.has(c),
      toggle: (c, force) => {
        const on = force ?? !classes.has(c);
        if (on) classes.add(c);
        else classes.delete(c);
        return on;
      },
    },
    getAttribute: (n) => attrs.get(n) ?? null,
    setAttribute: (n, v) => void attrs.set(n, v),
  };
  return { root, classes, attrs };
}

describe("initialTheme", () => {
  it("prefers the saved choice over the OS", () => {
    expect(initialTheme("dark", false)).toBe("dark");
    expect(initialTheme("light", true)).toBe("light");
  });

  it("follows the OS when nothing is saved", () => {
    expect(initialTheme(null, true)).toBe("dark");
    expect(initialTheme(null, false)).toBe("light");
    expect(initialTheme("", true)).toBe("dark");
  });

  it("reads any other saved value as light, as before", () => {
    expect(initialTheme("sepia", true)).toBe("light");
  });
});

describe("syncColorMode", () => {
  it("writes the Primer attributes from the dark class", () => {
    const { root, attrs } = fakeRoot(true);
    expect(syncColorMode(root)).toBe("dark");
    expect(Object.fromEntries(attrs)).toEqual({
      "data-color-mode": "dark",
      "data-light-theme": "light",
      "data-dark-theme": "dark",
    });
  });

  it("does not rewrite an attribute that already matches", () => {
    const { root } = fakeRoot(false);
    syncColorMode(root);
    const spy = vi.spyOn(root, "setAttribute");
    syncColorMode(root);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("applyTheme and saveTheme", () => {
  it("move the class and the colour mode together", () => {
    const { root, classes, attrs } = fakeRoot(false);
    applyTheme(root, "dark");
    expect(classes.has("dark")).toBe(true);
    expect(attrs.get("data-color-mode")).toBe("dark");
    applyTheme(root, "light");
    expect(classes.has("dark")).toBe(false);
    expect(attrs.get("data-color-mode")).toBe("light");
    expect(readTheme(root)).toBe("light");
  });

  it("saveTheme stores the choice under sbom.theme", () => {
    const { root } = fakeRoot(false);
    const storage = { setItem: vi.fn() };
    saveTheme(root, storage, "dark");
    expect(storage.setItem).toHaveBeenCalledWith(THEME_STORAGE_KEY, "dark");
    expect(THEME_STORAGE_KEY).toBe("sbom.theme");
    expect(root.getAttribute("data-color-mode")).toBe("dark");
  });
});

describe("primerColorMode", () => {
  it("maps the theme onto Primer's day and night", () => {
    expect(primerColorMode("light")).toBe("day");
    expect(primerColorMode("dark")).toBe("night");
  });
});

describe("watchColorMode", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("re-syncs and reports when the class is flipped from elsewhere", () => {
    let fire: () => void = () => {};
    const disconnect = vi.fn();
    vi.stubGlobal(
      "MutationObserver",
      class {
        constructor(cb: () => void) {
          fire = cb;
        }
        observe() {}
        disconnect = disconnect;
      },
    );
    const { root, classes, attrs } = fakeRoot(false);
    const onChange = vi.fn();
    const stop = watchColorMode(root as unknown as HTMLElement, onChange);
    expect(attrs.get("data-color-mode")).toBe("light");

    classes.add("dark");
    fire();
    expect(attrs.get("data-color-mode")).toBe("dark");
    expect(onChange).toHaveBeenCalledWith("dark");

    fire(); // a class change that leaves the mode as it was
    expect(onChange).toHaveBeenCalledTimes(1);

    stop();
    expect(disconnect).toHaveBeenCalled();
  });
});
