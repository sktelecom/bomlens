// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { unloadGuardEnabled, warnBeforeUnload } from "./unloadGuard";

describe("unloadGuardEnabled", () => {
  it("is on by default", () => {
    expect(unloadGuardEnabled({}, undefined)).toBe(true);
    expect(unloadGuardEnabled(undefined, undefined)).toBe(true);
  });

  it("is off with the build flag, the page flag or the storage entry", () => {
    expect(unloadGuardEnabled({}, "1")).toBe(false);
    expect(unloadGuardEnabled({ __BOMLENS_NO_UNLOAD_GUARD__: true }, undefined)).toBe(false);
    expect(
      unloadGuardEnabled({ localStorage: { getItem: (k) => (k === "bomlens.noUnloadGuard" ? "1" : null) } }, undefined),
    ).toBe(false);
  });

  it("stays on when storage cannot be read", () => {
    const win = {
      localStorage: {
        getItem: () => {
          throw new Error("blocked");
        },
      },
    };
    expect(unloadGuardEnabled(win, undefined)).toBe(true);
  });
});

describe("warnBeforeUnload", () => {
  it("asks the browser to raise its prompt", () => {
    let prevented = false;
    const e = { preventDefault: () => (prevented = true), returnValue: "x" } as unknown as BeforeUnloadEvent;
    warnBeforeUnload(e);
    expect(prevented).toBe(true);
    expect(e.returnValue).toBe("");
  });
});
