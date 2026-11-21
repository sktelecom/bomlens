// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  chooseInitialRoot,
  effectiveScanRoot,
  type MemoryStore,
  rememberScanRoot,
} from "./scanTargetMemory";

function memory(initial: Record<string, string> = {}): MemoryStore & { data: Record<string, string> } {
  const data = { ...initial };
  return {
    data,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
  };
}

const A = { path: "/scan-targets/a", hostPath: "/Users/me/a" };
const B = { path: "/scan-targets/b", hostPath: "/Users/me/b" };
const throwing: MemoryStore = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
};

describe("chooseInitialRoot", () => {
  it("is empty when no folder is added", () => {
    expect(chooseInitialRoot([], memory())).toBe("");
  });

  it("starts on the first folder when nothing is remembered", () => {
    expect(chooseInitialRoot([A, B], memory())).toBe(A.path);
  });

  it("returns to the folder scanned last", () => {
    const store = memory();
    chooseInitialRoot([A, B], store);
    rememberScanRoot([A, B], B.path, store);
    expect(chooseInitialRoot([A, B], store)).toBe(B.path);
  });

  it("moves to a folder added since the page was last open, once", () => {
    const store = memory();
    chooseInitialRoot([A], store);
    expect(chooseInitialRoot([A, B], store)).toBe(B.path);
    // The same folder is not new the next time.
    expect(chooseInitialRoot([A, B], store)).toBe(A.path);
  });

  it("ignores a remembered folder that is gone", () => {
    const store = memory();
    chooseInitialRoot([A, B], store);
    rememberScanRoot([A, B], B.path, store);
    expect(chooseInitialRoot([A], store)).toBe(A.path);
  });

  it("works without usable storage", () => {
    expect(chooseInitialRoot([A, B], throwing)).toBe(A.path);
    expect(chooseInitialRoot([A, B], null)).toBe(A.path);
    expect(() => rememberScanRoot([A, B], B.path, throwing)).not.toThrow();
  });

  it("treats damaged storage as empty", () => {
    expect(chooseInitialRoot([A, B], memory({ "bomlens.knownScanRoots": "{not json" }))).toBe(A.path);
  });
});

describe("effectiveScanRoot", () => {
  it("is the launch folder when nothing is added", () => {
    expect(effectiveScanRoot("", [], true)).toBe("");
    expect(effectiveScanRoot("", [], false)).toBe("");
  });

  it("keeps the launch folder when the list offers it", () => {
    expect(effectiveScanRoot("", [A, B], true)).toBe("");
  });

  it("takes the first added folder when the launch folder is not offered", () => {
    // The list shows a single added folder: that one is shown and sent.
    expect(effectiveScanRoot("", [A], false)).toBe(A.path);
    expect(effectiveScanRoot("", [A, B], false)).toBe(A.path);
  });

  it("keeps a chosen folder the list offers", () => {
    expect(effectiveScanRoot(B.path, [A, B], false)).toBe(B.path);
    expect(effectiveScanRoot(B.path, [A, B], true)).toBe(B.path);
  });

  it("falls back to the first entry when the chosen folder went away", () => {
    expect(effectiveScanRoot(B.path, [A], false)).toBe(A.path);
    expect(effectiveScanRoot(B.path, [A], true)).toBe("");
  });
});
