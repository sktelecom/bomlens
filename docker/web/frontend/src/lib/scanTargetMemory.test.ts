// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { chooseInitialRoot, type MemoryStore, rememberScanRoot } from "./scanTargetMemory";

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
