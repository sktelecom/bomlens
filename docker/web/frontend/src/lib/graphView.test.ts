// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { cssLengthToPx, defaultDependencyView, GRAPH_TREE_THRESHOLD } from "./graphView";

describe("defaultDependencyView", () => {
  it("opens the graph up to the threshold and the tree above it", () => {
    expect(GRAPH_TREE_THRESHOLD).toBe(150);
    expect(defaultDependencyView(3, false)).toBe("graph");
    expect(defaultDependencyView(150, false)).toBe("graph");
    expect(defaultDependencyView(151, false)).toBe("tree");
    expect(defaultDependencyView(1200, false)).toBe("tree");
  });

  it("always opens the tree for a jump from another section", () => {
    expect(defaultDependencyView(3, true)).toBe("tree");
  });
});

describe("cssLengthToPx", () => {
  it("converts rem against the root font size", () => {
    expect(cssLengthToPx("0.75rem")).toBe(12);
    expect(cssLengthToPx(" 1rem ")).toBe(16);
    expect(cssLengthToPx("0.75rem", 20)).toBe(15);
  });

  it("passes px through", () => {
    expect(cssLengthToPx("12px")).toBe(12);
  });

  it("returns null for anything it does not understand", () => {
    expect(cssLengthToPx("")).toBeNull();
    expect(cssLengthToPx("calc(1rem + 2px)")).toBeNull();
    expect(cssLengthToPx("1em")).toBeNull();
  });
});
