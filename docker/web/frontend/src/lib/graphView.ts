// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Which dependency view opens first, and the small unit conversion the canvas
 * needs to follow the font size tokens.
 *
 * A node-link graph reads well for a few dozen packages and turns into a
 * tangle of overlapping dots past a few hundred. Above the threshold the tree
 * (direct dependencies first, expand to go deeper) opens instead; the graph is
 * still one click away.
 */

/** Packages above which the tree is the opening view. */
export const GRAPH_TREE_THRESHOLD = 60;

export type DependencyView = "graph" | "tree";

/** The view to open with when the reader has not picked one. A "View in
 *  Dependencies" jump always means the tree: the graph has no equivalent
 *  jump-and-expand. */
export function defaultDependencyView(nodeCount: number, hasFocus: boolean): DependencyView {
  if (hasFocus) return "tree";
  return nodeCount > GRAPH_TREE_THRESHOLD ? "tree" : "graph";
}

/**
 * A CSS length (`0.75rem`, `12px`) as pixels, for a canvas that cannot use CSS.
 * Returns null for anything else so the caller can fall back, rather than
 * guessing at a unit.
 */
export function cssLengthToPx(value: string, rootFontPx = 16): number | null {
  const m = /^\s*(\d*\.?\d+)\s*(rem|px)\s*$/.exec(value);
  if (!m) return null;
  const n = Number(m[1]);
  return m[2] === "rem" ? n * rootFontPx : n;
}
