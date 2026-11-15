// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { type ReactNode, useEffect, useRef, useState } from "react";

import type { ComponentItem } from "@/lib/api";

/**
 * Rows are rendered in chunks of this size, one <tbody> per chunk. Chunks far
 * from the viewport are recycled into a single spacer row of their measured
 * height, so a firmware scan with 60,000 components scrolls as one list while
 * the DOM stays small. Row heights vary (wrapping names, the open detail row),
 * so each spacer uses its chunk's own measurement, not a fixed row height.
 */
export const CHUNK = 100;

/** Chunks live from the start, before the observer has seen anything. */
const INITIAL_LIVE: ReadonlySet<number> = new Set([0]);

/** How far beyond the window a chunk stays live, so a fast scroll finds rows. */
const ROOT_MARGIN = "600px 0px";

/**
 * The rows of a table, in chunks. The page scrolls (the table has no scroll
 * box of its own, so its head can stick under the top bar), so the observer
 * watches the window. `resetKey` is any value that changes when the visible
 * set does: it drops every measurement and starts again from the top.
 */
export function ChunkedBody({
  rows,
  render,
  openIndex,
  rowHeight,
  resetKey,
  observeRoot,
}: {
  rows: ComponentItem[];
  render: (c: ComponentItem, index: number) => ReactNode;
  /** Index of the open row; its chunk is pinned live so it is never recycled from under the detail row. */
  openIndex: number;
  /** Estimated row height for a chunk that has not been measured yet. */
  rowHeight: number;
  resetKey: unknown;
  /** The table element, to find the chunk <tbody>s under. */
  observeRoot: React.RefObject<HTMLElement | null>;
}) {
  const [live, setLive] = useState<ReadonlySet<number>>(INITIAL_LIVE);
  const heights = useRef(new Map<number, number>());

  useEffect(() => {
    setLive(INITIAL_LIVE);
    heights.current.clear();
  }, [resetKey]);

  const chunkCount = Math.ceil(rows.length / CHUNK);

  // One observer over the per-chunk <tbody> elements (stable nodes: React keeps
  // them keyed by chunk index across live and spacer). A chunk near the window
  // goes live; one leaving it is measured, then recycled.
  useEffect(() => {
    const root = observeRoot.current;
    if (!root) return;
    const io = new IntersectionObserver(
      (entries) =>
        setLive((prev) => {
          const next = new Set(prev);
          for (const e of entries) {
            const idx = Number((e.target as HTMLElement).dataset.chunk);
            if (Number.isNaN(idx)) continue;
            if (e.isIntersecting) {
              next.add(idx);
            } else {
              if (prev.has(idx)) heights.current.set(idx, e.boundingClientRect.height);
              next.delete(idx);
            }
          }
          return next;
        }),
      { root: null, rootMargin: ROOT_MARGIN },
    );
    for (const el of root.querySelectorAll("tbody[data-chunk]")) io.observe(el);
    return () => io.disconnect();
    // resetKey: a new visible set starts again from chunk 0, so the chunks are observed anew
    // (the observer's first report is what brings the right ones live after a re-sort mid-list).
  }, [chunkCount, observeRoot, resetKey]);

  const openChunk = openIndex < 0 ? -1 : Math.floor(openIndex / CHUNK);
  const out: ReactNode[] = [];
  for (let ci = 0; ci < chunkCount; ci++) {
    const start = ci * CHUNK;
    const size = Math.min(CHUNK, rows.length - start);
    if (live.has(ci) || ci === openChunk) {
      const body: ReactNode[] = [];
      for (let i = start; i < start + size; i++) body.push(render(rows[i], i));
      out.push(
        <tbody key={ci} data-chunk={ci} data-live="true" className="bl-comp-chunk">
          {body}
        </tbody>,
      );
    } else {
      // Recycled chunk: one spacer row holding the chunk's measured height (or
      // an estimate before its first paint), so the scroll geometry holds
      // without the row DOM.
      out.push(
        <tbody key={ci} data-chunk={ci} data-live="false" className="bl-comp-chunk" aria-hidden>
          <tr className="bl-comp-spacer">
            <td style={{ height: heights.current.get(ci) ?? size * rowHeight, padding: 0 }} />
          </tr>
        </tbody>,
      );
    }
  }
  return <>{out}</>;
}
