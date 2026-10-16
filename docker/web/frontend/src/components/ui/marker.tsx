// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { cn } from "@/lib/utils";

/**
 * A small shape that says what a colour says, so no meaning rides on hue alone.
 * Severity and licence tiers each get a shape of their own; the badge carries
 * the word, the shape survives a greyscale print or a colour-blind reader.
 * Drawn in `currentColor` at 10px, so the caller sets the colour with a token
 * text class (`text-role-danger-fg`) and the shape follows it.
 */
export type MarkerShape =
  | "diamond"
  | "triangle"
  | "circle"
  | "square"
  | "dash"
  | "ring"
  | "hexagon"
  | "plus"
  | "bars"
  | "dashed-ring";

/** Severity shapes, most to least urgent: diamond, triangle, circle, square, dash. */
export const SEVERITY_SHAPE = {
  critical: "diamond",
  high: "triangle",
  medium: "circle",
  low: "square",
  info: "dash",
} as const satisfies Record<string, MarkerShape>;

export type SeverityToneName = keyof typeof SEVERITY_SHAPE;

/** Licence tier shapes. Different from the severity set on purpose. */
export const TIER_SHAPE = {
  permissive: "ring",
  "weak-copyleft": "hexagon",
  "strong-copyleft": "plus",
  "network-copyleft": "bars",
  "review-needed": "dashed-ring",
  uncategorized: "dash",
} as const satisfies Record<string, MarkerShape>;

export function Marker({ shape, className }: { shape: MarkerShape; className?: string }) {
  return (
    <svg
      viewBox="0 0 10 10"
      width="10"
      height="10"
      aria-hidden
      focusable="false"
      data-marker={shape}
      className={cn("inline-block shrink-0", className)}
    >
      {shape === "diamond" && <polygon points="5,0.5 9.5,5 5,9.5 0.5,5" fill="currentColor" />}
      {shape === "triangle" && <polygon points="5,0.8 9.7,9.2 0.3,9.2" fill="currentColor" />}
      {shape === "circle" && <circle cx="5" cy="5" r="4.2" fill="currentColor" />}
      {shape === "square" && <rect x="1" y="1" width="8" height="8" fill="currentColor" />}
      {shape === "dash" && <rect x="0.5" y="4" width="9" height="2" rx="0.5" fill="currentColor" />}
      {shape === "ring" && (
        <circle cx="5" cy="5" r="3.6" fill="none" stroke="currentColor" strokeWidth="1.6" />
      )}
      {shape === "hexagon" && (
        <polygon points="5,0.4 9.2,2.7 9.2,7.3 5,9.6 0.8,7.3 0.8,2.7" fill="currentColor" />
      )}
      {shape === "plus" && (
        <path d="M4 0.5h2v3.5h3.5v2H6v3.5H4V6H0.5V4H4z" fill="currentColor" />
      )}
      {shape === "bars" && (
        <>
          <rect x="0.5" y="1" width="9" height="1.6" fill="currentColor" />
          <rect x="0.5" y="4.2" width="9" height="1.6" fill="currentColor" />
          <rect x="0.5" y="7.4" width="9" height="1.6" fill="currentColor" />
        </>
      )}
      {shape === "dashed-ring" && (
        <circle
          cx="5"
          cy="5"
          r="3.6"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeDasharray="2.2 1.6"
        />
      )}
    </svg>
  );
}
