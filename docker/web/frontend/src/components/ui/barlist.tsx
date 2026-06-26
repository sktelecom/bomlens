import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export interface BarDatum {
  key: string;
  label: ReactNode;
  value: number;
  /** Tint the fill to flag this row for review (e.g. copyleft licenses). */
  emphasis?: boolean;
}

interface Props {
  items: BarDatum[];
  /** Bar scale max; defaults to the largest value so the top bar fills the row. */
  max?: number;
  /** Accessible name for the list (the chart's purpose). */
  ariaLabel: string;
  /** When set, each bar becomes a toggle button (re-selecting clears upstream). */
  onSelect?: (key: string) => void;
  selectedKey?: string | null;
}

/**
 * A ranked horizontal bar list — a label, a proportional fill and a count per
 * row — for distributions where proportion matters at a glance (licenses,
 * component types). Colour is never the only signal: every row carries its
 * label and value as text, so the bars stay an aid, not the data. Fills resolve
 * from the design tokens, so the chart follows light/dark and passes the token
 * lint with no hardcoded colours.
 */
export function BarList({ items, max, ariaLabel, onSelect, selectedKey }: Props) {
  const top = max ?? Math.max(1, ...items.map((i) => i.value));
  const interactive = Boolean(onSelect);

  return (
    <ul role="list" aria-label={ariaLabel} className="space-y-1">
      {items.map((it) => {
        // Floor the width so a single-component licence still shows a sliver.
        const pct = Math.max(2, (it.value / top) * 100);
        const sel = selectedKey === it.key;
        const inner = (
          <div className="relative flex h-8 items-center overflow-hidden rounded-md">
            <div className="absolute inset-0 bg-muted" aria-hidden />
            <div
              className={cn(
                "absolute inset-y-0 left-0 origin-left animate-grow-x",
                it.emphasis ? "bg-risk-medium/25" : "bg-muted-foreground/20",
              )}
              style={{ width: `${pct}%` }}
              aria-hidden
            />
            <span className="relative z-10 truncate pl-2.5 text-sm text-foreground">
              {it.label}
            </span>
            <span className="relative z-10 ml-auto pr-2.5 text-xs tabular-nums text-muted-foreground">
              {it.value}
            </span>
          </div>
        );
        if (!interactive) {
          return <li key={it.key}>{inner}</li>;
        }
        return (
          <li key={it.key}>
            <button
              type="button"
              aria-pressed={sel}
              onClick={() => onSelect?.(it.key)}
              className={cn(
                "block w-full rounded-md text-left transition duration-fast ease-out-soft",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                sel ? "ring-2 ring-foreground ring-offset-1" : "hover:opacity-90",
              )}
            >
              {inner}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
