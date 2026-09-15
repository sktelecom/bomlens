// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRight } from "lucide-react";
import { useState, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Fold-away section with a chevron that turns as it opens.
 *
 * Built on `<details>`, which already gives the open/close state, keyboard
 * operation and the right semantics for free; what this adds is the part that
 * was being written out by hand at each site — the rotating chevron, the
 * hidden native marker, the focus ring — so that every collapsible surface
 * folds the same way and a reader can tell one is collapsible at all.
 *
 * `size` sets the chevron and the gap, not the label: the caller styles its
 * own summary content, because a panel heading, a table cell and a small
 * "evidence" toggle carry different type but the same affordance.
 */
export function Disclosure({
  summary,
  defaultOpen = false,
  size = "sm",
  className,
  summaryClassName,
  children,
}: {
  summary: ReactNode;
  defaultOpen?: boolean;
  size?: "sm" | "md";
  className?: string;
  summaryClassName?: string;
  children: ReactNode;
}) {
  // Captured once so React never fights the user's own open/close toggling.
  const [initialOpen] = useState(defaultOpen);
  return (
    <details className={cn("group", className)} open={initialOpen}>
      <summary
        className={cn(
          "flex cursor-pointer list-none items-center rounded-sm",
          "transition-colors duration-fast ease-out-soft hover:bg-muted/50",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          "[&::-webkit-details-marker]:hidden",
          size === "md" ? "gap-2" : "gap-1.5",
          summaryClassName,
        )}
      >
        <ChevronRight
          className={cn(
            "shrink-0 text-muted-foreground transition-transform duration-fast ease-out-soft group-open:rotate-90",
            size === "md" ? "h-4 w-4" : "h-3.5 w-3.5",
          )}
          aria-hidden
        />
        {summary}
      </summary>
      {children}
    </details>
  );
}
