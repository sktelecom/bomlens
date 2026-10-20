// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Loader2, type LucideIcon, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Shared empty / loading / error states.
 *
 * Every view that fetches or filters data renders one of these instead of an
 * ad-hoc <p> or inline spinner, so blank, busy and failed states look the same
 * across the dashboard. Tokens only — no literal colors or per-view padding
 * forks. Keep the message text translatable (pass a t(...) string).
 */

function StateShell({
  className,
  children,
  testId,
}: {
  className?: string;
  children: ReactNode;
  /** Lets a test assert that a section uses the shared state rather than its
   *  own paragraph, which is how the three empty states drifted apart before. */
  testId?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn(
        "flex flex-col items-center justify-center gap-2 px-4 py-8 text-center text-body-sm text-muted-foreground",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Busy state with a spinner. */
export function LoadingState({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <StateShell className={className} testId="loading-state">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      <span>{children}</span>
    </StateShell>
  );
}

/**
 * Nothing-to-show state with an optional leading icon.
 *
 * An empty section reads the same whether the scan looked and found nothing or
 * never looked at all, and the reader is left to guess which. `hint` says which
 * of the two it was, and `action` offers the one thing worth doing next. Both
 * are optional: a section with nothing useful to add stays a single line rather
 * than padding itself with a sentence that says the heading again.
 */
export function EmptyState({
  icon: Icon,
  children,
  hint,
  action,
  className,
}: {
  icon?: LucideIcon;
  children: ReactNode;
  /** Why this section is empty — found nothing, or was never run. */
  hint?: ReactNode;
  /** The next step, as a link or a button. */
  action?: ReactNode;
  className?: string;
}) {
  return (
    <StateShell className={className} testId="empty-state">
      {Icon ? (
        // The icon sits on a soft tinted plate (same language as the first-run
        // hero) so a blank section reads as intentional, not unfinished.
        <div className="mb-1 flex h-12 w-12 items-center justify-center rounded-xl bg-muted text-muted-foreground">
          <Icon className="h-6 w-6" aria-hidden />
        </div>
      ) : null}
      {/* The heading only steps up in weight when there is a reason under it to
          step down from. A one-line empty state has no hierarchy to express,
          and darkening it there would change screens this section never
          touched. */}
      <span className={hint ? "text-foreground" : undefined}>{children}</span>
      {hint ? <p className="max-w-prose text-body-sm">{hint}</p> : null}
      {action ? <div className="mt-1">{action}</div> : null}
    </StateShell>
  );
}

/**
 * A single shimmering placeholder bar. Compose several to mirror the shape of
 * the content that is loading (rows, cards). Token-driven so it matches the
 * surface in both themes.
 */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-muted", className)}
      aria-hidden
    />
  );
}

/**
 * Busy placeholder for a list/table region: a stack of skeleton rows wrapped in
 * a busy live region so assistive tech announces the load. Use instead of a
 * bare spinner when the eventual content has a known row shape.
 */
export function SkeletonRows({
  rows = 5,
  className,
}: {
  rows?: number;
  className?: string;
}) {
  return (
    <div
      className={cn("space-y-2", className)}
      role="status"
      aria-busy="true"
    >
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  );
}

/** Failed state with an optional retry action. */
export function ErrorState({
  children,
  onRetry,
  retryLabel,
  className,
}: {
  children: ReactNode;
  onRetry?: () => void;
  retryLabel?: string;
  className?: string;
}) {
  return (
    <StateShell className={className} testId="error-state">
      <div className="mb-1 flex h-12 w-12 items-center justify-center rounded-xl bg-destructive/10 text-destructive">
        <TriangleAlert className="h-6 w-6" aria-hidden />
      </div>
      <span>{children}</span>
      {onRetry ? (
        <Button type="button" size="sm" variant="outline" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </StateShell>
  );
}
