import { Loader2, type LucideIcon } from "lucide-react";
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
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 px-4 py-8 text-center text-sm text-muted-foreground",
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
    <StateShell className={className}>
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      <span>{children}</span>
    </StateShell>
  );
}

/** Nothing-to-show state with an optional leading icon. */
export function EmptyState({
  icon: Icon,
  children,
  className,
}: {
  icon?: LucideIcon;
  children: ReactNode;
  className?: string;
}) {
  return (
    <StateShell className={className}>
      {Icon ? <Icon className="h-5 w-5 opacity-60" aria-hidden /> : null}
      <span>{children}</span>
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
    <StateShell className={className}>
      <span>{children}</span>
      {onRetry ? (
        <Button type="button" size="sm" variant="outline" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </StateShell>
  );
}
