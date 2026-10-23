// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Info, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** The one callout surface for the notes above a findings table (coverage
 *  notices, upgrade bundles, the kernel note): a quiet border on a muted wash. */
export const CALLOUT =
  "rounded-md border bg-muted/30 px-3 py-2 text-left text-label text-muted-foreground";

/**
 * A notice about what a result does NOT cover (components that could not be
 * checked, advisories kept out of the counts). It states a limit of the data,
 * not a failure, so it uses the neutral surface and never the error style.
 * `title` is an optional bold first line; children carry the explanation.
 */
export function CoverageNotice({
  title,
  icon: Icon = Info,
  testId = "coverage-notice",
  className,
  children,
}: {
  title?: ReactNode;
  icon?: LucideIcon;
  testId?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      role="note"
      data-testid={testId}
      data-coverage-notice=""
      className={cn(
        "space-y-2",
        CALLOUT,
        className,
      )}
    >
      {title ? (
        <p className="flex items-start gap-2 text-body-sm font-medium text-foreground">
          <Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          {title}
        </p>
      ) : (
        <p className="flex items-start gap-2">
          <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>{children}</span>
        </p>
      )}
      {title ? children : null}
    </div>
  );
}
