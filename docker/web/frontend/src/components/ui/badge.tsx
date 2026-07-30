// Copyright 2026 SK Telecom Co., Ltd.
// Adapted from shadcn/ui — Copyright (c) 2023 shadcn, MIT licensed.
// SPDX-License-Identifier: Apache-2.0 AND MIT

import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * Badge — risk-tinted variants pair a status word with the design-system color
 * token (color is never the only signal). Text shades are darkened to clear
 * WCAG AA on the low-alpha tint (same approach as TRUSCA).
 */
const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors duration-fast ease-out-soft focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 whitespace-nowrap",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        outline: "text-foreground",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        muted:
          "border-transparent bg-muted text-slate-600 hover:bg-muted/80 dark:text-slate-300",
      },
      tone: {
        none: "",
        critical:
          "border-transparent bg-risk-critical/10 text-red-700 dark:text-red-300",
        high: "border-transparent bg-risk-high/10 text-orange-800 dark:text-orange-300",
        medium:
          "border-transparent bg-risk-medium/15 text-yellow-800 dark:text-yellow-300",
        low: "border-transparent bg-risk-low/10 text-blue-700 dark:text-blue-300",
        info: "border-transparent bg-risk-info/15 text-slate-600 dark:text-slate-300",
        success:
          "border-transparent bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
        // Text-only green matching the visual weight of the risk tones
        // (critical/high/info render as coloured text on a transparent tint),
        // so in a row of grade badges the RISK colour draws the eye rather than
        // a solid-green "ok" outshouting the "caution" beside it. Distinct from
        // `success`, which stays a solid positive-confirmation badge for
        // scan-complete / conformance-pass.
        positive:
          "border-transparent text-emerald-700 dark:text-emerald-300",
      },
    },
    defaultVariants: { variant: "outline", tone: "none" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, tone, ...props }, ref) => (
    <span
      ref={ref}
      className={cn(badgeVariants({ variant, tone }), className)}
      {...props}
    />
  ),
);
Badge.displayName = "Badge";

export { badgeVariants };
