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
          "border-transparent bg-muted text-risk-info-fg hover:bg-muted/80",
      },
      tone: {
        none: "",
        critical:
          "border-transparent bg-risk-critical/10 text-risk-critical-fg",
        high: "border-transparent bg-risk-high/10 text-risk-high-fg",
        medium:
          "border-transparent bg-risk-medium/15 text-risk-medium-fg",
        low: "border-transparent bg-risk-low/10 text-risk-low-fg",
        info: "border-transparent bg-risk-info/15 text-risk-info-fg",
        success:
          "border-transparent bg-success-surface text-success dark:bg-success-surface/15",
        // Status caution, the same tokens as the warning banners; the risk tones
        // above are severity colours and are not reused for a status.
        warning:
          "border-transparent bg-warning-surface text-warning dark:bg-warning-surface/15",
        // Text-only green matching the visual weight of the risk tones
        // (critical/high/info render as coloured text on a transparent tint),
        // so in a row of grade badges the RISK colour draws the eye rather than
        // a solid-green "ok" outshouting the "caution" beside it. Distinct from
        // `success`, which stays a solid positive-confirmation badge for
        // scan-complete / conformance-pass.
        positive: "border-transparent text-success",
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
