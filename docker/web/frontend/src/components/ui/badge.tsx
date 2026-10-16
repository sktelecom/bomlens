// Copyright 2026 SK Telecom Co., Ltd.
// Adapted from shadcn/ui — Copyright (c) 2023 shadcn, MIT licensed.
// SPDX-License-Identifier: Apache-2.0 AND MIT

import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type HTMLAttributes } from "react";

import { Marker, SEVERITY_SHAPE, type MarkerShape } from "@/components/ui/marker";
import { cn } from "@/lib/utils";

/**
 * Badge: role-coloured variants pair a status word (and, with `mark`, a shape)
 * with the design-system colour token, so colour is never the only signal. The
 * label uses each role's fg shade, which clears WCAG AA on its muted surface.
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
          "border-transparent bg-muted text-role-neutral-fg hover:bg-muted/80",
      },
      tone: {
        none: "",
        // Severity and status tones are the colour roles (index.css): a pale
        // opaque muted surface, the fg shade for the label (AA on that surface),
        // and no brand colour anywhere in this file (token-lint enforces it).
        critical: "border-transparent bg-role-danger-muted text-role-danger-fg",
        high: "border-transparent bg-role-severe-muted text-role-severe-fg",
        medium: "border-transparent bg-role-attention-muted text-role-attention-fg",
        low: "border-transparent bg-role-info-muted text-role-info-fg",
        info: "border-transparent bg-role-neutral-muted text-role-neutral-fg",
        success: "border-transparent bg-role-success-muted text-role-success-fg",
        // Status caution, the same role as the warning banners.
        warning: "border-transparent bg-role-attention-muted text-role-attention-fg",
        // Text-only green matching the visual weight of the risk tones, so in a
        // row of grade badges the RISK colour draws the eye rather than a solid
        // "ok" outshouting the "caution" beside it. Distinct from `success`,
        // which stays a positive-confirmation badge for scan-complete and pass.
        positive: "border-transparent text-role-success-fg",
        // Licence tiers: the category palette, not the severity roles, so an
        // obligation never reads as a vulnerability.
        catPermissive: "border-transparent bg-cat-permissive-muted text-cat-permissive-fg",
        catWeak: "border-transparent bg-cat-weak-muted text-cat-weak-fg",
        catStrong: "border-transparent bg-cat-strong-muted text-cat-strong-fg",
        catNetwork: "border-transparent bg-cat-network-muted text-cat-network-fg",
        catReview: "border-transparent bg-cat-review-muted text-cat-review-fg",
      },
    },
    defaultVariants: { variant: "outline", tone: "none" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  /**
   * Draw a shape before the label. `true` takes the severity shape of the tone
   * (critical diamond, high triangle, medium circle, low square, unknown dash);
   * a shape name picks one explicitly (the licence tiers do). Use it wherever
   * the badge is a grade, so the grade does not depend on hue.
   */
  mark?: boolean | MarkerShape;
}

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, tone, mark, children, ...props }, ref) => {
    const shape: MarkerShape | undefined =
      typeof mark === "string"
        ? mark
        : mark && tone && tone in SEVERITY_SHAPE
          ? SEVERITY_SHAPE[tone as keyof typeof SEVERITY_SHAPE]
          : undefined;
    return (
      <span
        ref={ref}
        className={cn(badgeVariants({ variant, tone }), className)}
        {...props}
      >
        {shape && <Marker shape={shape} />}
        {children}
      </span>
    );
  },
);
Badge.displayName = "Badge";

export { badgeVariants };
