// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDown } from "lucide-react";
import { forwardRef, type SelectHTMLAttributes } from "react";

import { FIELD_FOCUS } from "@/components/ui/selectable";
import { TOOLBAR_CONTROL } from "@/components/ui/toolbar";
import { cn } from "@/lib/utils";

/**
 * Native <select> styled with the shared input tokens.
 *
 * Deliberately not a Radix popover — the filter dropdowns only need plain
 * option lists, so this keeps the bundle and the interaction model simple.
 */
export const Select = forwardRef<
  HTMLSelectElement,
  SelectHTMLAttributes<HTMLSelectElement>
>(({ className, ...props }, ref) => (
  <select
    ref={ref}
    className={cn(
      "h-9 rounded-lg border border-input bg-background px-2 text-body-sm text-foreground",
      FIELD_FOCUS,
      "disabled:cursor-not-allowed disabled:opacity-50",
      className,
    )}
    {...props}
  />
));
Select.displayName = "Select";

/**
 * The same native <select> sized for a table toolbar, with the browser's own
 * arrow replaced by the chevron the menu buttons beside it use, so a select
 * and a menu read as the same kind of control. `className` sizes the select.
 */
export const ToolbarSelect = forwardRef<
  HTMLSelectElement,
  SelectHTMLAttributes<HTMLSelectElement>
>(({ className, ...props }, ref) => (
  <span className="relative inline-flex shrink-0">
    <Select
      ref={ref}
      className={cn(TOOLBAR_CONTROL, "appearance-none truncate pl-3.5 pr-8", className)}
      {...props}
    />
    <ChevronDown
      className="pointer-events-none absolute right-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
      aria-hidden
    />
  </span>
));
ToolbarSelect.displayName = "ToolbarSelect";
