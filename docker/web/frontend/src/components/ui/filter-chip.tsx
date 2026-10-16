// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FOCUS_RING, SELECTED_SOLID } from "@/components/ui/selectable";
import { cn } from "@/lib/utils";

/** A pressable chip: the solid fill when active, a quiet border otherwise. */
export function FilterChip({
  active,
  onClick,
  disabled,
  children,
}: {
  active: boolean;
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "rounded-md border px-2.5 py-1 text-label font-medium transition-colors duration-fast ease-out-soft disabled:cursor-not-allowed disabled:opacity-50",
        FOCUS_RING,
        active
          ? SELECTED_SOLID
          : "border-border text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}
