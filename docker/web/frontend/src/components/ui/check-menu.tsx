// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDown } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { cn } from "@/lib/utils";
import { TOOLBAR_CONTROL } from "@/components/ui/toolbar";

export interface CheckMenuItem {
  /** Stable id, used as the React key. */
  id: string;
  label: string;
  checked: boolean;
  onToggle: () => void;
}

/**
 * A button that opens a list of checkboxes — the shape both the filter menu and
 * the column menu need.
 *
 * The entries are real `<input type="checkbox">` elements rather than an ARIA
 * menu: a checkbox is announced with its checked state and operated with the
 * keyboard without any of it being written here, and a filter list is a set of
 * independent on/off choices, which is what a checkbox group is for. What this
 * adds is the opening and closing: Escape closes, a click outside closes, and
 * focus returns to the button so the keyboard does not land back at the top of
 * the page.
 */
export function CheckMenu({
  label,
  items,
  align = "start",
  className,
}: {
  label: string;
  items: CheckMenuItem[];
  /** Which edge the panel lines up with; "end" for a button near the right. */
  align?: "start" | "end";
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const checkedCount = items.filter((i) => i.checked).length;

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setOpen(false);
      buttonRef.current?.focus();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (items.length === 0) return null;

  return (
    <div ref={rootRef} className={cn("relative", className)}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        className={cn(
          TOOLBAR_CONTROL,
          "inline-flex items-center gap-1.5 border border-input bg-background px-3.5 text-body-sm",
          "shadow-sm transition-colors duration-fast ease-out-soft hover:bg-accent hover:text-accent-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        )}
      >
        {label}
        {checkedCount > 0 && (
          <span className="rounded-full bg-muted px-1.5 text-label tabular-nums text-muted-foreground">
            {checkedCount}
          </span>
        )}
        <ChevronDown
          className={cn(
            "h-3.5 w-3.5 text-muted-foreground transition-transform duration-fast ease-out-soft",
            open && "rotate-180",
          )}
          aria-hidden
        />
      </button>
      {open && (
        <div
          id={panelId}
          className={cn(
            "absolute z-40 mt-1 min-w-56 rounded-md border bg-popover p-1 shadow-md",
            align === "end" ? "right-0" : "left-0",
          )}
        >
          <ul className="max-h-72 overflow-auto">
            {items.map((item) => (
              <li key={item.id}>
                <label
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-body-sm",
                    "hover:bg-accent hover:text-accent-foreground",
                    "focus-within:bg-accent focus-within:text-accent-foreground",
                  )}
                >
                  {/* A real checkbox, tinted with the foreground colour rather than
                      hidden behind a drawn one: it is then the thing a click
                      and a screen reader both land on, with no second element
                      in front of it. */}
                  <input
                    type="checkbox"
                    checked={item.checked}
                    onChange={item.onToggle}
                    className="h-4 w-4 shrink-0 accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  />
                  {item.label}
                </label>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
