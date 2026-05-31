import { forwardRef, type InputHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * Switch — native checkbox with role="switch" for correct ARIA/keyboard
 * semantics. Visual style mirrors shadcn/ui (44×24 track, 20×20 thumb).
 */
export interface SwitchProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "onChange"> {
  checked: boolean;
  onCheckedChange?: (checked: boolean) => void;
  trackClassName?: string;
}

export const Switch = forwardRef<HTMLInputElement, SwitchProps>(function Switch(
  {
    checked,
    onCheckedChange,
    disabled,
    className,
    trackClassName,
    "aria-label": ariaLabel,
    ...props
  },
  ref,
) {
  return (
    <label
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors duration-fast ease-out-soft",
        "focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2",
        checked ? "bg-primary" : "bg-input",
        disabled && "cursor-not-allowed opacity-50",
        trackClassName,
      )}
      data-state={checked ? "checked" : "unchecked"}
      data-disabled={disabled ? "true" : undefined}
    >
      <input
        ref={ref}
        type="checkbox"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel}
        checked={checked}
        disabled={disabled}
        onChange={(event) => onCheckedChange?.(event.target.checked)}
        className={cn(
          "absolute inset-0 h-full w-full cursor-pointer appearance-none opacity-0",
          disabled && "cursor-not-allowed",
          className,
        )}
        {...props}
      />
      <span
        aria-hidden
        className={cn(
          "pointer-events-none block h-5 w-5 transform rounded-full bg-background shadow-sm ring-0 transition-transform duration-fast ease-out-soft",
          checked ? "translate-x-5" : "translate-x-0",
        )}
      />
    </label>
  );
});
