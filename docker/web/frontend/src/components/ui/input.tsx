// Copyright 2026 SK Telecom Co., Ltd.
// Adapted from shadcn/ui — Copyright (c) 2023 shadcn, MIT licensed.
// SPDX-License-Identifier: Apache-2.0 AND MIT

import { forwardRef, type InputHTMLAttributes } from "react";

import { FIELD_FOCUS } from "@/components/ui/selectable";
import { cn } from "@/lib/utils";

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        "flex h-10 w-full rounded-lg border border-input bg-background px-3 py-2 text-body-sm ring-offset-background transition-colors duration-fast ease-out-soft",
        "file:border-0 file:bg-transparent file:text-body-sm file:font-medium placeholder:text-muted-foreground",
        FIELD_FOCUS,
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
