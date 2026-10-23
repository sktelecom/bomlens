// Copyright 2026 SK Telecom Co., Ltd.
// Adapted from shadcn/ui — Copyright (c) 2023 shadcn, MIT licensed.
// SPDX-License-Identifier: Apache-2.0 AND MIT

import { forwardRef, type TextareaHTMLAttributes } from "react";

import { FIELD_FOCUS } from "@/components/ui/selectable";
import { cn } from "@/lib/utils";

export type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "flex min-h-[5rem] w-full rounded-lg border border-input bg-background px-3 py-2 text-body-sm ring-offset-background transition-colors duration-fast ease-out-soft",
        "placeholder:text-muted-foreground",
        FIELD_FOCUS,
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";
