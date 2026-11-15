// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Primer-backed stand-ins with the props the app's ui components take, so the
// long AI declaration flow is drawn on Primer with its logic unchanged. The
// layout class names it carries are served by the `.bl-decl` block in declaration.css.
import { AlertIcon, CheckIcon, ChevronRightIcon, PlusIcon, TrashIcon, XIcon } from "@primer/octicons-react";
import { Button as PButton, Label, Select as PSelect, Spinner, TextInput } from "@primer/react";
import React from "react";

export const cn = (...xs: (string | false | null | undefined)[]) => xs.filter(Boolean).join(" ");

// Icons: the lucide names the flow uses, drawn as Octicons.
type IconProps = { className?: string; "aria-hidden"?: boolean | "true" | "false" };
const icon = (I: React.ElementType, size = 16) => {
  const C = ({ className }: IconProps) => (
    <span className={cn("bl-decl-ico", className?.includes("animate-spin") && "bl-decl-spin")} aria-hidden style={{ display: "inline-flex" }}>
      <I size={/h-3\.5/.test(className ?? "") ? 14 : /\bh-3\b|\bw-3\b/.test(className ?? "") ? 12 : size} />
    </span>
  );
  C.isIcon = true;
  return C;
};
export const Check = icon(CheckIcon);
export const Plus = icon(PlusIcon);
export const Trash2 = icon(TrashIcon);
export const TriangleAlert = icon(AlertIcon);
export const X = icon(XIcon);
export const Loader2 = Object.assign((_: IconProps) => <Spinner size="small" srText={null} />, { isIcon: true });

export function Badge({ variant, tone, children, className }: { variant?: string; tone?: string; children: React.ReactNode; className?: string }) {
  const v =
    tone === "low" || tone === "success"
      ? "success"
      : tone === "critical"
        ? "danger"
        : tone === "medium" || tone === "warning"
          ? "attention"
          : "secondary";
  void variant;
  return (
    <Label variant={v} className={className}>
      {children}
    </Label>
  );
}

type BtnProps = {
  variant?: "default" | "outline" | "ghost";
  size?: "sm" | "default";
  onClick?: () => void;
  disabled?: boolean;
  children?: React.ReactNode;
  className?: string;
  "aria-label"?: string;
  title?: string;
  type?: "button" | "submit";
};
/** Default is the primary action, outline a secondary one, ghost an invisible one. */
export const Button = React.forwardRef<HTMLButtonElement, BtnProps>(function Button({ variant = "default", size, children, className, ...rest }, ref) {
  const kids = React.Children.toArray(children);
  const lead = kids.find((k) => React.isValidElement(k) && (k.type as { isIcon?: boolean }).isIcon) as React.ReactElement | undefined;
  const rest2 = kids.filter((k) => k !== lead);
  const pv = variant === "default" ? "primary" : variant === "ghost" ? "invisible" : "default";
  return (
    <PButton
      ref={ref}
      variant={pv}
      size={size === "sm" ? "small" : "medium"}
      className={className}
      leadingVisual={lead ? () => lead : undefined}
      {...rest}
    >
      {rest2.length ? rest2 : null}
    </PButton>
  );
});

export function Card({ children, className, ...rest }: { children: React.ReactNode; className?: string } & Record<string, unknown>) {
  return (
    <div className={cn("bl-box", className)} {...rest}>
      {children}
    </div>
  );
}
export function CardContent({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={className}>{children}</div>;
}

export function Disclosure({ defaultOpen, summary, children, className }: { defaultOpen?: boolean; summary: React.ReactNode; children: React.ReactNode; className?: string }) {
  // Captured once so React never fights the person's own open and close.
  const [initialOpen] = React.useState(Boolean(defaultOpen));
  return (
    <details open={initialOpen || undefined} className={className}>
      <summary className="bl-decl-sum">
        <span className="bl-decl-chev"><ChevronRightIcon size={16} /></span>
        {summary}
      </summary>
      {children}
    </details>
  );
}

type InputProps = React.InputHTMLAttributes<HTMLInputElement> & { className?: string };
export const Input = React.forwardRef<HTMLInputElement, InputProps>(function Input({ className, ...rest }, ref) {
  const narrow = /\bw-44\b|max-w-\[12rem\]/.test(className ?? "");
  return (
    <TextInput
      ref={ref}
      block={!narrow}
      className={className}
      style={narrow ? { width: /w-44/.test(className ?? "") ? 176 : 192 } : undefined}
      {...(rest as React.ComponentProps<typeof TextInput>)}
    />
  );
});

export function Select({ className, children, ...rest }: React.SelectHTMLAttributes<HTMLSelectElement> & { className?: string }) {
  return (
    <span style={{ flex: "none", minWidth: /h-10/.test(className ?? "") ? 128 : undefined, display: "inline-block" }}>
      <PSelect block {...(rest as React.ComponentProps<typeof PSelect>)}>{children}</PSelect>
    </span>
  );
}
