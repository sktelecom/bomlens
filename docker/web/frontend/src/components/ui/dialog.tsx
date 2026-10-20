// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useId, useRef, type ReactNode, type RefObject } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { FOCUSABLE_SELECTOR, wrapFocusIndex } from "@/lib/focus";
import { cn } from "@/lib/utils";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  /** Accessible name. Use `labelledBy` instead when a heading carries it. */
  label?: string;
  labelledBy?: string;
  describedBy?: string;
  /** Extra classes for the panel (size, layout). */
  className?: string;
  /** Where focus lands on open. Defaults to the first focusable control. */
  initialFocus?: RefObject<HTMLElement | null>;
  children: ReactNode;
}

/**
 * The app's modal shell: an overlay panel that holds focus while it is open.
 *
 * No dialog library — what a modal owes the user is a small, fixed list, and
 * all of it is here: focus enters the panel on open, Tab cycles inside it
 * instead of wandering into the page behind, Escape and a backdrop click close
 * it, and focus returns to whatever opened it. Everything modal in the app goes
 * through this component so those guarantees hold in one place.
 */
export function Modal({
  open,
  onClose,
  label,
  labelledBy,
  describedBy,
  className,
  initialFocus,
  children,
}: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    // Remember who opened us, to hand focus back on close.
    const opener = document.activeElement as HTMLElement | null;
    const focusables = () =>
      Array.from(
        panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ??
          [],
      );

    (initialFocus?.current ?? focusables()[0] ?? panelRef.current)?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const items = focusables();
      const next = wrapFocusIndex(
        items.length,
        items.indexOf(document.activeElement as HTMLElement),
        e.shiftKey,
      );
      if (next === null) return;
      e.preventDefault();
      items[next].focus();
    };

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      // The opener can be gone (a deleted row's button); focus then falls to
      // the body, which is the browser's own default.
      opener?.focus?.();
    };
  }, [open, onClose, initialFocus]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={cn(
          "relative z-10 flex w-full flex-col overflow-hidden rounded-xl border bg-card shadow-lg animate-fade-in focus-visible:outline-none",
          className,
        )}
      >
        {children}
      </div>
    </div>
  );
}

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: string;
  confirmLabel: string;
  cancelLabel?: string;
  /** Paints the confirm button as destructive. */
  destructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Confirmation step for an action that cannot be taken back. Focus opens on
 * Cancel, so a stray Enter or Escape leaves the data alone.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel,
  destructive,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const { t } = useTranslation();
  const id = useId();
  const cancelRef = useRef<HTMLButtonElement>(null);

  return (
    <Modal
      open={open}
      onClose={onCancel}
      labelledBy={`${id}-title`}
      describedBy={description ? `${id}-desc` : undefined}
      initialFocus={cancelRef}
      className="max-w-md gap-4 p-6"
    >
      <h2 id={`${id}-title`} className="text-body font-semibold">
        {title}
      </h2>
      {description && (
        <p id={`${id}-desc`} className="text-body-sm text-muted-foreground">
          {description}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button ref={cancelRef} variant="outline" size="sm" onClick={onCancel}>
          {cancelLabel ?? t("dialog.cancel")}
        </Button>
        <Button
          variant={destructive ? "destructive" : "default"}
          size="sm"
          onClick={onConfirm}
        >
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
