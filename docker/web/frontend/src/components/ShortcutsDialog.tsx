// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { XIcon } from "@primer/octicons-react";
import { Dialog, IconButton } from "@primer/react";
import type { ReactNode, RefObject } from "react";
import { useTranslation } from "react-i18next";

import { isAppleKeyboard } from "@/lib/platform";

/**
 * A Primer Dialog header with a translated close button. Primer's own close
 * button is labelled "Close" in English whatever the UI language.
 */
export function DialogHeader({
  id,
  title,
  onClose,
}: {
  id: string;
  title: ReactNode;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  return (
    // The same spacing as Primer's own Dialog header: 8px around, the title
    // padded 6px by 8px, title and close button centred on one line.
    <Dialog.Header
      style={{ display: "flex", alignItems: "center", gap: "var(--base-size-8)", padding: "var(--base-size-8)" }}
    >
      <div style={{ flex: 1, minWidth: 0, padding: "var(--base-size-6) var(--base-size-8)" }}>
        <Dialog.Title id={id}>{title}</Dialog.Title>
      </div>
      <IconButton
        icon={XIcon}
        variant="invisible"
        aria-label={t("viewer.close")}
        onClick={onClose}
        unsafeDisableTooltip
      />
    </Dialog.Header>
  );
}

/** The keys the app answers to. One list, so the dialog cannot drift from what
 *  the help menu says is there. */
export function ShortcutsDialog({
  onClose,
  returnFocusRef,
}: {
  onClose: () => void;
  /** Where focus goes when the dialog closes (the help menu button). */
  returnFocusRef?: RefObject<HTMLElement | null>;
}) {
  const { t } = useTranslation();
  const mod = isAppleKeyboard() ? "⌘" : "Ctrl";
  const rows: Array<{ keys: string[]; label: string }> = [
    { keys: [mod, "K"], label: t("shortcuts.search") },
    { keys: ["↑", "↓"], label: t("shortcuts.searchMove") },
    { keys: ["Enter"], label: t("shortcuts.searchOpen") },
    { keys: ["Esc"], label: t("shortcuts.close") },
    { keys: ["?"], label: t("shortcuts.list") },
  ];
  return (
    <Dialog
      title={t("shortcuts.title")}
      onClose={onClose}
      width="medium"
      returnFocusRef={returnFocusRef as RefObject<HTMLElement>}
      renderHeader={({ dialogLabelId }) => (
        <DialogHeader id={dialogLabelId} title={t("shortcuts.title")} onClose={onClose} />
      )}
    >
      <ul
        data-testid="shortcut-list"
        style={{ margin: 0, padding: 0, listStyle: "none", fontSize: "var(--text-body-size-medium)" }}
      >
        {rows.map((r) => (
          <li
            key={r.label}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "var(--base-size-16)",
              padding: "var(--base-size-4) 0",
            }}
          >
            <span>{r.label}</span>
            <span style={{ display: "flex", gap: "var(--base-size-4)", flex: "none" }}>
              {r.keys.map((k) => (
                <kbd key={k} className="bl-kbd">
                  {k}
                </kbd>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}
