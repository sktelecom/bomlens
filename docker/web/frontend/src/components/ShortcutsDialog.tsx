// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/dialog";
import { isAppleKeyboard } from "@/lib/platform";

const KBD =
  "inline-block rounded border bg-muted px-1.5 py-0.5 font-sans text-caption font-medium text-foreground";

/** The keys the app answers to. One list, so the dialog cannot drift from what
 *  the help menu says is there. */
export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const mod = isAppleKeyboard() ? "⌘" : "Ctrl";
  const rows: Array<{ keys: string[]; label: string }> = [
    { keys: [mod, "K"], label: t("shortcuts.search") },
    { keys: ["↑", "↓"], label: t("shortcuts.searchMove") },
    { keys: ["Enter"], label: t("shortcuts.searchOpen") },
    { keys: ["Esc"], label: t("shortcuts.close") },
    { keys: ["?"], label: t("shortcuts.list") },
  ];
  return (
    <Modal open={open} onClose={onClose} labelledBy={titleId} className="max-w-md">
      <div className="space-y-4 p-5">
        <h2 id={titleId} className="text-title font-semibold tracking-tight text-foreground">
          {t("shortcuts.title")}
        </h2>
        <ul className="space-y-2" data-testid="shortcut-list">
          {rows.map((r) => (
            <li key={r.label} className="flex items-center justify-between gap-4 text-body-sm">
              <span className="text-foreground">{r.label}</span>
              <span className="flex shrink-0 items-center gap-1">
                {r.keys.map((k) => (
                  <kbd key={k} className={KBD}>
                    {k}
                  </kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={onClose}>
            {t("shortcuts.done")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
