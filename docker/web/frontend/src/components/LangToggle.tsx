// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";
import { FOCUS_RING, SELECTED_SOLID } from "@/components/ui/selectable";

const LANGS: Array<[string, string]> = [
  ["ko", "KO"],
  ["en", "EN"],
];

export function LangToggle() {
  const { i18n, t } = useTranslation();
  const current = i18n.resolvedLanguage ?? i18n.language;

  return (
    <div
      className="inline-flex items-center rounded-md border border-input bg-background p-0.5"
      role="group"
      aria-label={t("lang.label")}
    >
      {LANGS.map(([code, label]) => {
        const active = current === code;
        return (
          <button
            key={code}
            type="button"
            onClick={() => void i18n.changeLanguage(code)}
            aria-pressed={active}
            className={cn(
              "rounded-sm border border-transparent px-2 py-1 text-label font-medium transition-colors duration-fast ease-out-soft",
              FOCUS_RING,
              active
                ? SELECTED_SOLID
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}
