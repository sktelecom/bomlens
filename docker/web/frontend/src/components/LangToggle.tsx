// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { SegmentedControl } from "@primer/react";
import { useTranslation } from "react-i18next";

/** The two UI languages: the short code shown, the language's own name read out. */
export const LANGUAGES: ReadonlyArray<{ code: "ko" | "en"; short: string; name: string }> = [
  { code: "ko", short: "KO", name: "한국어" },
  { code: "en", short: "EN", name: "English" },
];

/** The current UI language, as one of LANGUAGES' codes. */
export function useCurrentLanguage(): string {
  const { i18n } = useTranslation();
  return i18n.resolvedLanguage ?? i18n.language;
}

/** KO / EN switch in the top bar (the help menu carries it on narrow widths). */
export function LangToggle() {
  const { i18n, t } = useTranslation();
  const current = useCurrentLanguage();
  return (
    <SegmentedControl
      aria-label={t("lang.label")}
      size="small"
      onChange={(i) => void i18n.changeLanguage(LANGUAGES[i].code)}
    >
      {LANGUAGES.map((l) => (
        <SegmentedControl.Button
          key={l.code}
          selected={current === l.code}
          lang={l.code}
          // The visible code leads the name, so voice control by "KO" works.
          aria-label={`${l.short}, ${l.name}`}
        >
          {l.short}
        </SegmentedControl.Button>
      ))}
    </SegmentedControl>
  );
}
