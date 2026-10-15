// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

/** The BCP 47 tag used for number formatting; anything but Korean is English. */
export function numberLocale(language: string | undefined): string {
  return (language || "en").toLowerCase().startsWith("ko") ? "ko-KR" : "en-US";
}

const formatters = new Map<string, Intl.NumberFormat>();

/**
 * Format a count or metric with digit grouping for the UI language
 * (60123 -> "60,123"). Use it for user-visible counts only, never for
 * identifiers, versions, years, ports or hashes. Non-finite input is returned
 * as its plain string so a missing value never renders as "NaN".
 */
export function formatNumber(value: number, language?: string): string {
  if (!Number.isFinite(value)) return String(value);
  const tag = numberLocale(language);
  let nf = formatters.get(tag);
  if (!nf) {
    nf = new Intl.NumberFormat(tag);
    formatters.set(tag, nf);
  }
  return nf.format(value);
}

/** Bound `formatNumber` for the current UI language; re-renders on a language switch. */
export function useFormatNumber(): (value: number) => string {
  const { i18n } = useTranslation();
  const language = i18n.language;
  return (value: number) => formatNumber(value, language);
}
