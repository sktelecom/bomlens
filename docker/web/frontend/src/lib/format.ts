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

const dateTimeFormatters = new Map<string, Intl.DateTimeFormat>();

/**
 * A moment as date and time to the minute in the UI language, 24-hour clock
 * (ko "2026. 10. 15. 18:04", en "Oct 15, 2026, 18:04"), in the viewer's time
 * zone. Takes Unix seconds, the unit the scan list carries. Non-finite input
 * returns an empty string so a missing time never renders as "Invalid Date".
 */
export function formatDateTime(unixSec: number, language?: string): string {
  if (!Number.isFinite(unixSec)) return "";
  const tag = numberLocale(language);
  let df = dateTimeFormatters.get(tag);
  if (!df) {
    df = new Intl.DateTimeFormat(tag, {
      year: "numeric",
      month: tag === "ko-KR" ? "numeric" : "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    });
    dateTimeFormatters.set(tag, df);
  }
  return df.format(new Date(unixSec * 1000));
}
