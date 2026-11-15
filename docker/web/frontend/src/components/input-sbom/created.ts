// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

const formatters = new Map<string, Intl.DateTimeFormat>();

/**
 * The document's creation time as a localized date and time in UTC
 * (en "Jan 2, 2026, 03:04 UTC", ko "2026. 1. 2. 03:04 (UTC)"). The zone stays UTC
 * because that is what the document recorded; converting it to the viewer's zone
 * would show a time the supplier never wrote. A value that does not parse is
 * returned as it came, so nothing is invented.
 */
export function formatCreated(iso: string, language?: string): string {
  const time = Date.parse(iso);
  if (!Number.isFinite(time)) return iso;
  const ko = (language ?? "").startsWith("ko");
  const tag = ko ? "ko-KR" : "en-US";
  let df = formatters.get(tag);
  if (!df) {
    df = new Intl.DateTimeFormat(tag, {
      year: "numeric",
      month: ko ? "numeric" : "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
      timeZone: "UTC",
    });
    formatters.set(tag, df);
  }
  const text = df.format(new Date(time));
  return ko ? `${text} (UTC)` : `${text} UTC`;
}
