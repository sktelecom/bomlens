// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { formatDateTime, formatNumber, numberLocale } from "./format";

describe("numberLocale", () => {
  it("maps Korean variants to ko-KR and everything else to en-US", () => {
    expect(numberLocale("ko")).toBe("ko-KR");
    expect(numberLocale("ko-KR")).toBe("ko-KR");
    expect(numberLocale("en")).toBe("en-US");
    expect(numberLocale("fr")).toBe("en-US");
    expect(numberLocale(undefined)).toBe("en-US");
  });
});

describe("formatNumber", () => {
  it("groups thousands in both languages", () => {
    expect(formatNumber(60123, "ko")).toBe("60,123");
    expect(formatNumber(60123, "en")).toBe("60,123");
    expect(formatNumber(1234567, "en")).toBe("1,234,567");
  });
  it("leaves small numbers and zero alone", () => {
    expect(formatNumber(0, "en")).toBe("0");
    expect(formatNumber(999, "ko")).toBe("999");
  });
  it("handles negatives and defaults to English", () => {
    expect(formatNumber(-12000)).toBe("-12,000");
  });
  it("returns non-finite values as plain text", () => {
    expect(formatNumber(Number.NaN, "en")).toBe("NaN");
    expect(formatNumber(Infinity, "en")).toBe("Infinity");
  });
});

describe("formatDateTime", () => {
  // 2023-11-14T22:13:20Z. Compare through the same zone the formatter uses.
  const SEC = 1700000000;
  const d = new Date(SEC * 1000);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");

  it("shows the year, the day and a 24-hour time to the minute", () => {
    expect(formatDateTime(SEC, "en")).toContain(`${hh}:${mm}`);
    expect(formatDateTime(SEC, "ko")).toContain(`${hh}:${mm}`);
    expect(formatDateTime(SEC, "en")).toContain("2023");
  });
  it("spells the month in English and uses numbers in Korean", () => {
    expect(formatDateTime(SEC, "en")).toMatch(/^[A-Z][a-z]{2} \d{1,2}, 2023/);
    expect(formatDateTime(SEC, "ko")).toMatch(/^2023\. \d{1,2}\. \d{1,2}\./);
  });
  it("returns an empty string for a missing time", () => {
    expect(formatDateTime(Number.NaN, "en")).toBe("");
  });
});
