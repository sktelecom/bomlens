// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { formatNumber, numberLocale } from "./format";

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
