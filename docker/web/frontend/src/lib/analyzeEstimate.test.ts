// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { analyzeMinutesEstimate } from "./analyzeEstimate";

const MB = 1024 * 1024;

describe("analyzeMinutesEstimate", () => {
  it("shows nothing for a small file", () => {
    expect(analyzeMinutesEstimate(0)).toBeNull();
    expect(analyzeMinutesEstimate(4 * MB)).toBeNull();
    expect(analyzeMinutesEstimate(Number.NaN)).toBeNull();
  });

  it("scales with size, measured at about 5 minutes for 14 MB", () => {
    expect(analyzeMinutesEstimate(14 * MB)).toBe(5);
    expect(analyzeMinutesEstimate(5 * MB)).toBe(2);
    expect(analyzeMinutesEstimate(90 * MB)).toBe(30);
  });
});
