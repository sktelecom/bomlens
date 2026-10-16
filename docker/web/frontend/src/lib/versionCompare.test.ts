// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { compareVersions } from "./versionCompare";

describe("compareVersions", () => {
  it("compares numeric parts as numbers, not text", () => {
    expect(compareVersions("2.10.0", "2.9.0")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("0.9", "1.0")).toBeLessThan(0);
  });

  it("treats a shorter version as the earlier one when the rest is a release part", () => {
    expect(compareVersions("1.0", "1.0.1")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "1.0")).toBeGreaterThan(0);
  });

  it("ranks a pre-release below its release", () => {
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "1.0.0-rc1")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0-beta", "1.0.0-rc")).toBeLessThan(0);
  });

  it("ignores a leading v", () => {
    expect(compareVersions("v2.0.0", "1.9.9")).toBeGreaterThan(0);
    expect(compareVersions("v1.0.0", "1.0.0")).toBe(0);
  });
});
