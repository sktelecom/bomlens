// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { SecuritySummary } from "./api";
import { uncheckedReasonKey, uncheckedSummary } from "./unchecked";

const base: SecuritySummary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 0 };

describe("uncheckedSummary", () => {
  it("is null when every component was checked", () => {
    expect(uncheckedSummary(base)).toBeNull();
    expect(uncheckedSummary(null)).toBeNull();
    expect(uncheckedSummary({ ...base, uncheckedCount: 0, uncheckedComponents: [] })).toBeNull();
  });

  it("counts rows per reason and keeps a count larger than the capped list", () => {
    const u = uncheckedSummary({
      ...base,
      uncheckedCount: 640,
      uncheckedComponents: [
        { name: "busybox", version: "", reason: "no-version" },
        { name: "libfoo", version: "1.2", reason: "no-identifier", purl: "pkg:generic/libfoo@1.2" },
        { name: "bar", version: "", reason: "no-version" },
      ],
    })!;
    expect(u.count).toBe(640);
    expect(u.truncated).toBe(true);
    expect(u.byReason).toEqual([
      { reason: "no-version", count: 2 },
      { reason: "no-identifier", count: 1 },
    ]);
  });

  it("never reports fewer than the rows present, and folds an unrecognized reason into unknown", () => {
    const u = uncheckedSummary({
      ...base,
      uncheckedComponents: [{ name: "x", version: "", reason: "later" as never }],
    })!;
    expect(u.count).toBe(1);
    expect(u.truncated).toBe(false);
    expect(u.rows[0].reason).toBe("unknown");
  });
});

describe("uncheckedReasonKey", () => {
  it("maps each reason code to a label key", () => {
    expect(uncheckedReasonKey("no-version")).toBe("result.uncheckedReason.noVersion");
    expect(uncheckedReasonKey("no-identifier")).toBe("result.uncheckedReason.noIdentifier");
    expect(uncheckedReasonKey("unknown")).toBe("result.uncheckedReason.unknown");
  });
});
