// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { SecuritySummary } from "./api";
import { advisorySummary, vulnAliases } from "./advisories";

const base: SecuritySummary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 0 };

describe("advisorySummary", () => {
  it("is null when there are no advisories", () => {
    expect(advisorySummary(base)).toBeNull();
    expect(advisorySummary(null)).toBeNull();
    expect(advisorySummary({ ...base, advisoryCount: 0, advisories: [] })).toBeNull();
  });

  it("keeps a count larger than the capped list", () => {
    const a = advisorySummary({
      ...base,
      advisoryCount: 640,
      advisories: [
        {
          id: "DLA-4792-1",
          pkg: "tzdata",
          installed: "2025b-0+deb12u2",
          severity: "UNKNOWN",
          title: "tzdata - new timezone database",
          target: "sample (debian 12.12)",
          fixed: "2026c-0+deb12u1",
        },
      ],
    })!;
    expect(a.count).toBe(640);
    expect(a.truncated).toBe(true);
    expect(a.rows[0].id).toBe("DLA-4792-1");
  });

  it("drops rows without an id and folds an unrecognized severity into UNKNOWN", () => {
    const a = advisorySummary({
      ...base,
      advisories: [
        { id: "", pkg: "x", installed: "", severity: "LOW", title: "", target: "" },
        { id: "NSWG-ECO-1", pkg: "p", installed: "1.0.0", severity: "weird" as never, title: "", target: "Node.js" },
      ],
    })!;
    expect(a.count).toBe(1);
    expect(a.truncated).toBe(false);
    expect(a.rows).toHaveLength(1);
    expect(a.rows[0].severity).toBe("UNKNOWN");
  });
});

describe("vulnAliases", () => {
  it("lists advisory numbers other than the id, once each", () => {
    expect(vulnAliases({ id: "CVE-2020-8203", aliases: ["NSWG-ECO-516", "CVE-2020-8203", "NSWG-ECO-516"] })).toEqual([
      "NSWG-ECO-516",
    ]);
  });

  it("is empty when the row has none or a malformed list", () => {
    expect(vulnAliases({ id: "CVE-1" })).toEqual([]);
    expect(vulnAliases({ id: "CVE-1", aliases: "DLA-1" })).toEqual([]);
    expect(vulnAliases({ id: "CVE-1", aliases: [1, "", null] })).toEqual([]);
  });
});
