// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { Severity, VulnItem } from "./api";
import {
  applyVulnView,
  viewCounts,
  vulnViewFromQuery,
  vulnViewToQuery,
} from "./vulnView";

function v(id: string, severity: Severity, fixed: string, kev?: boolean): VulnItem {
  return { id, severity, pkg: "p", installed: "1", fixed, title: "", kev };
}

const ITEMS = [
  v("A", "CRITICAL", "2", true),
  v("B", "HIGH", ""),
  v("C", "MEDIUM", "3"),
  v("D", "LOW", ""),
];

describe("applyVulnView", () => {
  it("keeps everything for the default view", () => {
    expect(applyVulnView(ITEMS, "all")).toBe(ITEMS);
  });

  it("narrows to rows with a published fix", () => {
    expect(applyVulnView(ITEMS, "fixable").map((x) => x.id)).toEqual(["A", "C"]);
  });

  it("narrows to rows with no published fix", () => {
    expect(applyVulnView(ITEMS, "unfixed").map((x) => x.id)).toEqual(["B", "D"]);
  });

  it("narrows to actively exploited rows", () => {
    expect(applyVulnView(ITEMS, "exploited").map((x) => x.id)).toEqual(["A"]);
  });

  it("narrows to Critical and High", () => {
    expect(applyVulnView(ITEMS, "critical-high").map((x) => x.id)).toEqual(["A", "B"]);
  });

  it("narrows to Critical or High rows that have a fix", () => {
    expect(applyVulnView(ITEMS, "fixable-severe").map((x) => x.id)).toEqual(["A"]);
  });
});

describe("viewCounts", () => {
  it("counts each preset over the whole list", () => {
    expect(viewCounts(ITEMS)).toEqual({
      all: 4,
      fixable: 2,
      unfixed: 2,
      exploited: 1,
      "critical-high": 2,
      "fixable-severe": 1,
    });
  });
});

describe("view query", () => {
  it("leaves the defaults out of the URL", () => {
    expect(vulnViewToQuery("all", "list")).toEqual({});
  });

  it("round-trips a view and a layout", () => {
    const q = vulnViewToQuery("fixable", "package");
    expect(q).toEqual({ view: "fixable", group: "package" });
    expect(vulnViewFromQuery(q)).toEqual({ view: "fixable", layout: "package" });
  });

  it("reads the link-only fixable-severe view", () => {
    expect(vulnViewFromQuery({ view: "fixable-severe" }).view).toBe("fixable-severe");
  });

  it("reads an unknown or missing value as the default", () => {
    expect(vulnViewFromQuery(undefined)).toEqual({ view: "all", layout: "list" });
    expect(vulnViewFromQuery({ view: "vibes", group: "nope" })).toEqual({
      view: "all",
      layout: "list",
    });
  });
});
