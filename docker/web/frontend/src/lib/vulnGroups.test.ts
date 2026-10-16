// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { Severity, VulnItem } from "./api";
import { bundleSteps, effectiveFixed, groupByPackage, upgradeBundles } from "./vulnGroups";

function v(
  id: string,
  pkg: string,
  installed: string,
  fixed: string,
  severity: Severity = "HIGH",
  extra: Partial<VulnItem> = {},
): VulnItem {
  return { id, pkg, installed, fixed, severity, title: "", ...extra };
}

describe("effectiveFixed", () => {
  it("returns a single fixed version as is", () => {
    expect(effectiveFixed({ fixed: "2.8.0", installed: "2.1.0" })).toBe("2.8.0");
    expect(effectiveFixed({ fixed: "", installed: "2.1.0" })).toBe("");
  });

  it("picks the nearest listed version above the installed one", () => {
    expect(effectiveFixed({ fixed: "1.3.4, 1.2.9", installed: "1.2.0" })).toBe("1.2.9");
    expect(effectiveFixed({ fixed: "1.2.9, 1.3.4", installed: "1.3.0" })).toBe("1.3.4");
  });

  it("falls back to the first listed version", () => {
    expect(effectiveFixed({ fixed: "1.2.9, 1.3.4", installed: "" })).toBe("1.2.9");
    expect(effectiveFixed({ fixed: "1.2.9, 1.3.4", installed: "9.0.0" })).toBe("1.2.9");
  });
});

describe("groupByPackage", () => {
  const urllib3 = [
    v("A", "urllib3", "2.1.0", "2.8.0", "HIGH"),
    v("B", "urllib3", "2.1.0", "2.8.0", "MEDIUM"),
    v("C", "urllib3", "2.1.0", "2.6.0", "CRITICAL"),
    v("D", "urllib3", "2.1.0", "2.6.0", "LOW"),
    v("E", "urllib3", "2.1.0", "2.5.0", "LOW"),
    v("F", "urllib3", "2.1.0", "2.4.0", "LOW"),
    v("G", "urllib3", "2.1.0", "2.3.0", "LOW"),
    v("H", "urllib3", "2.1.0", "", "LOW"),
  ];

  it("merges a package's fix versions into cumulative steps", () => {
    const [g] = groupByPackage(urllib3);
    expect(g.pkg).toBe("urllib3");
    expect(g.vulns).toHaveLength(8);
    expect(g.steps).toEqual([
      { fixed: "2.3.0", count: 1 },
      { fixed: "2.4.0", count: 2 },
      { fixed: "2.5.0", count: 3 },
      { fixed: "2.6.0", count: 5 },
      { fixed: "2.8.0", count: 7 },
    ]);
    expect(g.unfixed).toBe(1);
    expect(g.maxSeverity).toBe("CRITICAL");
  });

  it("orders versions numerically, not as text", () => {
    const [g] = groupByPackage([
      v("A", "p", "1.0.0", "1.10.0"),
      v("B", "p", "1.0.0", "1.9.0"),
    ]);
    expect(g.steps.map((s) => s.fixed)).toEqual(["1.9.0", "1.10.0"]);
    expect(g.steps.map((s) => s.count)).toEqual([1, 2]);
  });

  it("keeps two installs of one name apart and keeps first-appearance order", () => {
    const groups = groupByPackage([
      v("A", "qs", "6.15.3", "6.16.0"),
      v("B", "lodash", "4.17.20", "4.17.21"),
      v("C", "qs", "6.14.0", "6.16.0"),
      v("D", "qs", "6.15.3", "6.16.0"),
    ]);
    expect(groups.map((g) => `${g.pkg}@${g.installed}`)).toEqual([
      "qs@6.15.3",
      "lodash@4.17.20",
      "qs@6.14.0",
    ]);
    expect(groups[0].vulns).toHaveLength(2);
  });

  it("flags a package carrying an actively exploited CVE", () => {
    const [g] = groupByPackage([v("A", "p", "1", "2"), v("B", "p", "1", "", "LOW", { kev: true })]);
    expect(g.kev).toBe(true);
    expect(g.steps).toEqual([{ fixed: "2", count: 1 }]);
    expect(g.unfixed).toBe(1);
  });
});

describe("upgradeBundles", () => {
  it("lists only packages whose top upgrade resolves two or more", () => {
    const groups = groupByPackage([
      v("A", "qs", "6.15.3", "6.16.0", "CRITICAL"),
      v("B", "qs", "6.15.3", "6.16.0", "HIGH"),
      v("C", "lodash", "4.17.20", "4.17.21", "HIGH"),
      // Two different fixed versions still make one upgrade that resolves both.
      v("D", "zlib", "1.2.0", "1.2.5", "LOW"),
      v("E", "zlib", "1.2.0", "1.2.8", "LOW"),
    ]);
    const bundles = upgradeBundles(groups);
    expect(bundles.map((g) => g.pkg)).toEqual(["qs", "zlib"]);
  });

  it("leads with the worst severity, then the biggest win", () => {
    const groups = groupByPackage([
      v("A", "small", "1", "2", "CRITICAL"),
      v("B", "small", "1", "2", "CRITICAL"),
      v("C", "big", "1", "2", "HIGH"),
      v("D", "big", "1", "2", "HIGH"),
      v("E", "big", "1", "2", "HIGH"),
      v("F", "mid", "1", "2", "HIGH"),
      v("G", "mid", "1", "2", "HIGH"),
    ]);
    expect(upgradeBundles(groups).map((g) => g.pkg)).toEqual(["small", "big", "mid"]);
  });
});

describe("bundleSteps", () => {
  it("returns the top target and the nearest lower ones", () => {
    const [g] = groupByPackage([
      v("A", "p", "1", "2"),
      v("B", "p", "1", "3"),
      v("C", "p", "1", "4"),
      v("D", "p", "1", "5"),
    ]);
    const { top, lower } = bundleSteps(g);
    expect(top).toEqual({ fixed: "5", count: 4 });
    expect(lower).toEqual([
      { fixed: "3", count: 2 },
      { fixed: "4", count: 3 },
    ]);
  });
});
