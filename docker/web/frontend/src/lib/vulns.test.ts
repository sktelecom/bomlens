// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { Severity, VulnItem } from "./api";
import { compareVulns, groupByUpgrade, sortVulns } from "./vulns";

function v(id: string, severity: Severity, cvss: number | null, epss?: number): VulnItem {
  return { id, severity, cvss, pkg: "p", installed: "1", fixed: "", title: "", epss };
}

const ITEMS = [
  v("CVE-low", "LOW", 3.1),
  v("CVE-crit-a", "CRITICAL", 9.1),
  v("CVE-crit-b", "CRITICAL", 9.8),
  v("CVE-high", "HIGH", 7.5),
  v("CVE-none", "MEDIUM", null),
];

describe("sortVulns — default severity then CVSS", () => {
  it("orders most severe first, highest CVSS within a band", () => {
    const ids = sortVulns(ITEMS).map((x) => x.id);
    expect(ids).toEqual(["CVE-crit-b", "CVE-crit-a", "CVE-high", "CVE-none", "CVE-low"]);
  });
});

describe("compareVulns — CVSS key", () => {
  it("sorts by score descending, missing scores last", () => {
    const ids = [...ITEMS].sort((a, b) => compareVulns(a, b, "cvss", "desc")).map((x) => x.id);
    expect(ids).toEqual(["CVE-crit-b", "CVE-crit-a", "CVE-high", "CVE-low", "CVE-none"]);
  });

  it("ascending reverses the score order", () => {
    const ids = [...ITEMS].sort((a, b) => compareVulns(a, b, "cvss", "asc")).map((x) => x.id);
    expect(ids[0]).toBe("CVE-none"); // -1 sentinel sorts first ascending
    expect(ids[ids.length - 1]).toBe("CVE-crit-b");
  });
});

describe("compareVulns — EPSS key", () => {
  const items = [
    v("CVE-a", "HIGH", 7, 0.2),
    v("CVE-b", "HIGH", 7, 0.9),
    v("CVE-c", "HIGH", 7, undefined), // no EPSS sorts last (desc)
  ];
  it("sorts by EPSS descending, missing scores last", () => {
    const ids = [...items].sort((a, b) => compareVulns(a, b, "epss", "desc")).map((x) => x.id);
    expect(ids).toEqual(["CVE-b", "CVE-a", "CVE-c"]);
  });
});

describe("compareVulns — nvdSeverity key", () => {
  function withNvd(
    id: string,
    severity: Severity,
    nvdSeverity?: Severity,
  ): VulnItem {
    return {
      id,
      severity,
      cvss: null,
      pkg: "p",
      installed: "1",
      fixed: "",
      title: "",
      nvdSeverity,
    };
  }
  const items = [
    withNvd("CVE-a", "MEDIUM", "LOW"),
    withNvd("CVE-b", "MEDIUM", "CRITICAL"),
    withNvd("CVE-c", "MEDIUM", undefined), // no NVD rating sorts last (desc)
  ];
  it("sorts by NVD severity descending, missing ratings last", () => {
    const ids = [...items].sort((a, b) => compareVulns(a, b, "nvdSeverity", "desc")).map((x) => x.id);
    expect(ids).toEqual(["CVE-b", "CVE-a", "CVE-c"]);
  });
});

describe("tiebreak", () => {
  it("breaks equal severity by CVSS desc then id", () => {
    const a = v("CVE-2", "CRITICAL", 9.0);
    const b = v("CVE-1", "CRITICAL", 9.0);
    // same severity, same cvss → id ascending
    expect(compareVulns(a, b, "severity", "desc")).toBeGreaterThan(0);
  });
});

describe("groupByUpgrade", () => {
  function vg(
    id: string,
    severity: Severity,
    pkg: string,
    installed: string,
    fixed: string,
    purl?: string,
  ): VulnItem {
    return { id, severity, cvss: null, pkg, installed, fixed, title: "", purl };
  }

  it("groups two or more CVEs on the same install that share a fixed version", () => {
    const items = [
      vg("CVE-a", "HIGH", "qs", "6.15.3", "6.16.0"),
      vg("CVE-b", "CRITICAL", "qs", "6.15.3", "6.16.0"),
    ];
    const groups = groupByUpgrade(items);
    expect(groups).toEqual([
      {
        pkg: "qs",
        installed: "6.15.3",
        fixed: "6.16.0",
        vulnIds: ["CVE-a", "CVE-b"],
        maxSeverity: "CRITICAL",
      },
    ]);
  });

  it("does not group a single CVE (not a bundle)", () => {
    const items = [vg("CVE-a", "HIGH", "qs", "6.15.3", "6.16.0")];
    expect(groupByUpgrade(items)).toEqual([]);
  });

  it("drops CVEs with no fixed version from every group", () => {
    const items = [
      vg("CVE-a", "HIGH", "qs", "6.15.3", "6.16.0"),
      vg("CVE-b", "CRITICAL", "qs", "6.15.3", "6.16.0"),
      vg("CVE-c", "CRITICAL", "qs", "6.15.3", ""), // no fix yet
    ];
    expect(groupByUpgrade(items).map((g) => g.vulnIds)).toEqual([["CVE-a", "CVE-b"]]);
  });

  // The real shape this was designed for: the same package name resolved to
  // two different installed versions in one SBOM (measured for real, a qs
  // dependency conflict). Grouping by name alone would wrongly merge the two.
  it("does not merge the same package name across two different installed versions", () => {
    const items = [
      vg("CVE-a", "HIGH", "qs", "6.15.3", "6.16.0"),
      vg("CVE-b", "CRITICAL", "qs", "6.15.3", "6.16.0"),
      vg("CVE-c", "LOW", "qs", "6.16.0", "6.16.1"), // already-updated sibling, own group
      vg("CVE-d", "LOW", "qs", "6.16.0", "6.16.1"),
    ];
    const groups = groupByUpgrade(items);
    expect(groups).toHaveLength(2);
    expect(groups.find((g) => g.installed === "6.15.3")?.vulnIds).toEqual(["CVE-a", "CVE-b"]);
    expect(groups.find((g) => g.installed === "6.16.0")?.vulnIds).toEqual(["CVE-c", "CVE-d"]);
  });

  // Two unrelated components (different ecosystems, here) can share a name,
  // installed version and fixed version by coincidence. Without the purl in
  // the key, this would wrongly bundle them as "one upgrade fixes both".
  it("does not merge two different components that share name, installed and fixed version", () => {
    const items = [
      vg("CVE-a", "HIGH", "foo", "1.0.0", "1.0.1", "pkg:npm/foo@1.0.0"),
      vg("CVE-b", "CRITICAL", "foo", "1.0.0", "1.0.1", "pkg:npm/foo@1.0.0"),
      vg("CVE-c", "LOW", "foo", "1.0.0", "1.0.1", "pkg:golang/foo@1.0.0"),
      vg("CVE-d", "LOW", "foo", "1.0.0", "1.0.1", "pkg:golang/foo@1.0.0"),
    ];
    const groups = groupByUpgrade(items);
    expect(groups).toHaveLength(2);
    expect(groups.find((g) => g.maxSeverity === "CRITICAL")?.vulnIds).toEqual(["CVE-a", "CVE-b"]);
    expect(groups.find((g) => g.maxSeverity === "LOW")?.vulnIds).toEqual(["CVE-c", "CVE-d"]);
  });

  it("sorts worst severity first, then by how many CVEs the upgrade resolves", () => {
    const items = [
      // 2-CVE MEDIUM bundle
      vg("CVE-a", "MEDIUM", "p1", "1.0", "1.1"),
      vg("CVE-b", "MEDIUM", "p1", "1.0", "1.1"),
      // 3-CVE HIGH bundle: worse severity should lead even though it's a
      // different package with more CVEs than the CRITICAL one below.
      vg("CVE-c", "HIGH", "p2", "1.0", "1.1"),
      vg("CVE-d", "HIGH", "p2", "1.0", "1.1"),
      vg("CVE-e", "HIGH", "p2", "1.0", "1.1"),
      // 2-CVE CRITICAL bundle: worst severity, leads regardless of count.
      vg("CVE-f", "CRITICAL", "p3", "1.0", "1.1"),
      vg("CVE-g", "CRITICAL", "p3", "1.0", "1.1"),
    ];
    const groups = groupByUpgrade(items);
    expect(groups.map((g) => g.pkg)).toEqual(["p3", "p2", "p1"]);
  });
});
