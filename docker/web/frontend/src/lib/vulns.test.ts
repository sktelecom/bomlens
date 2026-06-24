import { describe, expect, it } from "vitest";

import type { Severity, VulnItem } from "./api";
import { compareVulns, sortVulns } from "./vulns";

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

describe("tiebreak", () => {
  it("breaks equal severity by CVSS desc then id", () => {
    const a = v("CVE-2", "CRITICAL", 9.0);
    const b = v("CVE-1", "CRITICAL", 9.0);
    // same severity, same cvss → id ascending
    expect(compareVulns(a, b, "severity", "desc")).toBeGreaterThan(0);
  });
});
