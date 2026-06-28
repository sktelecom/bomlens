import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import {
  isCopyleft,
  licenseGroups,
  licenseRiskSummary,
  licenseRiskTier,
  reviewCount,
  reviewGroups,
} from "./licenses";

const c = (over: Partial<ComponentItem>): ComponentItem => ({
  name: "x", version: "1", group: "", purl: "", type: "library", licenses: [], ...over,
});

const COMPONENTS = [
  c({ name: "llama", licenses: ["LLaMA-3.1"], licenseReview: "behavioral-use" }),
  c({ name: "nc-data", licenses: ["CC-BY-NC-4.0"], licenseReview: "non-commercial" }),
  c({ name: "lib-a", licenses: ["MIT"] }),
  c({ name: "lib-b", licenses: ["MIT"] }),
  c({ name: "unlic", licenses: [] }),
];

describe("licenseGroups", () => {
  it("counts components per license, busiest first, plus unlicensed", () => {
    const { groups, unlicensed } = licenseGroups(COMPONENTS);
    expect(groups[0]).toEqual({ name: "MIT", count: 2 });
    expect(groups.map((g) => g.name)).toContain("CC-BY-NC-4.0");
    expect(unlicensed).toBe(1);
  });
});

describe("reviewGroups", () => {
  it("groups flagged components, behavioral-use before non-commercial", () => {
    const groups = reviewGroups(COMPONENTS);
    expect(groups.map((g) => g.flag)).toEqual(["behavioral-use", "non-commercial"]);
    expect(groups[0].components.map((x) => x.name)).toEqual(["llama"]);
  });

  it("is empty when nothing needs review", () => {
    expect(reviewGroups([c({ licenses: ["MIT"] })])).toEqual([]);
    expect(reviewCount(COMPONENTS)).toBe(2);
  });
});

describe("isCopyleft", () => {
  it("flags copyleft/reciprocal ids and leaves permissive ones alone", () => {
    for (const id of ["GPL-3.0-only", "AGPL-3.0", "LGPL-2.1", "MPL-2.0", "EPL-2.0"]) {
      expect(isCopyleft(id)).toBe(true);
    }
    for (const id of ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]) {
      expect(isCopyleft(id)).toBe(false);
    }
  });
});

describe("licenseRiskTier", () => {
  it("grades by copyleft strength, AGPL/LGPL before bare GPL", () => {
    expect(licenseRiskTier("AGPL-3.0")).toBe("network-copyleft");
    expect(licenseRiskTier("GPL-3.0-only")).toBe("strong-copyleft");
    expect(licenseRiskTier("LGPL-2.1")).toBe("weak-copyleft");
    expect(licenseRiskTier("MPL-2.0")).toBe("weak-copyleft");
    expect(licenseRiskTier("MIT")).toBe("permissive");
    expect(licenseRiskTier("Apache-2.0")).toBe("permissive");
  });

  it("never assumes an unrecognised license is permissive", () => {
    // The core safety property: unknown is uncategorized, not safe.
    expect(licenseRiskTier("Foo-1.0")).toBe("uncategorized");
    expect(licenseRiskTier("Proprietary")).toBe("uncategorized");
    expect(licenseRiskTier("MIT OR Apache-2.0")).toBe("uncategorized");
    expect(licenseRiskTier("")).toBe("uncategorized");
  });
});

describe("licenseRiskSummary", () => {
  it("counts each component once: review flag wins, no-license is uncategorized", () => {
    const s = licenseRiskSummary(COMPONENTS);
    expect(s["review-needed"]).toBe(2); // llama (behavioral) + nc-data
    expect(s.permissive).toBe(2); // lib-a + lib-b (MIT)
    expect(s.uncategorized).toBe(1); // unlic (no license)
    expect(s.TOTAL).toBe(5);
  });

  it("takes the worst tier across a component's licenses", () => {
    const s = licenseRiskSummary([c({ licenses: ["MIT", "GPL-3.0-only"] })]);
    expect(s["strong-copyleft"]).toBe(1);
    expect(s.permissive).toBe(0);
  });

  it("keeps an unknown license out of the permissive bucket", () => {
    const s = licenseRiskSummary([c({ licenses: ["Weird-1.0"] })]);
    expect(s.uncategorized).toBe(1);
    expect(s.permissive).toBe(0);
  });
});
