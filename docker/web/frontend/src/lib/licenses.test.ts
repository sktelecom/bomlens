import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import { licenseGroups, reviewCount, reviewGroups } from "./licenses";

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
