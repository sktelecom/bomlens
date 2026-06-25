import { describe, expect, it } from "vitest";

import {
  EMPTY_SCAN,
  NAV_GROUPS,
  type ScanContext,
  visibleGroups,
  visibleSectionIds,
} from "./nav";

const SOURCE_SCAN: ScanContext = {
  mode: "SOURCE",
  isAiScan: false,
  hasDependencies: true,
  hasSourceTree: false,
  hasConformance: false,
};
const AI_SCAN: ScanContext = {
  mode: "ANALYZE",
  isAiScan: true,
  hasDependencies: true,
  hasSourceTree: true,
  hasConformance: true,
};
// A supplier SBOM uploaded for review (ANALYZE) with no AI model: it produces a
// conformance report but is not an AI scan.
const SUPPLIER_SBOM: ScanContext = {
  mode: "ANALYZE",
  isAiScan: false,
  hasDependencies: true,
  hasSourceTree: false,
  hasConformance: true,
};

describe("visibleGroups — scan-type + data adaptation", () => {
  it("always shows the core sections", () => {
    const ids = visibleSectionIds(EMPTY_SCAN);
    expect(ids).toContain("overview");
    expect(ids).toContain("components");
    expect(ids).toContain("vulnerabilities");
    expect(ids).toContain("artifacts");
  });

  it("hides the models section for non-AI scans", () => {
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("models");
  });

  it("shows the models section only for AI scans", () => {
    expect(visibleSectionIds(AI_SCAN)).toContain("models");
  });

  it("shows conformance whenever a conformance report exists, AI or not", () => {
    // Core supplier-SBOM fix: a non-AI SBOM with a conformance report still
    // reaches the conformance section (it lives under Risk, not AI).
    expect(visibleSectionIds(SUPPLIER_SBOM)).toContain("conformance");
    expect(visibleSectionIds(AI_SCAN)).toContain("conformance");
    const riskGroup = visibleGroups(SUPPLIER_SBOM).find((g) => g.id === "risk");
    expect(riskGroup?.sections.map((s) => s.id)).toContain("conformance");
  });

  it("hides conformance when no conformance report exists", () => {
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("conformance");
    expect(
      visibleSectionIds({ ...AI_SCAN, hasConformance: false }),
    ).not.toContain("conformance");
  });

  it("gates dependencies/sourceTree on their data being present", () => {
    expect(visibleSectionIds(EMPTY_SCAN)).not.toContain("dependencies");
    expect(visibleSectionIds(EMPTY_SCAN)).not.toContain("sourceTree");
    expect(visibleSectionIds(SOURCE_SCAN)).toContain("dependencies");
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("sourceTree");
    expect(visibleSectionIds(AI_SCAN)).toContain("sourceTree");
  });

  it("drops a group that becomes empty after filtering (AI group on non-AI)", () => {
    expect(visibleGroups(SOURCE_SCAN).map((g) => g.id)).not.toContain("ai");
    expect(visibleGroups(AI_SCAN).map((g) => g.id)).toContain("ai");
  });

  it("preserves rail order and never mutates the source model", () => {
    const before = JSON.stringify(NAV_GROUPS.map((g) => g.sections.length));
    visibleGroups(AI_SCAN);
    expect(JSON.stringify(NAV_GROUPS.map((g) => g.sections.length))).toBe(before);
    expect(visibleSectionIds(EMPTY_SCAN)[0]).toBe("overview");
    expect(visibleSectionIds(AI_SCAN)[0]).toBe("overview");
  });
});
