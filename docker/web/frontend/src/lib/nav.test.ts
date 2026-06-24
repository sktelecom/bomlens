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
  hasG7: false,
};
const AI_SCAN: ScanContext = {
  mode: "ANALYZE",
  isAiScan: true,
  hasDependencies: true,
  hasSourceTree: true,
  hasG7: true,
};

describe("visibleGroups — scan-type + data adaptation", () => {
  it("always shows the core sections", () => {
    const ids = visibleSectionIds(EMPTY_SCAN);
    expect(ids).toContain("overview");
    expect(ids).toContain("components");
    expect(ids).toContain("vulnerabilities");
    expect(ids).toContain("artifacts");
  });

  it("hides AI-only sections for non-AI scans", () => {
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("models");
    expect(visibleSectionIds(SOURCE_SCAN)).not.toContain("g7");
  });

  it("shows AI-only sections for AI/ANALYZE scans", () => {
    expect(visibleSectionIds(AI_SCAN)).toContain("models");
    expect(visibleSectionIds(AI_SCAN)).toContain("g7"); // hasG7 true
  });

  it("hides g7 when an AI scan has no G7 conformance checks", () => {
    expect(visibleSectionIds({ ...AI_SCAN, hasG7: false })).not.toContain("g7");
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
