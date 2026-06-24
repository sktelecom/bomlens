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
};
const AI_SCAN: ScanContext = {
  mode: "ANALYZE",
  isAiScan: true,
  hasDependencies: true,
  hasSourceTree: true,
};

describe("visibleGroups — scan-type + data adaptation", () => {
  it("always shows the core sections", () => {
    const ids = visibleSectionIds(EMPTY_SCAN);
    expect(ids).toContain("overview");
    expect(ids).toContain("components");
    expect(ids).toContain("vulnerabilities");
  });

  it("hides AI-only sections for non-AI scans", () => {
    const ids = visibleSectionIds(SOURCE_SCAN);
    expect(ids).not.toContain("g7");
    expect(ids).not.toContain("models");
  });

  it("shows AI-only sections for AI/ANALYZE scans", () => {
    const ids = visibleSectionIds(AI_SCAN);
    expect(ids).toContain("g7");
    expect(ids).toContain("models");
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
