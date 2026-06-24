import { describe, expect, it } from "vitest";

import {
  EMPTY_SCAN,
  NAV_GROUPS,
  type ScanContext,
  visibleGroups,
  visibleSectionIds,
} from "./nav";

const AI_SCAN: ScanContext = { mode: "ANALYZE", isAiScan: true };

describe("visibleGroups — scan-type adaptation", () => {
  it("hides AI-only sections for non-AI scans", () => {
    const ids = visibleSectionIds(EMPTY_SCAN);
    expect(ids).not.toContain("g7");
    expect(ids).not.toContain("models");
    // Core sections are always present.
    expect(ids).toContain("overview");
    expect(ids).toContain("components");
    expect(ids).toContain("vulnerabilities");
    expect(ids).toContain("licenses");
    expect(ids).toContain("artifacts");
  });

  it("shows AI-only sections for AI/ANALYZE scans", () => {
    const ids = visibleSectionIds(AI_SCAN);
    expect(ids).toContain("g7");
    expect(ids).toContain("models");
  });

  it("drops a group that becomes empty after filtering (AI group on non-AI)", () => {
    const groupIds = visibleGroups(EMPTY_SCAN).map((g) => g.id);
    expect(groupIds).not.toContain("ai");
    expect(visibleGroups(AI_SCAN).map((g) => g.id)).toContain("ai");
  });

  it("preserves rail order and never mutates the source model", () => {
    const before = JSON.stringify(NAV_GROUPS.map((g) => g.sections.length));
    visibleGroups(AI_SCAN);
    expect(JSON.stringify(NAV_GROUPS.map((g) => g.sections.length))).toBe(before);
    // Overview leads the first group in both contexts.
    expect(visibleSectionIds(EMPTY_SCAN)[0]).toBe("overview");
    expect(visibleSectionIds(AI_SCAN)[0]).toBe("overview");
  });
});
