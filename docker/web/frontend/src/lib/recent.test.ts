import { describe, expect, it } from "vitest";

import type { RecentScan } from "./api";
import {
  formatRelativeTime,
  scanComparison,
  scanTypeLabelKey,
  summarizeRecent,
} from "./recent";

function scan(over: Partial<RecentScan> = {}): RecentScan {
  return {
    id: "p_1.0",
    project: "p",
    version: "1.0",
    components: 10,
    maxSeverity: null,
    isAiScan: false,
    componentType: null,
    generatedAt: 0,
    ...over,
  };
}

describe("summarizeRecent", () => {
  it("counts total, at-risk (CRITICAL/HIGH) and AI scans", () => {
    const s = summarizeRecent([
      scan({ maxSeverity: "CRITICAL" }),
      scan({ maxSeverity: "HIGH" }),
      scan({ maxSeverity: "MEDIUM" }),
      scan({ maxSeverity: null, isAiScan: true }),
    ]);
    expect(s).toEqual({ total: 4, atRisk: 2, ai: 1 });
  });

  it("is all-zero for an empty list", () => {
    expect(summarizeRecent([])).toEqual({ total: 0, atRisk: 0, ai: 0 });
  });
});

describe("scanTypeLabelKey", () => {
  it("labels AI scans, with AI winning over component type", () => {
    expect(scanTypeLabelKey(scan({ isAiScan: true }))).toBe("recent.typeAi");
    expect(
      scanTypeLabelKey(scan({ isAiScan: true, componentType: "application" })),
    ).toBe("recent.typeAi");
  });

  it("maps the CycloneDX root component type for non-AI scans", () => {
    expect(scanTypeLabelKey(scan({ componentType: "application" }))).toBe(
      "recent.typeSource",
    );
    expect(scanTypeLabelKey(scan({ componentType: "firmware" }))).toBe(
      "recent.typeFirmware",
    );
    expect(scanTypeLabelKey(scan({ componentType: "container" }))).toBe(
      "recent.typeContainer",
    );
    expect(scanTypeLabelKey(scan({ componentType: "operating-system" }))).toBe(
      "recent.typeRootfs",
    );
  });

  it("falls back to a generic SBOM for unknown/absent types", () => {
    expect(scanTypeLabelKey(scan({ componentType: null }))).toBe(
      "recent.typeSbom",
    );
    expect(scanTypeLabelKey(scan({ componentType: "data" }))).toBe(
      "recent.typeSbom",
    );
  });
});

describe("scanComparison", () => {
  const list: RecentScan[] = [
    scan({ id: "cur", version: "2.0", components: 13, maxSeverity: "CRITICAL", generatedAt: 200 }),
    scan({ id: "prev", version: "1.0", components: 10, maxSeverity: "HIGH", generatedAt: 100 }),
    scan({ id: "other", project: "q", components: 99, generatedAt: 150 }),
  ];

  it("compares against the most recent earlier scan of the same project", () => {
    const cmp = scanComparison(list, "cur");
    expect(cmp?.prev.id).toBe("prev");
    expect(cmp?.componentsDelta).toBe(3);
    expect(cmp?.severityDir).toBe("up"); // HIGH → CRITICAL
  });

  it("reports a drop and an unchanged severity by rank", () => {
    expect(
      scanComparison(
        [
          scan({ id: "cur", components: 8, maxSeverity: "LOW", generatedAt: 200 }),
          scan({ id: "prev", components: 10, maxSeverity: "CRITICAL", generatedAt: 100 }),
        ],
        "cur",
      ),
    ).toMatchObject({ componentsDelta: -2, severityDir: "down" });
    expect(
      scanComparison(
        [
          scan({ id: "cur", maxSeverity: "MEDIUM", generatedAt: 200 }),
          scan({ id: "prev", maxSeverity: "MEDIUM", generatedAt: 100 }),
        ],
        "cur",
      )?.severityDir,
    ).toBe("same");
  });

  it("is null with no prior scan of the same project, or an unknown id", () => {
    expect(scanComparison(list, "prev")).toBeNull(); // nothing older for project p
    expect(scanComparison(list, "missing")).toBeNull();
  });
});

describe("formatRelativeTime", () => {
  const nowMs = 1_000_000_000; // 1e9 s

  it("renders sub-minute as 'now'", () => {
    expect(formatRelativeTime(1_000_000_000 / 1000 - 30, nowMs, "en")).toBe(
      "now",
    );
  });

  it("renders hours and days ago", () => {
    const nowSec = nowMs / 1000;
    expect(formatRelativeTime(nowSec - 7200, nowMs, "en")).toBe("2 hours ago");
    expect(formatRelativeTime(nowSec - 86_400, nowMs, "en")).toBe("yesterday");
  });
});
