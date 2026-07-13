import { describe, expect, it } from "vitest";

import type { ConformanceCheck, DoneEvent } from "./api";
import {
  conformanceCount,
  deriveScanContext,
  sectionCounts,
  sourceTreeFileName,
} from "./results";

function makeResult(over: Partial<DoneEvent> = {}): DoneEvent {
  return {
    ok: true,
    mode: "SOURCE",
    results: [{ name: "demo_1.0_bom.json", size: 10 }],
    sbom: { components: 3 },
    security: null,
    conformance: null,
    ...over,
  };
}

describe("deriveScanContext", () => {
  it("returns the empty context before any scan", () => {
    const ctx = deriveScanContext(null);
    expect(ctx).toEqual({
      mode: null,
      isAiScan: false,
      hasDependencies: false,
      hasSourceTree: false,
      hasConformance: false,
    });
  });

  it("flags conformance when the report carries checks", () => {
    expect(deriveScanContext(makeResult()).hasConformance).toBe(false);
    const withConf = makeResult({
      conformance: {
        result: "fail",
        checks: [{ id: "purl", label: "PURL", required: true, status: "fail", detail: "" }],
      },
    });
    expect(deriveScanContext(withConf).hasConformance).toBe(true);
  });

  it("flags dependencies when a CycloneDX SBOM artifact exists", () => {
    expect(deriveScanContext(makeResult()).hasDependencies).toBe(true);
    expect(deriveScanContext(makeResult({ results: [] })).hasDependencies).toBe(false);
  });

  it("flags the source tree when a ScanCode artifact exists", () => {
    const withScancode = makeResult({
      results: [
        { name: "demo_1.0_bom.json", size: 10 },
        { name: "demo_1.0_scancode.json", size: 20 },
      ],
    });
    expect(deriveScanContext(withScancode).hasSourceTree).toBe(true);
    expect(deriveScanContext(makeResult()).hasSourceTree).toBe(false);
  });

  it("flags the source tree from the structure-only _files.json fallback", () => {
    const withFiles = makeResult({
      results: [
        { name: "demo_1.0_bom.json", size: 10 },
        { name: "demo_1.0_files.json", size: 20 },
      ],
    });
    expect(deriveScanContext(withFiles).hasSourceTree).toBe(true);
  });
});

describe("sourceTreeFileName", () => {
  it("prefers the ScanCode artifact over _files.json when both exist", () => {
    const both = makeResult({
      results: [
        { name: "demo_1.0_bom.json", size: 10 },
        { name: "demo_1.0_files.json", size: 20 },
        { name: "demo_1.0_scancode.json", size: 30 },
      ],
    });
    expect(sourceTreeFileName(both)).toBe("demo_1.0_scancode.json");
  });

  it("falls back to _files.json when no ScanCode artifact exists", () => {
    const filesOnly = makeResult({
      results: [
        { name: "demo_1.0_bom.json", size: 10 },
        { name: "demo_1.0_files.json", size: 20 },
      ],
    });
    expect(sourceTreeFileName(filesOnly)).toBe("demo_1.0_files.json");
  });

  it("returns undefined when no source-tree artifact exists (e.g. AI scan)", () => {
    expect(sourceTreeFileName(makeResult())).toBeUndefined();
  });

  it("carries the backend mode through", () => {
    expect(deriveScanContext(makeResult({ mode: "ANALYZE" })).mode).toBe("ANALYZE");
  });
});

describe("sectionCounts", () => {
  it("counts components and total vulnerabilities", () => {
    const counts = sectionCounts(
      makeResult({
        sbom: { components: 42 },
        security: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 7 },
      }),
    );
    expect(counts.components).toBe(42);
    expect(counts.vulnerabilities).toBe(7);
  });

  it("defaults missing data to zero", () => {
    const counts = sectionCounts(makeResult({ sbom: null, security: null }));
    expect(counts.components).toBe(0);
    expect(counts.vulnerabilities).toBe(0);
  });

  it("counts the dependency-graph size and distinct licenses", () => {
    const counts = sectionCounts(
      makeResult({
        sbom: {
          components: 3,
          directCount: 1,
          transitiveCount: 2,
          componentList: [
            { name: "a", version: "1", group: "", purl: "", type: "library", licenses: ["MIT"] },
            { name: "b", version: "1", group: "", purl: "", type: "library", licenses: ["MIT", "Apache-2.0"] },
            { name: "c", version: "1", group: "", purl: "", type: "library", licenses: [] },
          ],
        },
      }),
    );
    expect(counts.dependencies).toBe("1/2"); // direct / transitive
    expect(counts.licenses).toBe(2); // MIT, Apache-2.0
  });

  it("omits dependency/license badges when there's nothing to show", () => {
    // Flat SBOM: no direct/transitive split and no detected licenses.
    const counts = sectionCounts(makeResult({ sbom: { components: 5 } }));
    expect(counts.dependencies).toBeUndefined();
    expect(counts.licenses).toBeUndefined();
  });

  it("carries the conformance coverage as a badge", () => {
    const counts = sectionCounts(
      makeResult({
        conformance: {
          result: "pass",
          checks: [
            check({ id: "g7-a", status: "pass", source: "auto" }),
            check({ id: "g7-b", status: "warn", source: "auto" }),
          ],
        },
      }),
    );
    expect(counts.conformance).toBe("1/2");
    expect(sectionCounts(makeResult()).conformance).toBeUndefined();
  });
});

function check(over: Partial<ConformanceCheck>): ConformanceCheck {
  return { id: "x", label: "", required: false, status: "pass", detail: "", ...over };
}

describe("conformanceCount", () => {
  it("tallies G7 present over the automatable total", () => {
    const result = makeResult({
      conformance: {
        result: "pass",
        checks: [
          check({ id: "purl", required: true }), // base check, ignored when G7 exists
          check({ id: "g7-a", status: "pass", source: "auto" }),
          check({ id: "g7-b", status: "pass", source: "inferred" }),
          check({ id: "g7-c", status: "warn", source: "auto" }),
          check({ id: "g7-d", status: "warn", source: "na" }), // review-only, excluded
        ],
      },
    });
    expect(conformanceCount(result)).toBe("2/3");
  });

  it("falls back to the base format tally when there are no G7 checks", () => {
    const result = makeResult({
      conformance: {
        result: "fail",
        checks: [
          check({ id: "purl", required: true, status: "pass" }),
          check({ id: "license", required: true, status: "fail" }),
        ],
      },
    });
    expect(conformanceCount(result)).toBe("1/2");
  });

  it("is undefined without a conformance report", () => {
    expect(conformanceCount(makeResult())).toBeUndefined();
    expect(
      conformanceCount(makeResult({ conformance: { result: "unknown", checks: [] } })),
    ).toBeUndefined();
  });
});
