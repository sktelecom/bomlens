import { describe, expect, it } from "vitest";

import type { DoneEvent } from "./api";
import { deriveScanContext, sectionCounts } from "./results";

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
    });
  });

  it("flags dependencies when a CycloneDX SBOM artifact exists", () => {
    expect(deriveScanContext(makeResult()).hasDependencies).toBe(true);
    expect(deriveScanContext(makeResult({ results: [] })).hasDependencies).toBe(false);
  });

  it("flags the source tree only when a ScanCode artifact exists", () => {
    const withScancode = makeResult({
      results: [
        { name: "demo_1.0_bom.json", size: 10 },
        { name: "demo_1.0_scancode.json", size: 20 },
      ],
    });
    expect(deriveScanContext(withScancode).hasSourceTree).toBe(true);
    expect(deriveScanContext(makeResult()).hasSourceTree).toBe(false);
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
});
