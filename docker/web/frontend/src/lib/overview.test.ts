import { describe, expect, it } from "vitest";

import type { ComponentItem, DoneEvent } from "./api";
import { needsAttention } from "./overview";

function result(over: Partial<DoneEvent> = {}): DoneEvent {
  return {
    ok: true,
    mode: "SOURCE",
    results: [],
    sbom: { components: 0, componentList: [] },
    security: null,
    conformance: null,
    ...over,
  };
}

const sev = (o: Partial<Record<string, number>>) => ({
  CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 0, ...o,
}) as DoneEvent["security"];

const comp = (over: Partial<ComponentItem>): ComponentItem => ({
  name: "x", version: "1", group: "", purl: "", type: "library", licenses: [], ...over,
});

describe("needsAttention", () => {
  it("is empty for a clean scan", () => {
    expect(needsAttention(result())).toEqual([]);
  });

  it("flags critical+high vulnerabilities and tones critical when any critical", () => {
    const items = needsAttention(result({ security: sev({ CRITICAL: 2, HIGH: 3, TOTAL: 5 }) }));
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: "vulns", count: 5, tone: "critical", target: "vulnerabilities" });
  });

  it("tones high when there are highs but no criticals; ignores medium/low", () => {
    const items = needsAttention(result({ security: sev({ HIGH: 1, MEDIUM: 9, LOW: 9, TOTAL: 19 }) }));
    expect(items[0]).toMatchObject({ id: "vulns", count: 1, tone: "high" });
  });

  it("flags vendored components for review and orders vulns first", () => {
    const items = needsAttention(
      result({
        security: sev({ CRITICAL: 1, TOTAL: 1 }),
        sbom: { components: 2, componentList: [comp({ vendored: true }), comp({})] },
      }),
    );
    expect(items.map((i) => i.id)).toEqual(["vulns", "review"]);
    expect(items[1]).toMatchObject({ id: "review", count: 1, target: "components" });
  });
});
