// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { ComponentItem, DoneEvent } from "./api";
import { needsAttention, riskyComponentCount, topRiskComponents } from "./overview";

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

  it("puts malicious packages above everything else", () => {
    // A vulnerability is a flaw to schedule a fix for; a malicious package is
    // already running in the build, so it must lead even a failed conformance.
    const items = needsAttention(
      result({
        sbom: { components: 3, componentList: [], maliciousCount: 2 },
        security: sev({ CRITICAL: 5, TOTAL: 5 }),
      }),
    );
    expect(items[0]).toMatchObject({
      id: "malicious",
      count: 2,
      tone: "critical",
      target: "components",
    });
    expect(items.map((i) => i.id)).toEqual(["malicious", "vulns"]);
  });

  it("omits the malicious item when the count is absent or zero", () => {
    // Absent means the check did not run (no bundled snapshot), which must not
    // render as a reassuring zero.
    expect(needsAttention(result()).some((i) => i.id === "malicious")).toBe(false);
    expect(
      needsAttention(
        result({ sbom: { components: 1, componentList: [], maliciousCount: 0 } }),
      ).some((i) => i.id === "malicious"),
    ).toBe(false);
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

  it("flags a failed conformance and leads the list", () => {
    const items = needsAttention(
      result({
        conformance: {
          result: "fail",
          format: "CycloneDX",
          checks: [
            { id: "purl", label: "PURL coverage", required: true, status: "fail", detail: "" },
            { id: "g7-model-id", label: "Model id", required: false, status: "warn", detail: "" },
          ],
        },
        security: sev({ CRITICAL: 1, TOTAL: 1 }),
      }),
    );
    // Conformance leads, then the critical vuln — G7 advisory warn is not counted.
    expect(items.map((i) => i.id)).toEqual(["conformance", "vulns"]);
    expect(items[0]).toMatchObject({
      id: "conformance",
      count: 1,
      tone: "high",
      target: "conformance",
    });
  });

  it("does not flag a passing conformance", () => {
    const items = needsAttention(
      result({
        conformance: {
          result: "pass",
          checks: [{ id: "purl", label: "PURL", required: true, status: "pass", detail: "" }],
        },
      }),
    );
    expect(items).toEqual([]);
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

describe("topRiskComponents", () => {
  const list = [
    comp({ name: "clean" }),
    comp({ name: "low-one", maxSeverity: "LOW", vulnCount: 1 }),
    comp({ name: "crit-two", maxSeverity: "CRITICAL", vulnCount: 2 }),
    comp({ name: "crit-nine", maxSeverity: "CRITICAL", vulnCount: 9 }),
    comp({ name: "high-one", maxSeverity: "HIGH", vulnCount: 1 }),
  ];
  const scan = result({ sbom: { components: list.length, componentList: list } });

  it("ranks worst severity first, then by how many at that severity", () => {
    expect(topRiskComponents(scan).map((c) => c.name)).toEqual([
      "crit-nine",
      "crit-two",
      "high-one",
      "low-one",
    ]);
  });

  it("leaves out components with nothing against them", () => {
    // A "top risk" list padded with clean rows would imply a ranking that the
    // data does not support.
    expect(topRiskComponents(scan).map((c) => c.name)).not.toContain("clean");
  });

  it("caps the list, and takes the worst ones when it does", () => {
    expect(topRiskComponents(scan, 2).map((c) => c.name)).toEqual(["crit-nine", "crit-two"]);
    expect(topRiskComponents(scan, 0)).toEqual([]);
  });

  it("is empty when the scan has no vulnerable components at all", () => {
    expect(topRiskComponents(result())).toEqual([]);
    const clean = [comp({ name: "a" }), comp({ name: "b" })];
    expect(topRiskComponents(result({ sbom: { components: 2, componentList: clean } }))).toEqual([]);
  });

  it("breaks ties by name so the order never wobbles between renders", () => {
    const tied = [
      comp({ name: "zlib", maxSeverity: "HIGH", vulnCount: 1 }),
      comp({ name: "acorn", maxSeverity: "HIGH", vulnCount: 1 }),
    ];
    const r = result({ sbom: { components: 2, componentList: tied } });
    expect(topRiskComponents(r).map((c) => c.name)).toEqual(["acorn", "zlib"]);
  });
});

describe("riskyComponentCount", () => {
  it("counts every component with something against it, not just the listed ones", () => {
    // The block lists a handful; this is what sits behind it.
    const many = Array.from({ length: 9 }, (_, i) =>
      comp({ name: `c${i}`, maxSeverity: "HIGH", vulnCount: 1 }),
    );
    const r = result({ sbom: { components: 10, componentList: [...many, comp({ name: "clean" })] } });
    expect(riskyComponentCount(r)).toBe(9);
    expect(topRiskComponents(r)).toHaveLength(6);
  });

  it("is zero when nothing was found", () => {
    expect(riskyComponentCount(result())).toBe(0);
  });
});

describe("needsAttention on an AI scan", () => {
  // An AI scan reaches none of the software conditions: no vulnerability report,
  // conformance passes, nothing malicious or vendored. The Overview said nothing
  // at all while the model carried the one verdict the scan exists to produce.
  it("raises a model the pipeline graded caution or review", () => {
    const items = needsAttention(
      result({ sbom: { components: 1, componentList: [], assessCounts: { review: 1 } } }),
    );
    expect(items.map((i) => i.id)).toContain("modelRisk");
    const model = items.find((i) => i.id === "modelRisk")!;
    expect(model).toMatchObject({ count: 1, tone: "info", target: "models" });
  });

  it("weighs caution above review", () => {
    const items = needsAttention(
      result({
        sbom: { components: 2, componentList: [], assessCounts: { caution: 1, review: 1 } },
      }),
    );
    expect(items.find((i) => i.id === "modelRisk")).toMatchObject({ count: 2, tone: "high" });
  });

  it("says nothing when every grade is ok", () => {
    const items = needsAttention(
      result({ sbom: { components: 1, componentList: [], assessCounts: { ok: 3 } } }),
    );
    expect(items.map((i) => i.id)).not.toContain("modelRisk");
  });

  it("offers the conformance elements a passing SBOM can still fill", () => {
    // Distinct from the failed-mandatory item: this SBOM passes and has
    // documentation gaps a person can close, which is what the advisory
    // baselines are for.
    const items = needsAttention(
      result({
        conformance: {
          result: "pass",
          checks: [
            { id: "a", label: "a", detail: "", required: false, status: "warn", source: "auto" },
            { id: "b", label: "b", detail: "", required: false, status: "warn", source: "na" },
            { id: "c", label: "c", detail: "", required: false, status: "pass", source: "auto" },
          ],
        },
      }),
    );
    const gap = items.find((i) => i.id === "conformanceGap")!;
    // Only the one with an automated source: the na row needs a person, not a fix.
    expect(gap).toMatchObject({ count: 1, tone: "info", target: "conformance" });
  });

  it("does not repeat the gap when the verdict already failed", () => {
    const items = needsAttention(
      result({
        conformance: {
          result: "fail",
          checks: [
            { id: "a", label: "a", detail: "", required: true, status: "fail", source: "auto" },
          ],
        },
      }),
    );
    expect(items.map((i) => i.id)).toContain("conformance");
    expect(items.map((i) => i.id)).not.toContain("conformanceGap");
  });
});
