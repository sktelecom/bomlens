import { describe, expect, it } from "vitest";

import type { ConformanceCheck } from "./api";
import { baseTally, g7Tally, splitChecks } from "./conformance";

const check = (
  id: string,
  status: ConformanceCheck["status"],
  required = false,
): ConformanceCheck => ({ id, label: id, required, status, detail: "" });

// Mirrors the verified output of validate-sbom.sh on the AIBOM fixture:
// 9 base + 6 G7, with g7-model-hash and g7-openness as warnings → 4/6 present.
const CHECKS: ConformanceCheck[] = [
  check("timestamp", "pass", true),
  check("tools", "pass", true),
  check("license", "warn", false),
  check("g7-model-id", "pass"),
  check("g7-model-license", "pass"),
  check("g7-model-card", "pass"),
  check("g7-model-hash", "warn"),
  check("g7-datasets", "pass"),
  check("g7-openness", "warn"),
];

describe("splitChecks", () => {
  it("separates base format checks from G7 checks", () => {
    const { base, g7 } = splitChecks(CHECKS);
    expect(base.map((c) => c.id)).toEqual(["timestamp", "tools", "license"]);
    expect(g7).toHaveLength(6);
    expect(g7.every((c) => c.id.startsWith("g7-"))).toBe(true);
  });
});

describe("g7Tally", () => {
  it("counts present (pass) and advisory (warn) — 4/6 present, 2 advisory", () => {
    const t = g7Tally(splitChecks(CHECKS).g7);
    expect(t).toEqual({ present: 4, total: 6, advisory: 2, failed: 0 });
  });

  it("is empty for no G7 checks", () => {
    expect(g7Tally([])).toEqual({ present: 0, total: 0, advisory: 0, failed: 0 });
  });
});

describe("baseTally", () => {
  it("counts passes, required failures and warnings", () => {
    const t = baseTally(splitChecks(CHECKS).base);
    expect(t).toEqual({ passed: 2, total: 3, failed: 0, warnings: 1 });
  });
});
