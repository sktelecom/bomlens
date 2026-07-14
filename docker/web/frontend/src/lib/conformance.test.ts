import { describe, expect, it } from "vitest";

import type { AiProfile, ConformanceCheck } from "./api";
import {
  baseTally,
  clusterOf,
  crosswalkTotals,
  elementCoverage,
  g7Tally,
  groupG7ByCluster,
  profileCard,
  splitChecks,
} from "./conformance";

const check = (
  id: string,
  status: ConformanceCheck["status"],
  opts: { required?: boolean; cluster?: string; source?: string } = {},
): ConformanceCheck => ({
  id,
  label: id,
  required: opts.required ?? false,
  status,
  detail: "",
  cluster: opts.cluster,
  source: opts.source,
});

// A representative slice of the 51-element G7 registry (7 clusters), carrying
// the real ids/cluster/source values, plus two base format checks. Every
// cluster is present, with a mix of pass/warn statuses and na (human-review)
// sources so the tally splits can be exercised.
const CHECKS: ConformanceCheck[] = [
  // base format checks (no cluster)
  check("timestamp", "pass", { required: true }),
  check("license", "warn"),
  // metadata
  check("g7-meta-author", "pass", { cluster: "metadata", source: "auto" }),
  check("g7-meta-signature", "warn", { cluster: "metadata", source: "declared" }),
  // slp
  check("g7-slp-name", "pass", { cluster: "slp", source: "declared" }),
  check("g7-slp-data-flow", "warn", { cluster: "slp", source: "na" }),
  // models
  check("g7-model-name", "pass", { cluster: "models", source: "auto" }),
  check("g7-model-hash-value", "warn", { cluster: "models", source: "auto" }),
  check("g7-model-openness", "warn", { cluster: "models", source: "inferred" }),
  // dp
  check("g7-ds-name", "pass", { cluster: "dp", source: "auto" }),
  check("g7-ds-content", "warn", { cluster: "dp", source: "na" }),
  // infrastructure
  check("g7-infra-software", "pass", { cluster: "infrastructure", source: "auto" }),
  check("g7-infra-hardware", "warn", { cluster: "infrastructure", source: "declared" }),
  // sp
  check("g7-sec-vulns", "warn", { cluster: "sp", source: "auto" }),
  check("g7-sec-controls", "warn", { cluster: "sp", source: "na" }),
  // kpi
  check("g7-kpi-operational", "pass", { cluster: "kpi", source: "inferred" }),
  check("g7-kpi-security", "warn", { cluster: "kpi", source: "na" }),
];

describe("splitChecks", () => {
  it("separates base format checks from G7 checks", () => {
    const { base, g7 } = splitChecks(CHECKS);
    expect(base.map((c) => c.id)).toEqual(["timestamp", "license"]);
    expect(g7).toHaveLength(15);
    expect(g7.every((c) => c.id.startsWith("g7-"))).toBe(true);
  });
});

describe("clusterOf", () => {
  it("returns the cluster field for G7 checks", () => {
    expect(clusterOf(check("g7-model-name", "pass", { cluster: "models" }))).toBe("models");
  });

  it("maps an empty/absent cluster (base checks) to 'base'", () => {
    expect(clusterOf(check("timestamp", "pass"))).toBe("base");
    expect(clusterOf(check("license", "warn", { cluster: "" }))).toBe("base");
  });
});

describe("groupG7ByCluster", () => {
  it("groups G7 checks by cluster in canonical registry order", () => {
    const { g7 } = splitChecks(CHECKS);
    const groups = groupG7ByCluster(g7);
    expect(groups.map((g) => g.cluster)).toEqual([
      "metadata",
      "slp",
      "models",
      "dp",
      "infrastructure",
      "sp",
      "kpi",
    ]);
    // Every check lands in exactly one group, none dropped.
    expect(groups.reduce((n, g) => n + g.checks.length, 0)).toBe(g7.length);
    expect(groups.find((g) => g.cluster === "models")?.checks.map((c) => c.id)).toEqual([
      "g7-model-name",
      "g7-model-hash-value",
      "g7-model-openness",
    ]);
  });

  it("drops clusters with no checks and is empty for no G7 checks", () => {
    expect(groupG7ByCluster([])).toEqual([]);
    const groups = groupG7ByCluster([
      check("g7-model-name", "pass", { cluster: "models", source: "auto" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].cluster).toBe("models");
  });
});

describe("g7Tally", () => {
  it("splits present (pass), advisory (warn, non-na) and review (na)", () => {
    const t = g7Tally(splitChecks(CHECKS).g7);
    expect(t).toEqual({
      present: 6,
      advisory: 5,
      review: 4,
      total: 15,
      autoTotal: 11,
      failed: 0,
    });
  });

  it("is empty for no G7 checks", () => {
    expect(g7Tally([])).toEqual({
      present: 0,
      advisory: 0,
      review: 0,
      total: 0,
      autoTotal: 0,
      failed: 0,
    });
  });
});

describe("baseTally", () => {
  it("counts passes, required failures and warnings", () => {
    const t = baseTally(splitChecks(CHECKS).base);
    expect(t).toEqual({ passed: 1, total: 2, failed: 0, warnings: 1 });
  });
});

describe("crosswalkTotals", () => {
  it("sums the coverage counts across frameworks", () => {
    expect(
      crosswalkTotals([
        { total: 5, present: 3, gap: 1, review: 1 },
        { total: 4, present: 2, gap: 2, review: 0 },
      ]),
    ).toEqual({ total: 9, present: 5, gap: 3, review: 1 });
  });

  it("is all-zero for no frameworks", () => {
    expect(crosswalkTotals([])).toEqual({ total: 0, present: 0, gap: 0, review: 0 });
  });
});

describe("elementCoverage", () => {
  it("classifies a human-review element (source na) as review regardless of status", () => {
    expect(elementCoverage({ status: "warn", source: "na" })).toBe("review");
    expect(elementCoverage({ status: "pass", source: "na" })).toBe("review");
  });

  it("classifies a passing element as present and anything else as gap", () => {
    expect(elementCoverage({ status: "pass", source: "auto" })).toBe("present");
    expect(elementCoverage({ status: "warn", source: "inferred" })).toBe("gap");
    expect(elementCoverage({ status: "fail", source: "declared" })).toBe("gap");
  });
});

describe("profileCard", () => {
  const profile: AiProfile = {
    conformanceResult: "warn",
    g7: {
      total: 15,
      auto: 11,
      present: 6,
      gap: 5,
      review: 4,
      clusters: [{ cluster: "models", total: 3, present: 1, gap: 2, review: 0 }],
    },
    licenseReview: { total: 2, behavioral: 1, nonCommercial: 1 },
    regulatoryCrosswalk: {
      disclaimer: "not a verdict",
      frameworks: [
        { id: "eu-ai-act", title: "EU AI Act", total: 8, present: 5, gap: 2, review: 1 },
        { id: "kr-ai", title: "Korean AI Framework Act", total: 6, present: 3, gap: 2, review: 1 },
      ],
    },
  };

  it("derives the card values and aggregates the crosswalk coverage", () => {
    expect(profileCard(profile)).toEqual({
      result: "warn",
      g7Present: 6,
      g7Auto: 11,
      g7Gap: 5,
      g7Review: 4,
      licenseTotal: 2,
      licenseBehavioral: 1,
      licenseNonCommercial: 1,
      frameworkCount: 2,
      crosswalk: { total: 14, present: 8, gap: 4, review: 2 },
    });
  });
});
