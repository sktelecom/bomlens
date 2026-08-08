// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { AiProfile, ConformanceCheck } from "./api";
import {
  baseTally,
  clusterOf,
  crosswalkTotals,
  dedupeMissing,
  elementCoverage,
  g7Tally,
  groupG7ByCluster,
  missingOverflow,
  profileCard,
  sortByAttention,
  splitChecks,
  verdictTally,
} from "./conformance";

/** Object-shaped builder for the cases that vary more than one field. */
const chk = (o: Partial<ConformanceCheck> & { id: string }): ConformanceCheck => ({
  label: o.id,
  required: false,
  status: "warn",
  detail: "",
  ...o,
});

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

describe("splitChecks (three baselines)", () => {
  it("separates the checks the scripts write from each registry's elements", () => {
    const split = splitChecks([
      chk({ id: "purl" }),
      chk({ id: "cisa-component-license", cluster: "cisa-component" }),
      chk({ id: "g7-model-license", cluster: "models" }),
    ]);
    expect(split.base.map((c) => c.id)).toEqual(["purl"]);
    expect(split.cisa.map((c) => c.id)).toEqual(["cisa-component-license"]);
    expect(split.g7.map((c) => c.id)).toEqual(["g7-model-license"]);
  });
});

describe("sortByAttention", () => {
  it("puts failures first, then gaps, then review items, then what is met", () => {
    const sorted = sortByAttention([
      chk({ id: "d", status: "pass" }),
      chk({ id: "c", status: "warn", source: "na" }),
      chk({ id: "b", status: "warn" }),
      chk({ id: "a", status: "fail" }),
    ]);
    expect(sorted.map((c) => c.id)).toEqual(["a", "b", "c", "d"]);
  });

  it("is stable inside a status, so the registry's own order survives", () => {
    const sorted = sortByAttention([
      chk({ id: "first", status: "warn" }),
      chk({ id: "second", status: "warn" }),
    ]);
    expect(sorted.map((c) => c.id)).toEqual(["first", "second"]);
  });
});

describe("dedupeMissing", () => {
  it("collapses a repeated name and says how many times it appeared", () => {
    expect(dedupeMissing(["zlib", "systemd", "zlib"])).toEqual([
      { name: "zlib", count: 2 },
      { name: "systemd", count: 1 },
    ]);
  });
});

describe("missingOverflow", () => {
  it("reports how many offenders the list left out", () => {
    // 14 of 31 met => 17 missing, of which 3 are listed.
    expect(missingOverflow(chk({ id: "cisa-x", detail: "14/31 component(s)", missing: ["a", "b", "c"] }))).toBe(14);
  });

  it("is zero when the list is complete or the detail carries no count", () => {
    expect(missingOverflow(chk({ id: "cisa-y", detail: "2/3 component(s)", missing: ["a"] }))).toBe(0);
    expect(missingOverflow(chk({ id: "cisa-z", detail: "present", missing: [] }))).toBe(0);
  });
});

describe("verdictTally", () => {
  it("counts the verdict from the mandatory checks alone", () => {
    const v = verdictTally([
      chk({ id: "purl", required: true, status: "fail" }),
      chk({ id: "tools", required: true, status: "pass" }),
      chk({ id: "cisa-a", status: "warn" }),
      chk({ id: "cisa-b", status: "warn", source: "na" }),
      chk({ id: "cisa-c", status: "pass" }),
    ]);
    expect(v).toEqual({
      mandatoryFailed: 1,
      mandatoryTotal: 2,
      mandatoryPassed: 1,
      advisoryGap: 1,
      review: 1,
    });
  });
});

describe("crosswalkTotals", () => {
  it("sums the coverage counts across frameworks, failures included", () => {
    expect(
      crosswalkTotals([
        { total: 5, present: 3, gap: 1, review: 1, failed: 0 },
        { total: 4, present: 2, gap: 1, review: 0, failed: 1 },
      ]),
    ).toEqual({ total: 9, present: 5, gap: 2, review: 1, failed: 1 });
  });

  // The failure count is read, not derived. It used to be computed as the
  // remainder and shown under the heading "advisory", which put the most serious
  // category under the mildest name on the page.
  it("reads failed from the framework rather than inferring a remainder", () => {
    expect(crosswalkTotals([{ total: 4, present: 1, gap: 1, review: 1, failed: 1 }]).failed).toBe(1);
  });

  it("treats a report generated before the field existed as zero failures", () => {
    expect(crosswalkTotals([{ total: 3, present: 3, gap: 0, review: 0 }]).failed).toBe(0);
  });

  it("is all-zero for no frameworks", () => {
    expect(crosswalkTotals([])).toEqual({ total: 0, present: 0, gap: 0, review: 0, failed: 0 });
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
      crosswalk: { total: 14, present: 8, gap: 4, review: 2, failed: 0 },
    });
  });
});
