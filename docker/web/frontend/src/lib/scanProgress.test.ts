// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  SCAN_STAGES,
  scanStageIndex,
  anyStageMarker,
  stageStatuses,
  visiblePercent,
  visibleStages,
} from "./scanProgress";

describe("scanStageIndex", () => {
  it("is 0 before any recognizable marker", () => {
    expect(scanStageIndex([])).toBe(0);
    expect(scanStageIndex(["starting…"])).toBe(0);
  });

  it("advances to the furthest stage marker seen", () => {
    expect(scanStageIndex(["[1/2] cdxgen: source dir"])).toBe(0);
    expect(scanStageIndex(["[1/2] syft", "[normalize] normalized"])).toBe(1);
    expect(scanStageIndex(["[normalize] x", "[notice] generated"])).toBe(2);
    expect(scanStageIndex(["[security] running Trivy SBOM scan..."])).toBe(3);
    expect(scanStageIndex(["[nvd-cpe] grype CPE matching started"])).toBe(4);
    expect(scanStageIndex(["[risk] generated"])).toBe(5);
  });

  it("uses the furthest marker regardless of log order", () => {
    expect(scanStageIndex(["[risk] generated", "[1/2] cdxgen"])).toBe(5);
  });

  it("recognizes the deep-CVE matching marker even when the option is skipped", () => {
    // A run without deep CVE never emits [nvd-cpe]; a later marker (e.g. [risk])
    // still counts the skipped stage as passed, matching the "honest and
    // monotonic" contract documented at the top of this module.
    expect(
      scanStageIndex(["[security] running Trivy SBOM scan...", "[risk] generated"]),
    ).toBe(5);
  });
});

describe("stageStatuses", () => {
  it("marks reached stages done, the current active, the rest pending", () => {
    const s = stageStatuses(["[1/2] syft", "[notice] generated"], false);
    expect(s).toEqual(["done", "done", "active", "pending", "pending", "pending"]);
  });

  it("marks every stage done once finished", () => {
    expect(stageStatuses([], true)).toEqual(SCAN_STAGES.map(() => "done"));
  });
});


describe("visible steps", () => {
  const logs = ["[1/2] generate", "[normalize] x", "[notice] x"];
  it("leaves deep CVE matching out when the run did not ask for it", () => {
    expect(visibleStages(logs, false, false).map((v) => v.stage.id)).not.toContain("deepCve");
    expect(visibleStages(logs, false, true).map((v) => v.stage.id)).toContain("deepCve");
  });
  it("counts the percent over the visible steps only", () => {
    // notice is the third of five visible steps: (2 + 0.5) / 5
    expect(visiblePercent(visibleStages(logs, false, false))).toBe(50);
    // and the third of six when deep CVE matching is on
    expect(visiblePercent(visibleStages(logs, false, true))).toBe(42);
  });
  it("is 100 once finished", () => {
    expect(visiblePercent(visibleStages(logs, true, false))).toBe(100);
  });
});

describe("anyStageMarker", () => {
  it("is false until a step's marker appears", () => {
    expect(anyStageMarker(["git clone failed"])).toBe(false);
    expect(anyStageMarker(["[normalize] x"])).toBe(true);
  });
});
