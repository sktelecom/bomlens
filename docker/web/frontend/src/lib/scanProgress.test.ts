// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  SCAN_STAGES,
  scanStageIndex,
  stageProgress,
  stageStatuses,
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

describe("stageProgress", () => {
  it("advances monotonically with the furthest stage, never reaching 100", () => {
    const start = stageProgress([]); // generate active, no marker yet
    const mid = stageProgress(["[1/2] cdxgen", "[notice] generated"]);
    const late = stageProgress(["[risk] generated"]);
    expect(start).toBeLessThan(mid);
    expect(mid).toBeLessThan(late);
    expect(late).toBeLessThan(100); // the done event snaps to 100, not this
  });
});
