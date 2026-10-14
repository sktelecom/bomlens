// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { SecuritySummary, VulnItem } from "./api";
import { notReachableSummary, reachabilityJustificationKey, reachabilityOffered } from "./reachability";

const base: SecuritySummary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: 0 };

const row = (id: string, justification?: string): VulnItem => ({
  id,
  severity: "HIGH",
  pkg: "golang.org/x/text",
  installed: "v0.3.7",
  fixed: "v0.3.8",
  title: "",
  reachability: { state: "not_affected", justification, detail: "govulncheck (source): ..." },
});

describe("notReachableSummary", () => {
  it("is null when nothing was judged not reachable", () => {
    expect(notReachableSummary(base)).toBeNull();
    expect(notReachableSummary(null)).toBeNull();
    expect(notReachableSummary({ ...base, notReachableCount: 0, notReachable: [] })).toBeNull();
  });

  it("keeps a count larger than the capped list and drops rows without an id", () => {
    const s = notReachableSummary({
      ...base,
      notReachableCount: 3,
      notReachable: [row("CVE-1", "code_not_present"), { ...row(""), id: "" }],
    })!;
    expect(s.count).toBe(3);
    expect(s.rows.map((r) => r.id)).toEqual(["CVE-1"]);
    expect(s.truncated).toBe(true);
  });

  it("never reports fewer than the rows present", () => {
    const s = notReachableSummary({ ...base, notReachable: [row("CVE-1"), row("CVE-2")] })!;
    expect(s.count).toBe(2);
    expect(s.truncated).toBe(false);
  });
});

describe("reachabilityJustificationKey", () => {
  it("maps the two justifications the step writes, and anything else to a generic label", () => {
    expect(reachabilityJustificationKey("code_not_present")).toBe(
      "result.reachabilityJustification.codeNotPresent",
    );
    expect(reachabilityJustificationKey("code_not_reachable")).toBe(
      "result.reachabilityJustification.codeNotReachable",
    );
    expect(reachabilityJustificationKey(undefined)).toBe("result.reachabilityJustification.other");
    expect(reachabilityJustificationKey("protected_by_mitigating_control")).toBe(
      "result.reachabilityJustification.other",
    );
  });
});

describe("reachabilityOffered", () => {
  it("offers it for source trees and an uploaded executable when govulncheck is here", () => {
    for (const s of ["current-dir", "git-url", "zip-upload", "package-upload"] as const) {
      expect(reachabilityOffered(s, s, true)).toBe(true);
    }
    // A picked folder counts only when it is scanned deep (as source).
    expect(reachabilityOffered("rootfs-dir", "scan-target-src", true)).toBe(true);
    expect(reachabilityOffered("rootfs-dir", "rootfs-dir", true)).toBe(false);
  });

  it("hides it for every other input, and everywhere without govulncheck", () => {
    for (const s of ["docker-image", "sbom-upload", "firmware-upload", "ai-model", "model-upload"] as const) {
      expect(reachabilityOffered(s, s, true)).toBe(false);
    }
    expect(reachabilityOffered("current-dir", "current-dir", false)).toBe(false);
    expect(reachabilityOffered("current-dir", "current-dir", undefined)).toBe(false);
  });
});
