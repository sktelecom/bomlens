// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import {
  componentConflict,
  conflictGroups,
  isCopyleft,
  licenseGroups,
  licenseRiskSummary,
  licenseRiskTier,
  parseLicenseExpression,
  reviewCount,
  reviewGroups,
} from "./licenses";
import type { CompatRules } from "./licenses";

const c = (over: Partial<ComponentItem>): ComponentItem => ({
  name: "x",
  version: "1",
  group: "",
  purl: "",
  type: "library",
  licenses: [],
  ...over,
});

const COMPONENTS = [
  c({
    name: "llama",
    licenses: ["LLaMA-3.1"],
    licenseReview: "behavioral-use",
  }),
  c({
    name: "nc-data",
    licenses: ["CC-BY-NC-4.0"],
    licenseReview: "non-commercial",
  }),
  c({ name: "lib-a", licenses: ["MIT"] }),
  c({ name: "lib-b", licenses: ["MIT"] }),
  c({ name: "unlic", licenses: [] }),
];

describe("licenseGroups", () => {
  it("counts components per license, busiest first, plus unlicensed", () => {
    const { groups, unlicensed } = licenseGroups(COMPONENTS);
    expect(groups[0]).toEqual({ name: "MIT", count: 2 });
    expect(groups.map((g) => g.name)).toContain("CC-BY-NC-4.0");
    expect(unlicensed).toBe(1);
  });
});

describe("reviewGroups", () => {
  it("groups flagged components, behavioral-use before non-commercial", () => {
    const groups = reviewGroups(COMPONENTS);
    expect(groups.map((g) => g.flag)).toEqual([
      "behavioral-use",
      "non-commercial",
    ]);
    expect(groups[0].components.map((x) => x.name)).toEqual(["llama"]);
  });

  it("is empty when nothing needs review", () => {
    expect(reviewGroups([c({ licenses: ["MIT"] })])).toEqual([]);
    expect(reviewCount(COMPONENTS)).toBe(2);
  });
});

describe("isCopyleft", () => {
  it("flags copyleft/reciprocal ids and leaves permissive ones alone", () => {
    for (const id of [
      "GPL-3.0-only",
      "AGPL-3.0",
      "LGPL-2.1",
      "MPL-2.0",
      "EPL-2.0",
    ]) {
      expect(isCopyleft(id)).toBe(true);
    }
    for (const id of ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]) {
      expect(isCopyleft(id)).toBe(false);
    }
  });
});

describe("licenseRiskTier", () => {
  it("grades by copyleft strength, AGPL/LGPL before bare GPL", () => {
    expect(licenseRiskTier("AGPL-3.0")).toBe("network-copyleft");
    expect(licenseRiskTier("GPL-3.0-only")).toBe("strong-copyleft");
    expect(licenseRiskTier("LGPL-2.1")).toBe("weak-copyleft");
    expect(licenseRiskTier("MPL-2.0")).toBe("weak-copyleft");
    expect(licenseRiskTier("MIT")).toBe("permissive");
    expect(licenseRiskTier("Apache-2.0")).toBe("permissive");
  });

  it("does not label a GPL with an exception clause as strong copyleft", () => {
    // The clause exists to permit linking the bare license forbids (jakarta/javax
    // APIs and OpenJDK ship this way), so strong-copyleft would warn about an
    // obligation the component does not impose.
    expect(licenseRiskTier("GPL-2.0-with-classpath-exception")).toBe("weak-copyleft");
    expect(licenseRiskTier("GPL-2.0-only WITH Classpath-exception-2.0")).toBe("weak-copyleft");
    // Anchored on GPL: the word WITH alone must not pull a license into copyleft.
    expect(licenseRiskTier("Bespoke-1.0 WITH Vendor-exception")).toBe("uncategorized");
    // And a GPL without any exception is unchanged.
    expect(licenseRiskTier("GPL-2.0-only")).toBe("strong-copyleft");
  });

  it("never assumes an unrecognised license is permissive", () => {
    // The core safety property: unknown is uncategorized, not safe.
    expect(licenseRiskTier("Foo-1.0")).toBe("uncategorized");
    expect(licenseRiskTier("Proprietary")).toBe("uncategorized");
    expect(licenseRiskTier("MIT OR Apache-2.0")).toBe("uncategorized");
    expect(licenseRiskTier("")).toBe("uncategorized");
  });
});

describe("licenseRiskSummary", () => {
  it("counts each component once: review flag wins, no-license is uncategorized", () => {
    const s = licenseRiskSummary(COMPONENTS);
    expect(s["review-needed"]).toBe(2); // llama (behavioral) + nc-data
    expect(s.permissive).toBe(2); // lib-a + lib-b (MIT)
    expect(s.uncategorized).toBe(1); // unlic (no license)
    expect(s.TOTAL).toBe(5);
  });

  it("takes the worst tier across a component's licenses", () => {
    const s = licenseRiskSummary([c({ licenses: ["MIT", "GPL-3.0-only"] })]);
    expect(s["strong-copyleft"]).toBe(1);
    expect(s.permissive).toBe(0);
  });

  it("keeps an unknown license out of the permissive bucket", () => {
    const s = licenseRiskSummary([c({ licenses: ["Weird-1.0"] })]);
    expect(s.uncategorized).toBe(1);
    expect(s.permissive).toBe(0);
  });
});

// The rules the scanner ships in docker/lib/license-compat.json, trimmed to what
// these cases exercise. Kept literal rather than imported: the UI receives the
// verdict already computed by the scanner, so this file's job is to prove the
// mirror agrees with the jq side, case for case.
const RULES: CompatRules = {
  matrix: {
    permissive: {
      permissive: { verdict: "compatible", why: "" },
      "weak-copyleft": { verdict: "conditional", why: "" },
      "strong-copyleft": { verdict: "incompatible", why: "" },
      "network-copyleft": { verdict: "incompatible", why: "" },
      uncategorized: { verdict: "unknown", why: "" },
    },
    "strong-copyleft": {
      permissive: { verdict: "compatible", why: "" },
      "weak-copyleft": { verdict: "conditional", why: "" },
      "strong-copyleft": { verdict: "conditional", why: "" },
      "network-copyleft": { verdict: "conditional", why: "" },
      uncategorized: { verdict: "unknown", why: "" },
    },
  },
  pairs: [
    {
      outbound: "GPL-2.0-ONLY",
      dependency: "APACHE-2.0",
      verdict: "incompatible",
      why: "",
    },
  ],
};

describe("parseLicenseExpression", () => {
  // Every string here was measured in a real BomLens SBOM.
  it("splits OR alternatives", () => {
    expect(parseLicenseExpression("MIT OR Apache-2.0")).toEqual([
      ["MIT"],
      ["Apache-2.0"],
    ]);
  });

  it("keeps AND terms together", () => {
    expect(parseLicenseExpression("EPL-1.0 AND LGPL-2.1-only")).toEqual([
      ["EPL-1.0", "LGPL-2.1-only"],
    ]);
  });

  it("binds AND tighter than OR", () => {
    expect(parseLicenseExpression("A OR B AND C")).toEqual([["A"], ["B", "C"]]);
  });

  it("treats a lone slash as OR", () => {
    expect(parseLicenseExpression("MIT/X11")).toEqual([["MIT"], ["X11"]]);
  });

  it("leaves a URL intact", () => {
    expect(parseLicenseExpression("https://example.com/lic")).toEqual([
      ["https://example.com/lic"],
    ]);
  });

  it("refuses a parenthesised expression rather than guessing", () => {
    expect(parseLicenseExpression("(A OR B) AND C")).toEqual([]);
  });

  it("is empty for an empty string", () => {
    expect(parseLicenseExpression("")).toEqual([]);
  });
});

describe("componentConflict", () => {
  const v = (licenses: string[], outbound = "Apache-2.0") =>
    componentConflict(licenses, outbound, RULES).verdict;

  it("flags strong copyleft under a permissive outbound license", () => {
    expect(v(["GPL-3.0-only"])).toBe("incompatible");
  });

  it("clears an OR expression when one alternative fits", () => {
    expect(v(["MIT OR Apache-2.0"])).toBe("compatible");
  });

  it("takes the worst term of an AND expression", () => {
    expect(v(["EPL-1.0 AND LGPL-2.1-only"])).toBe("conditional");
  });

  // The case that decides the feature: java-maven's jakarta components. A naive
  // pair check calls this incompatible; the exception clause exists to allow it.
  it("caps a term carrying an exception clause at conditional", () => {
    expect(v(["EPL-2.0 AND GPL-2.0-with-classpath-exception"])).toBe(
      "conditional",
    );
  });

  it("treats several license entries as alternatives", () => {
    expect(v(["EPL-1.0", "LGPL-2.1-only"])).toBe("conditional");
  });

  it("applies an explicit pair over the class matrix", () => {
    expect(v(["Apache-2.0"], "GPL-2.0-only")).toBe("incompatible");
    expect(v(["Apache-2.0"], "GPL-3.0-only")).toBe("compatible");
  });

  it("is unknown for free-text that is not an SPDX id", () => {
    expect(
      v([
        "Eclipse Public License v. 2.0 OR Eclipse Distribution License v. 1.0",
      ]),
    ).toBe("unknown");
  });

  it("is unknown when the component declares no license", () => {
    expect(v([])).toBe("unknown");
  });
});

describe("conflictGroups", () => {
  const c = (
    name: string,
    verdict?: ComponentItem["licenseConflict"],
  ): ComponentItem => ({
    name,
    version: "1",
    group: "",
    purl: `pkg:maven/x/${name}@1`,
    type: "library",
    licenses: ["MIT"],
    vendored: false,
    matchConfidence: "",
    source: "",
    copyright: "",
    ...(verdict ? { licenseConflict: verdict } : {}),
  });

  it("orders the worst verdict first", () => {
    const groups = conflictGroups([
      c("a", "conditional"),
      c("b", "incompatible"),
      c("d", "unknown"),
    ]);
    expect(groups.map((g) => g.verdict)).toEqual([
      "incompatible",
      "conditional",
      "unknown",
    ]);
  });

  it("omits components that carry no conflict", () => {
    // "compatible" is not listed — the section shows what needs a look — and a
    // component with no verdict at all was never assessed.
    expect(conflictGroups([c("a", "compatible"), c("b")])).toEqual([]);
  });

  it("collects every component under its verdict", () => {
    const groups = conflictGroups([
      c("a", "incompatible"),
      c("b", "incompatible"),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].components.map((x) => x.name)).toEqual(["a", "b"]);
  });
});
