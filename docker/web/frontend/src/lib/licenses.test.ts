// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import {
  componentConflict,
  conflictGroups,
  isCopyleft,
  licenseNeedsDecision,
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

  it("grades Creative Commons by the one clause with a copyleft-like effect (Share-Alike)", () => {
    // Datasets and AI models carry these, not software licenses. Attribution and
    // a field-of-use limit (NC, ND) never propagate the license, so they land on
    // permissive for this axis; only Share-Alike does, the same way LGPL/MPL do
    // for modified files.
    expect(licenseRiskTier("CC-BY-4.0")).toBe("permissive");
    expect(licenseRiskTier("CC-BY-NC-4.0")).toBe("permissive");
    expect(licenseRiskTier("CC-BY-ND-4.0")).toBe("permissive");
    expect(licenseRiskTier("CC0-1.0")).toBe("permissive");
    // Anchored on CC-BY: SA is matched before the bare CC-BY test, same reason
    // AGPL/LGPL precede GPL.
    expect(licenseRiskTier("CC-BY-SA-4.0")).toBe("weak-copyleft");
    expect(licenseRiskTier("CC-BY-NC-SA-4.0")).toBe("weak-copyleft");
  });

  it("never assumes an unrecognised license is permissive", () => {
    // The core safety property: unknown is uncategorized, not safe.
    expect(licenseRiskTier("Foo-1.0")).toBe("uncategorized");
    expect(licenseRiskTier("Proprietary")).toBe("uncategorized");
    expect(licenseRiskTier("Foo-1.0 OR MIT")).toBe("uncategorized");
    expect(licenseRiskTier("(MIT OR Foo-1.0) AND Apache-2.0")).toBe("uncategorized");
    expect(licenseRiskTier("")).toBe("uncategorized");
  });
});

describe("licenseRiskTier of an SPDX expression", () => {
  // Measured on a real Rust project: 77 of 98 crates declare an expression such as
  // "MIT OR Apache-2.0" and were all counted as uncategorized.
  it("takes the strength of the worst term", () => {
    expect(licenseRiskTier("MIT OR Apache-2.0")).toBe("permissive");
    expect(licenseRiskTier("Unlicense/MIT")).toBe("permissive");
    expect(licenseRiskTier("(MIT OR Apache-2.0) AND Unicode-3.0")).toBe("permissive");
    expect(licenseRiskTier("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT")).toBe("permissive");
    // The label is a warning, so a copyleft branch of an OR is not hidden.
    expect(licenseRiskTier("GPL-3.0-only OR MIT")).toBe("strong-copyleft");
    expect(licenseRiskTier("Apache-2.0 AND (MIT OR GPL-2.0-only)")).toBe("strong-copyleft");
    expect(licenseRiskTier("MPL-2.0 OR MIT")).toBe("weak-copyleft");
  });

  it("reads a string that is not an expression as before", () => {
    expect(licenseRiskTier("GNU General Public License v2 or later (GPLv2+)")).toBe("strong-copyleft");
    expect(licenseRiskTier("BSD License")).toBe("uncategorized");
    expect(licenseRiskTier("(MIT")).toBe("uncategorized");
  });

  it("calls an expression of permissive licenses permissive, so it needs no decision", () => {
    expect(licenseNeedsDecision(["MIT OR Apache-2.0"])).toBe(false);
    expect(licenseNeedsDecision(["Foo-1.0 OR MIT"])).toBe(true);
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

  it("distributes a parenthesised expression into alternatives of AND terms", () => {
    expect(parseLicenseExpression("(A OR B) AND C")).toEqual([["A", "C"], ["B", "C"]]);
    expect(parseLicenseExpression("(MIT OR Apache-2.0) AND Unicode-3.0")).toEqual([
      ["MIT", "Unicode-3.0"],
      ["Apache-2.0", "Unicode-3.0"],
    ]);
    expect(parseLicenseExpression("A AND (B OR (C AND D))")).toEqual([["A", "B"], ["A", "C", "D"]]);
    expect(parseLicenseExpression("(MIT)")).toEqual([["MIT"]]);
  });

  it("keeps an exception clause with its license", () => {
    expect(parseLicenseExpression("(Apache-2.0 WITH LLVM-exception OR MIT) AND Zlib")).toEqual([
      ["Apache-2.0 WITH LLVM-exception", "Zlib"],
      ["MIT", "Zlib"],
    ]);
  });

  it("refuses what it cannot parse rather than guessing", () => {
    // (A string with no parenthesis is the flat reader's, which is unchanged.)
    for (const bad of ["(A OR B", "A OR B)", "(A OR)", "(OR A)", "(A AND)", "( )", "(A WITH)"]) {
      expect(parseLicenseExpression(bad), bad).toEqual([]);
    }
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

  const DEB = "pkg:deb/debian/libxxhash0@0.8.1-1?arch=amd64";
  const deb = (licenses: string[], outbound = "Apache-2.0") =>
    componentConflict(licenses, outbound, RULES, DEB).verdict;

  it("reads a parenthesised expression with the same rules as a flat one", () => {
    // AND applies every term (worst verdict), OR lets the consumer pick (best).
    expect(v(["(MIT OR GPL-2.0-only) AND BSD-3-Clause"])).toBe("compatible");
    expect(v(["GPL-3.0-only AND (MIT OR BSD-2-Clause)"])).toBe("incompatible");
    expect(v(["(GPL-3.0-only AND MIT) OR Apache-2.0"])).toBe("compatible");
    // One that cannot be parsed stays unknown.
    expect(v(["(MIT OR"])).toBe("unknown");
  });

  it("reads a Debian package's license entries as all applying", () => {
    expect(deb(["BSD-2-Clause", "GPL-2.0-only"])).toBe("incompatible");
    expect(v(["BSD-2-Clause", "GPL-2.0-only"])).toBe("compatible");
  });

  it("never clears a Debian package past an entry it cannot parse", () => {
    expect(deb(["MIT", "(MIT"])).toBe("unknown");
    expect(deb(["(MIT", "GPL-2.0-only"])).toBe("incompatible");
  });

  it("classes Debian's MIT-X11 license as permissive", () => {
    expect(deb(["MIT-X11", "X11", "BSD-3-Clause"])).toBe("compatible");
    // purl types are case-insensitive, and a single OR expression on a deb
    // package is a real choice stated in one entry.
    expect(
      componentConflict(["MIT", "GPL-2.0-only"], "Apache-2.0", RULES, "PKG:DEB/debian/x@1").verdict,
    ).toBe("incompatible");
    expect(deb(["GPL-2.0-only OR MIT"])).toBe("compatible");
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

describe("licenseNeedsDecision", () => {
  // The rows a person has to resolve by hand. Measured on real trees: 3 of 39
  // components in a small example, 57 of 113 in a research project.
  it("flags a component that declares no licence at all", () => {
    expect(licenseNeedsDecision([])).toBe(true);
  });

  it("flags a name that is not an identifier we can place", () => {
    // Seen verbatim on python-dateutil, which carries all three.
    expect(licenseNeedsDecision(["BSD License"])).toBe(true);
    expect(licenseNeedsDecision(["Dual License"])).toBe(true);
  });

  it("leaves a placed licence alone", () => {
    expect(licenseNeedsDecision(["MIT"])).toBe(false);
    expect(licenseNeedsDecision(["Apache-2.0", "BSD-3-Clause"])).toBe(false);
    expect(licenseNeedsDecision(["GPL-3.0-only"])).toBe(false);
  });

  it("flags a component where only one of several licences is unplaceable", () => {
    expect(licenseNeedsDecision(["Apache-2.0", "BSD License"])).toBe(true);
  });

  it("does not flag a precise id restated as its own generic classifier", () => {
    // babel/comm/nbclient's real shape: BSD-3-Clause plus the PyPI trove
    // classifier for the same grant, not a second, different license.
    expect(licenseNeedsDecision(["BSD-3-Clause", "BSD License"])).toBe(false);
    expect(licenseNeedsDecision(["MIT", "MIT License"])).toBe(false);
    // A genuinely different second license (not the classifier's family)
    // still needs a decision, exactly as line 339 above.
    expect(
      licenseNeedsDecision(["Apache-2.0", "Other/Proprietary License"]),
    ).toBe(true);
    // python-dateutil verbatim: BSD License has no BSD sibling here, and
    // Dual License is genuinely unidentified either way.
    expect(
      licenseNeedsDecision(["Apache-2.0", "BSD License", "Dual License"]),
    ).toBe(true);
  });
});

describe("worstTier via licenseRiskSummary (generic-classifier redundancy)", () => {
  // MIRROR of the license-flags.jq fixture in tests/test-postprocess.sh
  // ("Generic-classifier redundancy"), verified against a real SBOM
  // (examples/python/cellpose_1.0.0).
  it("does not drag a precise permissive id down because its own classifier is also listed", () => {
    const s = licenseRiskSummary([
      c({ licenses: ["BSD-3-Clause", "BSD License"] }),
    ]);
    expect(s.permissive).toBe(1);
    expect(s.uncategorized).toBe(0);
  });

  it("still classifies the generic classifier alone as uncategorized", () => {
    const s = licenseRiskSummary([c({ licenses: ["BSD License"] })]);
    expect(s.uncategorized).toBe(1);
    expect(s.permissive).toBe(0);
  });

  it("still pulls the class down for a genuinely different second license", () => {
    const s = licenseRiskSummary([
      c({ licenses: ["Apache-2.0", "Other/Proprietary License"] }),
    ]);
    expect(s.uncategorized).toBe(1);
  });
});
