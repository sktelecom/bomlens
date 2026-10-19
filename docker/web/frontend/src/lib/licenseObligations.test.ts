// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { licenseObligations } from "./licenseObligations";

describe("licenseObligations", () => {
  it("lists the conditions of a single known license", () => {
    expect(licenseObligations("MIT")).toEqual({ kind: "known", tags: ["include-copyright"] });
    expect(licenseObligations("GPL-3.0")).toEqual({
      kind: "known",
      tags: ["include-copyright", "document-changes", "disclose-source", "same-license"],
    });
  });

  it("matches ids case-insensitively and maps the -only / -or-later forms", () => {
    expect(licenseObligations("apache-2.0")).toEqual(licenseObligations("Apache-2.0"));
    expect(licenseObligations("GPL-2.0-only")).toEqual(licenseObligations("GPL-2.0"));
    expect(licenseObligations("LGPL-3.0-or-later")).toEqual(licenseObligations("LGPL-3.0"));
    expect(licenseObligations("GPL-2.0+")).toEqual(licenseObligations("GPL-2.0"));
  });

  it("reports a license with no conditions as known and empty", () => {
    expect(licenseObligations("CC0-1.0")).toEqual({ kind: "known", tags: [] });
  });

  it("never fills in a license that is not in the data set", () => {
    expect(licenseObligations("GPL")).toEqual({ kind: "unknown" });
    expect(licenseObligations("Dual License")).toEqual({ kind: "unknown" });
    expect(licenseObligations("")).toEqual({ kind: "unknown" });
  });

  it("does not apply the base license to a term with an exception clause", () => {
    expect(licenseObligations("GPL-2.0-with-classpath-exception")).toEqual({ kind: "unknown" });
    expect(licenseObligations("GPL-2.0-only WITH Classpath-exception-2.0")).toEqual({
      kind: "unknown",
    });
  });

  it("keeps the OR / AND structure of an expression", () => {
    const r = licenseObligations("MIT OR Apache-2.0");
    expect(r).toEqual({
      kind: "expression",
      alternatives: [
        [{ term: "MIT", tags: ["include-copyright"] }],
        [{ term: "Apache-2.0", tags: ["include-copyright", "document-changes"] }],
      ],
    });
    const both = licenseObligations("MIT AND Unicode-3.0");
    expect(both.kind).toBe("expression");
    if (both.kind === "expression") {
      expect(both.alternatives).toHaveLength(1);
      expect(both.alternatives[0].map((t) => t.tags === null)).toEqual([false, true]);
    }
  });

  it("is unknown when no term of an expression resolves", () => {
    expect(licenseObligations("Foo OR Bar")).toEqual({ kind: "unknown" });
  });
});
