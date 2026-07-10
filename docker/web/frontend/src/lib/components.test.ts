import { describe, expect, it } from "vitest";

import type { ComponentItem } from "./api";
import {
  EMPTY_FILTERS,
  compareComponents,
  matchesFilters,
  riskRank,
  selectComponents,
  typeGroups,
} from "./components";

function c(over: Partial<ComponentItem>): ComponentItem {
  return {
    name: "x",
    version: "1.0",
    group: "",
    purl: "",
    type: "library",
    licenses: [],
    ...over,
  };
}

const FLASK = c({ name: "flask", scope: "direct" });
const WERKZEUG = c({ name: "werkzeug", scope: "transitive", maxSeverity: "CRITICAL", vulnCount: 2 });
const ZLIB = c({ name: "zlib", scope: "transitive", maxSeverity: "LOW", vulnCount: 1 });
const VENDORED = c({ name: "blob", vendored: true });
const EOL_PKG = c({ name: "openssl", eol: "true", eolDate: "2023-09-11" });
const SUPPORTED = c({ name: "curl", eol: "false" });
const OUTDATED_PKG = c({ name: "lodash", outdated: "true", latestVersion: "4.17.21" });
const CURRENT_PKG = c({ name: "axios", outdated: "false" });
const ALL = [FLASK, WERKZEUG, ZLIB, VENDORED];

describe("matchesFilters", () => {
  it("hasVulns keeps only components with vulnerabilities", () => {
    const kept = ALL.filter((x) => matchesFilters(x, { ...EMPTY_FILTERS, hasVulns: true }));
    expect(kept.map((x) => x.name)).toEqual(["werkzeug", "zlib"]);
  });

  it("directOnly keeps only direct dependencies", () => {
    const kept = ALL.filter((x) => matchesFilters(x, { ...EMPTY_FILTERS, directOnly: true }));
    expect(kept.map((x) => x.name)).toEqual(["flask"]);
  });

  it("needsReview keeps only vendored components", () => {
    const kept = ALL.filter((x) => matchesFilters(x, { ...EMPTY_FILTERS, needsReview: true }));
    expect(kept.map((x) => x.name)).toEqual(["blob"]);
  });

  it("eolOnly keeps only components past upstream end-of-life", () => {
    const set = [FLASK, EOL_PKG, SUPPORTED];
    const kept = set.filter((x) => matchesFilters(x, { ...EMPTY_FILTERS, eolOnly: true }));
    expect(kept.map((x) => x.name)).toEqual(["openssl"]);
  });

  it("eolOnly excludes false/unknown/unmapped components", () => {
    expect(matchesFilters(SUPPORTED, { ...EMPTY_FILTERS, eolOnly: true })).toBe(false);
    expect(matchesFilters(c({ eol: "unknown" }), { ...EMPTY_FILTERS, eolOnly: true })).toBe(false);
    expect(matchesFilters(FLASK, { ...EMPTY_FILTERS, eolOnly: true })).toBe(false);
  });

  it("outdatedOnly keeps only components behind the latest patch", () => {
    const set = [FLASK, OUTDATED_PKG, CURRENT_PKG];
    const kept = set.filter((x) => matchesFilters(x, { ...EMPTY_FILTERS, outdatedOnly: true }));
    expect(kept.map((x) => x.name)).toEqual(["lodash"]);
  });

  it("outdatedOnly excludes false/unmapped components and is distinct from eol", () => {
    expect(matchesFilters(CURRENT_PKG, { ...EMPTY_FILTERS, outdatedOnly: true })).toBe(false);
    expect(matchesFilters(FLASK, { ...EMPTY_FILTERS, outdatedOnly: true })).toBe(false);
    // An EOL component is not automatically outdated (separate signal).
    expect(matchesFilters(EOL_PKG, { ...EMPTY_FILTERS, outdatedOnly: true })).toBe(false);
  });

  it("query matches name/version/type/license, combinable with toggles", () => {
    expect(matchesFilters(WERKZEUG, { ...EMPTY_FILTERS, query: "werk", hasVulns: true })).toBe(true);
    expect(matchesFilters(FLASK, { ...EMPTY_FILTERS, query: "werk" })).toBe(false);
  });
});

describe("riskRank + risk sort", () => {
  it("ranks worse severity higher; no-vuln components rank 0", () => {
    expect(riskRank(WERKZEUG)).toBeGreaterThan(riskRank(ZLIB));
    expect(riskRank(FLASK)).toBe(0);
  });

  it("sorts by risk descending with components-without-vulns last", () => {
    const sorted = selectComponents(ALL, EMPTY_FILTERS, { key: "risk", dir: "desc" });
    expect(sorted.map((x) => x.name)).toEqual(["werkzeug", "zlib", "blob", "flask"]);
  });
});

describe("scope sort", () => {
  it("orders direct above transitive above unknown", () => {
    const sorted = [...ALL].sort((a, b) => compareComponents(a, b, "scope", "desc"));
    expect(sorted[0].name).toBe("flask"); // the only direct one
    expect(sorted[sorted.length - 1].name).toBe("blob"); // no scope
  });
});

describe("selectComponents", () => {
  it("filters then sorts on the full set", () => {
    const out = selectComponents(ALL, { ...EMPTY_FILTERS, hasVulns: true }, { key: "risk", dir: "asc" });
    expect(out.map((x) => x.name)).toEqual(["zlib", "werkzeug"]);
  });
});

describe("typeGroups", () => {
  it("counts components per type, busiest first, skipping untyped", () => {
    const groups = typeGroups([
      c({ type: "library" }),
      c({ type: "framework" }),
      c({ type: "library" }),
      c({ type: "" }),
    ]);
    expect(groups).toEqual([
      { type: "library", count: 2 },
      { type: "framework", count: 1 },
    ]);
  });

  it("returns a single group for a uniform SBOM (caller gates on length>=2)", () => {
    expect(typeGroups([c({ type: "library" }), c({ type: "library" })])).toEqual([
      { type: "library", count: 2 },
    ]);
  });
});
