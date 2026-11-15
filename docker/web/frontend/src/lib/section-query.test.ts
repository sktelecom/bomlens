// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { EMPTY_FILTERS, type ComponentFilters } from "./components";
import { buildHash, parseHash, type RouteQuery } from "./route";
import {
  componentsFromQuery,
  componentsToQuery,
  conformanceFromQuery,
  conformanceToQuery,
  DEFAULT_VULN_SORT,
  dependenciesFromQuery,
  vulnsFromQuery,
  vulnsToQuery,
  type ComponentSort,
} from "./section-query";

describe("components query", () => {
  it("leaves an unfiltered, unsorted table out of the URL entirely", () => {
    expect(componentsToQuery(EMPTY_FILTERS, null)).toEqual({});
  });

  it("round-trips every field it carries", () => {
    const filters: ComponentFilters = {
      query: "openssl",
      type: "library",
      license: "MIT",
      hasVulns: true,
      directOnly: true,
      needsReview: true,
      eolOnly: true,
      outdatedOnly: true,
      licenseUnclear: true,
    };
    const sort: ComponentSort = { key: "risk", dir: "desc" };
    const back = componentsFromQuery(componentsToQuery(filters, sort));
    expect(back.filters).toEqual(filters);
    expect(back.sort).toEqual(sort);
  });

  it("round-trips a partly filtered table", () => {
    const filters: ComponentFilters = { ...EMPTY_FILTERS, query: "zlib", directOnly: true };
    const query = componentsToQuery(filters, null);
    expect(query).toEqual({ q: "zlib", direct: "1" });
    const back = componentsFromQuery(query);
    expect(back.filters).toEqual(filters);
    expect(back.sort).toBeNull();
  });

  it("falls back to defaults on a query it does not recognise", () => {
    const back = componentsFromQuery({ sort: "nonsense", dir: "sideways", direct: "yes" });
    expect(back.sort).toBeNull();
    // "yes" is not the "1" the flag travels as, so the filter stays off.
    expect(back.filters.directOnly).toBe(false);
  });

  it("defaults a sort direction the URL omits", () => {
    expect(componentsFromQuery({ sort: "name" })).toMatchObject({
      sort: { key: "name", dir: "asc" },
    });
  });
});

describe("vulnerabilities query", () => {
  it("leaves the default worst-first ordering out of the URL", () => {
    expect(vulnsToQuery("", "", DEFAULT_VULN_SORT)).toEqual({});
  });

  it("round-trips a filtered, re-sorted table", () => {
    const query = vulnsToQuery("CVE-2024", "CRITICAL", { key: "epss", dir: "asc" });
    expect(query).toEqual({ q: "CVE-2024", severity: "CRITICAL", sort: "epss", dir: "asc" });
    expect(vulnsFromQuery(query)).toEqual({
      term: "CVE-2024",
      severity: "CRITICAL",
      sort: { key: "epss", dir: "asc" },
    });
  });

  it("returns the default sort for a missing or unknown one", () => {
    expect(vulnsFromQuery(undefined).sort).toEqual(DEFAULT_VULN_SORT);
    expect(vulnsFromQuery({ sort: "vibes" }).sort).toEqual(DEFAULT_VULN_SORT);
  });

  it("round-trips the NVD severity sort key", () => {
    const query = vulnsToQuery("", "", { key: "nvdSeverity", dir: "desc" });
    expect(query).toEqual({ sort: "nvdSeverity", dir: "desc" });
    expect(vulnsFromQuery(query).sort).toEqual({ key: "nvdSeverity", dir: "desc" });
  });
});

describe("dependencies query", () => {
  it("is absent with no query at all", () => {
    expect(dependenciesFromQuery(undefined)).toBeNull();
  });

  it("is absent when q is missing, even if version is present", () => {
    // version alone can't drive findPathToRef, which requires a name.
    expect(dependenciesFromQuery({ version: "6.16.0" })).toBeNull();
  });

  it("carries name only when no version was given", () => {
    expect(dependenciesFromQuery({ q: "qs" })).toEqual({ name: "qs" });
  });

  it("carries name and version together", () => {
    expect(dependenciesFromQuery({ q: "qs", version: "6.15.3" })).toEqual({
      name: "qs",
      version: "6.15.3",
    });
  });
});

describe("through the hash", () => {
  it("survives the trip out to a URL and back", () => {
    const filters: ComponentFilters = {
      ...EMPTY_FILTERS,
      query: "openssl 3.0",
      license: "GPL-2.0-only",
      hasVulns: true,
    };
    const hash = buildHash({
      kind: "scan",
      id: "demo_1.0",
      section: "components",
      query: componentsToQuery(filters, { key: "name", dir: "asc" }),
    });
    const route = parseHash(hash);
    expect(route).toMatchObject({ kind: "scan", id: "demo_1.0", section: "components" });
    const back = componentsFromQuery(route.kind === "scan" ? route.query : undefined);
    expect(back.filters).toEqual(filters);
  });

  it("encodes a term that would otherwise break the hash", () => {
    // A query holding &, ? and # is exactly what an unescaped build would split on.
    const query: RouteQuery = { q: "a&b?c#d" };
    const hash = buildHash({ kind: "scan", id: "x", section: "components", query });
    const route = parseHash(hash);
    expect(route.kind === "scan" && route.query).toEqual(query);
  });

  it("keeps a section with no query at the bare hash", () => {
    expect(buildHash({ kind: "scan", id: "x", section: "components", query: {} })).toBe(
      "#/scan/x/components",
    );
  });
});

describe("conformance query", () => {
  it("leaves the screen's own start out of the URL", () => {
    expect(conformanceToQuery("actionable", "", "actionable")).toEqual({});
    expect(conformanceToQuery(null, "", null)).toEqual({});
  });

  it("names a chip, no chip, and a search", () => {
    expect(conformanceToQuery("pass", "", "actionable")).toEqual({ kind: "pass" });
    expect(conformanceToQuery(null, "hash", "actionable")).toEqual({ kind: "all", q: "hash" });
    expect(conformanceToQuery("actionable", "hash", null)).toEqual({ kind: "actionable", q: "hash" });
  });

  it("round-trips and falls back to the start on a bad kind", () => {
    for (const kind of ["actionable", "review", "na", "pass", null] as const) {
      const q = conformanceToQuery(kind, "x", "actionable");
      expect(conformanceFromQuery(q, "actionable")).toEqual({ kind, term: "x" });
    }
    expect(conformanceFromQuery({ kind: "bogus" }, "review")).toEqual({ kind: "review", term: "" });
    expect(conformanceFromQuery(undefined, null)).toEqual({ kind: null, term: "" });
  });

  it("falls back to the start when the named kind has no checks", () => {
    const counts = { actionable: 2, review: 0, na: 0, pass: 3 };
    expect(conformanceFromQuery({ kind: "review" }, "actionable", counts)).toEqual({ kind: "actionable", term: "" });
    expect(conformanceFromQuery({ kind: "pass" }, "actionable", counts)).toEqual({ kind: "pass", term: "" });
  });
});
