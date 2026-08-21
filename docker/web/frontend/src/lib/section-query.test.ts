// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { EMPTY_FILTERS, type ComponentFilters } from "./components";
import { buildHash, parseHash, type RouteQuery } from "./route";
import {
  componentsFromQuery,
  componentsToQuery,
  DEFAULT_VULN_SORT,
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
