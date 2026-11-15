// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { formatLookupDate, formatRange, parseLookupInput } from "./lookup";

describe("parseLookupInput: advisory ids", () => {
  it("recognizes every advisory-id prefix the server accepts", () => {
    expect(parseLookupInput("CVE-2021-44228")).toEqual({
      kind: "advisory",
      id: "CVE-2021-44228",
    });
    expect(parseLookupInput("GHSA-jfh8-c2jp-5v3q")).toEqual({
      kind: "advisory",
      id: "GHSA-jfh8-c2jp-5v3q",
    });
    expect(parseLookupInput("GO-2021-0113")).toEqual({
      kind: "advisory",
      id: "GO-2021-0113",
    });
    expect(parseLookupInput("PYSEC-2021-100")).toEqual({
      kind: "advisory",
      id: "PYSEC-2021-100",
    });
    expect(parseLookupInput("RUSTSEC-2021-0001")).toEqual({
      kind: "advisory",
      id: "RUSTSEC-2021-0001",
    });
    expect(parseLookupInput("OSV-2021-1820")).toEqual({
      kind: "advisory",
      id: "OSV-2021-1820",
    });
    expect(parseLookupInput("GSD-2021-1000001")).toEqual({
      kind: "advisory",
      id: "GSD-2021-1000001",
    });
    expect(parseLookupInput("MAL-2024-1234")).toEqual({
      kind: "advisory",
      id: "MAL-2024-1234",
    });
  });

  it("normalizes the prefix's casing but preserves the suffix verbatim", () => {
    expect(parseLookupInput("cve-2021-44228")).toEqual({
      kind: "advisory",
      id: "CVE-2021-44228",
    });
    expect(parseLookupInput("ghsa-jfh8-c2jp-5v3q")).toEqual({
      kind: "advisory",
      id: "GHSA-jfh8-c2jp-5v3q",
    });
  });

  it("trims surrounding whitespace", () => {
    expect(parseLookupInput("  CVE-2021-44228  ")).toEqual({
      kind: "advisory",
      id: "CVE-2021-44228",
    });
  });
});

describe("parseLookupInput: purls", () => {
  it("parses an npm purl with a version", () => {
    expect(parseLookupInput("pkg:npm/lodash@4.17.21")).toEqual({
      kind: "package",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.21",
    });
  });

  it("keeps a scoped npm package's namespace joined with '/'", () => {
    expect(parseLookupInput("pkg:npm/%40angular/core@6.6.6")).toEqual({
      kind: "package",
      ecosystem: "npm",
      name: "@angular/core",
      version: "6.6.6",
    });
  });

  it("joins a Maven groupId:artifactId with a colon", () => {
    expect(
      parseLookupInput("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
    ).toEqual({
      kind: "package",
      ecosystem: "maven",
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
    });
  });

  it("joins a Go module path with '/'", () => {
    expect(parseLookupInput("pkg:golang/github.com/gin-gonic/gin@v1.9.1")).toEqual({
      kind: "package",
      ecosystem: "go",
      name: "github.com/gin-gonic/gin",
      version: "v1.9.1",
    });
  });

  it("maps cargo/gem/composer/nuget to their OSV ecosystem slugs", () => {
    expect(parseLookupInput("pkg:cargo/tokio@1.35.0")).toMatchObject({
      kind: "package",
      ecosystem: "cargo",
      name: "tokio",
    });
    expect(parseLookupInput("pkg:gem/rails@7.0.0")).toMatchObject({
      kind: "package",
      ecosystem: "rubygems",
      name: "rails",
    });
    expect(parseLookupInput("pkg:composer/guzzlehttp/guzzle@7.8.0")).toEqual({
      kind: "package",
      ecosystem: "packagist",
      name: "guzzlehttp/guzzle",
      version: "7.8.0",
    });
    expect(parseLookupInput("pkg:nuget/Newtonsoft.Json@13.0.1")).toMatchObject({
      kind: "package",
      ecosystem: "nuget",
      name: "Newtonsoft.Json",
    });
  });

  it("leaves version empty when the purl carries none", () => {
    expect(parseLookupInput("pkg:pypi/django")).toEqual({
      kind: "package",
      ecosystem: "pypi",
      name: "django",
      version: "",
    });
  });

  it("is case-insensitive on the 'pkg:' scheme and the type token", () => {
    expect(parseLookupInput("PKG:NPM/lodash@4.17.21")).toEqual({
      kind: "package",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.21",
    });
  });

  it("drops qualifiers and a subpath", () => {
    expect(
      parseLookupInput("pkg:npm/lodash@4.17.21?arch=x86#lib/index.js"),
    ).toEqual({
      kind: "package",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.21",
    });
  });

  it("flags a purl type with no OSV ecosystem mapping", () => {
    expect(parseLookupInput("pkg:deb/debian/openssl@3.0.0")).toEqual({
      kind: "unsupportedPurl",
      type: "deb",
    });
  });
});

describe("parseLookupInput: bare names", () => {
  it("treats a plain name with nothing else as a package with no version yet", () => {
    expect(parseLookupInput("lodash")).toEqual({
      kind: "package",
      name: "lodash",
      version: "",
    });
  });

  it("splits 'name@version' on the last '@'", () => {
    expect(parseLookupInput("lodash@4.17.21")).toEqual({
      kind: "package",
      name: "lodash",
      version: "4.17.21",
    });
  });

  it("keeps a scoped name's leading '@' when a version follows", () => {
    expect(parseLookupInput("@angular/core@6.6.6")).toEqual({
      kind: "package",
      name: "@angular/core",
      version: "6.6.6",
    });
  });

  it("treats a bare scoped name with no version as the whole string", () => {
    expect(parseLookupInput("@angular/core")).toEqual({
      kind: "package",
      name: "@angular/core",
      version: "",
    });
  });

  it("splits 'name version' on whitespace", () => {
    expect(parseLookupInput("log4j-core 2.14.1")).toEqual({
      kind: "package",
      name: "log4j-core",
      version: "2.14.1",
    });
  });

  it("trims whitespace around the name and version", () => {
    expect(parseLookupInput("  lodash   4.17.21  ")).toEqual({
      kind: "package",
      name: "lodash",
      version: "4.17.21",
    });
  });
});

describe("parseLookupInput: empty", () => {
  it("treats blank / whitespace-only input as empty", () => {
    expect(parseLookupInput("")).toEqual({ kind: "empty" });
    expect(parseLookupInput("   ")).toEqual({ kind: "empty" });
  });
});

describe("formatRange", () => {
  it("reads introduced, fixed, last_affected and limit events", () => {
    expect(
      formatRange({ events: [{ introduced: "" }, { fixed: "2.0.1" }, { last_affected: "3" }, { limit: "4" }] }),
    ).toBe(">= 0, < 2.0.1, <= 3, < 4");
  });
  it("returns an empty string for anything that is not a range", () => {
    expect(formatRange(null)).toBe("");
    expect(formatRange({ events: "x" })).toBe("");
    expect(formatRange({ events: [null, {}] })).toBe("");
  });
});

describe("formatLookupDate", () => {
  it("keeps an unparseable date as it came", () => {
    expect(formatLookupDate("soon", "en")).toBe("soon");
  });
});
