// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { VulnItem } from "./api";
import { csvFilename, toCsv, vulnCsvRows } from "./csv";

describe("toCsv", () => {
  it("writes a header and rows separated by CRLF", () => {
    expect(toCsv([["name", "version"], ["openssl", "3.0.0"]])).toBe(
      "name,version\r\nopenssl,3.0.0",
    );
  });

  it("quotes a value holding a comma", () => {
    // License lists are the common case: "Apache-2.0, MIT" in one cell.
    expect(toCsv([["Apache-2.0, MIT"]])).toBe('"Apache-2.0, MIT"');
  });

  it("doubles quotes inside a quoted value", () => {
    expect(toCsv([['he said "hi", loudly']])).toBe('"he said ""hi"", loudly"');
  });

  it("quotes a value holding a newline", () => {
    expect(toCsv([["line one\nline two"]])).toBe('"line one\nline two"');
  });

  it("writes empty for null and undefined, and keeps a zero", () => {
    expect(toCsv([[null, undefined, 0, false]])).toBe(",,0,false");
  });

  it("keeps a formula-looking value as text", () => {
    // A package literally named "-rf" or a cell starting with = would run as a
    // formula on open; the leading quote keeps it a string.
    expect(toCsv([["=1+1", "-rf", "@name", "+7"]])).toBe("'=1+1,'-rf,'@name,'+7");
  });

  it("round-trips a row whose every cell needs escaping", () => {
    const row = ['a,b', 'c"d', "e\nf"];
    const out = toCsv([row]);
    // Parsed back by the rules it was written under.
    const cells = out.match(/("([^"]|"")*"|[^,]*)/g)?.filter((_, i) => i % 2 === 0) ?? [];
    const parsed = cells.map((c) =>
      c.startsWith('"') ? c.slice(1, -1).replace(/""/g, '"') : c,
    );
    expect(parsed).toEqual(row);
  });
});

describe("csvFilename", () => {
  it("names the scan, the list and the date", () => {
    expect(csvFilename("demo_1.0", "components", "2026-08-15")).toBe(
      "demo_1.0-components-2026-08-15.csv",
    );
  });

  it("replaces what a filesystem would refuse", () => {
    expect(csvFilename("a/b:c*d", "vulnerabilities", "2026-08-15")).toBe(
      "a-b-c-d-vulnerabilities-2026-08-15.csv",
    );
  });

  it("falls back when the scan id is entirely unusable", () => {
    expect(csvFilename("///", "components", "2026-08-15")).toBe(
      "scan-components-2026-08-15.csv",
    );
  });
});

describe("vulnCsvRows", () => {
  const base: VulnItem = { id: "CVE-1", severity: "HIGH", pkg: "tomcat-embed-core", installed: "10.1.1", fixed: "10.1.2", title: "t" };

  it("ends each row with the direct dependencies that introduce it", () => {
    const rows = vulnCsvRows(
      [
        { ...base, introducedBy: [{ name: "spring-boot-starter-web", version: "3.2.0" }, { name: "x" }] },
        base,
      ],
      ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
    );
    expect(rows[1][9]).toBe("spring-boot-starter-web 3.2.0; x");
    expect(rows[2][9]).toBe("");
  });
});
