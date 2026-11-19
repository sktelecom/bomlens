// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { VulnItem } from "./api";
import { columnFacts, columnOn, parseColumnPref } from "./vulnColumns";

const v = (extra: Partial<VulnItem> = {}): VulnItem => ({ id: "CVE-1", pkg: "x", installed: "1", fixed: "", severity: "HIGH", title: "", ...extra });

describe("vulnerability columns", () => {
  it("never offers a column without values", () => {
    const f = columnFacts([v(), v()]);
    expect(columnOn("epss", f, { epss: true })).toBe(false);
    expect(columnOn("nvd", f, { nvd: true })).toBe(false);
  });

  it("defaults a column to on as soon as any row has a value", () => {
    const some = columnFacts([v({ epss: 0.1, nvdSeverity: "HIGH" }), v()]);
    expect(columnOn("epss", some, {})).toBe(true);
    expect(columnOn("nvd", some, {})).toBe(true);
  });

  it("lets the stored choice win", () => {
    const some = columnFacts([v({ epss: 0.1, nvdSeverity: "HIGH" }), v()]);
    expect(columnOn("epss", some, { epss: true })).toBe(true);
    expect(columnOn("nvd", some, { nvd: true })).toBe(true);
    expect(columnOn("epss", some, { epss: false })).toBe(false);
  });

  it("offers the introduced-by column only when a row names a dependency", () => {
    expect(columnOn("introduced", columnFacts([v(), v({ introducedBy: [] })]), {})).toBe(false);
    const some = columnFacts([v({ introducedBy: [{ name: "spring-boot-starter-web", version: "3.2.0" }] }), v()]);
    expect(some.introducedRows).toBe(1);
    expect(columnOn("introduced", some, {})).toBe(true);
    expect(columnOn("introduced", some, { introduced: false })).toBe(false);
  });

  it("ignores a malformed stored value", () => {
    expect(parseColumnPref("not json")).toEqual({});
    expect(parseColumnPref('{"epss":"yes","nvd":true,"introduced":false,"x":1}')).toEqual({ nvd: true, introduced: false });
    expect(parseColumnPref(null)).toEqual({});
  });
});
