// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The checker is a plain .mjs shared with scripts/i18n-coverage.mjs; load it by
// a computed path so TypeScript does not need a declaration for it.
const SCRIPT = join(process.cwd(), "scripts", "forbidden-terms.mjs");
const mod = (await import(/* @vite-ignore */ SCRIPT)) as {
  findForbidden: (
    m: unknown,
    lng: string,
  ) => { key: string; found: string; prefer: string }[];
};

function load(lng: string) {
  return JSON.parse(readFileSync(join(process.cwd(), "src", "locales", lng, "common.json"), "utf8"));
}

describe("glossary forbidden terms", () => {
  it("flags a forbidden variant with its key and the preferred term", () => {
    const hits = mod.findForbidden({ nav: { conformance: "SBOM 규제 검사" } }, "ko");
    expect(hits).toEqual([{ key: "nav.conformance", found: "SBOM 규제 검사", prefer: "적합성 검사" }]);
  });

  it("checks each language only against its own list", () => {
    expect(mod.findForbidden({ a: "SBOM Validation" }, "ko")).toEqual([]);
    expect(mod.findForbidden({ a: "SBOM Validation" }, "en")).toHaveLength(1);
  });

  it("accepts the canonical terms", () => {
    expect(mod.findForbidden({ a: "적합성 검사 보고서, 산출물, 다시 스캔" }, "ko")).toEqual([]);
    expect(mod.findForbidden({ a: "Conformance check report" }, "en")).toEqual([]);
  });

  it("finds none in the shipped locale files", () => {
    expect(mod.findForbidden(load("en"), "en")).toEqual([]);
    expect(mod.findForbidden(load("ko"), "ko")).toEqual([]);
  });
});
