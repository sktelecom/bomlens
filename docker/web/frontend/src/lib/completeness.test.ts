// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { Completeness } from "./api";
import { gradeLabel, gradeVariant, isIncomplete, reasonLines } from "./completeness";

// The fixtures are the files the engine writes (tests/fixtures/completeness), so
// this checks the screen's reading of the real format, not a hand-made shape.
const fixtureDir = fileURLToPath(new URL("../../../../../tests/fixtures/completeness/", import.meta.url));
const load = (name: string): Completeness => JSON.parse(readFileSync(resolve(fixtureDir, `${name}.json`), "utf8"));

describe("isIncomplete", () => {
  it("is false for a missing file and for a complete result", () => {
    expect(isIncomplete(null)).toBe(false);
    expect(isIncomplete(undefined)).toBe(false);
    expect(isIncomplete(load("complete"))).toBe(false);
  });
  it("is true for partial and unreliable", () => {
    expect(isIncomplete(load("partial"))).toBe(true);
    expect(isIncomplete(load("unreliable"))).toBe(true);
  });
});

describe("reasonLines", () => {
  it("gives the engine's sentence in the UI language, word for word", () => {
    const c = load("partial");
    expect(reasonLines(c, "ko")[0].message).toBe(c.reasons[0].message.ko);
    expect(reasonLines(c, "ko-KR")[0].fix).toBe(c.reasons[0].fix.ko);
    expect(reasonLines(c, "en")[0].message).toBe(c.reasons[0].message.en);
    expect(reasonLines(c, "fr")[0].message).toBe(c.reasons[0].message.en);
  });
  it("falls back to the other language when one is empty", () => {
    const c = load("unreliable");
    c.reasons[0].message.ko = "";
    expect(reasonLines(c, "ko")[0].message).toBe(c.reasons[0].message.en);
  });
  it("is empty for a complete result", () => {
    expect(reasonLines(load("complete"), "en")).toEqual([]);
  });
});

describe("gradeLabel and gradeVariant", () => {
  it("reads the label in the UI language", () => {
    expect(gradeLabel(load("unreliable"), "ko")).toBe("신뢰 불가");
    expect(gradeLabel(load("partial"), "en")).toBe("Partial");
  });
  it("maps grades to a Label variant", () => {
    expect(gradeVariant("complete")).toBe("success");
    expect(gradeVariant("partial")).toBe("attention");
    expect(gradeVariant("unreliable")).toBe("danger");
  });
});
