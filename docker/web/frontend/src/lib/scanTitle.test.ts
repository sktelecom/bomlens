// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { projectText, scanProjectName } from "./scanTitle";

const RECENT = [
  { id: "SpringBootDemo_1.1.0", project: "SpringBootDemo", version: "1.1.0" },
  { id: "nightly_20261113T0101", project: "nightly", version: "" },
];

describe("scanProjectName", () => {
  it("names a listed scan by project and version, not by its id", () => {
    expect(scanProjectName("SpringBootDemo_1.1.0", RECENT)).toEqual({
      name: "SpringBootDemo",
      version: "1.1.0",
    });
  });

  it("drops an empty version", () => {
    expect(scanProjectName("nightly_20261113T0101", RECENT)).toEqual({ name: "nightly" });
  });

  it("falls back to the settings the scan ran with", () => {
    expect(scanProjectName("demo_1.0", [], { project: "demo", version: "1.0" })).toEqual({
      name: "demo",
      version: "1.0",
    });
  });

  it("prefers the scan list over the settings", () => {
    expect(
      scanProjectName("SpringBootDemo_1.1.0", RECENT, { project: "other", version: "9" }),
    ).toEqual({ name: "SpringBootDemo", version: "1.1.0" });
  });

  it("uses the id only when nothing else names the scan", () => {
    expect(scanProjectName("x_1", [], null)).toEqual({ name: "x_1" });
    expect(scanProjectName("x_1", [], { project: "" })).toEqual({ name: "x_1" });
  });
});

describe("projectText", () => {
  it("joins name and version with a space", () => {
    expect(projectText({ name: "SpringBootDemo", version: "1.1.0" })).toBe("SpringBootDemo 1.1.0");
  });

  it("is the name alone without a version, and empty without a name", () => {
    expect(projectText({ name: "nightly" })).toBe("nightly");
    expect(projectText(undefined)).toBe("");
  });
});
