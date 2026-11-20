// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { buildToolToSend, buildToolWhyKey, builtWith, hasBothBuildTools, normalizeBuildTool } from "./buildTool";

describe("buildTool", () => {
  it("shows the choice only when both build files exist", () => {
    expect(hasBothBuildTools({ maven: true, gradle: true })).toBe(true);
    expect(hasBothBuildTools({ maven: true, gradle: false })).toBe(false);
    expect(hasBothBuildTools({ maven: false, gradle: true })).toBe(false);
    expect(hasBothBuildTools({})).toBe(false);
    expect(hasBothBuildTools(null)).toBe(false);
    expect(hasBothBuildTools(undefined)).toBe(false);
  });

  it("narrows unknown values to auto", () => {
    expect(normalizeBuildTool("maven")).toBe("maven");
    expect(normalizeBuildTool("gradle")).toBe("gradle");
    expect(normalizeBuildTool("auto")).toBe("auto");
    expect(normalizeBuildTool("ant")).toBe("auto");
    expect(normalizeBuildTool(undefined)).toBe("auto");
  });

  it("sends auto whenever the choice is hidden", () => {
    expect(buildToolToSend(false, "maven")).toBe("auto");
    expect(buildToolToSend(true, "maven")).toBe("maven");
    expect(buildToolToSend(true, "auto")).toBe("auto");
  });

  it("reports the tool a scan used only for the two known values", () => {
    expect(builtWith("gradle")).toBe("gradle");
    expect(builtWith("maven")).toBe("maven");
    expect(builtWith("<b>")).toBeNull();
    expect(builtWith(null)).toBeNull();
  });

  it("maps the fixed build-tool reasons to locale keys and leaves others raw", () => {
    expect(buildToolWhyKey("requested with --build-tool maven")).toBe("overview.buildWhyRequestedMaven");
    expect(buildToolWhyKey("requested with --build-tool gradle")).toBe("overview.buildWhyRequestedGradle");
    expect(
      buildToolWhyKey("pom.xml and build.gradle both found; Gradle is the default (--build-tool maven reads pom.xml instead)"),
    ).toBe("overview.buildWhyBothDefaultGradle");
    expect(buildToolWhyKey("something else")).toBeNull();
    expect(buildToolWhyKey(null)).toBeNull();
  });
});
