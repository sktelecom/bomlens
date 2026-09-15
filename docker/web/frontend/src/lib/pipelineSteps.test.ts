// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { pipelineStepLabelKey } from "./pipelineSteps";

describe("pipelineStepLabelKey", () => {
  it("returns an i18n key for a known step id", () => {
    expect(pipelineStepLabelKey("enrich-cpe")).toBe("pipelineSteps.enrichCpe");
    expect(pipelineStepLabelKey("generate-notice")).toBe("pipelineSteps.generateNotice");
  });

  it("covers every step id the dependency-lock designs and firmware (#82) use", () => {
    for (const step of [
      "firmware-packages",
      "firmware-extra-roots",
      "cargo-lockfile",
      "go-mod-tidy",
      "bundle-lock",
      "gradle-dependencies",
      "android-release-classpath",
      "swift-package-resolve",
      "npm-production-set",
      "pip-install",
    ]) {
      expect(pipelineStepLabelKey(step)).toBeDefined();
    }
  });

  it("returns undefined for an unmapped step id, so the caller can fall back to the raw id", () => {
    expect(pipelineStepLabelKey("some-future-step")).toBeUndefined();
  });
});
