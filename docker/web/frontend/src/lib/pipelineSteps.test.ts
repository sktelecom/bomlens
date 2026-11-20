// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { currentLiveStep, formatElapsed, hasIncompleteSteps, pipelineStepLabelKey, splitFailedSteps } from "./pipelineSteps";

describe("currentLiveStep", () => {
  it("is null before any marker", () => {
    expect(currentLiveStep([])).toBeNull();
    expect(currentLiveStep(["hello"])).toBeNull();
  });

  it("follows the newest marker, not the first", () => {
    expect(currentLiveStep(["▶ Preparing a writable copy of app ..."])?.id).toBe("copy");
    expect(currentLiveStep(["[1/2] generating", "[build-prep] gradle: resolving", "more output"])?.id).toBe("buildPrep");
    expect(currentLiveStep(["[build-prep] gradle", "[1/2] cdxgen", "plain line"])?.id).toBe("generate");
    expect(currentLiveStep(["[1/2] cdxgen", "[security] trivy"])?.id).toBe("security");
  });

  it("names the image download the server starts", () => {
    expect(currentLiveStep(["[ui] pulling ghcr.io/x/y ..."])?.id).toBe("pull");
  });
});

describe("formatElapsed", () => {
  it("formats as m:ss and h:mm:ss", () => {
    expect(formatElapsed(0)).toBe("0:00");
    expect(formatElapsed(65)).toBe("1:05");
    expect(formatElapsed(3599)).toBe("59:59");
    expect(formatElapsed(3725)).toBe("1:02:05");
    expect(formatElapsed(-4)).toBe("0:00");
  });
});

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
      "gradle-wrapper-jdk",
      "maven-dependency-jars",
      "maven-dependency-resolve",
      "android-release-classpath",
      "swift-package-resolve",
      "npm-production-set",
      "pip-install",
      "cargo-workspace-metadata",
      "cargo-license-metadata",
      "ai-usage",
      "resolve-models",
      "composer-install",
      "pnpm-workspace-tree",
      "enrich-distro-supplier",
      "component-versions",
      "upstream-purl",
      "match-cpe",
    ]) {
      expect(pipelineStepLabelKey(step)).toBeDefined();
    }
  });

  it("returns undefined for an unmapped step id, so the caller can fall back to the raw id", () => {
    expect(pipelineStepLabelKey("some-future-step")).toBeUndefined();
  });

  it("has a label for every step id the pipeline scripts can record as failed", () => {
    // Relative to this file (docker/web/frontend/src/lib), so the working directory does not matter.
    const dockerDir = fileURLToPath(new URL("../../../..", import.meta.url));
    const code = (file: string) =>
      readFileSync(resolve(dockerDir, file), "utf8")
        .split("\n")
        .filter((line) => !line.trim().startsWith("#"))
        .join("\n");
    // The id is the first word after the call. A word built from a variable cannot be
    // read here, so it is not taken; every other word must have a label.
    const ids = new Set<string>();
    const collect = (text: string, call: RegExp) => {
      for (const m of text.matchAll(call)) if (!/^["$]/.test(m[1])) ids.add(m[1]);
    };
    collect(code("lib/build-prep.sh"), /\bprep_step (\S+) /g);
    collect(code("lib/build-prep.sh"), /\bmark_prep_failed (\S+)$/gm);
    collect(code("entrypoint.sh"), /\brun_optional_step (\S+) /g);
    // scan-firmware.sh names its step as the last argument of catalog_packages.
    collect(code("lib/scan-firmware.sh"), /\bcatalog_packages "[^"]*" "[^"]*" (\S+)(?:;|$)/gm);
    expect(ids.size).toBeGreaterThan(20);
    expect(ids).toContain("firmware-extra-roots");
    const unlabelled = [...ids].filter((id) => pipelineStepLabelKey(id) === undefined);
    expect(unlabelled).toEqual([]);
  });
});

describe("splitFailedSteps", () => {
  it("treats a skipped license lookup as a note, not incomplete data", () => {
    expect(splitFailedSteps(["license-fetch"])).toEqual({ incomplete: [], licenseLookupSkipped: true });
    expect(hasIncompleteSteps(["license-fetch"])).toBe(false);
  });

  it("keeps the other steps as incomplete", () => {
    expect(splitFailedSteps(["enrich-cpe", "license-fetch", "some-future-step"])).toEqual({
      incomplete: ["enrich-cpe", "some-future-step"],
      licenseLookupSkipped: true,
    });
    expect(hasIncompleteSteps(["enrich-cpe", "license-fetch"])).toBe(true);
  });

  it("counts steps past the listed cap as incomplete", () => {
    expect(hasIncompleteSteps(["license-fetch"], 2)).toBe(true);
  });

  it("handles no steps", () => {
    expect(splitFailedSteps(undefined)).toEqual({ incomplete: [], licenseLookupSkipped: false });
    expect(hasIncompleteSteps([])).toBe(false);
  });
});
