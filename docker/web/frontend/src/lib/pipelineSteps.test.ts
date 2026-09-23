// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
      "cargo-workspace-metadata",
      "cargo-license-metadata",
      "composer-install",
      "pnpm-workspace-tree",
      "enrich-distro-supplier",
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
    collect(code("entrypoint.sh"), /\brun_optional_step (\S+) /g);
    // scan-firmware.sh names its step as the last argument of catalog_packages.
    collect(code("lib/scan-firmware.sh"), /\bcatalog_packages "[^"]*" "[^"]*" (\S+)(?:;|$)/gm);
    expect(ids.size).toBeGreaterThan(20);
    expect(ids).toContain("firmware-extra-roots");
    const unlabelled = [...ids].filter((id) => pipelineStepLabelKey(id) === undefined);
    expect(unlabelled).toEqual([]);
  });
});
