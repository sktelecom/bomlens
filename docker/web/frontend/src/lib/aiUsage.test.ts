// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { AiUsageItem, SbomSummary } from "./api";
import {
  AI_USAGE_KIND_KEY,
  AI_USAGE_KINDS,
  AI_USAGE_REASON_HELP_KEY,
  AI_USAGE_REASON_KEY,
  AI_USAGE_REASONS,
  aiUsageScopeKey,
  aiUsageView,
} from "./aiUsage";

const item = (over: Partial<AiUsageItem>): AiUsageItem => ({
  kind: "model",
  name: "gpt-4o",
  scope: "runtime",
  reviewReasons: [],
  ...over,
});
const sbom = (aiUsage: unknown[], extra: Partial<SbomSummary> = {}): SbomSummary =>
  ({ components: 0, componentList: [], aiUsage, ...extra }) as SbomSummary;

describe("aiUsageView", () => {
  it("is null when the scan recorded no AI usage", () => {
    expect(aiUsageView(null)).toBeNull();
    expect(aiUsageView({ components: 0 })).toBeNull();
    expect(aiUsageView(sbom([]))).toBeNull();
  });

  it("groups by kind in a fixed order and puts items to review first", () => {
    const v = aiUsageView(
      sbom([
        item({ kind: "instruction-file", name: "AGENTS.md", scope: "development" }),
        item({ kind: "mcp-server", name: "b-server", scope: "development" }),
        item({ kind: "mcp-server", name: "z-server", scope: "development", reviewReasons: ["unpinned-package"] }),
        item({ kind: "mcp-server", name: "a-server", scope: "development" }),
        item({ kind: "ai-service", name: "OpenAI API", models: ["gpt-4o"] }),
        item({ kind: "model", name: "gpt-4o" }),
      ]),
    )!;
    expect(v.groups.map((g) => g.kind)).toEqual(["model", "ai-service", "mcp-server", "instruction-file"]);
    expect(v.groups[2].items.map((i) => i.name)).toEqual(["z-server", "a-server", "b-server"]);
    expect(v.total).toBe(6);
    expect(v.reviewCount).toBe(1);
    expect(v.reasons).toEqual(["unpinned-package"]);
    expect(v.truncated).toBe(false);
  });

  it("drops malformed items and unknown reasons, and keeps reasons in a fixed order", () => {
    const v = aiUsageView(
      sbom([
        null,
        { kind: "plugin", name: "x", scope: "runtime", reviewReasons: [] },
        { kind: "model", name: "", scope: "runtime", reviewReasons: [] },
        {
          kind: "mcp-server",
          name: "fs",
          scope: "weird",
          reviewReasons: ["unencrypted-transport", "made-up", "broad-filesystem-access"],
          models: ["m", 3],
        },
      ]),
    )!;
    expect(v.total).toBe(1);
    const fs = v.groups[0].items[0];
    expect(fs.scope).toBe("runtime");
    expect(fs.reviewReasons).toEqual(["broad-filesystem-access", "unencrypted-transport"]);
    expect(fs.models).toEqual(["m"]);
    expect(v.reasons).toEqual(["broad-filesystem-access", "unencrypted-transport"]);
  });

  it("reports the server cap", () => {
    expect(aiUsageView(sbom([item({})], { aiUsageTruncated: true }))!.truncated).toBe(true);
  });
});

describe("aiUsage labels", () => {
  const load = (lng: string) =>
    JSON.parse(readFileSync(join(process.cwd(), "src", "locales", lng, "common.json"), "utf8"));
  const lookup = (obj: Record<string, unknown>, key: string) =>
    key.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], obj);

  it("maps the scope", () => {
    expect(aiUsageScopeKey("runtime")).toBe("aiUsage.scope.runtime");
    expect(aiUsageScopeKey("development")).toBe("aiUsage.scope.development");
  });

  it("has a string in both languages for every kind, scope and reason", () => {
    const keys = [
      ...AI_USAGE_KINDS.map((k) => AI_USAGE_KIND_KEY[k]),
      ...AI_USAGE_REASONS.flatMap((r) => [AI_USAGE_REASON_KEY[r], AI_USAGE_REASON_HELP_KEY[r]]),
      aiUsageScopeKey("runtime"),
      aiUsageScopeKey("development"),
    ];
    for (const lng of ["en", "ko"]) {
      const messages = load(lng);
      for (const key of keys) expect(typeof lookup(messages, key), `${lng}:${key}`).toBe("string");
    }
  });
});
