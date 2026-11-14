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
  aiUsageModelDetail,
  aiUsageScopeKey,
  aiUsageView,
  hubModelId,
  safeHubUrl,
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

describe("hubModelId and safeHubUrl", () => {
  it("reads owner/name from a hub purl and refuses anything unsafe", () => {
    expect(hubModelId("pkg:huggingface/meta-llama/Llama-3.1-8B")).toBe("meta-llama/Llama-3.1-8B");
    expect(hubModelId("pkg:huggingface/acme/x@abc123")).toBe("acme/x");
    expect(hubModelId("pkg:generic/openai/gpt-4o")).toBeNull();
    expect(hubModelId("pkg:huggingface/acme/x%3Brm")).toBeNull();
    expect(hubModelId(undefined)).toBeNull();
  });

  it("accepts only huggingface.co links", () => {
    expect(safeHubUrl("https://huggingface.co/acme/x")).toBe("https://huggingface.co/acme/x");
    expect(safeHubUrl("http://huggingface.co/acme/x")).toBeUndefined();
    expect(safeHubUrl("https://huggingface.co.evil.test/x")).toBeUndefined();
    expect(safeHubUrl("javascript:alert(1)")).toBeUndefined();
    expect(safeHubUrl(undefined)).toBeUndefined();
  });
});

describe("aiUsageModelDetail", () => {
  const hub = (over: Partial<AiUsageItem>) =>
    item({ name: "acme/x", purl: "pkg:huggingface/acme/x", ...over });

  it("is null for other kinds and empty for a model that was not looked up", () => {
    expect(aiUsageModelDetail(item({ kind: "ai-service" }))).toBeNull();
    expect(aiUsageModelDetail(hub({}))?.hasDetail).toBe(false);
  });

  it("carries the resolved hub data and the command for the full model SBOM", () => {
    const d = aiUsageModelDetail(
      hub({
        resolved: "huggingface",
        license: "apache-2.0",
        gated: "manual",
        weightFormats: ["safetensors", "bin"],
        pickleFiles: 2,
        lineage: "meta-llama/Llama-3.1-8B:llama3.1 > acme/x:apache-2.0",
        verdict: "caution",
        hubUrl: "https://huggingface.co/acme/x",
      }),
    )!;
    expect(d.license).toBe("apache-2.0");
    expect(d.gated).toBe("manual");
    expect(d.pickleFiles).toBe(2);
    expect(d.verdict).toBe("caution");
    expect(d.hubUrl).toBe("https://huggingface.co/acme/x");
    expect(d.scanCommand).toBe("./scripts/scan-sbom.sh --model acme/x");
  });

  it("shows the link to a model SBOM instead of the command", () => {
    const d = aiUsageModelDetail(hub({ resolved: "huggingface", modelSbom: "x_bom.json" }))!;
    expect(d.modelSbom).toBe("x_bom.json");
    expect(d.scanCommand).toBeUndefined();
  });

  it("explains a failed lookup and drops hub data and unsafe links", () => {
    expect(aiUsageModelDetail(hub({ resolved: "unreadable", resolvedStatus: 404 }))!.resolution).toEqual({
      key: "aiUsage.resolution.unreadable",
      status: 404,
    });
    expect(aiUsageModelDetail(hub({ resolved: "unreadable" }))!.resolution?.key).toBe(
      "aiUsage.resolution.unreadableNoStatus",
    );
    expect(aiUsageModelDetail(hub({ resolved: "unreachable" }))!.resolution?.key).toBe(
      "aiUsage.resolution.unreachable",
    );
    const d = aiUsageModelDetail(
      hub({ resolved: "not-attempted", license: "mit", hubUrl: "https://evil.test/x" }),
    )!;
    expect(d.resolution?.key).toBe("aiUsage.resolution.notAttempted");
    expect(d.license).toBeUndefined();
    expect(d.hubUrl).toBeUndefined();
    expect(d.scanCommand).toBeUndefined();
  });

  it("survives aiUsageView and ignores a bad verdict", () => {
    const v = aiUsageView(sbom([hub({ resolved: "huggingface", verdict: "bogus" as never, license: "mit" })]))!;
    const d = aiUsageModelDetail(v.groups[0].items[0])!;
    expect(d.license).toBe("mit");
    expect(d.verdict).toBeUndefined();
  });
});
