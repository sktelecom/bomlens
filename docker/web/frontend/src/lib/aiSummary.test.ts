// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { AiProfile, AiRiskAssessment, ComponentItem, DoneEvent } from "./api";
import { computeAiSummary, worstGrade } from "./aiSummary";

function comp(o: Partial<ComponentItem> & { type: string }): ComponentItem {
  return {
    name: "model",
    version: "1.0",
    group: "",
    purl: "",
    licenses: [],
    ...o,
  };
}

function makeResult(over: Partial<DoneEvent> = {}): DoneEvent {
  return {
    ok: true,
    mode: "AI_MODEL",
    results: [],
    sbom: { components: 1, componentList: [] },
    security: null,
    conformance: null,
    ...over,
  };
}

const PROFILE: AiProfile = {
  conformanceResult: "warn",
  g7: { total: 41, auto: 41, present: 32, gap: 6, review: 3, clusters: [] },
  licenseReview: { total: 1, behavioral: 1, nonCommercial: 0 },
  regulatoryCrosswalk: {
    disclaimer: "not a verdict",
    frameworks: [
      { id: "eu-ai-act", title: "EU AI Act", total: 24, present: 18, gap: 4, review: 2 },
      { id: "kr-ai", title: "Korean AI Framework Act", total: 14, present: 6, gap: 6, review: 2 },
    ],
  },
};

const ASSESS_SINGLE: AiRiskAssessment = {
  usageContext: "internal",
  disclaimer: "Guidance, not legal advice.",
  disclaimer_ko: "법적 자문이 아닌 안내입니다.",
  counts: { ok: 0, conditional: 1, caution: 0, review: 0 },
  models: [
    {
      name: "openai/whisper-large-v3",
      version: "1",
      license: "Apache-2.0",
      overall: "conditional",
      usageContext: "internal",
      axes: { license: "conditional" },
      reasons: ["Non-commercial clause present"],
      summary: "A non-commercial clause allows internal testing only.",
      summary_ko: "비상업 조항이 있어 사내 시험 용도로만 조건부 허용됩니다.",
      conditions: [
        { id: "internal-only", label: "Internal use only", label_ko: "사내 용도로만 사용" },
        { id: "no-redistribute", label: "No redistribution", label_ko: "재배포 금지" },
      ],
      sourceUrls: ["https://huggingface.co/openai/whisper-large-v3"],
    },
  ],
};

describe("worstGrade", () => {
  it("picks caution over review over conditional over ok", () => {
    expect(worstGrade({ ok: 3, conditional: 2, review: 1, caution: 1 })).toBe("caution");
    expect(worstGrade({ ok: 3, conditional: 2, review: 1 })).toBe("review");
    expect(worstGrade({ ok: 3, conditional: 2 })).toBe("conditional");
    expect(worstGrade({ ok: 3 })).toBe("ok");
  });

  it("returns null when every count is zero or the map is empty", () => {
    expect(worstGrade({})).toBeNull();
    expect(worstGrade({ ok: 0, conditional: 0 })).toBeNull();
  });
});

describe("computeAiSummary", () => {
  it("names the single model, grades it, and fills every tile from the profile", () => {
    const result = makeResult({
      sbom: {
        components: 1,
        componentList: [comp({ type: "machine-learning-model", name: "openai/whisper-large-v3", version: "1" })],
      },
      aiProfile: { ...PROFILE, riskAssessment: ASSESS_SINGLE },
    });

    const s = computeAiSummary(result, "en");
    expect(s.header).toEqual({ kind: "single", name: "openai/whisper-large-v3", version: "1" });
    expect(s.grade).toBe("conditional");
    expect(s.modelCount).toBe(1);
    expect(s.datasetCount).toBe(0);
    expect(s.risk).toEqual({
      counts: ASSESS_SINGLE.counts,
      single: {
        conditionCount: 2,
        summary: "A non-commercial clause allows internal testing only.",
      },
      licenseReviewCount: 1,
    });
    expect(s.disclaimer).toBe("Guidance, not legal advice.");
    expect(s.g7).toEqual({ present: 32, auto: 41, gap: 6, review: 3 });
    expect(s.crosswalk).toEqual({ frameworkCount: 2, present: 24, total: 38 });
  });

  it("reads the Korean summary and disclaimer when the session language is Korean", () => {
    const result = makeResult({
      sbom: {
        components: 1,
        componentList: [comp({ type: "machine-learning-model" })],
      },
      aiProfile: { ...PROFILE, riskAssessment: ASSESS_SINGLE },
    });

    const s = computeAiSummary(result, "ko-KR");
    expect(s.risk?.single?.summary).toBe(
      "비상업 조항이 있어 사내 시험 용도로만 조건부 허용됩니다.",
    );
    expect(s.disclaimer).toBe("법적 자문이 아닌 안내입니다.");
  });

  it("falls back to the base copy when the Korean field is empty", () => {
    const assess: AiRiskAssessment = {
      ...ASSESS_SINGLE,
      disclaimer_ko: "",
      models: [{ ...ASSESS_SINGLE.models[0], summary_ko: "" }],
    };
    const result = makeResult({
      sbom: { components: 1, componentList: [comp({ type: "machine-learning-model" })] },
      aiProfile: { ...PROFILE, riskAssessment: assess },
    });

    const s = computeAiSummary(result, "ko-KR");
    expect(s.risk?.single?.summary).toBe(ASSESS_SINGLE.models[0].summary);
    expect(s.disclaimer).toBe(ASSESS_SINGLE.disclaimer);
  });

  it("collapses several models to a count and drops the single-model summary", () => {
    const result = makeResult({
      sbom: {
        components: 2,
        componentList: [
          comp({ type: "machine-learning-model", name: "model-a" }),
          comp({ type: "machine-learning-model", name: "model-b" }),
        ],
      },
      aiProfile: {
        ...PROFILE,
        riskAssessment: {
          ...ASSESS_SINGLE,
          counts: { ok: 1, conditional: 1, caution: 0, review: 0 },
          models: [
            ASSESS_SINGLE.models[0],
            { ...ASSESS_SINGLE.models[0], name: "model-b", overall: "ok" },
          ],
        },
      },
    });

    const s = computeAiSummary(result, "en");
    expect(s.header).toEqual({ kind: "multi", count: 2 });
    expect(s.grade).toBe("conditional");
    expect(s.risk?.single).toBeUndefined();
  });

  it("names a model-less dataset scan by its dataset count", () => {
    const result = makeResult({
      sbom: {
        components: 1,
        componentList: [comp({ type: "data", name: "common-voice" })],
      },
    });

    const s = computeAiSummary(result, "en");
    expect(s.header).toEqual({ kind: "datasets", count: 1 });
    expect(s.modelCount).toBe(0);
    expect(s.datasetCount).toBe(1);
  });

  it("falls back to sbom.assessCounts when there is no riskAssessment (older runs)", () => {
    const result = makeResult({
      sbom: {
        components: 1,
        componentList: [comp({ type: "machine-learning-model" })],
        assessCounts: { ok: 0, caution: 1 },
      },
      aiProfile: PROFILE, // no riskAssessment key
    });

    const s = computeAiSummary(result, "en");
    expect(s.grade).toBe("caution");
    expect(s.risk).toEqual({
      counts: { ok: 0, caution: 1 },
      single: undefined,
      licenseReviewCount: 1,
    });
    expect(s.disclaimer).toBe(""); // no assess object to disclaim from
  });

  it("drops the first tile when neither a risk assessment nor assessCounts exists", () => {
    const result = makeResult({
      sbom: { components: 1, componentList: [comp({ type: "machine-learning-model" })] },
      aiProfile: PROFILE,
    });

    const s = computeAiSummary(result, "en");
    expect(s.risk).toBeNull();
    expect(s.grade).toBeNull();
    // The profile's own tiles are unaffected — they don't depend on risk data.
    expect(s.g7).not.toBeNull();
    expect(s.crosswalk).not.toBeNull();
  });

  it("drops the g7 and crosswalk tiles when there is no AI profile at all", () => {
    const result = makeResult({
      sbom: {
        components: 1,
        componentList: [comp({ type: "machine-learning-model" })],
        assessCounts: { ok: 1 },
      },
      aiProfile: null,
    });

    const s = computeAiSummary(result, "en");
    expect(s.g7).toBeNull();
    expect(s.crosswalk).toBeNull();
    // The risk tile still comes from assessCounts, independent of the profile.
    expect(s.risk).not.toBeNull();
  });

  it("passes g7.auto === 0 through as zero rather than hiding the tile (the card decides the wording)", () => {
    const result = makeResult({
      sbom: { components: 1, componentList: [] },
      aiProfile: {
        ...PROFILE,
        g7: { total: 41, auto: 0, present: 0, gap: 0, review: 41, clusters: [] },
      },
    });

    const s = computeAiSummary(result, "en");
    expect(s.g7).toEqual({ present: 0, auto: 0, gap: 0, review: 41 });
  });

  it("drops the crosswalk tile when the profile maps no framework", () => {
    const result = makeResult({
      sbom: { components: 1, componentList: [] },
      aiProfile: {
        ...PROFILE,
        regulatoryCrosswalk: { disclaimer: "not a verdict", frameworks: [] },
      },
    });

    const s = computeAiSummary(result, "en");
    expect(s.crosswalk).toBeNull();
  });

  it("names nothing when the scan is an AI scan with no model or dataset component", () => {
    const result = makeResult({ sbom: { components: 0, componentList: [] } });
    const s = computeAiSummary(result, "en");
    expect(s.header).toEqual({ kind: "none" });
    expect(s.g7).toBeNull();
    expect(s.crosswalk).toBeNull();
    expect(s.risk).toBeNull();
  });
});
