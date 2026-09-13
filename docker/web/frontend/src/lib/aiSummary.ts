// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Derives the AI summary card's content from a finished scan. Pure and unit
 * tested — the component (AiSummaryCard) only translates and lays this out.
 *
 * The card is the entry point for an AI scan's findings, not a replacement for
 * the Models & Conformance sections it links into, so this stays a compact
 * rollup: what the pipeline already computed (profileCard, the risk
 * assessment, the SBOM's own component list), never re-derived here.
 */
import type { AiProfile, ComponentItem, DoneEvent } from "./api";
import { profileCard } from "./conformance";
import { GRADE_SEVERITY_ORDER, type AssessmentGrade } from "./models";

/** What the card's header names. A single model is named; several models (a
 *  multi-model package, or an ANALYZE supplier SBOM) collapse to a count; a
 *  model-less dataset scan names the dataset count instead; "none" is the
 *  floor when the scan carries neither (an AI scan by root component type
 *  alone, with nothing to point at). */
export type AiSummaryHeader =
  | { kind: "single"; name: string; version: string }
  | { kind: "multi"; count: number }
  | { kind: "datasets"; count: number }
  | { kind: "none" };

export interface AiSummaryRisk {
  /** Grade counts, from the risk assessment or (older runs) `assessCounts`. */
  counts: Partial<Record<AssessmentGrade, number>>;
  /** Set only when exactly one model was graded — the header names that same
   *  model, so the tile can show its own condition count and one-line summary
   *  instead of a distribution nobody asked to see for a single model. */
  single?: { conditionCount: number; summary: string };
  /** Components whose license needs human review (aiProfile.licenseReview),
   *  folded into this tile's sub-line rather than a tile of its own. */
  licenseReviewCount: number;
}

export interface AiSummaryG7 {
  present: number;
  auto: number;
  gap: number;
  review: number;
}

export interface AiSummaryCrosswalk {
  frameworkCount: number;
  present: number;
  total: number;
}

export interface AiSummary {
  header: AiSummaryHeader;
  /** Worst grade across the counts (caution > review > conditional > ok), or
   *  null when there is no grade data at all. Drives the header badge. */
  grade: AssessmentGrade | null;
  modelCount: number;
  datasetCount: number;
  /** First tile. Null when neither a risk assessment nor `assessCounts`
   *  exists — nothing to grade, so the tile does not render. */
  risk: AiSummaryRisk | null;
  /** The pipeline's own disclaimer for the risk verdict, in the reader's
   *  language. Empty when there is no risk assessment to disclaim. */
  disclaimer: string;
  /** Second tile. Null when the scan carries no AI compliance profile at all. */
  g7: AiSummaryG7 | null;
  /** Third tile. Null when there is no profile, or its crosswalk maps no
   *  framework. */
  crosswalk: AiSummaryCrosswalk | null;
}

/** Worst-first grade among non-zero counts, or null when every count is zero
 *  (or the map is empty). */
export function worstGrade(
  counts: Partial<Record<AssessmentGrade, number>>,
): AssessmentGrade | null {
  for (const g of GRADE_SEVERITY_ORDER) {
    if ((counts[g] ?? 0) > 0) return g;
  }
  return null;
}

function findModel(components: ComponentItem[]): ComponentItem | undefined {
  return components.find((c) => c.type === "machine-learning-model");
}

/** Pick the language-appropriate copy of a field the pipeline carries in both
 *  languages (`summary`/`summary_ko`, `disclaimer`/`disclaimer_ko`). Falls
 *  back to the base field when the `_ko` one is empty, same as the existing
 *  conformance-panel language pattern. */
function pick(lang: string, base: string, ko: string): string {
  return lang.startsWith("ko") && ko ? ko : base;
}

export function computeAiSummary(result: DoneEvent, lang: string): AiSummary {
  const components = result.sbom?.componentList ?? [];
  const modelCount = components.filter((c) => c.type === "machine-learning-model").length;
  const datasetCount = components.filter((c) => c.type === "data").length;

  const aiProfile: AiProfile | null = result.aiProfile ?? null;
  const assess = aiProfile?.riskAssessment;
  const card = aiProfile ? profileCard(aiProfile) : null;

  const counts: Partial<Record<AssessmentGrade, number>> | null =
    assess?.counts ?? result.sbom?.assessCounts ?? null;
  const grade = counts ? worstGrade(counts) : null;

  let header: AiSummaryHeader;
  if (modelCount === 1) {
    const named =
      (assess && assess.models.length === 1 && assess.models[0]) || findModel(components);
    header = named
      ? { kind: "single", name: named.name, version: named.version }
      : { kind: "none" };
  } else if (modelCount > 1) {
    header = { kind: "multi", count: modelCount };
  } else if (datasetCount > 0) {
    header = { kind: "datasets", count: datasetCount };
  } else {
    header = { kind: "none" };
  }

  let risk: AiSummaryRisk | null = null;
  if (counts) {
    let single: AiSummaryRisk["single"];
    if (assess && assess.models.length === 1) {
      const m = assess.models[0];
      single = {
        conditionCount: m.conditions.length,
        summary: pick(lang, m.summary, m.summary_ko),
      };
    }
    risk = {
      counts,
      single,
      licenseReviewCount: card?.licenseTotal ?? 0,
    };
  }

  const disclaimer = assess ? pick(lang, assess.disclaimer, assess.disclaimer_ko) : "";

  const g7: AiSummaryG7 | null = card
    ? { present: card.g7Present, auto: card.g7Auto, gap: card.g7Gap, review: card.g7Review }
    : null;

  const crosswalk: AiSummaryCrosswalk | null =
    card && card.frameworkCount > 0
      ? {
          frameworkCount: card.frameworkCount,
          present: card.crosswalk.present,
          total: card.crosswalk.total,
        }
      : null;

  return { header, grade, modelCount, datasetCount, risk, disclaimer, g7, crosswalk };
}
