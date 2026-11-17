// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Completeness, CompletenessGrade } from "./api";

/**
 * Pure helpers for the result-completeness display. The grade and the reason
 * sentences are written by the engine (`_completeness.json`) and passed through
 * by the server; nothing here judges a result again. A result without the file
 * (null/undefined) keeps the notices it always showed.
 */

/** The result is known to be partial or unreliable (a missing file is not). */
export function isIncomplete(c: Completeness | null | undefined): c is Completeness {
  return Boolean(c) && c!.grade !== "complete";
}

export interface ReasonLine {
  code: string;
  grade: CompletenessGrade;
  message: string;
  fix: string;
}

/**
 * The reasons in the UI language. Only Korean is told apart; every other
 * language reads the English sentences. A sentence missing in the chosen
 * language falls back to the other one rather than showing nothing.
 */
export function reasonLines(c: Completeness, language: string): ReasonLine[] {
  const lang = language.toLowerCase().startsWith("ko") ? "ko" : "en";
  const other = lang === "ko" ? "en" : "ko";
  return c.reasons.map((r) => ({
    code: r.code,
    grade: r.grade,
    message: r.message[lang] || r.message[other],
    fix: r.fix[lang] || r.fix[other],
  }));
}

/** The grade name in the UI language, from the engine's own label. */
export function gradeLabel(c: Completeness, language: string): string {
  const lang = language.toLowerCase().startsWith("ko") ? "ko" : "en";
  return c.gradeLabel[lang] || c.gradeLabel[lang === "ko" ? "en" : "ko"] || c.grade;
}

/** Primer Label variant for a grade: partial needs attention, unreliable is a danger. */
export function gradeVariant(grade: CompletenessGrade): "success" | "attention" | "danger" {
  return grade === "unreliable" ? "danger" : grade === "partial" ? "attention" : "success";
}
