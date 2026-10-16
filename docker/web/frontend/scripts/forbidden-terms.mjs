// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Forbidden UI terms, seeded from src/locales/GLOSSARY.md. Each entry is a
 * variant that was verified to be in use for a concept that has one canonical
 * name, so it must not come back. `prefer` is shown in the failure message.
 * Add an entry here and in the glossary's "seen variants" table together.
 */
export const FORBIDDEN_TERMS = [
  { lng: "ko", pattern: /SBOM 규제 검사/, prefer: "적합성 검사" },
  { lng: "ko", pattern: /적합성 검증/, prefer: "적합성 검사" },
  { lng: "ko", pattern: /적합성 보고서/, prefer: "적합성 검사 보고서" },
  { lng: "ko", pattern: /결과물/, prefer: "산출물 (스캔이 만든 파일)" },
  { lng: "ko", pattern: /재스캔/, prefer: "다시 스캔" },
  { lng: "ko", pattern: /위험분석/, prefer: "오픈소스 위험 보고서 (문서 이름) 또는 위험 분석 (띄어 씀)" },
  { lng: "ko", pattern: /포맷 검증/, prefer: "적합성 검사" },
  { lng: "ko", pattern: /아티팩트/, prefer: "산출물 또는 빌드 산출물" },
  { lng: "ko", pattern: /인벤토리/, prefer: "구성 정보 (레일 묶음) 또는 목록" },
  { lng: "ko", pattern: /컴플라이언스/, prefer: "규정 준수 또는 준수" },
  { lng: "en", pattern: /SBOM Validation/i, prefer: "Conformance check" },
  { lng: "en", pattern: /conformance validation/i, prefer: "conformance check" },
  { lng: "en", pattern: /conformance report/i, prefer: "Conformance check report" },
  { lng: "en", pattern: /Supplier SBOM risk report/i, prefer: "Open-source risk report (subtitle: Supplier SBOM under review)" },
  { lng: "en", pattern: /format validation/i, prefer: "Conformance check" },
];

/** Flatten a nested message object to [dottedKey, string] pairs. */
export function flattenMessages(obj, prefix = "") {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) out.push(...flattenMessages(v, key));
    else if (typeof v === "string") out.push([key, v]);
  }
  return out;
}

/**
 * Violations in one locale: [{ key, found, prefer }]. `messages` is the parsed
 * common.json of `lng`; only terms for that language are checked.
 */
export function findForbidden(messages, lng, terms = FORBIDDEN_TERMS) {
  const hits = [];
  for (const [key, text] of flattenMessages(messages)) {
    for (const t of terms) {
      if (t.lng !== lng) continue;
      const m = text.match(t.pattern);
      if (m) hits.push({ key, found: m[0], prefer: t.prefer });
    }
  }
  return hits;
}
