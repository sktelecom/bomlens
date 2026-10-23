// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { type LocalizedText, renderLocalized } from "./localized";
import { modelReasonKey } from "./modelReasons";

function messages(lng: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(process.cwd(), "src", "locales", lng, "common.json"), "utf8"));
}

/** A `t` over one catalogue with i18next-style {{name}} interpolation, failing
 *  loudly on a missing key so a typo in a key cannot pass. */
function tFor(lng: string) {
  const m = messages(lng);
  return (key: string, opts?: Record<string, unknown>) => {
    const s = key.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], m);
    if (typeof s !== "string") throw new Error(`missing ${lng} ${key}`);
    return s.replace(/\{\{(\w+)\}\}/g, (_, n: string) => String(opts?.[n] ?? `{{${n}}}`));
  };
}

const ko = tFor("ko");
const en = tFor("en");
const render = (r: string, t = ko) => renderLocalized(t, modelReasonKey(r) as LocalizedText);

// Every sentence shape assess-ai-risk.sh writes in English.
const SAMPLES = [
  "no license declared (review)",
  "license foo-1.0: not in the license-terms registry (review)",
  "license Apache-2.0: Permissive open-source license (ok)",
  "license cc-by-nc-4.0: Creative Commons NonCommercial (conditional for internal use)",
  "custom license text: restrictive wording found \u2014 non-commercial (caution)",
  "custom license text: no known restrictive wording matched",
  "human review still required (review)",
  "lineage: conditions of base model meta/llama may be inherited but are not declared here (caution)",
  "file security: HuggingFace scan flags unsafe content (caution)",
  "file security: HuggingFace scan reports all files safe (ok)",
  "file security: scan queued, pickle-format weights present (review)",
  "file security: scan unavailable (review)",
  "file security: local file scan found a code-execution risk \u2014 os.system (caution)",
  "file security: local file scan found a code-execution risk (caution)",
  "file security: local file scan found something that needs review \u2014 custom class (review)",
  "file security: local file scan found no code-execution risk (static analysis only, not a malware scan) (ok)",
  "file security: this weight format does not execute code on load (ok)",
  "file security: local file scan could not read the file (review)",
  "dataset signal pii (caution)",
  "dataset visibility gated: access-restricted (review)",
  'source "web crawl": not a hub reference, needs checking (review)',
  "sources past the depth limit were not read (review)",
  "source wikipedia: CC-BY-SA-3.0 (conditional)",
  "source c4 (through dolma): could not be read (review)",
  "datasets: 2 referenced, worst review (bookcorpus)",
  "datasets: 3 referenced, worst ok",
  "training data undisclosed: the terms of the data this model learned from were not declared",
];

describe("modelReasonKey", () => {
  it("recognises every English sentence shape and renders it in both languages", () => {
    for (const s of SAMPLES) {
      expect(modelReasonKey(s), s).not.toBeNull();
      expect(() => render(s, ko), s).not.toThrow();
      expect(() => render(s, en), s).not.toThrow();
    }
  });

  it("keeps the copied values and translates the verdict word", () => {
    expect(render("license Apache-2.0: Permissive open-source license (ok)")).toBe(
      "라이선스 Apache-2.0: Permissive open-source license (제약 신호 없음)",
    );
    expect(render("file security: scan queued, pickle-format weights present (review)")).toBe(
      "파일 보안: 스캔 상태 queued, pickle 형식 가중치 포함 (검토 필요)",
    );
    expect(render("license cc-by-nc-4.0: Creative Commons NonCommercial (conditional for internal use)")).toBe(
      "라이선스 cc-by-nc-4.0: Creative Commons NonCommercial (내부 검토·연구 시 조건부 사용)",
    );
  });

  it("picks the right sentence where two share a prefix", () => {
    expect(modelReasonKey("license foo: not in the license-terms registry (review)")?.key).toBe(
      "models.reason.notInRegistry",
    );
    expect(modelReasonKey("file security: local file scan could not read the file (review)")?.key).toBe(
      "models.reason.localUnreadable",
    );
    expect(modelReasonKey("source c4 (through dolma): could not be read (review)")?.key).toBe(
      "models.reason.sourceThrough",
    );
  });

  it("marks a dataset named because of its sources", () => {
    expect(render("datasets: 2 referenced, worst caution (a, via its sources, b)")).toBe(
      "데이터셋: 2개 참조, 최악 등급 주의 (a, 원천 때문, b)",
    );
  });

  it("leaves a Korean-stamped or unknown reason to the caller", () => {
    expect(modelReasonKey("라이선스 Apache-2.0: Permissive open-source license (제약 신호 없음)")).toBeNull();
    expect(modelReasonKey("something else entirely")).toBeNull();
  });
});
