// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { LocalizedParam, LocalizedText } from "./localized";

/**
 * One assessment reason (`bomlens:assessment:reasons`, split on ";") as an
 * i18n key, so a Korean reader of an English-stamped SBOM does not get English
 * sentences under Korean headings.
 *
 * assess-ai-risk.sh writes the reasons in the scan's language. Only the
 * English wording is recognised here: a Korean-stamped SBOM already reads in
 * Korean, and a sentence this does not recognise (another tool, a newer
 * scanner) returns null so the caller shows it verbatim. Values copied into the
 * sentence (license ids, registry family names, model and dataset names, scan
 * findings) stay as they are, as the scanner itself keeps them.
 */

const GRADE_KEY: Record<string, string> = {
  ok: "models.gradeOk",
  conditional: "models.gradeConditional",
  caution: "models.gradeCaution",
  review: "models.gradeReview",
};

const USAGE_KEY: Record<string, string> = {
  internal: "models.usageInternal",
  product: "models.usageProduct",
  redistribute: "models.usageRedistribute",
  "outputs-only": "models.usageOutputsOnly",
};

const V = "(ok|conditional|caution|review)";
const k = (name: string) => `models.reason.${name}`;
const verdict = (v: string): LocalizedText => ({ key: GRADE_KEY[v] });

/** The part after "source NAME: " in a dataset-source reason. */
function sourceWhy(why: string): LocalizedParam {
  switch (why) {
    case "could not be read":
      return { key: k("sourceUnread") };
    case "names its own sources only in words":
      return { key: k("sourceWordsOnly") };
    case "its sources past the depth limit were not read":
      return { key: k("sourceDepth") };
    case "no license declared":
      return { key: k("sourceNoLicense") };
    default:
      return why; // the dataset's declared license(s), verbatim
  }
}

/** "a, via its sources, b" back into names, each marked when its worst grade
 *  came from its sources. */
function namedDatasets(s: string): LocalizedParam[] {
  const out: LocalizedParam[] = [];
  for (const part of s.split(", ")) {
    if (part === "via its sources" && out.length > 0) {
      const name = out.pop() as string;
      out.push({ key: k("viaSources"), params: { name } });
    } else {
      out.push(part);
    }
  }
  return out;
}

type Rule = [RegExp, (m: RegExpExecArray) => LocalizedText];

const RULES: Rule[] = [
  [new RegExp(`^no license declared \\(${V}\\)$`), (m) => ({ key: k("noLicense"), params: { verdict: verdict(m[1]) } })],
  [
    new RegExp(`^license (.+?): not in the license-terms registry \\(${V}\\)$`),
    (m) => ({ key: k("notInRegistry"), params: { license: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^license (.+?): (.+) \\(${V} for (internal|product|redistribute|outputs-only) use\\)$`),
    (m) => ({
      key: k("licenseTermsFor"),
      params: { license: m[1], name: m[2], verdict: verdict(m[3]), usage: { key: USAGE_KEY[m[4]] } },
    }),
  ],
  [
    new RegExp(`^license (.+?): (.+) \\(${V}\\)$`),
    (m) => ({ key: k("licenseTerms"), params: { license: m[1], name: m[2], verdict: verdict(m[3]) } }),
  ],
  [
    new RegExp(`^custom license text: restrictive wording found \u2014 (.+) \\(${V}\\)$`),
    (m) => ({ key: k("customFound"), params: { quote: m[1], verdict: verdict(m[2]) } }),
  ],
  // Written as one sentence with a ";" in it, so the reasons splitter hands
  // it over in two halves.
  [/^custom license text: no known restrictive wording matched$/, () => ({ key: k("customNoMatch") })],
  [new RegExp(`^human review still required \\(${V}\\)$`), (m) => ({ key: k("humanReview"), params: { verdict: verdict(m[1]) } })],
  [
    new RegExp(`^lineage: conditions of base model (.+) may be inherited but are not declared here \\(${V}\\)$`),
    (m) => ({ key: k("lineage"), params: { model: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^file security: HuggingFace scan flags (.+) content \\(${V}\\)$`),
    (m) => ({ key: k("hfFlags"), params: { status: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^file security: HuggingFace scan reports all files safe \\(${V}\\)$`),
    (m) => ({ key: k("hfSafe"), params: { verdict: verdict(m[1]) } }),
  ],
  [
    new RegExp(`^file security: local file scan found a code-execution risk(?: \u2014 (.+))? \\(${V}\\)$`),
    (m) =>
      m[1]
        ? { key: k("localUnsafeFindings"), params: { findings: m[1], verdict: verdict(m[2]) } }
        : { key: k("localUnsafe"), params: { verdict: verdict(m[2]) } },
  ],
  [
    new RegExp(`^file security: local file scan found something that needs review(?: \u2014 (.+))? \\(${V}\\)$`),
    (m) =>
      m[1]
        ? { key: k("localSuspiciousFindings"), params: { findings: m[1], verdict: verdict(m[2]) } }
        : { key: k("localSuspicious"), params: { verdict: verdict(m[2]) } },
  ],
  [
    new RegExp(
      `^file security: local file scan found no code-execution risk \\(static analysis only, not a malware scan\\) \\(${V}\\)$`,
    ),
    (m) => ({ key: k("localClean"), params: { verdict: verdict(m[1]) } }),
  ],
  [
    new RegExp(`^file security: this weight format does not execute code on load \\(${V}\\)$`),
    (m) => ({ key: k("localNotApplicable"), params: { verdict: verdict(m[1]) } }),
  ],
  [
    new RegExp(`^file security: local file scan could not read the file \\(${V}\\)$`),
    (m) => ({ key: k("localUnreadable"), params: { verdict: verdict(m[1]) } }),
  ],
  // After the local-scan sentences, which also start "file security: ".
  [
    new RegExp(`^file security: scan (\\S+?)(, pickle-format weights present)? \\(${V}\\)$`),
    (m) => ({
      key: k(m[2] ? "hfStatusPickle" : "hfStatus"),
      params: { status: m[1], verdict: verdict(m[3]) },
    }),
  ],
  [
    new RegExp(`^dataset signal (\\S+) \\(${V}\\)$`),
    (m) => ({ key: k("datasetSignal"), params: { signal: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^dataset visibility (.+): access-restricted \\(${V}\\)$`),
    (m) => ({ key: k("datasetVisibility"), params: { visibility: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^source "(.+)": not a hub reference, needs checking \\(${V}\\)$`),
    (m) => ({ key: k("sourceText"), params: { source: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    new RegExp(`^sources past the depth limit were not read \\(${V}\\)$`),
    (m) => ({ key: k("sourcesDepth"), params: { verdict: verdict(m[1]) } }),
  ],
  [
    new RegExp(`^source (.+?) \\(through (.+?)\\): (.+) \\(${V}\\)$`),
    (m) => ({
      key: k("sourceThrough"),
      params: { source: m[1], through: m[2], why: sourceWhy(m[3]), verdict: verdict(m[4]) },
    }),
  ],
  [
    new RegExp(`^source (.+?): (.+) \\(${V}\\)$`),
    (m) => ({ key: k("source"), params: { source: m[1], why: sourceWhy(m[2]), verdict: verdict(m[3]) } }),
  ],
  [
    new RegExp(`^datasets: (\\d+) referenced, worst ${V} \\((.+)\\)$`),
    (m) => ({
      key: k("datasetsNamed"),
      params: { count: m[1], verdict: verdict(m[2]), names: namedDatasets(m[3]) },
    }),
  ],
  [
    new RegExp(`^datasets: (\\d+) referenced, worst ${V}$`),
    (m) => ({ key: k("datasets"), params: { count: m[1], verdict: verdict(m[2]) } }),
  ],
  [
    /^training data undisclosed: the terms of the data this model learned from were not declared$/,
    () => ({ key: k("trainingUndisclosed") }),
  ],
];

/** The i18n key for one reason, or null when it is not an English sentence
 *  assess-ai-risk.sh writes. */
export function modelReasonKey(reason: string): LocalizedText | null {
  const s = reason.trim();
  for (const [re, build] of RULES) {
    const m = re.exec(s);
    if (m) return build(m);
  }
  return null;
}
