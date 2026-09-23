// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * License grouping and restriction review for the Licenses section. The review
 * classes (behavioral-use / non-commercial) come from the component's
 * bomlens:licenseReview property (set by normalize-sbom.sh via the shared
 * license-flags.jq), so the badge and the NOTICE's review section never
 * disagree. Pure and unit tested.
 */
import type { ComponentItem } from "./api";

export type LicenseReview = NonNullable<ComponentItem["licenseReview"]>;

export interface LicenseGroup {
  /** License id/name, or "" for the unlicensed bucket. */
  name: string;
  count: number;
}

export interface ReviewGroup {
  flag: LicenseReview;
  components: ComponentItem[];
}

/** License distribution: license → component count, busiest first, then name. */
export function licenseGroups(components: ComponentItem[]): {
  groups: LicenseGroup[];
  unlicensed: number;
} {
  const counts = new Map<string, number>();
  let unlicensed = 0;
  for (const c of components) {
    if (c.licenses.length === 0) {
      unlicensed += 1;
      continue;
    }
    for (const l of c.licenses) counts.set(l, (counts.get(l) ?? 0) + 1);
  }
  const groups = [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  return { groups, unlicensed };
}

/**
 * License risk tier by copyleft strength — the obligation a license imposes, an
 * industry-standard axis. The headline rule: an unrecognised license is never
 * assumed permissive (that would be the most dangerous false-negative); it falls
 * to `uncategorized` (a human must look), not into the safe bucket.
 *
 * `review-needed` is a component-level concern (the bomlens:licenseReview flag),
 * not a property of a license string, so it isn't produced by `licenseRiskTier`.
 */
export type LicenseRiskTier =
  | "network-copyleft"
  | "strong-copyleft"
  | "weak-copyleft"
  | "permissive"
  | "review-needed"
  | "uncategorized";

/** Display/aggregation order: most concerning first. */
export const LICENSE_TIER_ORDER: LicenseRiskTier[] = [
  "network-copyleft",
  "strong-copyleft",
  "weak-copyleft",
  "review-needed",
  "uncategorized",
  "permissive",
];

// Worst-of ranking across a component's licenses. Known copyleft outranks an
// unknown license (we're certain it's reciprocal); an unknown license outranks
// known-permissive (unknown is riskier than confirmed-safe).
const TIER_RANK: Record<LicenseRiskTier, number> = {
  "network-copyleft": 5,
  "strong-copyleft": 4,
  "weak-copyleft": 3,
  uncategorized: 2,
  permissive: 1,
  "review-needed": 0,
};

// Known permissive SPDX ids (uppercased). An allowlist, not a heuristic — only
// licenses we positively recognise as permissive land in the safe bucket.
const PERMISSIVE = new Set([
  "MIT",
  "MIT-0",
  "ISC",
  "0BSD",
  "BSD-2-CLAUSE",
  "BSD-3-CLAUSE",
  "BSD-3-CLAUSE-LBNL",
  "APACHE-2.0",
  "APACHE-1.1",
  "ZLIB",
  "UNLICENSE",
  "BSL-1.0",
  "PSF-2.0",
  "PYTHON-2.0",
  "CC0-1.0",
  "WTFPL",
  "NCSA",
  "X11",
]);

/**
 * Classify a single license id by copyleft strength. Order matters: AGPL and
 * LGPL are matched before the bare GPL test so they don't fall to strong.
 *
 * Creative Commons (datasets and AI models carry these, not software licenses):
 * the axis here is copyleft strength, not content-licensing terms in general, so
 * only the one CC clause with a copyleft-like effect matters — Share-Alike, which
 * obligates a derivative to carry the same license, the same way LGPL/MPL do for
 * modified files. CC-BY-SA is matched before the bare CC-BY test for the same
 * reason AGPL/LGPL precede GPL: the more specific pattern first. Plain CC-BY (and
 * CC-BY-NC, CC-BY-ND) impose attribution or a field-of-use limit but never
 * propagate the license, so they land on permissive for THIS axis — a
 * non-commercial restriction is a real limitation, but flagging it is
 * license_flag's job (bomlens:licenseReview), not this one's; CC-BY-NC is
 * already caught there. CC-BY-ND is not, and neither axis currently says so.
 */
export function licenseRiskTier(license: string): LicenseRiskTier {
  const id = license.trim();
  if (!id) return "uncategorized";
  if (PERMISSIVE.has(id.toUpperCase())) return "permissive";
  if (/\bAGPL/i.test(id)) return "network-copyleft";
  if (/\bLGPL/i.test(id)) return "weak-copyleft";
  if (/\b(MPL|EPL|CDDL|CPL|OSL|EUPL|CeCILL|Sleepycat)\b/i.test(id))
    return "weak-copyleft";
  if (/\bCC-BY-(NC-)?SA\b/i.test(id)) return "weak-copyleft";
  // A GPL carrying an exception clause, before the bare GPL test. The clause exists
  // precisely to permit linking the bare license would forbid (the classpath exception
  // on jakarta/javax APIs and OpenJDK is the common one), so strong-copyleft would warn
  // about an obligation the component does not impose. The GPL prefix keeps it narrow:
  // "Apache-2.0 WITH LLVM-exception" must not be pulled into copyleft by WITH alone.
  if (/\bGPL.*(\bWITH\b|-with-.*-exception)/i.test(id)) return "weak-copyleft";
  if (/\bGPL/i.test(id)) return "strong-copyleft";
  if (/\bCC-BY\b/i.test(id)) return "permissive";
  return "uncategorized";
}

// ---------------------------------------------------------------------------
// Generic-classifier redundancy, MIRRORED in license-flags.jq
// (drop_redundant_generic_synonyms). A component can carry the same license
// twice: a precise SPDX id (from a lockfile or wheel metadata) and a PyPI
// trove-classifier string ("License :: OSI Approved :: BSD License") for the
// same grant. The classifier alone is genuinely ambiguous (which BSD?) and
// stays uncategorized on its own — that headline rule is unchanged. But
// worst-of was treating the SAME license stated twice as if the second
// statement were an unrelated, unidentified second license, which pulled real
// python packages (babel, python-dateutil's own BSD entry, every Jupyter
// package pinning "BSD License" alongside "BSD-3-Clause") down to
// Uncategorized despite an exact, known-permissive id sitting right next to it
// in the same array. Only drop the generic string when a specific id from its
// OWN family is also present on the SAME component — a genuinely different
// second license (nvidia-nvtx's Apache-2.0 + Other/Proprietary License,
// python-dateutil's + Dual License) still pulls the class down, since neither
// is this classifier's family.
const GENERIC_LICENSE_SYNONYM_FAMILY: Record<string, string> = {
  "BSD LICENSE": "BSD",
  "APACHE SOFTWARE LICENSE": "APACHE",
  "APACHE LICENSE 2.0": "APACHE",
  "APACHE LICENSE, VERSION 2.0": "APACHE",
  "MIT LICENSE": "MIT",
  "PYTHON SOFTWARE FOUNDATION LICENSE": "PYTHON",
};

const LICENSE_FAMILY_IDS: Record<string, string[]> = {
  BSD: ["BSD-2-CLAUSE", "BSD-3-CLAUSE"],
  APACHE: ["APACHE-1.1", "APACHE-2.0"],
  MIT: ["MIT", "MIT-0"],
  PYTHON: ["PSF-2.0", "PYTHON-2.0"],
};

/** Drop a generic classifier string when the same list also carries a precise
 *  id from its family; every other string (including a genuinely unidentified
 *  one) passes through untouched. */
function dropRedundantGenericSynonyms(licenses: string[]): string[] {
  const upper = licenses.map((l) => l.toUpperCase());
  return licenses.filter((l) => {
    const family = GENERIC_LICENSE_SYNONYM_FAMILY[l.toUpperCase()];
    if (!family) return true;
    return !upper.some((u) => LICENSE_FAMILY_IDS[family].includes(u));
  });
}

/** The most concerning tier across a component's (non-empty) license list. */
function worstTier(licenses: string[]): LicenseRiskTier {
  let tier: LicenseRiskTier = "permissive";
  let rank = -1;
  for (const l of dropRedundantGenericSynonyms(licenses)) {
    const t = licenseRiskTier(l);
    if (TIER_RANK[t] > rank) {
      rank = TIER_RANK[t];
      tier = t;
    }
  }
  return tier;
}

/**
 * Whether a component's licence has to be resolved by a person: nothing declared
 * at all, or a name that is not an identifier we can place (`BSD License`,
 * `Dual License`, a compound expression whose branch someone still has to pick).
 *
 * This is the set the "needs a licence decision" filter narrows to. Measured on
 * real trees: 3 of 39 components in a small example, 57 of 113 in a research
 * project — which is why finding them by eye is not the answer. Redundant
 * generic synonyms are dropped first (see dropRedundantGenericSynonyms) so this
 * agrees with worstTier: a component the risk tier calls permissive never also
 * shows up here as needing a decision.
 */
export function licenseNeedsDecision(licenses: string[]): boolean {
  const kept = dropRedundantGenericSynonyms(licenses);
  if (kept.length === 0) return true;
  return kept.some((l) => licenseRiskTier(l) === "uncategorized");
}

/** True for copyleft/reciprocal license ids worth a closer look. */
export function isCopyleft(license: string): boolean {
  const t = licenseRiskTier(license);
  return (
    t === "network-copyleft" || t === "strong-copyleft" || t === "weak-copyleft"
  );
}

export type LicenseRiskSummary = Record<LicenseRiskTier, number> & {
  TOTAL: number;
};

/**
 * A single component's license tier. A bomlens:licenseReview flag goes to
 * `review-needed` (the explicit legal flag is the actionable headline); a
 * component with no detected license is `uncategorized` — unknown, not safe;
 * otherwise it takes the worst tier across its licenses.
 */
export function componentRiskTier(c: ComponentItem): LicenseRiskTier {
  if (c.licenseReview) return "review-needed";
  if (c.licenses.length === 0) return "uncategorized";
  return worstTier(c.licenses);
}

/**
 * Per-tier component counts for the license classification axis. Each component
 * is counted once by its {@link componentRiskTier}.
 */
export function licenseRiskSummary(
  components: ComponentItem[],
): LicenseRiskSummary {
  const counts: Record<LicenseRiskTier, number> = {
    "network-copyleft": 0,
    "strong-copyleft": 0,
    "weak-copyleft": 0,
    permissive: 0,
    "review-needed": 0,
    uncategorized: 0,
  };
  for (const c of components) counts[componentRiskTier(c)] += 1;
  return { ...counts, TOTAL: components.length };
}

// Most-restrictive first.
const REVIEW_ORDER: LicenseReview[] = ["behavioral-use", "non-commercial"];

/** Components grouped by their restriction class — empty when none need review. */
export function reviewGroups(components: ComponentItem[]): ReviewGroup[] {
  const byFlag = new Map<LicenseReview, ComponentItem[]>();
  for (const c of components) {
    if (!c.licenseReview) continue;
    const list = byFlag.get(c.licenseReview) ?? [];
    list.push(c);
    byFlag.set(c.licenseReview, list);
  }
  return REVIEW_ORDER.filter((f) => byFlag.has(f)).map((flag) => ({
    flag,
    components: byFlag.get(flag)!,
  }));
}

/** Total components needing license review. */
export function reviewCount(components: ComponentItem[]): number {
  return components.filter((c) => c.licenseReview).length;
}

// ---------------------------------------------------------------------------
// SPDX expression parsing + outbound-license conflict verdicts.
//
// MIRROR of parse_license_expr / license_conflict in
// docker/lib/license-flags.jq; tests/test-postprocess.sh diffs the operator
// patterns of the two files, so neither side can change alone.
//
// Why a parser: a component's license arrives either as several entries in
// `licenses[]` or as ONE string holding an SPDX expression ("MIT OR
// Apache-2.0"). OR and AND mean opposite things for a verdict — OR lets the
// consumer pick one, AND applies every term — so licenseRiskTier's worst-of
// rule, right for a strength label, is wrong here.
//
// Flat expressions only: a parenthesised expression yields no terms and the
// caller reports "unknown" rather than guessing. AND binds tighter than OR, as
// in the SPDX spec.
// ---------------------------------------------------------------------------

/** A slash is the other OR spelling in the wild ("MIT/X11") — only when there
 *  is exactly one and no URL scheme, so a license name holding a link survives. */
function slashIsOr(s: string): boolean {
  return (s.match(/\//g) ?? []).length === 1 && !s.includes("://");
}

/** OR alternatives, each a list of AND terms. `[]` when nothing is parseable. */
export function parseLicenseExpression(s: string): string[][] {
  const e = (s ?? "").trim();
  if (!e || /[()]/.test(e)) return [];
  const flat = slashIsOr(e) ? e.replace(/\s*\/\s*/, " OR ") : e;
  return flat
    .split(/\s+OR\s+/i)
    .map((group) =>
      group
        .split(/\s+AND\s+/i)
        .map((t) => t.trim())
        .filter(Boolean),
    )
    .filter((group) => group.length > 0);
}

/** True when a term carries an exception clause, which exists precisely to
 *  permit a combination the base license would otherwise forbid. */
export function hasLicenseException(term: string): boolean {
  return /\bWITH\b|-with-.*-exception/i.test(term ?? "");
}

export type ConflictVerdict =
  "compatible" | "conditional" | "incompatible" | "unknown";

/** Worst-first ordering; AND takes the max, OR takes the min. */
export const CONFLICT_RANK: Record<ConflictVerdict, number> = {
  compatible: 0,
  conditional: 1,
  unknown: 2,
  incompatible: 3,
};

/** Display order for grouping: the ones a person must act on come first. */
export const CONFLICT_ORDER: ConflictVerdict[] = [
  "incompatible",
  "conditional",
  "unknown",
  "compatible",
];

/** The rules file (docker/lib/license-compat.json) as the UI consumes it. */
export interface CompatRules {
  matrix: Record<
    string,
    Record<string, { verdict: ConflictVerdict; why: string }>
  >;
  pairs?: {
    outbound: string;
    dependency: string;
    verdict: ConflictVerdict;
    why: string;
  }[];
}

export interface ConflictResult {
  verdict: ConflictVerdict;
  why: string;
}

/** Verdict for ONE dependency term. Explicit pairs win over the class matrix;
 *  an exception clause caps the result at "conditional". */
export function termVerdict(
  term: string,
  outbound: string,
  rules: CompatRules,
): ConflictResult {
  const pair = (rules.pairs ?? []).find(
    (p) =>
      p.outbound.toUpperCase() === outbound.toUpperCase() &&
      p.dependency.toUpperCase() === term.toUpperCase(),
  );
  let result: ConflictResult = pair
    ? { verdict: pair.verdict, why: pair.why }
    : (rules.matrix[licenseRiskTier(outbound)]?.[licenseRiskTier(term)] ?? {
        verdict: "unknown" as const,
        why: "No rule for this combination.",
      });
  if (hasLicenseException(term) && result.verdict === "incompatible") {
    result = {
      verdict: "conditional",
      why: `The dependency carries an exception clause, which exists to permit exactly this combination. Confirm the exception covers your use. (${result.why})`,
    };
  }
  return result;
}

/** Verdict for one license string, which may be an SPDX expression. `null`
 *  when nothing parseable came out of it. */
export function expressionVerdict(
  s: string,
  outbound: string,
  rules: CompatRules,
): ConflictResult | null {
  const groups = parseLicenseExpression(s);
  if (groups.length === 0) return null;
  const perGroup = groups.map((terms) =>
    terms
      .map((t) => termVerdict(t, outbound, rules))
      .reduce((worst, v) =>
        CONFLICT_RANK[v.verdict] > CONFLICT_RANK[worst.verdict] ? v : worst,
      ),
  );
  return perGroup.reduce((best, v) =>
    CONFLICT_RANK[v.verdict] < CONFLICT_RANK[best.verdict] ? v : best,
  );
}

/** Verdict for a whole component. Several license entries are alternatives
 *  (the consumer may pick one), so the best verdict across them wins. */
export function componentConflict(
  licenses: string[],
  outbound: string,
  rules: CompatRules,
): ConflictResult {
  if (licenses.length === 0)
    return { verdict: "unknown", why: "The component declares no license." };
  const verdicts = licenses
    .map((l) => expressionVerdict(l, outbound, rules))
    .filter((v): v is ConflictResult => v !== null);
  if (verdicts.length === 0)
    return {
      verdict: "unknown",
      why: "The declared license could not be parsed as an SPDX expression.",
    };
  return verdicts.reduce((best, v) =>
    CONFLICT_RANK[v.verdict] < CONFLICT_RANK[best.verdict] ? v : best,
  );
}

export interface ConflictGroup {
  verdict: ConflictVerdict;
  components: ComponentItem[];
}

/** Components grouped by conflict verdict, worst first, skipping "compatible" —
 *  the section lists what needs a look, not what is already fine. Empty when the
 *  scan carried no outbound license, since then nothing was assessed. */
export function conflictGroups(components: ComponentItem[]): ConflictGroup[] {
  const byVerdict = new Map<ConflictVerdict, ComponentItem[]>();
  for (const c of components) {
    const v = c.licenseConflict;
    if (!v || v === "compatible") continue;
    const list = byVerdict.get(v) ?? [];
    list.push(c);
    byVerdict.set(v, list);
  }
  return CONFLICT_ORDER.filter((v) => byVerdict.has(v)).map((verdict) => ({
    verdict,
    components: byVerdict.get(verdict)!,
  }));
}
