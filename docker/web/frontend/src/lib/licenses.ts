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
 */
export function licenseRiskTier(license: string): LicenseRiskTier {
  const id = license.trim();
  if (!id) return "uncategorized";
  if (PERMISSIVE.has(id.toUpperCase())) return "permissive";
  if (/\bAGPL/i.test(id)) return "network-copyleft";
  if (/\bLGPL/i.test(id)) return "weak-copyleft";
  if (/\b(MPL|EPL|CDDL|CPL|OSL|EUPL|CeCILL|Sleepycat)\b/i.test(id))
    return "weak-copyleft";
  if (/\bGPL/i.test(id)) return "strong-copyleft";
  return "uncategorized";
}

/** The most concerning tier across a component's (non-empty) license list. */
function worstTier(licenses: string[]): LicenseRiskTier {
  let tier: LicenseRiskTier = "permissive";
  let rank = -1;
  for (const l of licenses) {
    const t = licenseRiskTier(l);
    if (TIER_RANK[t] > rank) {
      rank = TIER_RANK[t];
      tier = t;
    }
  }
  return tier;
}

/** True for copyleft/reciprocal license ids worth a closer look. */
export function isCopyleft(license: string): boolean {
  const t = licenseRiskTier(license);
  return (
    t === "network-copyleft" ||
    t === "strong-copyleft" ||
    t === "weak-copyleft"
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
