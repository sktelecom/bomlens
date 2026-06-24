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
