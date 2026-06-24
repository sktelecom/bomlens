/**
 * Decision-first Overview helpers: what, if anything, needs the reviewer's
 * attention right now. Pure and unit tested so the leading "Needs attention"
 * block reflects the data, not guesswork.
 */
import type { DoneEvent } from "./api";
import type { SectionId } from "./nav";

export interface AttentionItem {
  id: "vulns" | "review";
  /** How many findings of this kind. */
  count: number;
  /** Badge tone / severity of the item. */
  tone: "critical" | "high" | "info";
  /** Section to open when the item is actioned. */
  target: SectionId;
}

/**
 * Actionable findings, most severe first: critical/high vulnerabilities, then
 * components flagged for review (vendored / copied-in open source). Returns an
 * empty list when nothing needs attention.
 */
export function needsAttention(result: DoneEvent): AttentionItem[] {
  const items: AttentionItem[] = [];

  const sec = result.security;
  if (sec) {
    const crit = sec.CRITICAL ?? 0;
    const high = sec.HIGH ?? 0;
    if (crit + high > 0) {
      items.push({
        id: "vulns",
        count: crit + high,
        tone: crit > 0 ? "critical" : "high",
        target: "vulnerabilities",
      });
    }
  }

  const vendored = (result.sbom?.componentList ?? []).filter((c) => c.vendored).length;
  if (vendored > 0) {
    items.push({ id: "review", count: vendored, tone: "info", target: "components" });
  }

  return items;
}
