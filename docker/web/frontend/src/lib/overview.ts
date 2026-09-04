// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Decision-first Overview helpers: what, if anything, needs the reviewer's
 * attention right now. Pure and unit tested so the leading "Needs attention"
 * block reflects the data, not guesswork.
 */
import type { ComponentItem, DoneEvent } from "./api";
import { riskRank } from "./components";
import { baseTally, kindTally, splitChecks } from "./conformance";
import type { SectionId } from "./nav";

export interface AttentionItem {
  id: "malicious" | "conformance" | "vulns" | "review" | "modelRisk" | "conformanceGap";
  /** How many findings of this kind. */
  count: number;
  /** Badge tone / severity of the item. */
  tone: "critical" | "high" | "info";
  /** Section to open when the item is actioned. */
  target: SectionId;
}

/**
 * Actionable findings, most urgent first: known-malicious packages, then a
 * failed SBOM conformance, then
 * critical/high vulnerabilities, then components flagged for review (vendored /
 * copied-in open source). Returns an empty list when nothing needs attention.
 */
export function needsAttention(result: DoneEvent): AttentionItem[] {
  const items: AttentionItem[] = [];

  // Known-malicious packages lead everything else. A vulnerability is a flaw to
  // schedule a fix for; a package published to attack whoever installs it is
  // already running in the build, so it outranks even a failed conformance.
  const malicious = result.sbom?.maliciousCount ?? 0;
  if (malicious > 0) {
    items.push({ id: "malicious", count: malicious, tone: "critical", target: "components" });
  }

  // Supplier-SBOM review: a failed format conformance leads the list — an
  // incomplete or non-conformant SBOM makes the vuln and license findings below
  // unreliable, so it should be fixed first.
  const conf = result.conformance;
  if (conf && conf.result === "fail") {
    const failed = baseTally(splitChecks(conf.checks ?? []).base).failed;
    if (failed > 0) {
      items.push({ id: "conformance", count: failed, tone: "high", target: "conformance" });
    }
  }

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

  // A model the pipeline graded caution or review. An AI scan reached none of
  // the conditions above. It has no vulnerability report, its conformance
  // passes, and its components are neither malicious nor vendored, so the
  // Overview said nothing at all while the model carried the one verdict the
  // scan exists to produce.
  const grades = result.sbom?.assessCounts;
  if (grades) {
    const caution = grades.caution ?? 0;
    const review = grades.review ?? 0;
    if (caution + review > 0) {
      items.push({
        id: "modelRisk",
        count: caution + review,
        tone: caution > 0 ? "high" : "info",
        target: "models",
      });
    }
  }

  const vendored = (result.sbom?.componentList ?? []).filter((c) => c.vendored).length;
  if (vendored > 0) {
    items.push({ id: "review", count: vendored, tone: "info", target: "components" });
  }

  // Conformance elements the scan itself could fill. Distinct from the failed
  // mandatory check above: this SBOM passes and still has documentation gaps a
  // person can close, which is the whole point of the advisory baselines. Last,
  // and informational, because nothing here blocks the SBOM.
  if (conf && conf.result !== "fail") {
    const actionable = kindTally(conf.checks ?? []).actionable;
    if (actionable > 0) {
      items.push({
        id: "conformanceGap",
        count: actionable,
        tone: "info",
        target: "conformance",
      });
    }
  }

  return items;
}

/**
 * The components carrying the most risk, worst first — what the reader would
 * otherwise have to go and sort the Components table to find.
 *
 * Only components that actually carry a vulnerability are listed: a "top risk"
 * table padded with clean components would suggest a ranking where there is
 * none. An empty list means the scan found nothing to rank, and the caller
 * leaves the block out rather than showing an empty one.
 *
 * Ordering is worst severity, then how many vulnerabilities at that severity,
 * then name — the same weighting the Components table's risk sort uses, so the
 * two never disagree about what is worst.
 */
export function topRiskComponents(
  result: DoneEvent,
  limit = 6,
): ComponentItem[] {
  return [...riskyComponents(result)]
    .sort((a, b) => {
      const d = riskRank(b) - riskRank(a);
      if (d !== 0) return d;
      const n = (b.vulnCount ?? 0) - (a.vulnCount ?? 0);
      if (n !== 0) return n;
      return `${a.group} ${a.name}`.trim().localeCompare(`${b.group} ${b.name}`.trim());
    })
    .slice(0, Math.max(0, limit));
}

/** The components a scan found something against — what topRiskComponents ranks. */
function riskyComponents(result: DoneEvent): ComponentItem[] {
  return (result.sbom?.componentList ?? []).filter(
    (c) => (c.vulnCount ?? 0) > 0 || c.maxSeverity,
  );
}

/**
 * How many components carry a vulnerability at all.
 *
 * The top-risk block shows a handful, and on an OS image the worst handful can
 * be six variants of the same kernel package — true, but it reads as if that
 * were the whole story. Naming the total beside the list says how much sits
 * behind it.
 */
export function riskyComponentCount(result: DoneEvent): number {
  return riskyComponents(result).length;
}
