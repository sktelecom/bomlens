// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import {
  Biohazard,
  Boxes,
  CalendarX,
  ChevronRight,
  Container,
  Cpu,
  Eye,
  FileCheck2,
  FileJson,
  FileText,
  FolderOpen,
  GitBranch,
  type LucideIcon,
  History,
  Package,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  TriangleAlert,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
import {
  loadScan,
  type ComponentItem,
  type DoneEvent,
  type RecentScan,
  type ResultFile,
  type Severity,
  type YoctoVex,
} from "@/lib/api";
import type { LicenseRiskTier } from "@/lib/licenses";
import type { SectionId } from "@/lib/nav";
import {
  type AttentionItem,
  overviewAttention,
  riskyComponentCount,
  topRiskComponents,
} from "@/lib/overview";
import { type ProvenanceKind, provenanceOf } from "@/lib/provenance";
import { formatRelativeTime, scanComparison } from "@/lib/recent";
import { conformanceCount, inputSbomFileName, isAiScan, sbomFileName } from "@/lib/results";
import { scanHash } from "@/lib/route";
import { diffComponents, diffVulnerabilities, type ComponentDiff, type VulnDiff } from "@/lib/scanDiff";
import { cn, formatBytes } from "@/lib/utils";
import { useFormatNumber } from "@/lib/format";

import { FirstChecks } from "./FirstChecks";
import { LicenseRiskBar } from "./LicenseRiskBar";
import { PipelineStepsFailedNote } from "./PipelineStepsFailedNote";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";

/** Tone → token-driven icon colour (graphical, so 3:1 is enough). Applied to
 *  an aria-hidden Icon at the usage site, not read directly as body text.
 *  token-lint-ignore */
const TONE_ICON: Record<AttentionItem["tone"], string> = {
  critical: "text-risk-critical", // token-lint-ignore
  high: "text-risk-high", // token-lint-ignore
  info: "text-risk-info", // token-lint-ignore
};
const ATTN_ICON: Record<AttentionItem["id"], LucideIcon> = {
  malicious: Biohazard,
  conformance: FileCheck2,
  vulns: ShieldAlert,
  review: Eye,
  modelRisk: Cpu,
  conformanceGap: FileCheck2,
};

/** Icon per provenance kind, so the input reads at a glance. */
const PROVENANCE_ICON: Record<ProvenanceKind, LucideIcon> = {
  folder: FolderOpen,
  yocto: FolderOpen,
  git: GitBranch,
  image: Container,
  file: FileText,
  sbom: FileJson,
  model: Cpu,
  declaration: FileText,
};

/** Which body copy explains why cdxgen fell back to a direct-deps-only scan. */
function sbomDegradedBodyKey(reason: string): string {
  switch (reason) {
    case "disk-space":
      return "result.sbomDegradedDisk";
    case "oom":
      return "result.sbomDegradedOom";
    case "network":
      return "result.sbomDegradedNetwork";
    case "cdxgen-crash":
      return "result.sbomDegradedCrash";
    case "cdxgen-unavailable":
      return "result.sbomDegradedNotRun";
    default:
      return "result.sbomDegradedBody";
  }
}

function ProvenanceIcon({
  kind,
  ...props
}: { kind: ProvenanceKind } & React.ComponentProps<LucideIcon>) {
  const Icon = PROVENANCE_ICON[kind];
  return <Icon {...props} />;
}

/** Arrow for the severity trend. Direction carries the meaning; the colour and
 *  the wording beside it say the same thing, so it is decorative here. */
function TrendIcon({ up, ...props }: { up: boolean } & React.ComponentProps<LucideIcon>) {
  const Icon = up ? TrendingUp : TrendingDown;
  return <Icon {...props} aria-hidden />;
}

/** A component's display label, matching the group/name convention used in
 *  the components table and the top-risk list. */
function compLabel(c: ComponentItem): string {
  return c.group ? `${c.group}/${c.name}` : c.name;
}

const DIFF_LIST_CAP = 8;

/** The first `DIFF_LIST_CAP` rows of a change list, plus how many were cut. */
function capList<T>(items: T[]): { shown: T[]; more: number } {
  return { shown: items.slice(0, DIFF_LIST_CAP), more: Math.max(0, items.length - DIFF_LIST_CAP) };
}

/** A comparison-card diff entry's name, linking into the section it names
 *  filtered to that name (the same free-text `q` filter TopRisk's rows use).
 *  Foreground colour plus an underline, never the brand red (reserved for the
 *  primary button, the logo and the focus ring). Underlined at rest, not just on hover:
 *  the "moved from X to Y" line sets this link next to plain muted-foreground
 *  text, and that colour pair is only 1.21:1 apart, far under the 3:1 axe
 *  requires to tell a link from prose by colour alone. */
const DIFF_ITEM_LINK_CLASS =
  "rounded text-foreground underline underline-offset-2 hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

/** Severity tone for the risk badge, matching the components table. */
const SEV_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

/**
 * The handful of components carrying the most risk, as a short table that links
 * into the row it names.
 *
 * The overview used to stop at counts and distributions: it could say 973
 * critical-or-high findings without naming one component, so every reader's
 * next move was the same — open Components, sort by risk. This does that sort
 * for them. It is not a replacement for the table (six rows, no filtering),
 * and it renders nothing at all when no component carries a vulnerability.
 */
function TopRisk({
  result,
  scanId,
}: {
  result: DoneEvent;
  scanId: string | null;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const rows = topRiskComponents(result);
  const affected = riskyComponentCount(result);
  if (rows.length === 0) return null;
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-baseline justify-between gap-4">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-body-sm font-semibold text-foreground">
              {t("overview.topRisk")}
            </span>
            {/* On an OS image the worst six can all be variants of one kernel
                package. True, but it reads as the whole story unless the size
                of what sits behind it is stated. */}
            <span className="text-label text-muted-foreground">
              {t("overview.topRiskOf", { shown: rows.length, total: affected })}
            </span>
          </div>
          {scanId && (
            <a
              href={scanHash(scanId, "components")}
              className="rounded text-label text-muted-foreground underline underline-offset-2 hover:text-foreground hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
            >
              {t("overview.topRiskAll")}
            </a>
          )}
        </div>
        <ul className="flex flex-col">
          {rows.map((c) => (
            <li key={c.purl || `${c.group}-${c.name}-${c.version}`}>
              <a
                href={scanId ? scanHash(scanId, "vulnerabilities", { q: c.name }) : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-md px-2 py-2 text-body-sm",
                  "transition-colors duration-fast ease-out-soft hover:bg-muted",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                )}
              >
                <span className="min-w-0 flex-1 truncate font-mono text-foreground">
                  {c.group ? `${c.group} / ` : ""}
                  {c.name}
                </span>
                {/* Fixed-width version and badge cells, so the versions line up
                    in one column whatever the badge text's length. */}
                <span
                  className="w-20 shrink-0 truncate text-right font-mono text-label text-muted-foreground sm:w-36"
                  title={c.version}
                >
                  {c.version}
                </span>
                <span className="flex shrink-0 sm:w-32">
                  {c.maxSeverity && (
                    <Badge tone={SEV_TONE[c.maxSeverity]} mark>
                      {t(`severity.${c.maxSeverity}`)}
                      {c.vulnCount ? ` · ${fmt(c.vulnCount)}` : ""}
                    </Badge>
                  )}
                </span>
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
              </a>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

/**
 * Decision-first Overview: what needs attention first, then the at-a-glance
 * numbers as jump cards into the detail sections, then the two risk axes
 * (severity, license classification) — instead of repeating full tables here.
 * The jump cards sit above the axes so they stay visible without scrolling.
 *
 * Only risk axes belong here. A component-type distribution used to sit below
 * them and was dropped: type is an inventory fact the Components table already
 * filters on, and as a chart it was mostly one bar (a single-ecosystem SBOM is
 * all "library") or one bar drowning the rest (a container image is nearly all
 * "file").
 */
export function Overview({
  result,
  scanId,
  recent = [],
  generatedAt,
  onPick,
}: {
  result: DoneEvent;
  /** The scan's id; section links resolve to `#/scan/<id>/<section>`. */
  scanId: string | null;
  /** Local Recent-scans list, for the "vs previous scan" comparison line. */
  recent?: RecentScan[];
  /** Unix seconds when this scan was made; the "check first" block names it as
   *  the point the counts are taken at. */
  generatedAt?: number;
  /**
   * Route into a section with a filter pre-applied — clicking a severity band
   * opens Vulnerabilities filtered to it; clicking a license class opens
   * Licenses filtered to it. Omit for a non-interactive Overview.
   */
  onPick?: (
    section: SectionId,
    seed: { severity?: Severity; tier?: LicenseRiskTier },
  ) => void;
}) {
  const { t, i18n } = useTranslation();
  // Rows the first-checks card already carries (a failed conformance, the
  // Critical-and-High count when all of it is fixable) are not listed twice.
  const attention = overviewAttention(result);
  const hasDeps = Boolean(sbomFileName(result));
  const ai = isAiScan(result);
  // Mirrors nav.ts's gate on the Conformance section itself: a jump card that
  // opened a section the sidebar doesn't show would be a dead end. A
  // self-generated AI SBOM's G7 rollup has its own entry points instead
  // (AiSummaryCard above, and the "models" jump card below) — every other
  // scan, supplied or self-generated software, shows the section.
  const hasConformance =
    Boolean(result.conformance?.checks?.length) &&
    (Boolean(inputSbomFileName(result)) || !ai);
  const comparison = scanId ? scanComparison(recent, scanId) : null;
  const provenance = provenanceOf(result.scanConfig);

  // The comparison card above renders instantly from the Recent-scans summary
  // (component count + worst severity, no fetch). What actually changed, which
  // components and which CVEs, needs the previous scan's full component and
  // vulnerability lists, which the summary doesn't carry, so it loads in a
  // second pass and fills the card in once it lands.
  const [changes, setChanges] = useState<{
    components: ComponentDiff;
    vulns: VulnDiff;
    /** Either scan's component list was capped server-side, so the diff may
     *  be missing rows outside what was actually shown. */
    partial: boolean;
  } | null>(null);
  const [changesLoading, setChangesLoading] = useState(false);
  useEffect(() => {
    setChanges(null);
    if (!comparison) return;
    let cancelled = false;
    setChangesLoading(true);
    loadScan(comparison.prev.id).then((prev) => {
      if (cancelled) return;
      setChangesLoading(false);
      if (!prev) return;
      setChanges({
        components: diffComponents(
          prev.sbom?.componentList ?? [],
          result.sbom?.componentList ?? [],
        ),
        vulns: diffVulnerabilities(
          prev.security?.vulnerabilities ?? [],
          result.security?.vulnerabilities ?? [],
        ),
        partial: Boolean(prev.sbom?.truncated || result.sbom?.truncated),
      });
    });
    return () => {
      cancelled = true;
    };
    // result and scanId change together (a new scan replaces both); comparison
    // is derived from scanId + recent, so scanId is the one stable dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, comparison?.prev.id]);

  return (
    <div className="space-y-6">
      {/* A scan that ended in `done.ok=false` still lands here (the badge next
          to the heading is the only other place this shows) with everything
          else below rendering the empty/absent shape of a scan that produced
          nothing. errorMessage is the scanner's own [ERROR] block when the
          server had no other classification for the failure (see server.py's
          _ScanErrorTracker); same title/fallback copy as the running-scan
          failure card, so the two read consistently. */}
      {!result.ok && (
        <Card role="alert" className="border-destructive/40 bg-destructive/5">
          <CardContent className="space-y-1 p-4">
            <div className="flex items-center gap-2 text-body-sm font-semibold text-foreground">
              <TriangleAlert className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
              {t("run.failedTitle")}
            </div>
            <p className="whitespace-pre-wrap break-words text-body-sm text-muted-foreground">
              {result.errorMessage || t("run.failedBody")}
            </p>
          </CardContent>
        </Card>
      )}
      {provenance && (
        // What was scanned. Sits above the counts because it frames them: the
        // same "71 components" means something different for a folder on disk
        // than for an image someone pulled.
        <div
          className="flex flex-wrap items-center gap-x-2 gap-y-1 text-label text-muted-foreground"
          data-testid="provenance"
        >
          <ProvenanceIcon
            kind={provenance.kind}
            className="h-3.5 w-3.5 shrink-0"
            aria-hidden
          />
          <span>{t(provenance.labelKey)}</span>
          <code
            className="min-w-0 break-all rounded bg-muted px-1.5 py-0.5 font-mono text-foreground"
            title={provenance.value}
          >
            {provenance.value}
          </code>
        </div>
      )}
      {result.sbom?.detection === "static" && (
        // A scan that read a lock file says so: it skipped the build, which is why
        // it finished quickly and what its dependency list rests on.
        <div className="text-label text-muted-foreground" data-testid="detection">
          {result.sbom.detectionSource
            ? t("overview.detectionStaticFrom", { file: result.sbom.detectionSource })
            : t("overview.detectionStatic")}
        </div>
      )}
      {/* How this run moved against the last one of the same project. It used to
          be a line of grey text under the title, which is where a reader's eye
          goes last; a scan that got worse deserves better than that. Absent
          entirely when there is no earlier run to compare against. */}
      {comparison && (
        <Card>
          <CardContent className="p-4">
            <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
              <div>
                <div className="text-label text-muted-foreground">
                  {t("overview.vsPrevious", {
                    label:
                      comparison.prev.version ||
                      formatRelativeTime(
                        comparison.prev.generatedAt,
                        Date.now(),
                        i18n.language,
                      ),
                  })}
                </div>
                <div className="mt-1 text-body-sm font-medium text-foreground">
                  {comparison.componentsDelta === 0
                    ? t("overview.compSame")
                    : t("overview.compDelta", {
                        delta:
                          comparison.componentsDelta > 0
                            ? `+${comparison.componentsDelta}`
                            : `${comparison.componentsDelta}`,
                      })}
                </div>
              </div>
              <div>
                <div className="text-label text-muted-foreground">
                  {t("overview.sevTrendLabel")}
                </div>
                <div
                  className={cn(
                    "mt-1 flex items-center gap-1.5 text-body-sm font-medium",
                    // The graphical/badge token (used at full saturation for
                    // icons and badge backgrounds) fails WCAG AA text contrast
                    // on this card's background in light mode (3.56:1, needs
                    // 4.5:1); badge.tsx already uses the -fg variant for the
                    // same reason, and it passes here in both themes (7.31:1
                    // light, 10.2:1 dark).
                    comparison.severityDir === "up" && "text-risk-high-fg",
                    // Bare token, but already passing in both themes (5.17:1
                    // light, 6.76:1 dark), left as-is, nothing to fix.
                    comparison.severityDir === "down" && "text-risk-low", // token-lint-ignore: body text on card, contrast checked
                    comparison.severityDir === "same" && "text-foreground",
                  )}
                >
                  {comparison.severityDir !== "same" && (
                    <TrendIcon
                      className="h-4 w-4 shrink-0"
                      up={comparison.severityDir === "up"}
                    />
                  )}
                  {t(
                    comparison.severityDir === "up"
                      ? "overview.sevUp"
                      : comparison.severityDir === "down"
                        ? "overview.sevDown"
                        : "overview.sevSame",
                  )}
                </div>
              </div>
            </div>
            {/* The two figures above can hide real churn: +3/-3 components nets
                to "no change", and a worst-severity direction says nothing
                about which CVEs actually moved. These need the previous
                scan's full lists (a second fetch), so they fill in a moment
                after the row above already rendered; opening either reveals
                what specifically moved, not just how many. */}
            {(changesLoading || changes) && (
              <div className="mt-4 grid gap-x-8 gap-y-4 border-t pt-3 sm:grid-cols-2">
                <Disclosure
                  summary={
                    <div className="min-w-0 flex-1 text-left">
                      <div className="text-label text-muted-foreground">
                        {t("overview.compChangeLabel")}
                      </div>
                      <div
                        className="mt-1 text-body-sm font-medium text-foreground"
                        data-testid="comp-change-summary"
                      >
                        {changesLoading || !changes
                          ? t("overview.diffLoading")
                          : t("overview.compChangeSummary", {
                              added: changes.components.added.length,
                              removed: changes.components.removed.length,
                              changed: changes.components.changed.length,
                            })}
                      </div>
                    </div>
                  }
                  summaryClassName="items-start"
                >
                  {changes && (
                    <div className="mt-2 space-y-3 pl-5 text-label" data-testid="comp-change-details">
                      {(() => {
                        const added = capList(changes.components.added);
                        const removed = capList(changes.components.removed);
                        const upgraded = capList(changes.components.changed);
                        return (
                          <>
                            {added.shown.length > 0 && (
                              <div>
                                <div className="font-medium text-foreground">
                                  {t("overview.compAddedHeading")}
                                </div>
                                <ul className="mt-1 space-y-0.5 font-mono text-muted-foreground">
                                  {added.shown.map((c) =>
                                    scanId ? (
                                      <li key={compLabel(c)}>
                                        <a
                                          href={scanHash(scanId, "components", { q: compLabel(c) })}
                                          className={DIFF_ITEM_LINK_CLASS}
                                        >
                                          {compLabel(c)}@{c.version}
                                        </a>
                                      </li>
                                    ) : (
                                      <li key={compLabel(c)}>
                                        {compLabel(c)}@{c.version}
                                      </li>
                                    ),
                                  )}
                                </ul>
                                {added.more > 0 && (
                                  <p className="mt-1 font-sans text-muted-foreground">
                                    {t("overview.diffMore", { count: added.more })}
                                  </p>
                                )}
                              </div>
                            )}
                            {removed.shown.length > 0 && (
                              <div>
                                <div className="font-medium text-foreground">
                                  {t("overview.compRemovedHeading")}
                                </div>
                                <ul className="mt-1 space-y-0.5 font-mono text-muted-foreground">
                                  {removed.shown.map((c) =>
                                    scanId ? (
                                      <li key={compLabel(c)}>
                                        <a
                                          href={scanHash(scanId, "components", { q: compLabel(c) })}
                                          className={DIFF_ITEM_LINK_CLASS}
                                        >
                                          {compLabel(c)}@{c.version}
                                        </a>
                                      </li>
                                    ) : (
                                      <li key={compLabel(c)}>
                                        {compLabel(c)}@{c.version}
                                      </li>
                                    ),
                                  )}
                                </ul>
                                {removed.more > 0 && (
                                  <p className="mt-1 font-sans text-muted-foreground">
                                    {t("overview.diffMore", { count: removed.more })}
                                  </p>
                                )}
                              </div>
                            )}
                            {upgraded.shown.length > 0 && (
                              <div>
                                <div className="font-medium text-foreground">
                                  {t("overview.compChangedHeading")}
                                </div>
                                <ul className="mt-1 space-y-0.5 text-muted-foreground">
                                  {upgraded.shown.map((c) => {
                                    const name = c.group ? `${c.group}/${c.name}` : c.name;
                                    return (
                                      <li key={name} className="font-mono">
                                        {scanId ? (
                                          <a
                                            href={scanHash(scanId, "components", { q: name })}
                                            className={DIFF_ITEM_LINK_CLASS}
                                          >
                                            {name}
                                          </a>
                                        ) : (
                                          name
                                        )}{" "}
                                        {t("overview.compChangedSuffix", { from: c.from, to: c.to })}
                                      </li>
                                    );
                                  })}
                                </ul>
                                {upgraded.more > 0 && (
                                  <p className="mt-1 font-sans text-muted-foreground">
                                    {t("overview.diffMore", { count: upgraded.more })}
                                  </p>
                                )}
                              </div>
                            )}
                            {scanId && (
                              <a
                                href={scanHash(scanId, "components")}
                                data-testid="comp-diff-all-link"
                                className="inline-block rounded text-foreground underline underline-offset-2 hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                              >
                                {t("overview.topRiskAll")}
                              </a>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  )}
                </Disclosure>
                <Disclosure
                  summary={
                    <div className="min-w-0 flex-1 text-left">
                      <div className="text-label text-muted-foreground">
                        {t("overview.vulnChangeLabel")}
                      </div>
                      <div
                        className="mt-1 text-body-sm font-medium text-foreground"
                        data-testid="vuln-change-summary"
                      >
                        {changesLoading || !changes
                          ? t("overview.diffLoading")
                          : t("overview.vulnChangeSummary", {
                              added: changes.vulns.new.length,
                              resolved: changes.vulns.resolved.length,
                            })}
                      </div>
                    </div>
                  }
                  summaryClassName="items-start"
                >
                  {changes && (
                    <div className="mt-2 space-y-3 pl-5 text-label" data-testid="vuln-change-details">
                      {(() => {
                        const news = capList(changes.vulns.new);
                        const resolved = capList(changes.vulns.resolved);
                        return (
                          <>
                            {news.shown.length > 0 && (
                              <div>
                                <div className="font-medium text-foreground">
                                  {t("overview.vulnNewHeading")}
                                </div>
                                <ul className="mt-1 space-y-0.5 font-mono text-muted-foreground">
                                  {news.shown.map((v) =>
                                    scanId ? (
                                      <li key={v.id}>
                                        <a
                                          href={scanHash(scanId, "vulnerabilities", { q: v.id })}
                                          className={DIFF_ITEM_LINK_CLASS}
                                        >
                                          {v.id} ({v.pkg})
                                        </a>
                                      </li>
                                    ) : (
                                      <li key={v.id}>
                                        {v.id} ({v.pkg})
                                      </li>
                                    ),
                                  )}
                                </ul>
                                {news.more > 0 && (
                                  <p className="mt-1 font-sans text-muted-foreground">
                                    {t("overview.diffMore", { count: news.more })}
                                  </p>
                                )}
                              </div>
                            )}
                            {resolved.shown.length > 0 && (
                              <div>
                                <div className="font-medium text-foreground">
                                  {t("overview.vulnResolvedHeading")}
                                </div>
                                <ul className="mt-1 space-y-0.5 font-mono text-muted-foreground">
                                  {resolved.shown.map((v) =>
                                    scanId ? (
                                      <li key={v.id}>
                                        <a
                                          href={scanHash(scanId, "vulnerabilities", { q: v.id })}
                                          className={DIFF_ITEM_LINK_CLASS}
                                        >
                                          {v.id} ({v.pkg})
                                        </a>
                                      </li>
                                    ) : (
                                      <li key={v.id}>
                                        {v.id} ({v.pkg})
                                      </li>
                                    ),
                                  )}
                                </ul>
                                {resolved.more > 0 && (
                                  <p className="mt-1 font-sans text-muted-foreground">
                                    {t("overview.diffMore", { count: resolved.more })}
                                  </p>
                                )}
                              </div>
                            )}
                            {scanId && (
                              <a
                                href={scanHash(scanId, "vulnerabilities")}
                                data-testid="vuln-diff-all-link"
                                className="inline-block rounded text-foreground underline underline-offset-2 hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                              >
                                {t("overview.allVulnerabilities")}
                              </a>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  )}
                </Disclosure>
              </div>
            )}
          </CardContent>
          {changes?.partial && (
            <p className="border-t px-4 py-2 text-label text-muted-foreground">
              {t("overview.diffPartial")}
            </p>
          )}
        </Card>
      )}
      {/* Zero components is the one result a reader reliably misreads: it looks
          like "nothing to worry about" when it almost always means the scan had
          nothing to read. The CLI says so twice in its log; before this the web
          UI said nothing at all. An AI scan is excluded — a model SBOM legitimately
          carries no components, the model itself being the document. */}
      {!ai && result.sbom && result.sbom.components === 0 && (
        <div
          className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30"
          data-testid="zero-components"
        >
          <div className="text-body-sm font-medium">{t("result.zeroComponentsTitle")}</div>
          <p className="mt-1 text-body-sm">
            {t(
              result.sbom.sbomToolDegraded
                ? "result.zeroComponentsBodyDegraded"
                : "result.zeroComponentsBody",
            )}
          </p>
        </div>
      )}

      {/* A fact recorded in the document outranks this run's own log (unlike
          scanWarnings below, which only exists for this run), see
          PipelineStepsFailedNote. */}
      <PipelineStepsFailedNote
        steps={result.sbom?.pipelineStepsFailed ?? []}
        more={result.sbom?.pipelineStepsFailedMore ?? 0}
        context="scan"
        isSuppliedDocument={Boolean(inputSbomFileName(result))}
      />

      {/* Firmware only: the parts of the image the unpacker could not open. The
          vulnerability counts describe what was opened, and this says how much
          that was. Worded as scope, not failure. A submitted SBOM's properties
          are the supplier's data, not this scan's own statement, so it is not
          shown for one. */}
      {result.sbom?.firmwareScope && !inputSbomFileName(result) && (
        <div
          className="rounded-md border bg-muted/40 px-4 py-3 text-muted-foreground"
          data-testid="firmware-scope"
        >
          <div className="text-body-sm font-medium text-foreground">{t("result.firmwareScopeTitle")}</div>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-label">
            {result.sbom.firmwareScope.unknownBytes > 0 && (
              <li>
                {t("result.firmwareScopeUnknown", {
                  percent: result.sbom.firmwareScope.unknownPercent,
                  bytes: formatBytes(result.sbom.firmwareScope.unknownBytes),
                })}
              </li>
            )}
            {result.sbom.firmwareScope.failedSteps > 0 && (
              <li>
                {t("result.firmwareScopeFailed", { count: result.sbom.firmwareScope.failedSteps })}
                {result.sbom.firmwareScope.failedFormats.length > 0 &&
                  ` ${t("result.firmwareScopeFormats", { formats: result.sbom.firmwareScope.failedFormats.join(", ") })}`}
              </li>
            )}
            {result.sbom.firmwareScope.encryptedRegions > 0 && (
              <li>
                {t("result.firmwareScopeEncrypted", { count: result.sbom.firmwareScope.encryptedRegions })}
              </li>
            )}
            {result.sbom.firmwareScope.missingExtractors.length > 0 && (
              <li>
                {t("result.firmwareScopeMissing", {
                  tools: result.sbom.firmwareScope.missingExtractors.join(", "),
                })}
              </li>
            )}
          </ul>
          {result.sbom.firmwareScope.namesMore > 0 && (
            <p className="mt-1 text-body-sm">
              {t("result.firmwareScopeMore", { count: result.sbom.firmwareScope.namesMore })}
            </p>
          )}
          <p className="mt-1 text-body-sm">{t("result.firmwareScopeBody")}</p>
        </div>
      )}

      {/* What the scan warned about while it ran. The log is streamed and never
          stored, so a result opened later had no way to say it had warned at
          all — and these are the lines that decide how far to trust the counts. */}
      {(result.scanWarnings?.length ?? 0) > 0 && (
        <div
          className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30"
          data-testid="scan-warnings"
        >
          <div className="text-body-sm font-medium">{t("result.scanWarningsTitle")}</div>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-label">
            {result.scanWarnings?.map((w) => (
              <li key={w} className="break-words font-mono">
                {w.replace(/^\[WARN\]\s*/, "")}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Versions the resolver chose, not versions anyone installed. The numbers
          in the components table look specific either way, so without this the
          reader has no way to tell which kind they are looking at — and reads a
          vulnerability count that was measured against a fresh install. */}
      {result.sbom?.versionPinning === "unpinned" && (
        <div
          className="rounded-md border bg-muted/40 px-4 py-3 text-muted-foreground"
          data-testid="version-pinning"
        >
          <div className="text-body-sm font-medium text-foreground">
            {t("result.unpinnedTitle")}
          </div>
          <p className="mt-1 text-body-sm">{t("result.unpinnedBody")}</p>
        </div>
      )}

      {!ai && result.sbom?.suggestIdentifyVendored && (
        <div className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30">
          <div className="text-body-sm font-medium">{t("result.vendoredHintTitle")}</div>
          <p className="mt-1 text-body-sm">{t("result.vendoredHintBody")}</p>
        </div>
      )}

      {/* Gated on components > 0: at 0 components this banner's own claim
          ("direct dependencies only") would contradict the zero-components
          banner above ("nothing was found"). That banner already covers a
          fully failed scan, folding in the degraded cause via
          zeroComponentsBodyDegraded, so this one steps aside rather than
          repeat a claim that isn't true here. */}
      {result.sbom?.sbomToolDegraded && result.sbom.components > 0 && (
        <div className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30">
          <div className="text-body-sm font-medium">{t("result.sbomDegradedTitle")}</div>
          <p className="mt-1 text-body-sm">{t(sbomDegradedBodyKey(result.sbom.sbomToolDegraded))}</p>
        </div>
      )}

      {/* An empty dependency graph is a real pipeline defect: cdxgen ran, but
          a later step dropped the graph before it reached the SBOM (the
          failure mode carry-dependencies.py exists to prevent for firmware
          merges) — the same causal-banner treatment sbomToolDegraded already
          gives a different cause, rather than leaving it to the Conformance
          screen's own "transitive" row alone. hasConformance is false only
          for a self-generated AI SBOM (its G7 rollup lives on Models &
          datasets instead, with no "transitive" check to speak of), so this
          is effectively dormant there and never fires for the software scans
          it was written for now that the Conformance screen shows for them. */}
      {!hasConformance &&
        result.conformance?.checks?.some(
          (c) => c.id === "transitive" && c.status === "fail",
        ) && (
          <div className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30">
            <div className="text-body-sm font-medium">{t("result.sbomGraphEmptyTitle")}</div>
            <p className="mt-1 text-body-sm">{t("result.sbomGraphEmptyBody")}</p>
          </div>
        )}

      {result.scanoss?.status === "unavailable" && (
        <div className="rounded-md border border-warning-border/60 bg-warning-surface px-4 py-3 text-warning dark:border-warning-border/20 dark:bg-warning-surface/30">
          <div className="text-body-sm font-medium">{t("result.scanossUnavailableTitle")}</div>
          <p className="mt-1 text-body-sm">{t("result.scanossUnavailableBody")}</p>
        </div>
      )}

      {result.scanoss?.status === "no-match" && (
        <div className="rounded-md border bg-muted/40 px-4 py-3 text-muted-foreground">
          <div className="text-body-sm font-medium text-foreground">{t("result.scanossNoMatchTitle")}</div>
          <p className="mt-1 text-body-sm">{t("result.scanossNoMatchBody")}</p>
        </div>
      )}

      {/* From 2xl up the first checks and the worst components sit in a main
          column and the two risk axes and the section links in a narrow column
          beside it, so a wide window is used instead of left empty. Below 2xl
          the wrappers vanish (`contents`) and `order` keeps the single-column
          sequence this page always had. */}
      <div className="flex flex-col gap-6 2xl:grid 2xl:grid-cols-[minmax(0,1fr)_22rem] 2xl:items-start">
        <div className="contents 2xl:flex 2xl:min-w-0 2xl:flex-col 2xl:gap-6">
          <div className="order-1 empty:hidden 2xl:order-none">
            <FirstChecks result={result} scanId={scanId} generatedAt={generatedAt} />
          </div>
          {attention.length > 0 && (
            <div className="order-2 empty:hidden 2xl:order-none">
              <Card data-testid="needs-attention">
                <CardContent className="p-4">
                  <div className="mb-2 text-body-sm font-semibold text-foreground">
                    {t("overview.needsAttention")}
                  </div>
                  <ul className="flex flex-col gap-1">
                    {attention.map((item) => {
                      const Icon = ATTN_ICON[item.id];
                      const ATTN_KEY: Record<AttentionItem["id"], string> = {
                        malicious: "overview.attnMalicious",
                        conformance: "overview.attnConformance",
                        vulns: "overview.attnVulns",
                        review: "overview.attnReview",
                        modelRisk: "overview.attnModelRisk",
                        conformanceGap: "overview.attnConformanceGap",
                      };
                      const label = t(ATTN_KEY[item.id], { count: item.count });
                      return (
                        <li key={item.id}>
                          <a
                            href={scanId ? scanHash(scanId, item.target) : undefined}
                            className={cn(
                              "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-body-sm",
                              "transition-colors duration-fast ease-out-soft hover:bg-muted",
                              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                            )}
                          >
                            <Icon className={cn("h-4 w-4 shrink-0", TONE_ICON[item.tone])} aria-hidden />
                            <span className="text-foreground">{label}</span>
                            <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                </CardContent>
              </Card>
            </div>
          )}
          {result.yoctoVex && (
            <div className="order-3 empty:hidden 2xl:order-none">
              <YoctoVexNote vex={result.yoctoVex} />
            </div>
          )}
          <div className="order-5 empty:hidden 2xl:order-none">
            <TopRisk result={result} scanId={scanId} />
          </div>
        </div>
        <div className="contents 2xl:flex 2xl:min-w-0 2xl:flex-col 2xl:gap-6">
          <div className="order-4 empty:hidden 2xl:order-none">
            {/* The two risk axes side by side; clicking a band routes into its
                section with that filter applied. */}
            {/* Two columns only when there are two axes: an AI scan has no
                security report, and the licence axis alone took half the width. */}
            <div
              className={cn(
                "grid grid-cols-1 gap-x-8 gap-y-6",
                result.security && "lg:grid-cols-2 2xl:grid-cols-1",
              )}
            >
              {result.security && (
                <SeverityBar
                  security={result.security}
                  onSelect={
                    onPick ? (s) => onPick("vulnerabilities", { severity: s }) : undefined
                  }
                />
              )}
              <LicenseRiskBar
                components={result.sbom?.componentList ?? []}
                onSelect={onPick ? (tier) => onPick("licenses", { tier }) : undefined}
              />
            </div>
          </div>
          <div className="order-6 empty:hidden 2xl:order-none">
            {/* Section links come last: the rail already carries the same counts, so
                the first screen leads with what to look at (first checks, needs
                attention, the two risk axes) and keeps this strip as a way on. */}
            <JumpCards
              result={result}
              hasDeps={hasDeps}
              ai={ai}
              hasConformance={hasConformance}
              scanId={scanId}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Vulnerability work the Yocto build already did.
 *
 * A Yocto SBOM carries bitbake's own CVE verdicts, and on a real image the
 * patched count dwarfs the open one (measured on core-image-minimal: 12255
 * patched, 63 not applicable, 0 open). The security panel lists only what is
 * still open, so without this note "0 vulnerabilities" would read as "nothing
 * was checked" instead of "the build closed all of them" — the opposite of the
 * truth. Rendered only for Yocto input; `yoctoVex` is null everywhere else.
 */
function YoctoVexNote({ vex }: { vex: YoctoVex }) {
  const { t } = useTranslation();
  const handled = vex.fixed + vex.notAffected;
  if (handled === 0) return null;
  return (
    <Card>
      <CardContent className="flex items-start gap-3 p-4">
        <ShieldCheck className="mt-0.5 size-5 shrink-0 text-risk-info" aria-hidden />
        <div className="space-y-1">
          <div className="text-body-sm font-medium">{t("overview.yoctoVex.title")}</div>
          <p className="text-body-sm text-muted-foreground">
            {vex.unresolved > 0
              ? t("overview.yoctoVex.withOpen", {
                  fixed: vex.fixed,
                  notAffected: vex.notAffected,
                  open: vex.unresolved,
                })
              : t("overview.yoctoVex.allHandled", {
                  fixed: vex.fixed,
                  notAffected: vex.notAffected,
                })}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

interface Jump {
  id: SectionId;
  icon: LucideIcon;
  value: number | string | null;
  /** Optional secondary line, e.g. the dependency direct/transitive split. */
  sub?: string;
  /** Overrides the nav-derived label (e.g. the End-of-life tile → Components). */
  label?: string;
  /** Emphasis class for the number (e.g. at-risk end-of-life in the risk tone). */
  valueClass?: string;
  /** Stable list key when several tiles target the same section. */
  key?: string;
}

function JumpCards({
  result,
  hasDeps,
  ai,
  hasConformance,
  scanId,
}: {
  result: DoneEvent;
  hasDeps: boolean;
  ai: boolean;
  hasConformance: boolean;
  scanId: string | null;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  // Models AND datasets: the tile carries the section's name, and counting only
  // the models left it reading "1" next to a rail badge of 4 for the same
  // screen. Kept in step with sectionCounts.
  const modelCount = (result.sbom?.componentList ?? []).filter(
    (c) => c.type === "machine-learning-model" || c.type === "data",
  ).length;
  const direct = result.sbom?.directCount ?? 0;
  const transitive = result.sbom?.transitiveCount ?? 0;
  const depTotal = direct + transitive;
  const eolCount = result.sbom?.eolCount ?? 0;
  const atRiskCount = result.sbom?.atRiskCount ?? 0;
  const outdatedCount = result.sbom?.outdatedCount ?? 0;
  const jumps: Jump[] = [
    { id: "components", icon: Boxes, value: result.sbom?.components ?? 0 },
    // End-of-life tile: only when the scan flagged EOL components. It routes into
    // Components; the count turns risk-toned when some are also vulnerable (the
    // actionable set — an EOL component gets no upstream patch for its CVEs).
    ...(eolCount > 0
      ? [
          {
            id: "components" as SectionId,
            key: "eol",
            icon: CalendarX,
            value: eolCount,
            label: t("result.eolTile"),
            // Bare token, but already passing on this tile's bg-card in both
            // themes (4.83:1 light, 6.22:1 dark); left as-is, nothing to fix.
            valueClass: atRiskCount > 0 ? "text-risk-critical" : undefined, // token-lint-ignore: body text on card, contrast checked
            sub: atRiskCount > 0 ? t("result.eolAtRisk", { count: atRiskCount }) : undefined,
          },
        ]
      : []),
    // Version-currency tile: components behind the latest in-cycle patch. Routes
    // into Components. Weaker signal than EOL (still supported), so no risk tone.
    ...(outdatedCount > 0
      ? [
          {
            id: "components" as SectionId,
            key: "outdated",
            icon: History,
            value: outdatedCount,
            label: t("result.outdatedTile"),
          },
        ]
      : []),
    ...(result.security
      ? [
          {
            id: "vulnerabilities" as SectionId,
            icon: ShieldAlert,
            value: result.security.TOTAL,
            // A 0 here covers only the components a check reached. Findings
            // judged not reachable are out of TOTAL, as in the security report.
            sub: result.security.uncheckedCount
              ? t("result.uncheckedTile", { count: result.security.uncheckedCount })
              : result.security.notReachableCount
                ? t("result.notReachableTile", { count: result.security.notReachableCount })
                : undefined,
          },
        ]
      : []),
    // The rail keeps this section whenever the scan produced a dependency view,
    // so hiding the tile made the two disagree about whether the section exists.
    // It stays, and says what it has: a count with its split, a count alone when
    // nothing is transitive (an AI scan's root model is not a dependency of
    // itself), or that no relationships were recorded.
    ...(hasDeps
      ? [
          {
            id: "dependencies" as SectionId,
            icon: GitBranch,
            value: depTotal,
            sub:
              depTotal === 0
                ? t("overview.depNone")
                : transitive === 0
                  ? undefined
                  : t("overview.depBreakdown", { direct, transitive }),
          },
        ]
      : []),
    ...(ai ? [{ id: "models" as SectionId, icon: Cpu, value: modelCount }] : []),
    // Coverage as `passed/total` — same figure as the rail badge (G7 when the
    // scan has AI checks, base format tally otherwise).
    ...(hasConformance
      ? [
          {
            id: "conformance" as SectionId,
            icon: FileCheck2,
            value: conformanceCount(result) ?? null,
          },
        ]
      : []),
    { id: "artifacts", icon: Package, value: result.results.length },
  ];

  // One compact set of entries instead of a row of tall cards. The set is
  // conditional (2 to 7 entries), so it is an even grid of equal columns: a
  // wrapped flex row left one entry alone on the second line, and in the narrow
  // right column at 2xl it collapses to one entry per line. A secondary figure
  // goes on its own line inside the entry instead of widening it.
  return (
    <div>
      <ul
        aria-label={t("overview.summaryLabel")}
        className="grid grid-cols-[repeat(auto-fill,minmax(12.5rem,1fr))] gap-2"
      >
        {jumps.map(({ id, key, icon: Icon, value, sub, label, valueClass }) => {
          const text = label ?? t(`nav.${id}`);
          return (
            <li key={key ?? id} className="flex min-w-0">
              <a
                href={scanId ? scanHash(scanId, id) : undefined}
                aria-label={t("overview.jumpHint", { section: text })}
                className={cn(
                  "group flex w-full min-w-0 items-center gap-2 rounded-lg border bg-card px-3 py-2",
                  "transition-[border-color,background-color] duration-fast ease-out-soft",
                  "hover:border-foreground/30 hover:bg-muted/50",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                )}
              >
                <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                <span
                  className={cn(
                    "text-body-sm font-semibold tabular-nums text-foreground",
                    valueClass,
                  )}
                >
                  {typeof value === "number" ? fmt(value) : (value ?? "—")}
                </span>
                <span className="min-w-0 truncate text-body-sm text-muted-foreground" title={text}>
                  {text}
                </span>
                {/* Takes only the room the column has left, cut short with the
                    full text in the tooltip, so every entry stays one line. */}
                {sub && (
                  <span
                    className="min-w-0 flex-1 truncate text-label text-muted-foreground"
                    title={sub}
                  >
                    {sub}
                  </span>
                )}
                <ChevronRight
                  className="ml-auto h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-fast ease-out-soft group-hover:translate-x-0.5"
                  aria-hidden
                />
              </a>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** The standalone Artifacts section (jump-card target). */
export function ArtifactsSection({
  result,
  scanId,
  onResultsChange,
  onResultPatch,
}: {
  result: DoneEvent;
  scanId: string | null;
  /** Passed through so an on-demand SPDX export updates the owning result. */
  onResultsChange?: (files: ResultFile[]) => void;
  /** The SPDX 3.0.1 actions also refresh the document's summary. */
  onResultPatch?: (patch: Partial<DoneEvent>) => void;
}) {
  return (
    <ResultsList
      results={result.results}
      scanId={scanId}
      onResultsChange={onResultsChange}
      aiScan={isAiScan(result)}
      uploadedSbom={result.scanConfig?.source === "sbom-upload"}
      spdx3={result.spdx3}
      onResultPatch={onResultPatch}
    />
  );
}
