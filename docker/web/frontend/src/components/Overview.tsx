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
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type {
  ComponentItem,
  DoneEvent,
  RecentScan,
  ResultFile,
  Severity,
  YoctoVex,
} from "@/lib/api";
import type { LicenseRiskTier } from "@/lib/licenses";
import type { SectionId } from "@/lib/nav";
import { type AttentionItem, needsAttention } from "@/lib/overview";
import { type ProvenanceKind, provenanceOf } from "@/lib/provenance";
import { formatRelativeTime, scanComparison } from "@/lib/recent";
import { conformanceCount, isAiScan, sbomFileName } from "@/lib/results";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

import { LicenseRiskBar } from "./LicenseRiskBar";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";

/** Tone → token-driven icon colour (graphical, so 3:1 is enough). */
const TONE_ICON: Record<AttentionItem["tone"], string> = {
  critical: "text-risk-critical",
  high: "text-risk-high",
  info: "text-risk-info",
};
const ATTN_ICON: Record<AttentionItem["id"], LucideIcon> = {
  malicious: Biohazard,
  conformance: FileCheck2,
  vulns: ShieldAlert,
  review: Eye,
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
};

function ProvenanceIcon({
  kind,
  ...props
}: { kind: ProvenanceKind } & React.ComponentProps<LucideIcon>) {
  const Icon = PROVENANCE_ICON[kind];
  return <Icon {...props} />;
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
  onPick,
}: {
  result: DoneEvent;
  /** The scan's id; section links resolve to `#/scan/<id>/<section>`. */
  scanId: string | null;
  /** Local Recent-scans list, for the "vs previous scan" comparison line. */
  recent?: RecentScan[];
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
  const attention = needsAttention(result);
  const hasDeps = Boolean(sbomFileName(result));
  const ai = isAiScan(result);
  const hasConformance = Boolean(result.conformance?.checks?.length);
  const comparison = scanId ? scanComparison(recent, scanId) : null;
  const provenance = provenanceOf(result.scanConfig);

  return (
    <div className="space-y-6">
      {provenance && (
        // What was scanned. Sits above the counts because it frames them: the
        // same "71 components" means something different for a folder on disk
        // than for an image someone pulled.
        <div
          className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground"
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
      {comparison && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span>
            {t("overview.vsPrevious", {
              label:
                comparison.prev.version ||
                formatRelativeTime(
                  comparison.prev.generatedAt,
                  Date.now(),
                  i18n.language,
                ),
            })}
          </span>
          <span className="text-foreground">
            {comparison.componentsDelta === 0
              ? t("overview.compSame")
              : t("overview.compDelta", {
                  delta:
                    comparison.componentsDelta > 0
                      ? `+${comparison.componentsDelta}`
                      : `${comparison.componentsDelta}`,
                })}
          </span>
          <span
            className={cn(
              comparison.severityDir === "up" && "text-risk-high",
              comparison.severityDir === "down" && "text-risk-low",
            )}
          >
            {t(
              comparison.severityDir === "up"
                ? "overview.sevUp"
                : comparison.severityDir === "down"
                  ? "overview.sevDown"
                  : "overview.sevSame",
            )}
          </span>
        </div>
      )}
      {ai && (
        <div className="rounded-md border bg-muted/40 px-4 py-3 text-muted-foreground">
          <div className="text-sm font-medium text-foreground">{t("result.aiScanTitle")}</div>
          <p className="mt-1 text-xs">{t("result.aiScanBody")}</p>
        </div>
      )}

      {!ai && result.sbom?.suggestIdentifyVendored && (
        <div className="rounded-md border border-amber-300/60 bg-amber-50 px-4 py-3 text-amber-900 dark:border-amber-400/20 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="text-sm font-medium">{t("result.vendoredHintTitle")}</div>
          <p className="mt-1 text-xs">{t("result.vendoredHintBody")}</p>
        </div>
      )}

      {result.sbom?.sbomToolDegraded && (
        <div className="rounded-md border border-amber-300/60 bg-amber-50 px-4 py-3 text-amber-900 dark:border-amber-400/20 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="text-sm font-medium">{t("result.sbomDegradedTitle")}</div>
          <p className="mt-1 text-xs">
            {t(
              result.sbom.sbomToolDegraded === "disk-space"
                ? "result.sbomDegradedDisk"
                : "result.sbomDegradedBody",
            )}
          </p>
        </div>
      )}

      {result.scanoss?.status === "unavailable" && (
        <div className="rounded-md border border-amber-300/60 bg-amber-50 px-4 py-3 text-amber-900 dark:border-amber-400/20 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="text-sm font-medium">{t("result.scanossUnavailableTitle")}</div>
          <p className="mt-1 text-xs">{t("result.scanossUnavailableBody")}</p>
        </div>
      )}

      {result.scanoss?.status === "no-match" && (
        <div className="rounded-md border bg-muted/40 px-4 py-3 text-muted-foreground">
          <div className="text-sm font-medium text-foreground">{t("result.scanossNoMatchTitle")}</div>
          <p className="mt-1 text-xs">{t("result.scanossNoMatchBody")}</p>
        </div>
      )}

      <JumpCards
        result={result}
        hasDeps={hasDeps}
        ai={ai}
        hasConformance={hasConformance}
        scanId={scanId}
      />

      {attention.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-2 text-sm font-semibold text-foreground">
              {t("overview.needsAttention")}
            </div>
            <ul className="flex flex-col gap-1">
              {attention.map((item) => {
                const Icon = ATTN_ICON[item.id];
                const label =
                  item.id === "malicious"
                    ? t("overview.attnMalicious", { count: item.count })
                    : item.id === "conformance"
                      ? t("overview.attnConformance", { count: item.count })
                      : item.id === "vulns"
                        ? t("overview.attnVulns", { count: item.count })
                        : t("overview.attnReview", { count: item.count });
                return (
                  <li key={item.id}>
                    <a
                      href={scanId ? scanHash(scanId, item.target) : undefined}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm",
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
      )}

      {result.yoctoVex && <YoctoVexNote vex={result.yoctoVex} />}

      {/* The two risk axes side by side; clicking a band routes into its
          section with that filter applied. */}
      <div className="grid grid-cols-1 gap-x-8 gap-y-6 lg:grid-cols-2">
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
          <div className="text-sm font-medium">{t("overview.yoctoVex.title")}</div>
          <p className="text-sm text-muted-foreground">
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
  const modelCount = (result.sbom?.componentList ?? []).filter(
    (c) => c.type === "machine-learning-model",
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
            valueClass: atRiskCount > 0 ? "text-risk-critical" : undefined,
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
      ? [{ id: "vulnerabilities" as SectionId, icon: ShieldAlert, value: result.security.TOTAL }]
      : []),
    // Only when the SBOM has a real dependency graph (flat firmware/image SBOMs
    // have no direct/transitive split, so the tile would be a meaningless 0).
    ...(hasDeps && depTotal > 0
      ? [
          {
            id: "dependencies" as SectionId,
            icon: GitBranch,
            value: depTotal,
            sub: t("overview.depBreakdown", { direct, transitive }),
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

  // auto-fit: the card set is conditional (2–6 cards), so a fixed 4-column
  // grid left a lopsided empty tail. Let however many render fill the row.
  return (
    <div className="grid grid-cols-2 gap-3 md:[grid-template-columns:repeat(auto-fit,minmax(11rem,1fr))]">
      {jumps.map(({ id, key, icon: Icon, value, sub, label, valueClass }) => {
        const text = label ?? t(`nav.${id}`);
        return (
        <a
          key={key ?? id}
          href={scanId ? scanHash(scanId, id) : undefined}
          aria-label={t("overview.jumpHint", { section: text })}
          className={cn(
            "group rounded-lg border bg-card p-4 text-left",
            "transition-[border-color,background-color,box-shadow] duration-fast ease-out-soft",
            "hover:border-brand/40 hover:bg-muted/50 hover:shadow-md",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
          )}
        >
          <div className="flex items-center justify-between">
            <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
            <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform duration-fast ease-out-soft group-hover:translate-x-0.5" aria-hidden />
          </div>
          <div
            className={cn(
              "mt-3 text-2xl font-semibold tabular-nums text-foreground",
              valueClass,
            )}
          >
            {value ?? "—"}
          </div>
          <div className="truncate text-xs text-muted-foreground">{text}</div>
          {sub && (
            <div className="mt-0.5 truncate text-[0.6875rem] text-muted-foreground">
              {sub}
            </div>
          )}
        </a>
        );
      })}
    </div>
  );
}

/** The standalone Artifacts section (jump-card target). */
export function ArtifactsSection({
  result,
  scanId,
  onResultsChange,
}: {
  result: DoneEvent;
  scanId: string | null;
  /** Passed through so an on-demand SPDX export updates the owning result. */
  onResultsChange?: (files: ResultFile[]) => void;
}) {
  return (
    <ResultsList
      results={result.results}
      scanId={scanId}
      onResultsChange={onResultsChange}
    />
  );
}
