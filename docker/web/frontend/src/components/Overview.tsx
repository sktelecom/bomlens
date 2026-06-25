import {
  Boxes,
  ChevronRight,
  Cpu,
  Eye,
  FileCheck2,
  GitBranch,
  type LucideIcon,
  Package,
  ShieldAlert,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { DoneEvent } from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { type AttentionItem, needsAttention } from "@/lib/overview";
import { isAiScan, sbomFileName } from "@/lib/results";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

import { LicenseSummary } from "./LicenseSummary";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";

/** Tone → token-driven icon colour (graphical, so 3:1 is enough). */
const TONE_ICON: Record<AttentionItem["tone"], string> = {
  critical: "text-risk-critical",
  high: "text-risk-high",
  info: "text-risk-info",
};
const ATTN_ICON: Record<AttentionItem["id"], LucideIcon> = {
  vulns: ShieldAlert,
  review: Eye,
};

/**
 * Decision-first Overview: what needs attention first, then the at-a-glance
 * numbers and summaries, then jump cards into the detail sections — instead of
 * repeating full tables here.
 */
export function Overview({
  result,
  scanId,
}: {
  result: DoneEvent;
  /** The scan's id; section links resolve to `#/scan/<id>/<section>`. */
  scanId: string | null;
}) {
  const { t } = useTranslation();
  const attention = needsAttention(result);
  const hasDeps = Boolean(sbomFileName(result));
  const ai = isAiScan(result);
  const hasG7 = Boolean(
    result.conformance?.checks?.some((c) => c.id?.startsWith("g7-")),
  );

  return (
    <div className="space-y-6">
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
                  item.id === "vulns"
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

      {result.security && <SeverityBar security={result.security} />}

      <LicenseSummary components={result.sbom?.componentList ?? []} />

      <JumpCards
        result={result}
        hasDeps={hasDeps}
        ai={ai}
        hasG7={hasG7}
        scanId={scanId}
      />
    </div>
  );
}

interface Jump {
  id: SectionId;
  icon: LucideIcon;
  value: number | null;
  /** Optional secondary line, e.g. the dependency direct/transitive split. */
  sub?: string;
}

function JumpCards({
  result,
  hasDeps,
  ai,
  hasG7,
  scanId,
}: {
  result: DoneEvent;
  hasDeps: boolean;
  ai: boolean;
  hasG7: boolean;
  scanId: string | null;
}) {
  const { t } = useTranslation();
  const modelCount = (result.sbom?.componentList ?? []).filter(
    (c) => c.type === "machine-learning-model",
  ).length;
  const direct = result.sbom?.directCount ?? 0;
  const transitive = result.sbom?.transitiveCount ?? 0;
  const depTotal = direct + transitive;
  const jumps: Jump[] = [
    { id: "components", icon: Boxes, value: result.sbom?.components ?? 0 },
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
    ...(hasG7 ? [{ id: "g7" as SectionId, icon: FileCheck2, value: null }] : []),
    { id: "artifacts", icon: Package, value: result.results.length },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {jumps.map(({ id, icon: Icon, value, sub }) => (
        <a
          key={id}
          href={scanId ? scanHash(scanId, id) : undefined}
          aria-label={t("overview.jumpHint", { section: t(`nav.${id}`) })}
          className={cn(
            "group rounded-lg border bg-card p-4 text-left",
            "transition-colors duration-fast ease-out-soft hover:border-brand/40 hover:bg-muted/50",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
          )}
        >
          <div className="flex items-center justify-between">
            <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
            <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform duration-fast ease-out-soft group-hover:translate-x-0.5" aria-hidden />
          </div>
          <div className="mt-3 text-2xl font-semibold tabular-nums text-foreground">
            {value ?? "—"}
          </div>
          <div className="truncate text-xs text-muted-foreground">{t(`nav.${id}`)}</div>
          {sub && (
            <div className="mt-0.5 truncate text-[0.6875rem] text-muted-foreground">
              {sub}
            </div>
          )}
        </a>
      ))}
    </div>
  );
}

/** The standalone Artifacts section (jump-card target). */
export function ArtifactsSection({ result }: { result: DoneEvent }) {
  return <ResultsList results={result.results} />;
}
