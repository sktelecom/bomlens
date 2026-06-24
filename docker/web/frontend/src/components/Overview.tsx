import {
  Boxes,
  ChevronRight,
  Eye,
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
import { sbomFileName } from "@/lib/results";
import { cn } from "@/lib/utils";

import { KpiCards } from "./KpiCards";
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
  onNavigate,
}: {
  result: DoneEvent;
  onNavigate: (section: SectionId) => void;
}) {
  const { t } = useTranslation();
  const attention = needsAttention(result);
  const hasDeps = Boolean(sbomFileName(result));

  return (
    <div className="space-y-6">
      {result.sbom?.suggestIdentifyVendored && (
        <div className="rounded-md border border-amber-300/60 bg-amber-50 px-4 py-3 text-amber-900 dark:border-amber-400/20 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="text-sm font-medium">{t("result.vendoredHintTitle")}</div>
          <p className="mt-1 text-xs">{t("result.vendoredHintBody")}</p>
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
                    <button
                      type="button"
                      onClick={() => onNavigate(item.target)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm",
                        "transition-colors duration-fast ease-out-soft hover:bg-muted",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                      )}
                    >
                      <Icon className={cn("h-4 w-4 shrink-0", TONE_ICON[item.tone])} aria-hidden />
                      <span className="text-foreground">{label}</span>
                      <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                    </button>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>
      )}

      <KpiCards sbom={result.sbom} security={result.security} conformance={result.conformance} />

      {result.security && <SeverityBar security={result.security} />}

      <LicenseSummary components={result.sbom?.componentList ?? []} />

      <JumpCards
        result={result}
        hasDeps={hasDeps}
        onNavigate={onNavigate}
      />
    </div>
  );
}

interface Jump {
  id: SectionId;
  icon: LucideIcon;
  value: number | null;
}

function JumpCards({
  result,
  hasDeps,
  onNavigate,
}: {
  result: DoneEvent;
  hasDeps: boolean;
  onNavigate: (section: SectionId) => void;
}) {
  const { t } = useTranslation();
  const jumps: Jump[] = [
    { id: "components", icon: Boxes, value: result.sbom?.components ?? 0 },
    ...(result.security
      ? [{ id: "vulnerabilities" as SectionId, icon: ShieldAlert, value: result.security.TOTAL }]
      : []),
    ...(hasDeps ? [{ id: "dependencies" as SectionId, icon: GitBranch, value: null }] : []),
    { id: "artifacts", icon: Package, value: result.results.length },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {jumps.map(({ id, icon: Icon, value }) => (
        <button
          key={id}
          type="button"
          onClick={() => onNavigate(id)}
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
        </button>
      ))}
    </div>
  );
}

/** The standalone Artifacts section (jump-card target). */
export function ArtifactsSection({ result }: { result: DoneEvent }) {
  return <ResultsList results={result.results} />;
}
