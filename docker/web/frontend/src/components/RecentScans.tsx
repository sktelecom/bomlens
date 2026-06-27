import {
  FileJson,
  FolderOpen,
  Plus,
  ScanLine,
  ScrollText,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { RecentScan, Severity } from "@/lib/api";
import {
  formatRelativeTime,
  scanTypeLabelKey,
  summarizeRecent,
} from "@/lib/recent";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

interface Props {
  scans: RecentScan[];
  /** Hash for the New scan screen (empty-state CTA). */
  newHref: string;
  /** Delete a past scan (removes its artifacts from the output folder). */
  onDelete: (id: string) => void;
}

const SEV_TONE: Record<
  Severity,
  "critical" | "high" | "medium" | "low" | "info"
> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

function SummaryCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1.5 p-5">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span
          className={cn(
            "text-3xl font-semibold tabular-nums",
            accent && "text-brand-accent",
          )}
        >
          {value}
        </span>
      </CardContent>
    </Card>
  );
}

const TH = "px-4 py-3 text-left font-medium";

/**
 * Recent scans — the home screen (logo / `#/` target). A light summary strip
 * over a table of past local scans. Every figure is computed from real
 * `/scans` data; Type is AI-vs-SBOM only (no invented Source/Firmware split),
 * and there is no Review column — the data isn't there to fill it honestly.
 */
export function RecentScans({ scans, newHref, onDelete }: Props) {
  const { t, i18n } = useTranslation();
  const summary = summarizeRecent(scans);
  const now = Date.now();

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-3xl font-semibold tracking-tight text-foreground">
          {t("recent.title")}
        </h1>
        <p className="text-sm text-muted-foreground">{t("recent.subtitle")}</p>
      </div>

      {scans.length === 0 ? (
        // First-run hero: this empty Recent list is what a new user sees first,
        // so orient them — what BomLens does, how to start, and what it produces.
        <Card>
          <CardContent className="flex flex-col items-center gap-5 px-6 py-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand/10 text-brand">
              <ScanLine className="h-6 w-6" aria-hidden />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-xl font-semibold tracking-tight text-foreground">
                {t("recent.emptyTitle")}
              </h2>
              <p className="mx-auto max-w-md text-sm text-muted-foreground">
                {t("recent.emptyBody")}
              </p>
            </div>
            <a href={newHref} className={cn(buttonVariants())}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("shell.newScan")}
            </a>
            <ul className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
              {[
                { icon: FileJson, label: t("recent.emptyOutSbom") },
                { icon: ScrollText, label: t("recent.emptyOutNotice") },
                { icon: ShieldCheck, label: t("recent.emptyOutSecurity") },
              ].map(({ icon: Icon, label }) => (
                <li key={label} className="inline-flex items-center gap-1.5">
                  <Icon className="h-3.5 w-3.5 opacity-70" aria-hidden />
                  {label}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-4">
            <SummaryCard label={t("recent.total")} value={summary.total} />
            <SummaryCard
              label={t("recent.atRisk")}
              value={summary.atRisk}
              accent={summary.atRisk > 0}
            />
            <SummaryCard label={t("recent.ai")} value={summary.ai} />
          </div>

          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-xs text-muted-foreground">
                    <th className={TH}>{t("recent.colScan")}</th>
                    <th className={TH}>{t("recent.colType")}</th>
                    <th className={TH}>{t("recent.colGenerated")}</th>
                    <th className={cn(TH, "text-right")}>
                      {t("recent.colComponents")}
                    </th>
                    <th className={TH}>{t("recent.colSeverity")}</th>
                    <th className={cn(TH, "text-right")}>
                      <span className="sr-only">{t("recent.delete")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr
                      key={s.id}
                      className="border-b transition-colors duration-fast ease-out-soft last:border-0 hover:bg-muted/40"
                    >
                      <td className="px-4 py-3">
                        <a
                          href={scanHash(s.id)}
                          className="rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        >
                          <span className="font-medium text-foreground">
                            {s.project}
                          </span>
                          {s.version && (
                            <span className="text-muted-foreground">
                              {" @"}
                              {s.version}
                            </span>
                          )}
                        </a>
                      </td>
                      <td className="px-4 py-3">
                        {s.isAiScan ? (
                          <Badge className="border-transparent bg-brand/10 text-brand">
                            {t(scanTypeLabelKey(s))}
                          </Badge>
                        ) : (
                          <Badge variant="muted">{t(scanTypeLabelKey(s))}</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {formatRelativeTime(s.generatedAt, now, i18n.language)}
                      </td>
                      <td className="px-4 py-3 text-right tabular-nums">
                        {s.components}
                      </td>
                      <td className="px-4 py-3">
                        {s.maxSeverity ? (
                          <Badge tone={SEV_TONE[s.maxSeverity]}>
                            {t(`severity.${s.maxSeverity}`)}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => onDelete(s.id)}
                          aria-label={t("recent.delete")}
                          title={t("recent.delete")}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-full text-muted-foreground transition-colors duration-fast ease-out-soft hover:bg-destructive/10 hover:text-destructive focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        >
                          <Trash2 className="h-4 w-4" aria-hidden />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>

          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <FolderOpen className="h-3.5 w-3.5" aria-hidden />
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono">
              ~/sbom-output
            </code>
            <span>{t("recent.source")}</span>
          </p>
        </>
      )}
    </div>
  );
}
