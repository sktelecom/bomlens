// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";
import { Bot } from "lucide-react";
import { Fragment } from "react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { SbomSummary } from "@/lib/api";
import {
  AI_USAGE_KIND_KEY,
  AI_USAGE_REASON_HELP_KEY,
  AI_USAGE_REASON_KEY,
  aiUsageScopeKey,
  aiUsageView,
} from "@/lib/aiUsage";
import { useFormatNumber } from "@/lib/format";

/**
 * The AI the scanned code uses: models and AI services it calls, MCP servers
 * and their configuration files, agent instruction files. One dense table
 * grouped by kind, review reasons as labels with their explanation listed
 * under the table. Renders nothing when the scan recorded no AI usage.
 */
export function AiUsageCard({ sbom }: { sbom: SbomSummary | null | undefined }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const view = aiUsageView(sbom);
  if (!view) return null;

  return (
    <Card data-testid="ai-usage">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <Bot className="h-4 w-4 shrink-0 self-center text-muted-foreground" aria-hidden />
          <span className="text-body-sm font-semibold text-foreground">{t("aiUsage.title")}</span>
          <span className="text-label text-muted-foreground">
            {t("aiUsage.count", { count: view.total, n: fmt(view.total) })}
            {view.reviewCount > 0 &&
              `, ${t("aiUsage.reviewCount", { count: view.reviewCount, n: fmt(view.reviewCount) })}`}
          </span>
        </div>
        <p className="text-label text-muted-foreground">{t("aiUsage.note")}</p>
        <div className="max-h-96 overflow-auto rounded-md border bg-card">
          <table className="w-full text-left text-label">
            <thead className="border-b bg-muted/40 text-muted-foreground">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">
                  {t("aiUsage.colName")}
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  {t("aiUsage.colWhere")}
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  {t("aiUsage.colScope")}
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  {t("aiUsage.colReview")}
                </th>
              </tr>
            </thead>
            <tbody>
              {view.groups.map((g) => (
                <Fragment key={g.kind}>
                  <tr className="border-b bg-muted/20">
                    <th
                      scope="colgroup"
                      colSpan={4}
                      className="px-3 py-1.5 font-semibold text-foreground"
                      data-testid={`ai-usage-group-${g.kind}`}
                    >
                      {t(AI_USAGE_KIND_KEY[g.kind])}{" "}
                      <span className="font-normal text-muted-foreground tabular-nums">
                        {fmt(g.items.length)}
                      </span>
                    </th>
                  </tr>
                  {g.items.map((it, i) => (
                    <tr key={`${it.name}-${it.path ?? ""}-${i}`} className="border-b last:border-0 align-top">
                      <td className="px-3 py-1.5">
                        <div className="break-all font-mono text-foreground" title={it.purl}>
                          {it.name}
                        </div>
                        {it.kind === "ai-service" && it.models && it.models.length > 0 && (
                          <div className="mt-0.5 text-foreground/70">
                            {t("aiUsage.models", { models: it.models.join(", ") })}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-1.5">
                        {it.provider && <div className="text-foreground">{it.provider}</div>}
                        {it.path && (
                          <div className="break-all font-mono text-foreground/70">{it.path}</div>
                        )}
                        {!it.provider && !it.path && <span className="text-foreground/70">-</span>}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5">
                        <Label variant="secondary">{t(aiUsageScopeKey(it.scope))}</Label>
                      </td>
                      <td className="px-3 py-1.5">
                        {it.reviewReasons.length === 0 ? (
                          <span className="text-foreground/70">-</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {it.reviewReasons.map((r) => (
                              <Label key={r} variant="attention" title={t(AI_USAGE_REASON_HELP_KEY[r])}>
                                {t(AI_USAGE_REASON_KEY[r])}
                              </Label>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        {view.reasons.length > 0 && (
          <dl className="space-y-1 text-label" data-testid="ai-usage-reasons">
            {view.reasons.map((r) => (
              <div key={r} className="flex flex-wrap gap-x-2">
                <dt className="font-medium text-foreground">{t(AI_USAGE_REASON_KEY[r])}</dt>
                <dd className="text-muted-foreground">{t(AI_USAGE_REASON_HELP_KEY[r])}</dd>
              </div>
            ))}
          </dl>
        )}
        {view.truncated && (
          <p className="text-label text-muted-foreground">{t("aiUsage.truncated", { n: fmt(view.total) })}</p>
        )}
      </CardContent>
    </Card>
  );
}
