// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ShieldMinus } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import type { SecuritySummary } from "@/lib/api";
import { notReachableSummary, reachabilityJustificationKey } from "@/lib/reachability";
import { severityTone } from "@/lib/severity";
import { cn } from "@/lib/utils";

/**
 * Findings govulncheck judged not reachable (--reachability), with why. They
 * are not in the severity figures above, as in the generated security report,
 * so they are listed here instead of disappearing. Renders nothing when there
 * are none.
 */
export function NotReachableFindings({
  security,
  className,
}: {
  security: SecuritySummary;
  className?: string;
}) {
  const { t } = useTranslation();
  const s = notReachableSummary(security);
  if (!s) return null;
  return (
    <div
      data-testid="not-reachable-findings"
      className={cn("space-y-2 rounded-md border bg-muted/30 px-3 py-2 text-left text-xs", className)}
    >
      <p className="flex items-start gap-2 text-sm font-medium text-foreground">
        <ShieldMinus className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        {t("result.notReachableTitle", { count: s.count })}
      </p>
      <p className="text-muted-foreground">{t("result.notReachableHint")}</p>
      {s.rows.length > 0 && (
        <Disclosure
          summary={<span className="text-xs font-medium text-foreground">{t("result.notReachableList")}</span>}
        >
          <div className="mt-2 max-h-80 overflow-auto rounded-md border bg-card">
            <table className="w-full text-left text-xs">
              <thead className="border-b bg-muted/40 text-muted-foreground">
                <tr>
                  <th scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                    {t("result.colSeverity")}
                  </th>
                  <th scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                    {t("result.colCve")}
                  </th>
                  <th scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                    {t("result.colPackage")}
                  </th>
                  <th scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                    {t("result.colInstalled")}
                  </th>
                  <th scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                    {t("result.colFixed")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.notReachableWhy")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {s.rows.map((v, i) => (
                  <tr key={`${v.id}-${v.purl || v.pkg}-${i}`} className="border-b align-top last:border-0">
                    <td className="px-3 py-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge tone={severityTone(v.severity)}>{t(`severity.${v.severity}`)}</Badge>
                        <Badge tone="info">{t("result.notReachableBadge")}</Badge>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono text-foreground">{v.id}</td>
                    <td className="break-all px-3 py-1.5 font-mono text-foreground" title={v.purl}>
                      {v.pkg}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-foreground">{v.installed || "-"}</td>
                    <td className="px-3 py-1.5 font-mono text-foreground">{v.fixed || "-"}</td>
                    <td className="px-3 py-1.5 text-foreground">
                      <span className="block font-medium">
                        {t(reachabilityJustificationKey(v.reachability?.justification))}
                      </span>
                      {v.reachability?.detail && (
                        <span className="block break-words text-muted-foreground">{v.reachability.detail}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {s.truncated && (
            <p className="mt-1 text-muted-foreground">
              {t("result.notReachableTruncated", { shown: s.rows.length, count: s.count })}
            </p>
          )}
        </Disclosure>
      )}
    </div>
  );
}
