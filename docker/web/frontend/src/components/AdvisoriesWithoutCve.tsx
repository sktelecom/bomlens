// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FileWarning } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import { advisorySummary } from "@/lib/advisories";
import type { SecuritySummary } from "@/lib/api";
import { severityTone } from "@/lib/severity";
import { cn } from "@/lib/utils";

/**
 * Distribution advisory numbers (DLA-..., SUSE-SU-...) for which the vulnerability database
 * names no CVE. Listed on their own, below the findings: they are not counted in
 * the severity figures, and one advisory can cover several issues, so mixing them
 * into the CVE list would misstate both. Renders nothing when there are none.
 */
export function AdvisoriesWithoutCve({
  security,
  className,
}: {
  security: SecuritySummary;
  className?: string;
}) {
  const { t } = useTranslation();
  const a = advisorySummary(security);
  if (!a) return null;
  return (
    <div
      data-testid="advisories-without-cve"
      className={cn("space-y-2 rounded-md border bg-muted/30 px-3 py-2 text-left text-xs", className)}
    >
      <p className="flex items-start gap-2 text-sm font-medium text-foreground">
        <FileWarning className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        {t("result.advisoriesTitle", { count: a.count })}
      </p>
      <p className="text-muted-foreground">{t("result.advisoriesHint")}</p>
      {a.rows.length > 0 && (
        <Disclosure
          summary={<span className="text-xs font-medium text-foreground">{t("result.advisoriesList")}</span>}
        >
          <div className="mt-2 max-h-80 overflow-auto rounded-md border bg-card">
            <table className="w-full text-left text-xs">
              <thead className="border-b bg-muted/40 text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.colSeverity")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.advisoryId")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.colPackage")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.colInstalled")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.colFixed")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.advisoryTarget")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {a.rows.map((r, i) => (
                  <tr key={`${r.id}-${r.purl || r.pkg}-${i}`} className="border-b last:border-0">
                    <td className="px-3 py-1.5">
                      <Badge tone={severityTone(r.severity)} mark>{t(`severity.${r.severity}`)}</Badge>
                    </td>
                    <td className="px-3 py-1.5">
                      <span className="font-mono text-foreground">{r.id}</span>
                      {r.title ? <div className="mt-0.5 max-w-md text-muted-foreground">{r.title}</div> : null}
                    </td>
                    <td className="break-all px-3 py-1.5 font-mono text-foreground" title={r.purl}>
                      {r.pkg || "-"}
                    </td>
                    <td className="px-3 py-1.5 font-mono tabular-nums text-foreground">{r.installed || "-"}</td>
                    <td className="px-3 py-1.5 font-mono tabular-nums text-foreground">{r.fixed || "-"}</td>
                    <td className="px-3 py-1.5 text-muted-foreground">{r.target || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {a.truncated && (
            <p className="mt-1 text-muted-foreground">
              {t("result.advisoriesTruncated", { shown: a.rows.length, count: a.count })}
            </p>
          )}
        </Disclosure>
      )}
    </div>
  );
}
