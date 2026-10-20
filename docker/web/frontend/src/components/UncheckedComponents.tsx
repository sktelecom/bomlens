// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ShieldQuestion } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Disclosure } from "@/components/ui/disclosure";
import type { SecuritySummary } from "@/lib/api";
import { uncheckedReasonKey, uncheckedSummary } from "@/lib/unchecked";
import { useFormatNumber } from "@/lib/format";
import { CoverageNotice } from "@/components/ui/coverage-notice";

/**
 * Components the vulnerability check could not reach, with why and which.
 * Renders nothing when every component was checked. Shown next to the findings
 * and in place of "No vulnerabilities found", which would otherwise read as a
 * clean result when it only covers part of the inventory.
 */
export function UncheckedComponents({
  security,
  className,
}: {
  security: SecuritySummary;
  className?: string;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const u = uncheckedSummary(security);
  if (!u) return null;
  return (
    <CoverageNotice
      testId="unchecked-components"
      icon={ShieldQuestion}
      title={t("result.uncheckedTitle", { count: u.count })}
      className={className}
    >
      <p className="text-muted-foreground">
        {t("result.uncheckedHint")}{" "}
        {u.byReason.map((b) => `${t(uncheckedReasonKey(b.reason))} ${fmt(b.count)}`).join(", ")}
      </p>
      {u.rows.length > 0 && (
        <Disclosure
          summary={<span className="text-label font-medium text-foreground">{t("result.uncheckedList")}</span>}
        >
          <div className="mt-2 max-h-80 overflow-auto rounded-md border bg-card">
            <table className="w-full text-left text-label">
              <thead className="border-b bg-muted/40 text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.uncheckedName")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.uncheckedVersion")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("result.uncheckedReasonCol")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {u.rows.map((r, i) => (
                  <tr key={`${r.name}-${r.version}-${i}`} className="border-b last:border-0">
                    <td className="break-all px-3 py-1.5 font-mono text-foreground" title={r.purl}>
                      {r.name}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-foreground">{r.version || "-"}</td>
                    <td className="px-3 py-1.5 text-foreground">{t(uncheckedReasonKey(r.reason))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {u.truncated && (
            <p className="mt-1 text-muted-foreground">
              {t("result.uncheckedTruncated", { shown: u.rows.length, count: u.count })}
            </p>
          )}
        </Disclosure>
      )}
    </CoverageNotice>
  );
}
