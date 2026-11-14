// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FileIcon } from "@primer/octicons-react";
import { useTranslation } from "react-i18next";

import { SeverityLabel } from "@/components/primer";
import { advisorySummary } from "@/lib/advisories";
import type { SecuritySummary } from "@/lib/api";

import { CoverageBox } from "./vulns/CoverageBox";

/**
 * Distribution advisory numbers (DLA-..., SUSE-SU-...) for which the
 * vulnerability database names no CVE. Listed on their own, below the findings:
 * they are not counted in the severity figures, and one advisory can cover
 * several issues, so mixing them into the CVE list would misstate both.
 * Renders nothing when there are none.
 */
export function AdvisoriesWithoutCve({ security }: { security: SecuritySummary }) {
  const { t } = useTranslation();
  const a = advisorySummary(security);
  if (!a) return null;
  return (
    <CoverageBox
      testId="advisories-without-cve"
      icon={FileIcon}
      title={t("result.advisoriesTitle", { count: a.count })}
      hint={t("result.advisoriesHint")}
      listLabel={t("result.advisoriesList")}
      columns={[
        { label: t("result.colSeverity") },
        { label: t("result.advisoryId") },
        { label: t("result.colPackage") },
        { label: t("result.colInstalled") },
        { label: t("result.colFixed") },
        { label: t("result.advisoryTarget") },
      ]}
      grid="auto minmax(160px, 1fr) minmax(160px, 1fr) minmax(70px, auto) minmax(70px, auto) minmax(120px, auto)"
      rows={a.rows.map((r, i) => ({
        key: `${r.id}-${r.purl || r.pkg}-${i}`,
        cells: [
          <SeverityLabel key="s" severity={r.severity} quiet />,
          <div key="i">
            <span className="bl-mono">{r.id}</span>
            {r.title && <div className="bl-muted bl-small">{r.title}</div>}
          </div>,
          <span key="p" className="bl-mono bl-breakall" title={r.purl}>
            {r.pkg || "-"}
          </span>,
          <span key="in" className="bl-mono bl-num">
            {r.installed || "-"}
          </span>,
          <span key="f" className="bl-mono bl-num">
            {r.fixed || "-"}
          </span>,
          <span key="t" className="bl-muted">
            {r.target || "-"}
          </span>,
        ],
      }))}
      note={a.truncated ? t("result.advisoriesTruncated", { shown: a.rows.length, count: a.count }) : undefined}
    />
  );
}
