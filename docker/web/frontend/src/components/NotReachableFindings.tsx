// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ShieldCheckIcon } from "@primer/octicons-react";
import { Label } from "@primer/react";
import { useTranslation } from "react-i18next";

import { SeverityLabel } from "@/components/primer";
import type { SecuritySummary } from "@/lib/api";
import { notReachableSummary, reachabilityJustificationKey } from "@/lib/reachability";

import { CoverageBox } from "./vulns/CoverageBox";

/**
 * Findings govulncheck judged not reachable (--reachability), with why. They
 * are not in the severity figures, as in the generated security report, so they
 * are listed here instead of disappearing. Renders nothing when there are none.
 */
export function NotReachableFindings({ security }: { security: SecuritySummary }) {
  const { t } = useTranslation();
  const s = notReachableSummary(security);
  if (!s) return null;
  return (
    <CoverageBox
      testId="not-reachable-findings"
      icon={ShieldCheckIcon}
      title={t("result.notReachableTitle", { count: s.count })}
      hint={t("result.notReachableHint")}
      listLabel={t("result.notReachableList")}
      columns={[
        { label: t("result.colSeverity") },
        { label: t("result.colCve") },
        { label: t("result.colPackage") },
        { label: t("result.colInstalled") },
        { label: t("result.colFixed") },
        { label: t("result.notReachableWhy") },
      ]}
      grid="auto auto minmax(160px, 1fr) minmax(70px, auto) minmax(70px, auto) minmax(200px, 1fr)"
      rows={s.rows.map((v, i) => ({
        key: `${v.id}-${v.purl || v.pkg}-${i}`,
        cells: [
          <SeverityLabel key="s" severity={v.severity} quiet />,
          <span key="i" className="bl-mono">
            {v.id}
          </span>,
          <span key="p" className="bl-mono bl-breakall" title={v.purl}>
            {v.pkg}
          </span>,
          <span key="in" className="bl-mono">
            {v.installed || "-"}
          </span>,
          <span key="f" className="bl-mono">
            {v.fixed || "-"}
          </span>,
          <div key="w">
            <Label variant="secondary">{t("result.notReachableBadge")}</Label>{" "}
            <span className="bl-strong">{t(reachabilityJustificationKey(v.reachability?.justification))}</span>
            {v.reachability?.detail && <div className="bl-muted bl-small bl-breakall">{v.reachability.detail}</div>}
          </div>,
        ],
      }))}
      note={s.truncated ? t("result.notReachableTruncated", { shown: s.rows.length, count: s.count }) : undefined}
    />
  );
}
