// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ShieldIcon } from "@primer/octicons-react";
import { useTranslation } from "react-i18next";

import type { SecuritySummary } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { uncheckedReasonKey, uncheckedSummary } from "@/lib/unchecked";

import { CoverageBox } from "./vulns/CoverageBox";

/**
 * Components the vulnerability check could not reach, with why and which.
 * Renders nothing when every component was checked. Shown next to the findings
 * and in place of "No vulnerabilities found", which would otherwise read as a
 * clean result when it only covers part of the inventory.
 */
export function UncheckedComponents({ security }: { security: SecuritySummary }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const u = uncheckedSummary(security);
  if (!u) return null;
  return (
    <CoverageBox
      testId="unchecked-components"
      icon={ShieldIcon}
      title={t("result.uncheckedTitle", { count: u.count })}
      hint={
        <>
          {t("result.uncheckedHint")} {u.byReason.map((b) => `${t(uncheckedReasonKey(b.reason))} ${fmt(b.count)}`).join(", ")}
        </>
      }
      listLabel={t("result.uncheckedList")}
      columns={[{ label: t("result.uncheckedName") }, { label: t("result.uncheckedVersion") }, { label: t("result.uncheckedReasonCol") }]}
      grid="minmax(200px, 1fr) minmax(80px, auto) minmax(160px, auto)"
      rows={u.rows.map((r, i) => ({
        key: `${r.name}-${r.version}-${i}`,
        cells: [
          <span key="n" className="bl-mono bl-breakall" title={r.purl}>
            {r.name}
          </span>,
          <span key="v" className="bl-mono">
            {r.version || "-"}
          </span>,
          t(uncheckedReasonKey(r.reason)),
        ],
      }))}
      note={u.truncated ? t("result.uncheckedTruncated", { shown: u.rows.length, count: u.count }) : undefined}
    />
  );
}
