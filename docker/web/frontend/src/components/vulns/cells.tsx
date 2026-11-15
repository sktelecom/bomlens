// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import type { VexReceived, VexState, VulnItem } from "@/lib/api";
import { effectiveFixed } from "@/lib/vulnGroups";

import type { VexFields } from "./vexFields";
import { STATUS_HINT_KEY, STATUS_LABEL_KEY, VEX_LABEL_KEY } from "./vulnStatus";

/** Primer Label variant of a VEX state: resolved states are green, open ones amber. */
export const VEX_VARIANT: Record<VexState, "success" | "attention" | "secondary"> = {
  fixed: "success",
  not_affected: "success",
  affected: "attention",
  under_investigation: "secondary",
};

/**
 * The labels beside a vulnerability's title: known exploited, reached by the
 * code, no fix, the vendor's own status, the supplier's judgement and a received
 * VEX statement. `everyStatus` also lists the "fixed" status, which the table
 * leaves out because the Fixed column already says it.
 */
export function StatusLabels({
  vuln: v,
  vex,
  received,
  everyStatus = false,
}: {
  vuln: VulnItem;
  vex: VexFields;
  received?: VexReceived;
  everyStatus?: boolean;
}) {
  const { t } = useTranslation();
  const out: ReactNode[] = [];
  if (v.kev)
    out.push(
      <Label key="kev" variant="danger" title={t("result.kevHint")}>
        {t("result.kevBadge")}
      </Label>,
    );
  if (v.reachability?.state === "exploitable")
    out.push(
      <Label key="reached" variant="attention" title={v.reachability.detail || t("result.reachedHint")}>
        {t("result.reachedBadge")}
      </Label>,
    );
  if (!v.fixed)
    out.push(
      <Label key="nofix" variant="secondary">
        {t("result.vulnViewUnfixed")}
      </Label>,
    );
  if (v.status && (everyStatus || v.status !== "fixed"))
    out.push(
      <Label key="status" variant="secondary" title={STATUS_HINT_KEY[v.status] ? t(STATUS_HINT_KEY[v.status]) : undefined}>
        {STATUS_LABEL_KEY[v.status] ? t(STATUS_LABEL_KEY[v.status]) : v.status}
      </Label>,
    );
  if (vex.state)
    out.push(
      <Label key="vex" variant={VEX_VARIANT[vex.state]} title={t("result.vexSectionHint")}>
        {t("result.vexBadge", { state: t(VEX_LABEL_KEY[vex.state]) })}
      </Label>,
    );
  if (received)
    out.push(
      <Label key="received" variant={VEX_VARIANT[received.state]} title={t("result.vexReceivedHint")}>
        {t("result.vexReceivedBadge", { state: t(VEX_LABEL_KEY[received.state]) })}
      </Label>,
    );
  return <>{out}</>;
}

/**
 * Fixed versions, one per line. When several branches are listed, the one the
 * installed version can move to is bold and green and the others are muted; the
 * highlighted one also carries a screen-reader note.
 */
export function FixedVersions({ vuln: v }: { vuln: Pick<VulnItem, "fixed" | "installed"> }) {
  const { t } = useTranslation();
  const listed = (v.fixed || "").split(/[,;]/).map((s) => s.trim()).filter(Boolean);
  if (listed.length === 0) return <span className="bl-muted">-</span>;
  const eff = effectiveFixed(v);
  return (
    <span className="bl-mono bl-fixed">
      {listed.map((f) => {
        const mine = listed.length > 1 && f === eff;
        return (
          <span key={f} className={mine ? "bl-fixed-mine" : listed.length > 1 ? "bl-muted" : undefined}>
            {f}
            {mine && <span className="bl-visually-hidden"> ({t("result.vulnFixedForBranch")})</span>}
          </span>
        );
      })}
    </span>
  );
}
