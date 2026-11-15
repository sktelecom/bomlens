// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  BugIcon,
  CalendarIcon,
  ChecklistIcon,
  CpuIcon,
  EyeIcon,
  FlameIcon,
  HistoryIcon,
  ShieldIcon,
  ToolsIcon,
} from "@primer/octicons-react";
import { CounterLabel } from "@primer/react";
import type { ElementType } from "react";
import { useTranslation } from "react-i18next";

import type { DoneEvent } from "@/lib/api";
import { formatDateTime, useFormatNumber } from "@/lib/format";
import { type AttentionItem, firstChecks, overviewAttention, staleRows } from "@/lib/overview";
import { scanHash } from "@/lib/route";

import { OvRow } from "./parts";

const FIRST_ICON = { knownExploited: FlameIcon, fixableSevere: ToolsIcon, requiredItems: ChecklistIcon } as const;

const ATTN_ICON: Record<AttentionItem["id"], ElementType> = {
  malicious: BugIcon,
  conformance: ChecklistIcon,
  vulns: ShieldIcon,
  review: EyeIcon,
  modelRisk: CpuIcon,
  conformanceGap: ChecklistIcon,
};

const ATTN_KEY: Record<AttentionItem["id"], string> = {
  malicious: "overview.attnMalicious",
  conformance: "overview.attnConformance",
  vulns: "overview.attnVulns",
  review: "overview.attnReview",
  modelRisk: "overview.attnModelRisk",
  conformanceGap: "overview.attnConformanceGap",
};

/** The icon colour of an attention row. Red only for the critical ones. */
const TONE_FG: Record<AttentionItem["tone"], string> = {
  critical: "var(--fgColor-danger)",
  high: "var(--fgColor-severe)",
  info: "var(--fgColor-muted)",
};

/**
 * "Items to check first" and "Needs attention" in one Box. The first part is up
 * to three links with the count each rests on, where the count came from and
 * when the scan was made: a reference order, not a verdict or a ranking, so its
 * icons are neutral. The second part lists what else is worth a look, without
 * the rows the first part already carries (`overviewAttention`), then the
 * components past end of life and the outdated ones, which used to be cards.
 * Every row keeps its section filter. Renders nothing when no row applies.
 */
export function AttentionBox({
  result,
  scanId,
  generatedAt,
}: {
  result: DoneEvent;
  scanId: string | null;
  generatedAt?: number;
}) {
  const { t, i18n } = useTranslation();
  const fmt = useFormatNumber();
  const items = firstChecks(result);
  const to = (section: Parameters<typeof scanHash>[1], query?: Record<string, string>) =>
    scanId ? scanHash(scanId, section, query) : undefined;

  const rows = [
    ...overviewAttention(result).map((item) => ({
      key: item.id,
      Icon: ATTN_ICON[item.id],
      color: TONE_FG[item.tone],
      label: t(ATTN_KEY[item.id], { count: item.count }),
      sub: undefined as string | undefined,
      // The filter travels with the link: the Critical and High row opens
      // exactly the rows it counted.
      href: to(item.target, item.query),
    })),
    ...staleRows(result).map((row) => ({
      key: row.id,
      Icon: row.id === "eol" ? CalendarIcon : HistoryIcon,
      color: TONE_FG.info,
      label: t(row.id === "eol" ? "overview.attnEol" : "overview.attnOutdated", { count: row.count }),
      sub: row.atRisk ? t("result.eolAtRisk", { count: row.atRisk }) : undefined,
      href: to(row.target, row.query),
    })),
  ];
  if (items.length === 0 && rows.length === 0) return null;

  const asOf = generatedAt ? t("overview.firstChecks.asOf", { time: formatDateTime(generatedAt, i18n.language) }) : "";
  const onlyAttention = items.length === 0;

  return (
    <section className="bl-box" data-testid="first-checks" aria-labelledby="ov-attn-title">
      <div className="bl-box-head" style={{ flexDirection: "column", alignItems: "flex-start", gap: "var(--base-size-4)" }}>
        <h2 id="ov-attn-title">{t(onlyAttention ? "overview.needsAttention" : "overview.firstChecks.title")}</h2>
        {!onlyAttention && <span className="bl-muted bl-small">{t("overview.firstChecks.note")}</span>}
      </div>
      {items.length > 0 && (
        <ol className="bl-ovlist">
          {items.map((item) => {
            const source =
              item.source === "conformance"
                ? t("overview.firstChecks.sourceConformance")
                : item.rowsListed !== undefined
                  ? t("overview.firstChecks.sourceVulnsPartial", { listed: fmt(item.rowsListed), total: fmt(item.rowsTotal ?? 0) })
                  : t("overview.firstChecks.sourceVulns");
            return (
              <li key={item.id}>
                <OvRow
                  href={to(item.target, item.query)}
                  icon={FIRST_ICON[item.id]}
                  end={<CounterLabel>{fmt(item.count)}</CounterLabel>}
                >
                  <span>{t(`overview.firstChecks.${item.id}`)}</span>
                  <span className="bl-muted bl-small">{asOf ? `${source}, ${asOf}` : source}</span>
                </OvRow>
              </li>
            );
          })}
        </ol>
      )}
      {rows.length > 0 && (
        <>
          {!onlyAttention && <h3 className="bl-box-sub">{t("overview.needsAttention")}</h3>}
          <ul className="bl-ovlist" data-testid="needs-attention">
            {rows.map((r) => (
              <li key={r.key}>
                <OvRow href={r.href} icon={r.Icon} iconColor={r.color}>
                  <span>
                    {r.label}
                    {r.sub && (
                      <span className="bl-ovrow-sub" style={{ color: "var(--fgColor-attention)" }}>
                        {r.sub}
                      </span>
                    )}
                  </span>
                </OvRow>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
