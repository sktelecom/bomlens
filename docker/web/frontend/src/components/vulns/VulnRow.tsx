// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Fragment } from "react";
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { VulnItem } from "@/lib/api";
import { vulnAliases } from "@/lib/advisories";
import { severityTone } from "@/lib/severity";
import { receivedFor, type ReceivedIndex } from "@/lib/vexReceived";
import { cn } from "@/lib/utils";

import { vulnLinks, VulnDetail, type VexFields } from "./VulnDetail";
import {
  STATUS_HINT_KEY,
  STATUS_LABEL_KEY,
  STATUS_TONE,
  VEX_LABEL_KEY,
  VEX_TONE,
} from "./vulnStatus";

/** Number of columns of the table (severity, CVSS, CVE, package, installed,
 *  fixed) before the optional EPSS and NVD severity columns. */
export const BASE_COLUMNS = 6;

interface Props {
  vuln: VulnItem;
  isOpen: boolean;
  onToggle: () => void;
  anyEpss: boolean;
  anyNvdSeverity: boolean;
  scanId?: string | null;
  /** A verdict saved this session, overriding what the scan payload carried. */
  override?: VexFields;
  /** The VEX document imported this session; wins over the scan payload. */
  imported: ReceivedIndex | null;
  onPickComponent?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
  onVexSaved: (saved: VexFields) => void;
}

/** One CVE row, and the detail row it expands into. */
export function VulnRow({
  vuln: v,
  isOpen,
  onToggle,
  anyEpss,
  anyNvdSeverity,
  scanId,
  override,
  imported,
  onPickComponent,
  onPickDependency,
  onVexSaved,
}: Props) {
  const { t } = useTranslation();
  const links = vulnLinks(v);
  const vex: VexFields = override ?? {
    state: v.vexState,
    detail: v.vexDetail,
    updatedAt: v.vexUpdatedAt,
  };
  const received = imported ? receivedFor(imported, v) : v.vexReceived;
  const hasDetail =
    v.cvss != null ||
    !!v.description ||
    links.length > 0 ||
    !!v.publishedDate ||
    // The judgement panel is reachable even for a CVE with no other
    // detail: a component's own scan is the one place to set it.
    Boolean(scanId) ||
    Boolean(vex.state) ||
    Boolean(received);
  const aliases = vulnAliases(v);
  const hasStatus =
    Boolean(v.status) ||
    Boolean(vex.state) ||
    Boolean(received) ||
    v.reachability?.state === "exploitable" ||
    Boolean(v.kev);
  return (
    <Fragment>
      <tr
        className={cn(
          "border-b align-top last:border-0 hover:bg-accent/50",
          hasDetail && "cursor-pointer",
        )}
        {...(hasDetail
          ? {
              role: "button",
              tabIndex: 0,
              "aria-expanded": isOpen,
              "aria-label": t("result.vulnRowToggle"),
              onClick: onToggle,
              onKeyDown: (e: React.KeyboardEvent) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onToggle();
                }
              },
            }
          : {})}
      >
        <td className="px-3 py-2">
          <div className="flex items-center gap-1.5">
            {hasDetail ? (
              <ChevronRight
                className={cn(
                  "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                  isOpen && "rotate-90",
                )}
                aria-hidden
              />
            ) : (
              <span className="w-3.5 shrink-0" />
            )}
            <Badge tone={severityTone(v.severity)} mark>
              {t(`severity.${v.severity}`)}
            </Badge>
          </div>
        </td>
        <td className="px-3 py-2 font-mono tabular-nums">
          {v.cvss != null ? v.cvss : <span className="text-muted-foreground">—</span>}
        </td>
        {anyEpss && (
          <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
            {typeof v.epss === "number" ? `${(v.epss * 100).toFixed(1)}%` : "—"}
          </td>
        )}
        {anyNvdSeverity && (
          <td className="px-3 py-2">
            {v.nvdSeverity ? (
              <Badge tone={severityTone(v.nvdSeverity)} mark>
                {t(`severity.${v.nvdSeverity}`)}
              </Badge>
            ) : (
              <span className="text-muted-foreground">—</span>
            )}
          </td>
        )}
        <td className="px-3 py-2">
          <span className="font-mono">{v.id}</span>
          {/* Status badges sit under the ID rather than beside the severity:
              three in one cell made the severity column wide enough to push
              the fixed-version column out of a 1440px window. */}
          {hasStatus ? (
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {v.status && (
                <Badge
                  tone={STATUS_TONE[v.status] ?? "info"}
                  title={STATUS_HINT_KEY[v.status] ? t(STATUS_HINT_KEY[v.status]) : undefined}
                >
                  {STATUS_LABEL_KEY[v.status] ? t(STATUS_LABEL_KEY[v.status]) : v.status}
                </Badge>
              )}
              {vex.state && (
                <Badge tone={VEX_TONE[vex.state]} title={t("result.vexSectionHint")}>
                  {t("result.vexBadge", { state: t(VEX_LABEL_KEY[vex.state]) })}
                </Badge>
              )}
              {received && (
                <Badge tone={VEX_TONE[received.state]} title={t("result.vexReceivedHint")}>
                  {t("result.vexReceivedBadge", { state: t(VEX_LABEL_KEY[received.state]) })}
                </Badge>
              )}
              {v.reachability?.state === "exploitable" && (
                <Badge tone="medium" title={v.reachability.detail || t("result.reachedHint")}>
                  {t("result.reachedBadge")}
                </Badge>
              )}
              {v.kev && (
                <Badge tone="critical" title={t("result.kevHint")}>
                  {t("result.kevBadge")}
                </Badge>
              )}
            </div>
          ) : null}
          {aliases.length > 0 ? (
            <div className="mt-0.5 text-muted-foreground">
              {t("result.vulnAliases")} <span className="font-mono">{aliases.join(", ")}</span>
            </div>
          ) : null}
          {v.title ? <div className="mt-0.5 max-w-md text-muted-foreground">{v.title}</div> : null}
        </td>
        <td className="px-3 py-2 font-mono [overflow-wrap:anywhere]">{v.pkg}</td>
        <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground [overflow-wrap:anywhere]">
          {v.installed || "—"}
        </td>
        {/* Fixed version carries the success foreground, which is set to the
            darker green on light surfaces: the lighter one measures 3.77 there,
            under the 4.5 minimum. */}
        <td className="px-3 py-2 font-mono tabular-nums [overflow-wrap:anywhere]">
          {v.fixed ? (
            // A list of fixed versions wraps after each comma. A single long
            // version (a Debian revision) can still break, so it never pushes
            // the column out of the table.
            <span className="text-success">{v.fixed.split(/,\s*/).join(", ")}</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
      </tr>
      {isOpen && (
        <tr className="border-b last:border-0">
          <td
            colSpan={BASE_COLUMNS + (anyEpss ? 1 : 0) + (anyNvdSeverity ? 1 : 0)}
            className="bg-muted/30 px-3 py-3"
          >
            <VulnDetail
              vuln={v}
              links={links}
              onPickComponent={onPickComponent}
              onPickDependency={onPickDependency}
              scanId={scanId}
              vex={vex}
              received={received}
              onVexSaved={onVexSaved}
            />
          </td>
        </tr>
      )}
    </Fragment>
  );
}
