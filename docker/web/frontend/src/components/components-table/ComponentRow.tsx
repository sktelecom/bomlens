// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Package } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import type { ComponentItem, Severity } from "@/lib/api";
import { licenseBadges } from "@/lib/components";
import { useFormatNumber } from "@/lib/format";

const SEV_TONE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

/** Which optional columns the table is showing right now. */
export interface ShownColumns {
  version: boolean;
  type: boolean;
  scope: boolean;
  risk: boolean;
  license: boolean;
}

interface Props {
  item: ComponentItem;
  isOpen: boolean;
  onToggle: () => void;
  shown: ShownColumns;
  /** Total number of columns, for the expanded detail row to span. */
  colCount: number;
  onPickVulns?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
}

/** One component row and, when open, the detail row it expands into. */
export function ComponentRow({
  item: c,
  isOpen,
  onToggle,
  shown,
  colCount,
  onPickVulns,
  onPickDependency,
}: Props) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const { version: showVersion, type: showType, scope: showScope, risk: showRisk, license: showLicense } = shown;
  const lic = licenseBadges(c.licenses);
  return (
    <>
    {/* role="button" makes aria-expanded valid here (it is not allowed
        on a plain table row) and, with tabIndex + the key handler,
        keeps the expandable row reachable by keyboard. */}
    <tr
      className="group cursor-pointer border-b last:border-0 hover:bg-accent/50"
      role="button"
      tabIndex={0}
      aria-expanded={isOpen}
      aria-label={t("result.componentRowToggle")}
      onClick={onToggle}
      onKeyDown={(e: React.KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
    >
      {/* Pinned like its header. The row tint is painted per-cell here
          (group-hover) because a pinned cell needs its own opaque
          background and would otherwise stay unhighlighted. */}
      <td className="sticky left-0 z-10 max-w-80 bg-background px-3 py-2 group-hover:bg-accent/50">
        <div className="flex items-center gap-2">
          <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <span
            className="truncate font-mono"
            title={`${c.group ? `${c.group} / ` : ""}${c.name}`}
          >
            {c.group ? `${c.group} / ` : ""}
            {c.name}
          </span>
          {c.vendored && (
            <Badge
              variant="muted"
              title={
                c.matchConfidence
                  ? `${t("result.vendoredBadgeHint")} (${t("result.vendoredMatch", { pct: c.matchConfidence })})`
                  : t("result.vendoredBadgeHint")
              }
            >
              {t("result.vendoredBadge")}
            </Badge>
          )}
          {/* Leads the badges: a package to remove outranks anything
              that is merely out of date or vulnerable. */}
          {c.malicious && (
            <Badge
              tone="critical"
              title={
                c.maliciousId
                  ? `${t("result.maliciousBadgeHint")} (${c.maliciousId}${c.maliciousSource ? `, ${c.maliciousSource}` : ""})`
                  : t("result.maliciousBadgeHint")
              }
            >
              {t("result.maliciousBadge")}
            </Badge>
          )}
          {c.eol === "true" && (
            <Badge tone="high" title={t("result.eolBadgeHint")}>
              {t("result.eolBadge")}
              {c.eolDate ? ` · ${t("result.eolSince", { date: c.eolDate })}` : ""}
            </Badge>
          )}
          {/* Weaker emphasis than EOL: a supported component that simply
              has a newer patch available. Muted, not warning-toned. */}
          {c.outdated === "true" && (
            <Badge variant="muted" title={t("result.outdatedBadgeHint")}>
              {t("result.outdatedBadge")}
              {c.latestVersion
                ? ` · ${t("result.outdatedLatest", { version: c.latestVersion })}`
                : ""}
            </Badge>
          )}
        </div>
      </td>
      {/* A presence-only row has no version by construction, so an
          em dash here would read as a gap in the data rather than as
          the finding it is: the component is there, the version is
          not recoverable, and no advisory lookup applies to it. */}
      {showVersion && (
      <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted-foreground">
        {c.version || (c.presenceOnly ? (
          <span
            className="font-sans text-label"
            title={t("result.presenceOnlyHint")}
          >
            {t("result.presenceOnlyVersion")}
          </span>
        ) : "—")}
      </td>
      )}
      {showType && (
      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">{c.type || "—"}</td>
      )}
      {showScope && (
        <td className="whitespace-nowrap px-3 py-2">
          {c.scope ? (
            <span
              className={
                c.scope === "direct"
                  ? "font-medium text-foreground"
                  : "text-muted-foreground"
              }
            >
              {t(c.scope === "direct" ? "result.scopeDirect" : "result.scopeTransitive")}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
      )}
      {showRisk && (
        <td className="whitespace-nowrap px-3 py-2">
          {c.maxSeverity ? (
            <Badge tone={SEV_TONE[c.maxSeverity]} mark>
              {t(`severity.${c.maxSeverity}`)}
              {c.vulnCount ? ` · ${fmt(c.vulnCount)}` : ""}
            </Badge>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
      )}
      {/* Badges past the limit fold into a count so a component with a
          dozen licenses does not stand three rows tall. The expanded
          row below lists them all. */}
      {showLicense && (
      <td className="whitespace-nowrap px-3 py-2">
        {c.licenses.length ? (
          <div className="flex items-center gap-1">
            {lic.shown.map((l, j) => (
              <Badge key={j} variant="muted">
                {l}
              </Badge>
            ))}
            {lic.hidden > 0 && (
              <span
                className="text-muted-foreground"
                title={c.licenses.join(", ")}
              >
                {t("result.licenseMore", { count: lic.hidden })}
              </span>
            )}
          </div>
        ) : (
          <span className="text-muted-foreground">{t("result.licenseNone")}</span>
        )}
      </td>
      )}
    </tr>
    {isOpen && (
      <tr className="border-b last:border-0">
        <td colSpan={colCount} className="bg-muted/30 px-3 py-3">
          <dl className="grid grid-cols-[max-content,1fr] gap-x-4 gap-y-1.5 text-label">
            {c.purl ? (
              <>
                <dt className="font-medium text-muted-foreground">purl</dt>
                <dd className="break-all font-mono">{c.purl}</dd>
              </>
            ) : null}
            {c.source ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("result.colSource")}</dt>
                <dd>
                  <a
                    href={c.source}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="break-all text-primary underline-offset-2 hover:underline"
                  >
                    {c.source}
                  </a>
                </dd>
              </>
            ) : null}
            {c.copyright ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("result.colCopyright")}</dt>
                <dd className="break-words">{c.copyright}</dd>
              </>
            ) : null}
            {c.licenses.length > 0 ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("result.colLicense")}</dt>
                <dd>{c.licenses.join(", ")}</dd>
              </>
            ) : null}
            {c.eol === "true" ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("result.colEol")}</dt>
                <dd>
                  {t("result.eolBadge")}
                  {c.eolDate ? ` (${c.eolDate})` : ""}
                </dd>
              </>
            ) : null}
            {c.outdated === "true" ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("result.colCurrency")}</dt>
                <dd>
                  {c.latestVersion
                    ? t("result.outdatedLatest", { version: c.latestVersion })
                    : t("result.outdatedBadge")}
                  {typeof c.releasesBehind === "number"
                    ? ` · ${t("result.outdatedReleasesBehind", { count: c.releasesBehind })}`
                    : ""}
                  {c.lastReleased
                    ? ` · ${t("result.outdatedLastReleased", { date: c.lastReleased })}`
                    : ""}
                </dd>
              </>
            ) : null}
            {c.vulnCount ? (
              <>
                <dt className="font-medium text-muted-foreground">{t("nav.vulnerabilities")}</dt>
                <dd className="flex flex-wrap items-baseline gap-2">
                  <span>
                    {c.maxSeverity ? `${t(`severity.${c.maxSeverity}`)} · ` : ""}
                    {fmt(c.vulnCount)}
                  </span>
                  {/* Into the CVEs behind this row. It sits in the
                      expanded detail rather than on the risk badge
                      because the row itself is the toggle control,
                      and a control inside a control is not announced
                      reliably. */}
                  {onPickVulns && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onPickVulns(c.name);
                      }}
                      className="rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {t("result.viewInVulns", { name: c.name })}
                    </button>
                  )}
                </dd>
              </>
            ) : null}
            {onPickDependency && (
              <>
                <dt className="font-medium text-muted-foreground">{t("nav.dependencies")}</dt>
                <dd>
                  {/* Same reason as View in Vulnerabilities above: the
                      row itself is the toggle control. */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onPickDependency(c.name, c.version);
                    }}
                    className="rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    {t("result.viewInDependencies", { name: c.name })}
                  </button>
                </dd>
              </>
            )}
          </dl>
        </td>
      </tr>
    )}
    </>
  );
}
