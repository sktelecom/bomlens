// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CheckIcon, GearIcon, ListUnorderedIcon, PackageIcon, SearchIcon } from "@primer/octicons-react";
import { ActionList, ActionMenu, SegmentedControl, TextInput } from "@primer/react";
import { useTranslation } from "react-i18next";

import { ActiveFilters, SeverityLabel, severityFill } from "@/components/primer";
import { SEVERITY_ORDER, type SecuritySummary, type Severity } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import type { Density } from "@/lib/tableDensity";
import { VULN_VIEWS, type VulnLayout, type VulnView } from "@/lib/vulnView";

const VIEW_LABEL: Record<VulnView, string> = {
  all: "result.vulnViewAll",
  fixable: "result.vulnViewFixable",
  unfixed: "result.vulnViewUnfixed",
  exploited: "result.vulnViewExploited",
  "critical-high": "result.vulnViewCriticalHigh",
  "fixable-severe": "result.vulnViewFixableSevere",
};

export interface ColumnChoice {
  id: string;
  label: string;
  checked: boolean;
  onToggle: () => void;
  /** How many rows carry a value, shown at the end of the menu item. */
  detail?: string;
}

/**
 * Preset views with their counts (one segment each; an empty preset is disabled
 * unless it is the one on screen) and the View menu: layout, row height and the
 * optional columns. "Critical and High with a fix", opened from the Overview,
 * has no segment of its own: it shows as the Critical and High segment plus a
 * removable filter.
 */
export function ViewRow({
  view,
  counts,
  onView,
  layout,
  onLayout,
  density,
  onDensity,
  columns,
}: {
  view: VulnView;
  counts: Record<VulnView, number>;
  onView: (view: VulnView) => void;
  layout: VulnLayout;
  onLayout: (layout: VulnLayout) => void;
  density: Density;
  onDensity: (density: Density) => void;
  columns: ColumnChoice[];
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const segmentView: VulnView = view === "fixable-severe" ? "critical-high" : view;
  return (
    <div className="bl-v-viewrow">
      <div className="bl-v-views">
        <SegmentedControl aria-label={t("result.vulnViews")} onChange={(i) => onView(VULN_VIEWS[i])} data-testid="vuln-views">
          {VULN_VIEWS.map((v) => (
            <SegmentedControl.Button key={v} selected={segmentView === v} count={fmt(counts[v])} disabled={counts[v] === 0 && segmentView !== v}>
              {t(VIEW_LABEL[v])}
            </SegmentedControl.Button>
          ))}
        </SegmentedControl>
      </div>
      <ActionMenu>
        <ActionMenu.Button leadingVisual={GearIcon} data-testid="vuln-view-menu">
          {t("result.vulnViewMenu")}
        </ActionMenu.Button>
        <ActionMenu.Overlay width="auto" align="end">
          <ActionList>
            <ActionList.Group selectionVariant="single" data-testid="vuln-layout">
              <ActionList.GroupHeading>{t("result.vulnLayout")}</ActionList.GroupHeading>
              <ActionList.Item selected={layout === "list"} onSelect={() => onLayout("list")}>
                <ActionList.LeadingVisual>
                  <ListUnorderedIcon />
                </ActionList.LeadingVisual>
                {t("result.vulnLayoutList")}
              </ActionList.Item>
              <ActionList.Item selected={layout === "package"} onSelect={() => onLayout("package")}>
                <ActionList.LeadingVisual>
                  <PackageIcon />
                </ActionList.LeadingVisual>
                {t("result.vulnLayoutPackage")}
              </ActionList.Item>
            </ActionList.Group>
            <ActionList.Divider />
            <ActionList.Group selectionVariant="single" data-testid="density-toggle">
              <ActionList.GroupHeading>{t("result.density")}</ActionList.GroupHeading>
              <ActionList.Item selected={density === "compact"} onSelect={() => onDensity("compact")}>
                {t("result.densityCompact")}
              </ActionList.Item>
              <ActionList.Item selected={density === "comfortable"} onSelect={() => onDensity("comfortable")}>
                {t("result.densityComfortable")}
              </ActionList.Item>
            </ActionList.Group>
            {columns.length > 0 && (
              <>
                <ActionList.Divider />
                <ActionList.Group selectionVariant="multiple">
                  <ActionList.GroupHeading>{t("result.vulnColumnsGroup")}</ActionList.GroupHeading>
                  {columns.map((c) => (
                    <ActionList.Item key={c.id} selected={c.checked} onSelect={c.onToggle}>
                      {c.label}
                      {c.detail && <ActionList.Description variant="block">{c.detail}</ActionList.Description>}
                    </ActionList.Item>
                  ))}
                </ActionList.Group>
              </>
            )}
          </ActionList>
        </ActionMenu.Overlay>
      </ActionMenu>
    </div>
  );
}

/**
 * Search, the severity distribution bar with its filter buttons, and the active
 * filters with "M of N shown". Picking a severity again clears it; the bar dims
 * the other severities while one is picked.
 */
export function FilterRow({
  security,
  term,
  onTerm,
  severity,
  onSeverity,
  chips,
  onClear,
  shown,
}: {
  security: SecuritySummary;
  term: string;
  onTerm: (term: string) => void;
  severity: string;
  onSeverity: (s: Severity) => void;
  chips: { key: string; label: string; onRemove: () => void }[];
  onClear: () => void;
  shown?: string;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const total = security.TOTAL || 1;
  const bar = SEVERITY_ORDER.map((s) => `${t(`severity.${s}`)} ${fmt(security[s])}`).join(", ");
  return (
    <>
      <div className="bl-v-filterbar">
        <div className="bl-v-search">
          <TextInput
            block
            type="search"
            leadingVisual={SearchIcon}
            value={term}
            onChange={(e) => onTerm(e.target.value)}
            placeholder={t("result.vulnSearchPlaceholder")}
            aria-label={t("result.vulnSearchPlaceholder")}
            data-testid="vuln-search"
          />
        </div>
        <div className="bl-v-sev">
          <div className="bl-v-bar" role="img" aria-label={`${t("result.severityTitle")}: ${bar}`}>
            {SEVERITY_ORDER.map((s) =>
              security[s] ? (
                <span key={s} style={{ flex: security[s] / total, background: severityFill(s), opacity: severity && severity !== s ? 0.3 : 1 }} />
              ) : null,
            )}
          </div>
          <div className="bl-v-chipgroup" role="group" aria-label={t("result.vulnFilterBySeverity")} aria-describedby="bl-v-sev-hint" data-active={Boolean(severity)}>
            {SEVERITY_ORDER.map((s) => (
              <button
                key={s}
                type="button"
                className="bl-v-chip"
                aria-pressed={severity === s}
                disabled={security[s] === 0}
                onClick={() => onSeverity(s)}
              >
                <SeverityLabel severity={s} count={security[s]} quiet />
                {severity === s && (
                  <span className="bl-v-check">
                    <CheckIcon size={12} />
                  </span>
                )}
              </button>
            ))}
          </div>
          <span id="bl-v-sev-hint" className="bl-visually-hidden">
            {t("result.vulnSeverityChipHint")}
          </span>
        </div>
      </div>
      <ActiveFilters chips={chips} onClear={onClear} summary={shown} />
    </>
  );
}
