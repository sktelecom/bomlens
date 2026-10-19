// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { Layers, List } from "lucide-react";

import { DensityToggle } from "@/components/ui/density-toggle";
import { FilterChip } from "@/components/ui/filter-chip";
import { FOCUS_RING, SELECTED_SOLID } from "@/components/ui/selectable";
import { useFormatNumber } from "@/lib/format";
import type { Density } from "@/lib/tableDensity";
import { cn } from "@/lib/utils";
import { VULN_VIEWS, type VulnLayout, type VulnView } from "@/lib/vulnView";

const VIEW_LABEL: Record<VulnView, string> = {
  all: "result.vulnViewAll",
  fixable: "result.vulnViewFixable",
  unfixed: "result.vulnViewUnfixed",
  exploited: "result.vulnViewExploited",
  "critical-high": "result.vulnViewCriticalHigh",
};

const LAYOUTS: { value: VulnLayout; labelKey: string; Icon: typeof List }[] = [
  { value: "list", labelKey: "result.vulnLayoutList", Icon: List },
  { value: "package", labelKey: "result.vulnLayoutPackage", Icon: Layers },
];

/**
 * The three things that change how the table reads without changing what it
 * holds: a preset view (chips), the layout (flat list or one block per
 * package), and the row density.
 */
export function VulnViewBar({
  view,
  counts,
  onView,
  layout,
  onLayout,
  density,
  onDensity,
}: {
  view: VulnView;
  counts: Record<VulnView, number>;
  onView: (view: VulnView) => void;
  layout: VulnLayout;
  onLayout: (layout: VulnLayout) => void;
  density: Density;
  onDensity: (density: Density) => void;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div
        role="group"
        aria-label={t("result.vulnViews")}
        data-testid="vuln-views"
        className="flex flex-wrap items-center gap-1.5"
      >
        {VULN_VIEWS.map((v) => (
          <FilterChip
            key={v}
            active={view === v}
            // An empty preset has nothing to show; it stays clickable while it
            // is the active one so a shared link into it can be left again.
            disabled={counts[v] === 0 && view !== v}
            onClick={() => onView(v)}
          >
            {t(VIEW_LABEL[v])}
            <span className="ml-1.5 tabular-nums">{fmt(counts[v])}</span>
          </FilterChip>
        ))}
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2">
        <div
          role="group"
          aria-label={t("result.vulnLayout")}
          data-testid="vuln-layout"
          className="inline-flex shrink-0 rounded-md border p-0.5"
        >
          {LAYOUTS.map(({ value, labelKey, Icon }) => (
            <button
              key={value}
              type="button"
              aria-pressed={layout === value}
              onClick={() => onLayout(value)}
              className={cn(
                "inline-flex items-center gap-1 rounded border border-transparent px-2 py-1 text-label font-medium transition-colors duration-fast ease-out-soft",
                FOCUS_RING,
                layout === value
                  ? SELECTED_SOLID
                  : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden />
              {t(labelKey)}
            </button>
          ))}
        </div>
        <DensityToggle density={density} onChange={onDensity} />
      </div>
    </div>
  );
}
