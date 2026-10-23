// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { BarList, type BarDatum } from "@/components/ui/barlist";
import { Button } from "@/components/ui/button";
import type { ComponentItem } from "@/lib/api";
import { licenseGroups, licenseRiskTier } from "@/lib/licenses";
import { useFormatNumber } from "@/lib/format";

import { TIER_FILL, TierBadge } from "./LicenseRiskBar";

/**
 * License distribution: how many components declare each license, as
 * proportional bars so the permissive bulk vs. the long tail reads at a glance.
 * Reuses the SBOM component data already shown in the Components section — no
 * extra computation beyond grouping.
 *
 * The Licenses section makes each row a link into the Components table
 * filtered to that license, and passes `collapseAfter` so an OS image with
 * hundreds of licenses opens on the busiest ones with a "show all" button (the
 * same control as the obligations card). A caller that only wants a fixed
 * preview passes `limit`.
 */
export function LicenseSummary({
  components,
  limit,
  collapseAfter,
  onPickLicense,
}: {
  components: ComponentItem[];
  /** Show at most this many licenses, with a "+N more" line. Omit for all. */
  limit?: number;
  /** Show this many licenses first, with a button that reveals the rest. */
  collapseAfter?: number;
  /** Open the Components table filtered to this license id. Rows stay inert
   *  when absent — and the unlicensed bucket always does, since the Components
   *  license filter selects an id and has no "none" option. */
  onPickLicense?: (license: string) => void;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const listId = useId();
  const [all, setAll] = useState(false);
  const { groups, unlicensed } = useMemo(
    () => licenseGroups(components),
    [components],
  );

  if (components.length === 0) return null;

  const collapsible = collapseAfter !== undefined && groups.length > collapseAfter;
  const cap = collapsible && !all ? collapseAfter : limit;
  const shown = cap === undefined ? groups : groups.slice(0, cap);
  const more = collapsible ? 0 : groups.length - shown.length;
  // Scale every bar to the busiest license so proportions stay comparable even
  // when the unlicensed bucket isn't the largest.
  const max = Math.max(1, groups[0]?.count ?? 0, unlicensed);

  // Same tier colouring as the Licenses section, so a bar means the same thing
  // in both places.
  const items: BarDatum[] = shown.map((g) => {
    const tier = licenseRiskTier(g.name);
    return {
      key: g.name,
      label: g.name,
      value: g.count,
      fill: TIER_FILL[tier],
      badge: <TierBadge tier={tier} />,
    };
  });
  if (unlicensed > 0) {
    items.push({
      key: "__none__",
      label: t("result.licenseNone"),
      value: unlicensed,
      inert: true,
    });
  }

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-body-sm font-medium">
          {t("result.licenseSummaryTitle")}{" "}
          {groups.length > 0 && (
            <span className="tabular-nums text-muted-foreground">{fmt(groups.length)}</span>
          )}
        </span>
        {onPickLicense && (
          <span className="text-label text-muted-foreground">
            {t("result.licenseRowHint")}
          </span>
        )}
      </div>
      <div id={listId}>
        <BarList
          items={items}
          max={max}
          ariaLabel={t("result.licenseSummaryTitle")}
          onActivate={onPickLicense}
          activateHint={onPickLicense ? t("result.licenseRowHint") : undefined}
        />
      </div>
      {collapsible && (
        <Button
          variant="outline"
          size="sm"
          aria-expanded={all}
          aria-controls={listId}
          data-testid="license-summary-toggle"
          onClick={() => setAll((v) => !v)}
        >
          {all
            ? t("result.licenseShowLess")
            : t("result.licenseShowAll", { count: groups.length })}
        </Button>
      )}
      {more > 0 && (
        <div className="text-label text-muted-foreground">
          {t("result.licenseMore", { count: more })}
        </div>
      )}
    </div>
  );
}
