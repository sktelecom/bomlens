import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { BarList, type BarDatum } from "@/components/ui/barlist";
import type { ComponentItem } from "@/lib/api";
import { isCopyleft, licenseGroups } from "@/lib/licenses";

const TOP = 8;

/**
 * License distribution for the Overview: how many components declare each
 * license, shown as proportional bars so the permissive bulk vs. the long tail
 * reads at a glance. Reuses the SBOM component data already shown in the
 * Components section — no extra computation beyond grouping.
 */
export function LicenseSummary({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();
  const { groups, unlicensed } = useMemo(
    () => licenseGroups(components),
    [components],
  );

  if (components.length === 0) return null;

  const shown = groups.slice(0, TOP);
  const more = groups.length - shown.length;
  // Scale every bar to the busiest license so proportions stay comparable even
  // when the unlicensed bucket isn't the largest.
  const max = Math.max(1, groups[0]?.count ?? 0, unlicensed);

  const items: BarDatum[] = shown.map((g) => ({
    key: g.name,
    label: g.name,
    value: g.count,
    emphasis: isCopyleft(g.name),
  }));
  if (unlicensed > 0) {
    items.push({ key: "__none__", label: t("result.licenseNone"), value: unlicensed });
  }

  return (
    <div className="space-y-3">
      <div className="text-sm font-medium">{t("result.licenseSummaryTitle")}</div>
      <BarList items={items} max={max} ariaLabel={t("result.licenseSummaryTitle")} />
      {more > 0 && (
        <div className="text-xs text-muted-foreground">
          {t("result.licenseMore", { count: more })}
        </div>
      )}
    </div>
  );
}
