import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import type { ComponentItem } from "@/lib/api";

const TOP = 15;

/**
 * License distribution for the summary tab: how many components declare each
 * license, plus an "unlicensed" group. Reuses the SBOM component data already
 * shown in the components tab — no extra computation beyond grouping.
 */
export function LicenseSummary({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();

  const { groups, none } = useMemo(() => {
    const counts = new Map<string, number>();
    let unlicensed = 0;
    for (const c of components) {
      if (c.licenses.length === 0) {
        unlicensed += 1;
        continue;
      }
      for (const l of c.licenses) counts.set(l, (counts.get(l) ?? 0) + 1);
    }
    const sorted = [...counts.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    );
    return { groups: sorted, none: unlicensed };
  }, [components]);

  if (components.length === 0) return null;

  const shown = groups.slice(0, TOP);
  const more = groups.length - shown.length;

  return (
    <div className="space-y-3">
      <div className="text-sm font-medium">{t("result.licenseSummaryTitle")}</div>
      <div className="flex flex-wrap items-center gap-1.5">
        {shown.map(([name, n]) => (
          <Badge key={name} variant="muted">
            {name} <span className="tabular-nums opacity-70">{n}</span>
          </Badge>
        ))}
        {none > 0 && (
          <Badge variant="muted">
            {t("result.licenseNone")}{" "}
            <span className="tabular-nums opacity-70">{none}</span>
          </Badge>
        )}
        {more > 0 && (
          <span className="text-xs text-muted-foreground">
            {t("result.licenseMore", { count: more })}
          </span>
        )}
      </div>
    </div>
  );
}
