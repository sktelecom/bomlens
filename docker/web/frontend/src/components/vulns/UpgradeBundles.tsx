// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { PackageCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { CALLOUT } from "@/components/ui/coverage-notice";
import { severityTone } from "@/lib/severity";
import { bundleSteps, type PackageGroup } from "@/lib/vulnGroups";
import { cn } from "@/lib/utils";

/** Bundles shown before the rest are summarised as a count. */
const SHOWN = 5;

/**
 * "One upgrade resolves more than one CVE". The same callout surface as the
 * coverage notices above the table, with an info-role icon (the brand colour is not a data colour), one line per package,
 * worst severity first. Clicking a line searches the table for that package.
 */
export function UpgradeBundles({
  bundles,
  onPick,
}: {
  bundles: PackageGroup[];
  onPick: (pkg: string) => void;
}) {
  const { t } = useTranslation();
  if (bundles.length === 0) return null;
  return (
    <section
      data-testid="upgrade-bundles"
      aria-labelledby="upgrade-bundles-title"
      className={cn("space-y-2", CALLOUT)}
    >
      <h3
        id="upgrade-bundles-title"
        className="flex items-center gap-1.5 text-label font-medium text-foreground"
      >
        <PackageCheck className="h-4 w-4 shrink-0 text-role-info-fg" aria-hidden />
        {t("result.upgradeBundlesTitle")}
      </h3>
      <ul className="space-y-1">
        {bundles.slice(0, SHOWN).map((g) => {
          const { top, lower } = bundleSteps(g);
          const line =
            lower.length === 0
              ? t("result.upgradeBundleLine", { pkg: g.pkg, fixed: top.fixed, count: top.count })
              : t("result.upgradeBundleLineSteps", {
                  pkg: g.pkg,
                  fixed: top.fixed,
                  count: top.count,
                  steps: lower
                    .map((s) => t("result.upgradeBundleStep", { fixed: s.fixed, count: s.count }))
                    .join(", "),
                });
          return (
            <li key={g.key} className="flex flex-wrap items-center gap-2">
              <Badge tone={severityTone(g.maxSeverity)} mark>
                {t(`severity.${g.maxSeverity}`)}
              </Badge>
              <button
                type="button"
                onClick={() => onPick(g.pkg)}
                className="rounded text-left text-label text-primary underline underline-offset-2 hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {line}
              </button>
              {g.kev && (
                <Badge tone="critical" title={t("result.kevHint")}>
                  {t("result.kevBadge")}
                </Badge>
              )}
            </li>
          );
        })}
      </ul>
      {bundles.length > SHOWN && (
        <p className="text-body-sm text-muted-foreground">
          {t("result.upgradeBundlesMore", { count: bundles.length - SHOWN })}
        </p>
      )}
    </section>
  );
}
