// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, PackageIcon } from "@primer/octicons-react";
import { Label } from "@primer/react";
import { useTranslation } from "react-i18next";

import { PackageCoordinate, SeverityLabel, splitPackage } from "@/components/primer";
import { bundleSteps, type PackageGroup } from "@/lib/vulnGroups";

/** Bundles shown before the rest are summarised as a count. */
const SHOWN = 5;

/**
 * "One upgrade resolves more than one CVE": a collapsed box that says how many
 * packages and CVEs it covers; opened, one line per package, worst severity
 * first. Choosing a package searches the table for it.
 */
export function UpgradeBundles({
  bundles,
  onPick,
  onByPackage,
}: {
  bundles: PackageGroup[];
  onPick: (pkg: string) => void;
  onByPackage: () => void;
}) {
  const { t } = useTranslation();
  if (bundles.length === 0) return null;
  const cves = bundles.reduce((n, g) => n + g.steps[g.steps.length - 1].count, 0);
  return (
    <details className="bl-box bl-v-bundles" data-testid="upgrade-bundles">
      <summary className="bl-v-bundles-sum">
        <span className="bl-chev">
          <ChevronRightIcon size={16} />
        </span>
        <span className="bl-ovrow-icon">
          <PackageIcon size={16} />
        </span>
        <h2 className="bl-v-h2">{t("result.vulnBundleSummary", { count: bundles.length, cves })}</h2>
      </summary>
      <div className="bl-v-bundles-sub bl-muted">
        {t("result.upgradeBundlesTitle")}
        <button type="button" className="bl-linkbtn bl-small" onClick={onByPackage}>
          {t("result.vulnViewByPackage")}
        </button>
      </div>
      <ul className="bl-v-bundles-list">
        {bundles.slice(0, SHOWN).map((g) => {
          const { top, lower } = bundleSteps(g);
          const rest =
            lower.length === 0
              ? t("result.pkgGroupUpgrade", { fixed: top.fixed, count: top.count })
              : t("result.pkgGroupUpgradeSteps", {
                  fixed: top.fixed,
                  count: top.count,
                  steps: lower.map((s) => t("result.upgradeBundleStep", { fixed: s.fixed, count: s.count })).join(", "),
                });
          return (
            <li key={g.key}>
              <SeverityLabel severity={g.maxSeverity} quiet />
              <button type="button" className="bl-linkbtn" onClick={() => onPick(g.pkg)} title={t("result.vulnSearchPlaceholder")}>
                <PackageCoordinate {...splitPackage(g.pkg)} title={g.pkg} strongName className="bl-mono bl-breakall" />
              </button>
              <span>{rest}</span>
              {g.kev && (
                <Label variant="danger" title={t("result.kevHint")}>
                  {t("result.kevBadge")}
                </Label>
              )}
            </li>
          );
        })}
      </ul>
      {bundles.length > SHOWN && (
        <p className="bl-muted bl-small bl-v-bundles-more">{t("result.upgradeBundlesMore", { count: bundles.length - SHOWN })}</p>
      )}
    </details>
  );
}
