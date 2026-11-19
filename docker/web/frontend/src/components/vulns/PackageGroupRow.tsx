// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDownIcon, ChevronRightIcon } from "@primer/octicons-react";
import { Label } from "@primer/react";
import { Table } from "@primer/react/experimental";
import { useTranslation } from "react-i18next";

import { PackageCoordinate, SeverityLabel, splitPackage } from "@/components/primer";
import { useFormatNumber } from "@/lib/format";
import { bundleSteps, type PackageGroup } from "@/lib/vulnGroups";

/**
 * Head of one package in the by-package layout: worst severity, package and
 * installed version, how many CVEs, known exploited, and what upgrading would do.
 * The whole head is the toggle for the package's rows, which follow it.
 */
export function PackageGroupRow({ group: g, isOpen, onToggle }: { group: PackageGroup; isOpen: boolean; onToggle: () => void }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const { top, lower } = g.steps.length ? bundleSteps(g) : { top: null, lower: [] };
  return (
    <Table.Row data-testid="vuln-package-row" data-pkg={g.pkg}>
      <Table.Cell className="bl-v-grouprow">
        <button
          type="button"
          className="bl-v-disclose"
          aria-expanded={isOpen}
          aria-label={t("result.pkgGroupToggle", { pkg: g.pkg })}
          onClick={onToggle}
        >
          <span className="bl-muted bl-inline">{isOpen ? <ChevronDownIcon size={16} /> : <ChevronRightIcon size={16} />}</span>
          <SeverityLabel severity={g.maxSeverity} quiet />
          <PackageCoordinate {...splitPackage(g.pkg)} title={g.pkg} strongName className="bl-mono bl-breakall" />
          <span className="bl-mono bl-muted">{g.installed || "-"}</span>
          {g.vulns.some((v) => v.buildTool) && (
            <span className="bl-small bl-muted" title={t("result.buildToolHint")} data-testid="vuln-build-tool">
              {t("result.buildToolTag")}
            </span>
          )}
          <span className="bl-muted bl-small">{t("result.pkgGroupCount", { count: g.vulns.length, n: fmt(g.vulns.length) })}</span>
          {g.kev && (
            <Label variant="danger" title={t("result.kevHint")}>
              {t("result.kevBadge")}
            </Label>
          )}
          <span className="bl-small bl-v-upgrade">
            {top
              ? lower.length === 0
                ? t("result.pkgGroupUpgrade", { fixed: top.fixed, count: top.count })
                : t("result.pkgGroupUpgradeSteps", {
                    fixed: top.fixed,
                    count: top.count,
                    steps: lower.map((s) => t("result.upgradeBundleStep", { fixed: s.fixed, count: s.count })).join(", "),
                  })
              : t("result.pkgGroupNoFix")}
            {top && g.unfixed > 0 ? `, ${t("result.pkgGroupUnfixed", { count: g.unfixed })}` : ""}
          </span>
        </button>
      </Table.Cell>
    </Table.Row>
  );
}
