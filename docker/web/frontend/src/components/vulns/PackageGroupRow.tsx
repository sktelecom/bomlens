// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useFormatNumber } from "@/lib/format";
import { severityTone } from "@/lib/severity";
import { bundleSteps, type PackageGroup } from "@/lib/vulnGroups";
import { cn } from "@/lib/utils";

/**
 * Header row of one package in the grouped layout: package and installed
 * version, how many CVEs, the worst severity, and what upgrading would do. It
 * is the toggle for the package's CVE rows, which follow it.
 */
export function PackageGroupRow({
  group: g,
  isOpen,
  onToggle,
  colSpan,
}: {
  group: PackageGroup;
  isOpen: boolean;
  onToggle: () => void;
  colSpan: number;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const { top, lower } = g.steps.length ? bundleSteps(g) : { top: null, lower: [] };
  return (
    <tr
      role="button"
      tabIndex={0}
      aria-expanded={isOpen}
      aria-label={t("result.pkgGroupToggle", { pkg: g.pkg })}
      data-testid="vuln-package-row"
      data-pkg={g.pkg}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
      className="cursor-pointer border-b bg-muted/40 hover:bg-accent/50"
    >
      <td colSpan={colSpan} className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <ChevronRight
            className={cn(
              "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
              isOpen && "rotate-90",
            )}
            aria-hidden
          />
          <Badge tone={severityTone(g.maxSeverity)} mark>
            {t(`severity.${g.maxSeverity}`)}
          </Badge>
          <span className="font-mono font-medium">{g.pkg}</span>
          <span className="font-mono tabular-nums text-muted-foreground">{g.installed || "—"}</span>
          <span className="tabular-nums text-muted-foreground">
            {t("result.pkgGroupCount", { count: g.vulns.length, n: fmt(g.vulns.length) })}
          </span>
          {g.kev && (
            <Badge tone="critical" title={t("result.kevHint")}>
              {t("result.kevBadge")}
            </Badge>
          )}
          <span className="ml-auto text-muted-foreground">
            {top
              ? lower.length === 0
                ? t("result.pkgGroupUpgrade", { fixed: top.fixed, count: top.count })
                : t("result.pkgGroupUpgradeSteps", {
                    fixed: top.fixed,
                    count: top.count,
                    steps: lower
                      .map((s) => t("result.upgradeBundleStep", { fixed: s.fixed, count: s.count }))
                      .join(", "),
                  })
              : t("result.pkgGroupNoFix")}
            {top && g.unfixed > 0 ? ` · ${t("result.pkgGroupUnfixed", { count: g.unfixed })}` : ""}
          </span>
        </div>
      </td>
    </tr>
  );
}
