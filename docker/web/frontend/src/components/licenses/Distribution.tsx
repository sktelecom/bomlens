// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Button, CounterLabel, SegmentedControl } from "@primer/react";
import { useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { LicenseTierMark, tierFill, TIER_LABEL_KEY } from "@/components/primer";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { licenseGroups, type LicenseSortKey, licenseRiskTier, sortLicenseGroups } from "@/lib/licenses";

import { useTierHint } from "./tierHint";

/** Licenses listed before the "show all" button. An OS image declares a few
 *  hundred; the busiest twenty cover most components. */
export const LICENSE_LIST_TOP = 20;

const SORTS: LicenseSortKey[] = ["count", "name"];

/**
 * Licenses by component count (or by name), each a row that opens Components
 * filtered to that license. Components with no declared license are one inert
 * row at the end: the Components license filter selects an id and has no
 * "none" option.
 */
export function Distribution({
  components,
  licenseHref,
}: {
  components: ComponentItem[];
  /** Where a license row goes. Rows stay plain text when absent. */
  licenseHref?: (license: string) => string;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const hint = useTierHint();
  const listId = useId();
  const [all, setAll] = useState(false);
  const [sort, setSort] = useState<LicenseSortKey>("count");
  const { groups: byCount, unlicensed } = useMemo(() => licenseGroups(components), [components]);
  const groups = useMemo(() => sortLicenseGroups(byCount, sort), [byCount, sort]);
  if (components.length === 0) return null;

  const collapsible = groups.length > LICENSE_LIST_TOP;
  const shown = collapsible && !all ? groups.slice(0, LICENSE_LIST_TOP) : groups;
  // Scale every bar to the busiest license so proportions stay comparable.
  const max = Math.max(1, byCount[0]?.count ?? 0, unlicensed);
  const bar = (n: number, fill: string) => (
    <span className="bl-licbar" aria-hidden>
      <span style={{ width: `${Math.max(2, (n / max) * 100)}%`, background: fill }} />
    </span>
  );

  return (
    <section className="bl-box" aria-labelledby="lic-dist" data-testid="license-distribution">
      <div className="bl-box-head">
        <h2 id="lic-dist">{t("result.licenseSummaryTitle")}</h2>
        {groups.length > 0 && (
          <CounterLabel aria-label={t("licenses.distributionCount", { count: groups.length })}>{fmt(groups.length)}</CounterLabel>
        )}
        <span className="bl-box-head-end bl-lic-headtools">
          {licenseHref && <span className="bl-muted bl-small">{t("result.licenseRowHint")}</span>}
          {groups.length > 1 && (
            <SegmentedControl
              size="small"
              aria-label={t("licenses.sortLabel")}
              onChange={(i) => setSort(SORTS[i])}
            >
              <SegmentedControl.Button selected={sort === "count"} data-testid="license-sort-count">
                {t("licenses.sortCount")}
              </SegmentedControl.Button>
              <SegmentedControl.Button selected={sort === "name"} data-testid="license-sort-name">
                {t("licenses.sortName")}
              </SegmentedControl.Button>
            </SegmentedControl>
          )}
        </span>
      </div>
      <ul id={listId} className="bl-licrows" aria-label={t("result.licenseSummaryTitle")}>
        {shown.map((g) => {
          const tier = licenseRiskTier(g.name);
          const label = t(TIER_LABEL_KEY[tier]);
          const href = licenseHref?.(g.name);
          const inner = (
            <>
              <span title={`${label}. ${hint(tier)}`} className="bl-licrow-mark" aria-hidden>
                <LicenseTierMark tier={tier} />
              </span>
              {/* The spaces keep the cells apart as words (the row is a flex
                  box, so they take no room): the link is named by what it
                  shows, "MIT Permissive 3", then the hint. */}
              <span className="bl-mono bl-licrow-name">{g.name}</span>{" "}
              <span className="bl-muted bl-small bl-licrow-tier">{label}</span>{" "}
              {bar(g.count, tierFill(tier))}
              <span className="bl-num bl-licrow-count">{fmt(g.count)}</span>
            </>
          );
          return (
            <li key={g.name}>
              {href ? (
                <a className="bl-licrow" href={href}>
                  {inner}{" "}
                  <span className="bl-visually-hidden">. {t("result.licenseRowHint")}</span>
                </a>
              ) : (
                <div className="bl-licrow">{inner}</div>
              )}
            </li>
          );
        })}
        {unlicensed > 0 && (
          <li>
            <div className="bl-licrow" title={t("licenses.unlicensedInert")}>
              <span className="bl-licrow-mark" aria-hidden />
              <span className="bl-muted bl-licrow-name">{t("result.licenseNone")}</span>
              <span className="bl-licrow-tier" />
              {bar(unlicensed, "var(--borderColor-default)")}
              <span className="bl-num bl-licrow-count">{fmt(unlicensed)}</span>
            </div>
          </li>
        )}
      </ul>
      {collapsible && (
        <div className="bl-lic-foot">
          <Button
            size="small"
            aria-expanded={all}
            aria-controls={listId}
            data-testid="license-summary-toggle"
            onClick={() => setAll((v) => !v)}
          >
            {all ? t("result.licenseShowLess") : t("result.licenseShowAll", { count: groups.length })}
          </Button>
        </div>
      )}
    </section>
  );
}
