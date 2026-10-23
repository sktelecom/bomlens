// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Scale, ScrollText, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Disclosure } from "@/components/ui/disclosure";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem } from "@/lib/api";
import {
  componentRiskTier,
  conflictGroups,
  conflictReasonGroups,
  type ConflictVerdict,
  type LicenseReview,
  type LicenseRiskTier,
  reviewGroups,
} from "@/lib/licenses";

import { buildQuery, parseQuery, type RouteQuery } from "@/lib/route";
import { licensesFromQuery, licensesToQuery } from "@/lib/section-query";
import { useFormatNumber } from "@/lib/format";
import { conflictWhyKey } from "@/lib/licenseWhy";
import { renderLocalized } from "@/lib/localized";

import { LicenseObligations } from "./LicenseObligations";
import { LicenseRiskBar } from "./LicenseRiskBar";
import { LicenseSummary } from "./LicenseSummary";

/** Licenses listed before the "show all" button. An OS image declares a few
 *  hundred; the busiest twenty cover most components. */
const LICENSE_LIST_TOP = 20;

const FLAG_LABEL:Record<LicenseReview, string> = {
  "behavioral-use": "licenses.flagBehavioral",
  "non-commercial": "licenses.flagNonCommercial",
};

const CONFLICT_LABEL: Record<ConflictVerdict, string> = {
  incompatible: "licenses.conflictIncompatible",
  conditional: "licenses.conflictConditional",
  unknown: "licenses.conflictUnknown",
  compatible: "licenses.conflictCompatible",
};

/** Badge tone per verdict. Tone alone never carries the meaning — the label
 *  text says which verdict it is, so the section reads without colour. */
const CONFLICT_TONE: Record<ConflictVerdict, "high" | "medium" | "info"> = {
  incompatible: "high",
  conditional: "medium",
  unknown: "info",
  compatible: "info",
};

/**
 * Licenses — the classification axis (copyleft strength) over the per-license
 * distribution, followed by the obligations a component list cannot express:
 * conflicts with the declared outbound license, and terms that need human
 * review (AI behavioral-use / non-commercial, flagged from the
 * bomlens:licenseReview property so the badge matches the NOTICE review
 * section). Picking a classification narrows the distribution below it; picking
 * a license opens the Components table filtered to it.
 */
export function Licenses({
  components,
  query,
  onQueryChange,
  outboundLicense,
  onPickLicense,
  onRescanWithLicense,
}: {
  components: ComponentItem[];
  /** Tier filter as carried in the URL — a shared link, a reload, or a tier
   *  routed in from an Overview classification-bar click. */
  query?: RouteQuery;
  /** Report the tier back so the URL can carry it. */
  onQueryChange?: (query: RouteQuery) => void;
  /** The license the project declares it ships under. Absent means the conflict
   *  check never ran, which the section states outright rather than leaving the
   *  reader to read an empty table as an all-clear. */
  outboundLicense?: string;
  /** Open the Components section filtered to one license id. */
  onPickLicense?: (license: string) => void;
  /** Open the New scan form on the outbound-license field, so the check can be
   *  turned on without the command line. Absent where a re-scan is not possible. */
  onRescanWithLicense?: () => void;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  // Clicking a classification tier filters the rest of the tab to that tier.
  const [tier, setTier] = useState<LicenseRiskTier | "">(() => licensesFromQuery(query).tier);

  // The URL is the source; see ComponentsTable for why this compares strings.
  const urlQuery = buildQuery(query);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    setTier(licensesFromQuery(parseQuery(urlQuery)).tier);
  }, [urlQuery]);

  useEffect(() => {
    const next = buildQuery(licensesToQuery(tier));
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tier]);

  const filtered = useMemo(
    () =>
      tier ? components.filter((c) => componentRiskTier(c) === tier) : components,
    [tier, components],
  );
  const review = useMemo(() => reviewGroups(filtered), [filtered]);
  const conflicts = useMemo(() => conflictGroups(filtered), [filtered]);

  if (components.length === 0) {
    return (
      <EmptyState icon={ScrollText} hint={t("licenses.emptyHint")}>
        {t("licenses.empty")}
      </EmptyState>
    );
  }

  // The scanner records the reason in English; show it in the UI language
  // when it is one of the sentences BomLens writes, verbatim otherwise.
  const localizeWhy = (why: string) => {
    const key = conflictWhyKey(why);
    return key ? renderLocalized(t, key) : why;
  };

  const toggleTier = (next: LicenseRiskTier) => {
    setTier((cur) => (cur === next ? "" : next));
  };

  return (
    <div className="space-y-6">
      {/* The bar keeps the whole scan's proportions — it is the filter control,
          so filtering it by its own selection would erase what was picked. The
          distribution below is what narrows. */}
      <LicenseRiskBar components={components} selected={tier} onSelect={toggleTier} />

      {/* From 2xl up the distribution and the review cards sit in a main
          column and the obligations card in a narrow one beside it. Below 2xl
          the wrappers vanish and `order` keeps the single-column sequence. */}
      <div className="flex flex-col gap-6 2xl:grid 2xl:grid-cols-[minmax(0,1fr)_28rem] 2xl:items-start">
        <div className="contents 2xl:flex 2xl:min-w-0 2xl:flex-col 2xl:gap-6">
          <div className="order-1 empty:hidden 2xl:order-none">
            <LicenseSummary
              components={filtered}
              collapseAfter={LICENSE_LIST_TOP}
              onPickLicense={onPickLicense}
            />
          </div>
          <div className="order-3 empty:hidden 2xl:order-none">
            {outboundLicense && conflicts.length > 0 && (
              <Card className="border-warning-border/60 bg-warning-surface/60 dark:border-warning-border/20 dark:bg-warning-surface/20">
                <CardContent className="space-y-3 p-4">
                  <div className="flex items-center gap-2 text-body-sm font-semibold text-foreground">
                    <Scale className="h-4 w-4 text-risk-medium" aria-hidden />
                    {t("licenses.conflictTitle", { license: outboundLicense })}
                  </div>
                  <p className="text-body-sm text-muted-foreground">{t("licenses.conflictHint")}</p>
                  <div className="space-y-3">
                    {conflicts.map((g) => (
                      <div key={g.verdict} className="space-y-1.5">
                        <div className="flex items-center gap-2 text-body-sm">
                          <Badge tone={CONFLICT_TONE[g.verdict]}>{t(CONFLICT_LABEL[g.verdict])}</Badge>
                          <span className="tabular-nums text-muted-foreground">
                            {fmt(g.components.length)}
                          </span>
                        </div>
                        {/* Most components in one verdict share a reason (it
                            comes from the license class pair), so the reason
                            is said once above the components it applies to
                            and the rows carry only component and license. */}
                        {conflictReasonGroups(g.components).map((r) => (
                          <div key={r.why} className="space-y-1.5">
                            {r.why ? (
                              <p className="text-body-sm text-muted-foreground" title={r.why}>
                                {localizeWhy(r.why)}
                              </p>
                            ) : null}
                            <ul className="divide-y rounded-md border bg-card">
                              {r.components.map((c, i) => (
                                <li
                                  key={c.purl || `${c.name}-${i}`}
                                  className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-body-sm"
                                >
                                  <span className="font-mono">
                                    {c.group ? `${c.group} / ` : ""}
                                    {c.name}
                                    {c.version ? (
                                      <span className="text-muted-foreground"> {c.version}</span>
                                    ) : null}
                                  </span>
                                  <span className="text-label text-muted-foreground">
                                    {c.licenses.join(", ")}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
          <div className="order-4 empty:hidden 2xl:order-none">
            {review.length > 0 && (
              <Card className="border-warning-border/60 bg-warning-surface/60 dark:border-warning-border/20 dark:bg-warning-surface/20">
                <CardContent className="space-y-3 p-4">
                  <div className="flex items-center gap-2 text-body-sm font-semibold text-foreground">
                    <TriangleAlert className="h-4 w-4 text-risk-medium" aria-hidden />
                    {t("licenses.reviewTitle")}
                  </div>
                  <p className="text-body-sm text-muted-foreground">{t("licenses.reviewHint")}</p>
                  <div className="space-y-3">
                    {review.map((g) => (
                      <div key={g.flag} className="space-y-1.5">
                        <div className="flex items-center gap-2 text-body-sm">
                          <Badge tone="medium">{t(FLAG_LABEL[g.flag])}</Badge>
                          <span className="tabular-nums text-muted-foreground">
                            {fmt(g.components.length)}
                          </span>
                        </div>
                        <ul className="divide-y rounded-md border bg-card">
                          {g.components.map((c, i) => (
                            <li
                              key={c.purl || `${c.name}-${i}`}
                              className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-body-sm"
                            >
                              <span className="font-mono">
                                {c.group ? `${c.group} / ` : ""}
                                {c.name}
                                {c.version ? (
                                  <span className="text-muted-foreground"> {c.version}</span>
                                ) : null}
                              </span>
                              {c.licenses.map((l) => (
                                <Badge key={l} variant="muted">
                                  {l}
                                </Badge>
                              ))}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
        <div className="contents 2xl:flex 2xl:min-w-0 2xl:flex-col 2xl:gap-6">
          <div className="order-2 empty:hidden 2xl:order-none">
            <LicenseObligations components={filtered} />
          </div>
          <div className="order-5 empty:hidden 2xl:order-none">
            {!outboundLicense && (
              <Card>
                <CardContent className="space-y-1 p-4">
                  <div className="text-body-sm font-semibold text-foreground">
                    {t("licenses.conflictOffTitle")}
                  </div>
                  <p className="text-body-sm text-muted-foreground">{t("licenses.conflictOffHint")}</p>
                  {onRescanWithLicense && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-2"
                      data-testid="rescan-with-license"
                      onClick={onRescanWithLicense}
                    >
                      {t("licenses.conflictOffAction")}
                    </Button>
                  )}
                  <Disclosure
                    className="pt-2"
                    summary={
                      <span className="text-label text-muted-foreground">
                        {t("licenses.conflictOffCli")}
                      </span>
                    }
                  >
                    <p className="mt-1 text-label text-muted-foreground">
                      {t("licenses.conflictOffCliBody")}
                    </p>
                  </Disclosure>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
