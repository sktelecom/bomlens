import { Scale, ScrollText, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { BarList, type BarDatum } from "@/components/ui/barlist";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem } from "@/lib/api";
import {
  componentRiskTier,
  conflictGroups,
  type ConflictVerdict,
  isCopyleft,
  type LicenseReview,
  type LicenseRiskTier,
  licenseGroups,
  reviewGroups,
} from "@/lib/licenses";

import { LicenseRiskBar } from "./LicenseRiskBar";

const FLAG_LABEL: Record<LicenseReview, string> = {
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
 * Licenses — the full license distribution, led by any components whose terms
 * need human review (AI behavioral-use / non-commercial), flagged from the
 * bomlens:licenseReview property so the badge matches the NOTICE review section.
 * The distribution is a proportional bar chart (copyleft tinted for review);
 * click a bar to list its components.
 */
export function Licenses({
  components,
  initialTier,
  outboundLicense,
}: {
  components: ComponentItem[];
  /** Tier seeded from an Overview classification-bar click (filters on open). */
  initialTier?: LicenseRiskTier | "";
  /** The license the project declares it ships under. Absent means the conflict
   *  check never ran, which the section states outright rather than leaving the
   *  reader to read an empty table as an all-clear. */
  outboundLicense?: string;
}) {
  const { t } = useTranslation();
  // Clicking a classification tier filters the rest of the tab to that tier.
  const [tier, setTier] = useState<LicenseRiskTier | "">(initialTier ?? "");
  const [selected, setSelected] = useState<string | null>(null);
  // Re-seed the tier filter when an Overview bar click routes one in.
  useEffect(() => {
    if (initialTier !== undefined) setTier(initialTier);
  }, [initialTier]);

  const filtered = useMemo(
    () =>
      tier ? components.filter((c) => componentRiskTier(c) === tier) : components,
    [tier, components],
  );
  const review = useMemo(() => reviewGroups(filtered), [filtered]);
  const conflicts = useMemo(() => conflictGroups(filtered), [filtered]);
  const { groups, unlicensed } = useMemo(() => licenseGroups(filtered), [filtered]);
  const selectedComps = useMemo(
    () => (selected ? filtered.filter((c) => c.licenses.includes(selected)) : []),
    [selected, filtered],
  );

  if (components.length === 0) {
    return <EmptyState icon={ScrollText}>{t("licenses.empty")}</EmptyState>;
  }

  // Toggle the tier filter; clear the license drill-down when the class changes.
  const toggleTier = (next: LicenseRiskTier) => {
    setTier((cur) => (cur === next ? "" : next));
    setSelected(null);
  };

  const bars: BarDatum[] = groups.map((g) => ({
    key: g.name,
    label: g.name,
    value: g.count,
    emphasis: isCopyleft(g.name),
  }));

  return (
    <div className="space-y-6">
      <LicenseRiskBar components={components} selected={tier} onSelect={toggleTier} />

      {outboundLicense && conflicts.length > 0 && (
        <Card className="border-amber-300/60 bg-amber-50/60 dark:border-amber-400/20 dark:bg-amber-950/20">
          <CardContent className="space-y-3 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Scale className="h-4 w-4 text-risk-medium" aria-hidden />
              {t("licenses.conflictTitle", { license: outboundLicense })}
            </div>
            <p className="text-xs text-muted-foreground">{t("licenses.conflictHint")}</p>
            <div className="space-y-3">
              {conflicts.map((g) => (
                <div key={g.verdict} className="space-y-1.5">
                  <div className="flex items-center gap-2 text-sm">
                    <Badge tone={CONFLICT_TONE[g.verdict]}>{t(CONFLICT_LABEL[g.verdict])}</Badge>
                    <span className="tabular-nums text-muted-foreground">
                      {g.components.length}
                    </span>
                  </div>
                  <ul className="divide-y rounded-md border bg-card">
                    {g.components.map((c, i) => (
                      <li key={c.purl || `${c.name}-${i}`} className="space-y-1 px-3 py-2 text-sm">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          <span className="font-mono">
                            {c.group ? `${c.group} / ` : ""}
                            {c.name}
                            {c.version ? (
                              <span className="text-muted-foreground"> {c.version}</span>
                            ) : null}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {c.licenses.join(", ")}
                          </span>
                        </div>
                        {c.licenseConflictWhy ? (
                          <p className="text-xs text-muted-foreground">{c.licenseConflictWhy}</p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {review.length > 0 && (
        <Card className="border-amber-300/60 bg-amber-50/60 dark:border-amber-400/20 dark:bg-amber-950/20">
          <CardContent className="space-y-3 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <TriangleAlert className="h-4 w-4 text-risk-medium" aria-hidden />
              {t("licenses.reviewTitle")}
            </div>
            <p className="text-xs text-muted-foreground">{t("licenses.reviewHint")}</p>
            <div className="space-y-3">
              {review.map((g) => (
                <div key={g.flag} className="space-y-1.5">
                  <div className="flex items-center gap-2 text-sm">
                    <Badge tone="medium">{t(FLAG_LABEL[g.flag])}</Badge>
                    <span className="tabular-nums text-muted-foreground">
                      {g.components.length}
                    </span>
                  </div>
                  <ul className="divide-y rounded-md border bg-card">
                    {g.components.map((c, i) => (
                      <li
                        key={c.purl || `${c.name}-${i}`}
                        className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-sm"
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

      {!outboundLicense && (
        <Card>
          <CardContent className="space-y-1 p-4">
            <div className="text-sm font-semibold text-foreground">
              {t("licenses.conflictOffTitle")}
            </div>
            <p className="text-xs text-muted-foreground">{t("licenses.conflictOffHint")}</p>
          </CardContent>
        </Card>
      )}

      <div className="space-y-3">
        <div className="flex items-baseline justify-between gap-3">
          <div className="text-sm font-semibold text-foreground">
            {t("licenses.distribution")}
          </div>
          <span className="text-xs text-muted-foreground">{t("licenses.clickHint")}</span>
        </div>
        <div className="max-h-[26rem] overflow-auto rounded-md">
          <BarList
            items={bars}
            ariaLabel={t("licenses.distribution")}
            selectedKey={selected}
            onSelect={(key) => setSelected((cur) => (cur === key ? null : key))}
          />
        </div>
        {unlicensed > 0 && (
          <div className="text-xs text-muted-foreground">
            {t("result.licenseNone")}{" "}
            <span className="tabular-nums">{unlicensed}</span>
          </div>
        )}

        {selected && (
          <div className="space-y-1.5 pt-1">
            <div className="text-sm">
              <span className="font-medium">{selected}</span>{" "}
              <span className="tabular-nums text-muted-foreground">· {selectedComps.length}</span>
            </div>
            <ul className="max-h-[28rem] resize-y divide-y overflow-auto rounded-md border bg-card">
              {selectedComps.map((c, i) => (
                <li
                  key={c.purl || `${c.name}-${i}`}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-sm"
                >
                  <span className="font-mono">
                    {c.group ? `${c.group} / ` : ""}
                    {c.name}
                    {c.version ? <span className="text-muted-foreground"> {c.version}</span> : null}
                  </span>
                  {c.licenses.length > 1 && (
                    <span className="text-xs text-muted-foreground">({c.licenses.join(", ")})</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
