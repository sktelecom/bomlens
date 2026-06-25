import { ScrollText, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ComponentItem } from "@/lib/api";
import { type LicenseReview, licenseGroups, reviewGroups } from "@/lib/licenses";
import { cn } from "@/lib/utils";

const FLAG_LABEL: Record<LicenseReview, string> = {
  "behavioral-use": "licenses.flagBehavioral",
  "non-commercial": "licenses.flagNonCommercial",
};

// Copyleft / reciprocal licenses get a "review" tone so they stand out from the
// permissive bulk (Apache/MIT/BSD). Heuristic on the SPDX id; a human judges.
const COPYLEFT = /\b(A?GPL|LGPL|MPL|EPL|CDDL|CPL|OSL|EUPL|CeCILL)/i;

/**
 * Licenses — the full license distribution, led by any components whose terms
 * need human review (AI behavioral-use / non-commercial), flagged from the
 * bomlens:licenseReview property so the badge matches the NOTICE review section.
 */
export function Licenses({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();
  const review = useMemo(() => reviewGroups(components), [components]);
  const { groups, unlicensed } = useMemo(() => licenseGroups(components), [components]);
  const [selected, setSelected] = useState<string | null>(null);
  const selectedComps = useMemo(
    () => (selected ? components.filter((c) => c.licenses.includes(selected)) : []),
    [selected, components],
  );

  if (components.length === 0) {
    return <EmptyState icon={ScrollText}>{t("licenses.empty")}</EmptyState>;
  }

  return (
    <div className="space-y-6">
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

      <div className="space-y-3">
        <div className="flex items-baseline justify-between gap-3">
          <div className="text-sm font-semibold text-foreground">
            {t("licenses.distribution")}
          </div>
          <span className="text-xs text-muted-foreground">{t("licenses.clickHint")}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {groups.map((g) => {
            const sel = selected === g.name;
            const copyleft = COPYLEFT.test(g.name);
            return (
              <button
                key={g.name}
                type="button"
                aria-pressed={sel}
                onClick={() => setSelected(sel ? null : g.name)}
                className={cn(
                  "rounded-full transition duration-fast ease-out-soft",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                  sel ? "ring-2 ring-foreground ring-offset-1" : "hover:opacity-80",
                )}
              >
                <Badge tone={copyleft ? "medium" : undefined} variant={copyleft ? undefined : "muted"}>
                  {g.name} <span className="tabular-nums opacity-70">{g.count}</span>
                </Badge>
              </button>
            );
          })}
          {unlicensed > 0 && (
            <Badge variant="muted">
              {t("result.licenseNone")}{" "}
              <span className="tabular-nums opacity-70">{unlicensed}</span>
            </Badge>
          )}
        </div>

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
