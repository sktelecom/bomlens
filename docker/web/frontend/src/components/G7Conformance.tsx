import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ConformanceCheck, ConformanceSummary } from "@/lib/api";
import { baseTally, g7Tally, splitChecks } from "@/lib/conformance";
import { cn } from "@/lib/utils";

const STATUS = {
  pass: { Icon: CircleCheck, color: "text-risk-low", key: "g7.sPass" },
  fail: { Icon: CircleX, color: "text-risk-critical", key: "g7.sFail" },
  warn: { Icon: CircleAlert, color: "text-risk-medium", key: "g7.sWarn" },
} as const;

function statusOf(s: ConformanceCheck["status"]) {
  return STATUS[s] ?? STATUS.warn;
}

function CheckRow({ check }: { check: ConformanceCheck }) {
  const { t } = useTranslation();
  const { Icon, color, key } = statusOf(check.status);
  // G7 checks carry a plain-language "what this is" line, and a "how to satisfy"
  // hint when not yet met. Base format checks have neither (defaultValue "").
  const isG7 = check.id.startsWith("g7-");
  const what = isG7 ? t(`g7.help.${check.id}.what`, { defaultValue: "" }) : "";
  const fix =
    isG7 && check.status !== "pass"
      ? t(`g7.help.${check.id}.fix`, { defaultValue: "" })
      : "";
  return (
    <li className="flex items-start gap-2.5 px-3 py-2.5">
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", color)} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-foreground">{check.label}</span>
          {check.required ? (
            <Badge variant="muted">{t("g7.required")}</Badge>
          ) : null}
          <span className="sr-only">{t(key)}</span>
        </div>
        {check.detail ? (
          <div className="mt-0.5 text-xs tabular-nums text-muted-foreground">{check.detail}</div>
        ) : null}
        {what ? (
          <div className="mt-1 text-xs leading-relaxed text-muted-foreground">{what}</div>
        ) : null}
        {fix ? (
          <div className="mt-1 rounded-md bg-muted/50 px-2.5 py-1.5 text-xs leading-relaxed text-foreground">
            <span className="font-medium">{t("g7.howToFix")}</span> {fix}
          </div>
        ) : null}
      </div>
    </li>
  );
}

/**
 * G7 conformance — the AI minimum-element checks split from the base format
 * checks. The headline "N / total present" and the advisory count come straight
 * from the check statuses (no invented numbers); G7 elements are all advisory.
 */
export function G7Conformance({ conformance }: { conformance: ConformanceSummary }) {
  const { t } = useTranslation();
  const checks = conformance.checks ?? [];
  if (checks.length === 0) {
    return <EmptyState>{t("g7.empty")}</EmptyState>;
  }

  const { base, g7 } = splitChecks(checks);
  const g7t = g7Tally(g7);
  const baseT = baseTally(base);
  const pass = conformance.result === "pass";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {conformance.format ? (
          <span className="font-medium text-foreground">{conformance.format}</span>
        ) : null}
        <Badge tone={pass ? "success" : "critical"}>
          {pass ? t("result.verdictPass") : t("result.verdictFail")}
        </Badge>
      </div>

      {g7.length > 0 && (
        <Card>
          <CardContent className="space-y-3 p-4">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <div className="text-sm font-semibold text-foreground">{t("g7.subtitle")}</div>
              <div className="text-2xl font-semibold tabular-nums text-foreground">
                {t("g7.present", { present: g7t.present, total: g7t.total })}
              </div>
              {g7t.advisory > 0 && (
                <span className="text-xs text-muted-foreground">
                  · {t("g7.advisory", { count: g7t.advisory })}
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t("g7.allAdvisory")}</p>
            <ul className="divide-y rounded-md border">
              {g7.map((c) => (
                <CheckRow key={c.id} check={c} />
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {base.length > 0 && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <div className="text-sm font-semibold text-foreground">{t("g7.formatTitle")}</div>
            <span className="text-xs text-muted-foreground">
              {t("g7.basePassed", { passed: baseT.passed, total: baseT.total })}
            </span>
          </div>
          <ul className="divide-y rounded-md border">
            {base.map((c) => (
              <CheckRow key={c.id} check={c} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
