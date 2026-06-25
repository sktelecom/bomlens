import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ConformanceCheck, ConformanceSummary } from "@/lib/api";
import { baseTally, g7Tally, splitChecks } from "@/lib/conformance";
import { G7_GUIDANCE } from "@/lib/g7Guidance";
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
  // G7 checks carry a plain-language "what this is" line, a "how to satisfy"
  // hint when not yet met, and (on the pass side) the actual SBOM values that
  // satisfied it. Base format checks have none of these (defaultValue "").
  const isG7 = check.id.startsWith("g7-");
  const what = isG7 ? t(`g7.help.${check.id}.what`, { defaultValue: "" }) : "";
  const notMet = check.status !== "pass";
  const fix =
    isG7 && notMet ? t(`g7.help.${check.id}.fix`, { defaultValue: "" }) : "";
  // Evidence: the real values pulled from the SBOM (purl, license id, hash alg…)
  // — shown only when the element is present, so it reads as "met with these".
  const evidence = isG7 && !notMet ? (check.evidence ?? []) : [];
  const guidance = isG7 ? G7_GUIDANCE[check.id] : undefined;
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
        {evidence.length > 0 ? (
          <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
            <span className="font-medium">{t("g7.evidence")}</span>
            {evidence.map((e, i) => (
              <code
                key={`${e}-${i}`}
                className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
              >
                {e}
              </code>
            ))}
          </div>
        ) : null}
        {fix ? (
          <div className="mt-1 rounded-md bg-muted/50 px-2.5 py-1.5 text-xs leading-relaxed text-foreground">
            <span className="font-medium">{t("g7.howToFix")}</span> {fix}
          </div>
        ) : null}
        {fix && guidance?.snippet ? (
          <div className="mt-1">
            <div className="text-xs font-medium text-muted-foreground">{t("g7.example")}</div>
            <pre className="mt-0.5 overflow-x-auto rounded-md bg-muted px-2.5 py-2 text-[11px] leading-relaxed text-foreground">
              <code className="font-mono">{guidance.snippet}</code>
            </pre>
          </div>
        ) : null}
        {guidance?.docUrl ? (
          <a
            href={guidance.docUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-1 inline-block text-xs font-medium text-primary hover:underline"
          >
            {t("g7.learnMore")}
          </a>
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
