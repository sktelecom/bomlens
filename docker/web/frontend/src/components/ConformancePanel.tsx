import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type { ConformanceCheck, ConformanceSummary } from "@/lib/api";
import { baseTally, g7Tally, groupG7ByCluster, splitChecks } from "@/lib/conformance";
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

// Provenance badge: where a satisfied value comes from. Reuses existing badge
// tones (no invented colours); the word carries the meaning, colour only backs
// it. "na" (no automated source) takes the review-needed tone.
function SourceBadge({ source }: { source?: string }) {
  const { t } = useTranslation();
  if (!source) return null;
  const label = t(`g7.source.${source}`, { defaultValue: "" });
  if (!label) return null;
  switch (source) {
    case "auto":
      return <Badge tone="low">{label}</Badge>;
    case "inferred":
      return <Badge tone="info">{label}</Badge>;
    case "na":
      return <Badge tone="medium">{label}</Badge>;
    case "declared":
    default:
      return <Badge variant="muted">{label}</Badge>;
  }
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
          {isG7 ? <SourceBadge source={check.source} /> : null}
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
 * SBOM conformance — the supplier-SBOM verdict plus the base CycloneDX format
 * checks, and (only when the SBOM carries an AI model) the G7 AI minimum-element
 * checks as a sub-block. The headline "N / total present" and the advisory count
 * come straight from the check statuses (no invented numbers); G7 is advisory.
 */
export function ConformancePanel({ conformance }: { conformance: ConformanceSummary }) {
  const { t } = useTranslation();
  const checks = conformance.checks ?? [];
  if (checks.length === 0) {
    return <EmptyState>{t("g7.empty")}</EmptyState>;
  }

  const { base, g7 } = splitChecks(checks);
  const g7t = g7Tally(g7);
  const g7groups = groupG7ByCluster(g7);
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
          <CardContent className="space-y-4 p-4">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <div className="text-sm font-semibold text-foreground">{t("g7.subtitle")}</div>
              <div className="text-2xl font-semibold tabular-nums text-foreground">
                {t("g7.present", { present: g7t.present, total: g7t.autoTotal })}
              </div>
              {g7t.advisory > 0 && (
                <span className="text-xs text-muted-foreground">
                  · {t("g7.advisory", { count: g7t.advisory })}
                </span>
              )}
              {g7t.review > 0 && (
                <span className="text-xs text-muted-foreground">
                  · {t("g7.review", { count: g7t.review })}
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t("g7.allAdvisory")}</p>
            <div className="space-y-4">
              {g7groups.map((group) => (
                <div key={group.cluster} className="space-y-2">
                  <div className="text-xs font-semibold text-foreground">
                    {t(`g7.cluster.${group.cluster}`, { defaultValue: group.cluster })}
                  </div>
                  <ul className="divide-y rounded-md border">
                    {group.checks.map((c) => (
                      <CheckRow key={c.id} check={c} />
                    ))}
                  </ul>
                </div>
              ))}
            </div>
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
