import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type {
  AiProfile,
  ConformanceCheck,
  ConformanceSummary,
  CrosswalkFramework,
} from "@/lib/api";
import {
  baseTally,
  crosswalkTotals,
  elementCoverage,
  g7Tally,
  groupG7ByCluster,
  profileCard,
  splitChecks,
} from "@/lib/conformance";
import { cn } from "@/lib/utils";

const STATUS = {
  pass: { Icon: CircleCheck, color: "text-risk-low", key: "g7.sPass" },
  fail: { Icon: CircleX, color: "text-risk-critical", key: "g7.sFail" },
  warn: { Icon: CircleAlert, color: "text-risk-medium", key: "g7.sWarn" },
} as const;

function statusOf(s: ConformanceCheck["status"]) {
  return STATUS[s] ?? STATUS.warn;
}

// Crosswalk element coverage: present / gap / review. Colour only backs the word
// (each carries its own label), reusing the existing risk tones — no new colours.
const COVERAGE = {
  present: { Icon: CircleCheck, color: "text-risk-low", key: "crosswalk.present" },
  gap: { Icon: CircleAlert, color: "text-risk-medium", key: "crosswalk.gap" },
  review: { Icon: CircleAlert, color: "text-muted-foreground", key: "crosswalk.review" },
} as const;

/** AI compliance summary card — a compact one-glance rollup shown at the top of
 *  the Conformance section when an AI profile exists. Consumes only the profile
 *  summary counts (no big arrays). Documentation aid, not a compliance verdict. */
function AiProfileCard({ profile }: { profile: AiProfile }) {
  const { t } = useTranslation();
  const m = profileCard(profile);
  const verdictTone =
    m.result === "pass"
      ? "success"
      : m.result === "fail"
        ? "critical"
        : m.result === "warn"
          ? "medium"
          : "info";
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-sm font-semibold text-foreground">
            {t("aiProfile.title")}
          </div>
          <Badge tone={verdictTone}>
            {t(`aiProfile.verdict.${m.result}`, { defaultValue: m.result })}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">{t("aiProfile.note")}</p>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-md border p-3">
            <div className="text-xs font-medium text-muted-foreground">
              {t("aiProfile.g7Label")}
            </div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
              {t("aiProfile.g7Value", { present: m.g7Present, auto: m.g7Auto })}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {t("aiProfile.g7Detail", { gap: m.g7Gap, review: m.g7Review })}
            </div>
          </div>
          <div className="rounded-md border p-3">
            <div className="text-xs font-medium text-muted-foreground">
              {t("aiProfile.licenseLabel")}
            </div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
              {t("aiProfile.licenseValue", { count: m.licenseTotal })}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {t("aiProfile.licenseDetail", {
                behavioral: m.licenseBehavioral,
                nonCommercial: m.licenseNonCommercial,
              })}
            </div>
          </div>
          <div className="rounded-md border p-3">
            <div className="text-xs font-medium text-muted-foreground">
              {t("aiProfile.crosswalkLabel")}
            </div>
            <div className="mt-0.5 text-lg font-semibold tabular-nums text-foreground">
              {t("aiProfile.crosswalkValue", { count: m.frameworkCount })}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {t("aiProfile.crosswalkDetail", {
                present: m.crosswalk.present,
                total: m.crosswalk.total,
              })}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/** One framework's mapped elements, in the detailed crosswalk sub-block. */
function CrosswalkFrameworkBlock({ framework }: { framework: CrosswalkFramework }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <div className="text-xs font-semibold text-foreground">{framework.title}</div>
        <span className="text-xs tabular-nums text-muted-foreground">
          {t("crosswalk.frameworkSummary", {
            present: framework.present,
            gap: framework.gap,
            review: framework.review,
            total: framework.total,
          })}
        </span>
      </div>
      <div className="overflow-x-auto">
        <ul className="min-w-full divide-y rounded-md border">
          {framework.elements.map((el, i) => {
            const cov = COVERAGE[elementCoverage(el)];
            return (
              <li key={`${el.label}-${i}`} className="flex items-start gap-2.5 px-3 py-2.5">
                <cov.Icon className={cn("mt-0.5 h-4 w-4 shrink-0", cov.color)} aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="text-foreground">{el.label}</span>
                    <Badge variant="muted">{t(cov.key)}</Badge>
                  </div>
                  {el.refs.length > 0 ? (
                    <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                      <span className="font-medium">{t("crosswalk.refs")}</span>
                      {el.refs.map((r, j) => (
                        <code
                          key={`${r}-${j}`}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
                        >
                          {r}
                        </code>
                      ))}
                    </div>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

/** "Regulatory crosswalk" sub-block inside the conformance panel — shown only for
 *  AI SBOMs that carry `conformance.regulatoryCrosswalk`. Maps each mapped G7
 *  element to the documentation obligation it touches. Not a certification. */
function CrosswalkBlock({
  crosswalk,
}: {
  crosswalk: NonNullable<ConformanceSummary["regulatoryCrosswalk"]>;
}) {
  const { t } = useTranslation();
  const totals = crosswalkTotals(crosswalk.frameworks);
  return (
    <Card>
      <CardContent className="space-y-4 p-4">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <div className="text-sm font-semibold text-foreground">{t("crosswalk.title")}</div>
          <span className="text-xs tabular-nums text-muted-foreground">
            {t("crosswalk.totals", {
              present: totals.present,
              gap: totals.gap,
              review: totals.review,
              total: totals.total,
            })}
          </span>
        </div>
        <p className="text-xs text-muted-foreground">{t("crosswalk.disclaimer")}</p>
        <div className="space-y-4">
          {crosswalk.frameworks.map((fw) => (
            <CrosswalkFrameworkBlock key={fw.id} framework={fw} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
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
  // Supplied by the report itself (validate-sbom.sh joins docker/lib/g7-guidance.json),
  // so the CLI artifacts and this panel show the same fragment. Runs from before
  // the guidance registry carry none.
  const guidance = check.guidance;
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
        {notMet && (check.missing?.length ?? 0) > 0 ? (
          // Which items lack the element (e.g. the model components without a
          // license) — the count in detail says how many, this names them.
          <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
            <span className="font-medium">{t("g7.missing")}</span>
            {(check.missing ?? []).map((m, i) => (
              <code
                key={`${m}-${i}`}
                className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
              >
                {m}
              </code>
            ))}
          </div>
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
export function ConformancePanel({
  conformance,
  aiProfile,
}: {
  conformance: ConformanceSummary;
  /** AI compliance profile card (AI SBOMs only); null otherwise. */
  aiProfile?: AiProfile | null;
}) {
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

      {aiProfile ? <AiProfileCard profile={aiProfile} /> : null}

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

      {conformance.regulatoryCrosswalk &&
      conformance.regulatoryCrosswalk.frameworks.length > 0 ? (
        <CrosswalkBlock crosswalk={conformance.regulatoryCrosswalk} />
      ) : null}

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
