// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/state";
import type {
  AiProfile,
  ConformanceCheck,
  ConformanceSummary,
} from "@/lib/api";
import {
  CISA_CLUSTER_ORDER,
  crosswalkTotals,
  dedupeMissing,
  groupByCluster,
  groupG7ByCluster,
  isRegistryCheck,
  missingOverflow,
  profileCard,
  registryTally,
  sortByAttention,
  splitChecks,
  verdictTally,
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

/** "Regulatory crosswalk" sub-block inside the conformance panel — one row per
 *  framework, present for any SBOM that carries `conformance.regulatoryCrosswalk`.
 *  It answers only "how much of each framework does this SBOM document"; each
 *  mapped requirement carries its own reference down in the check tables, so this
 *  stays a roll-up instead of reprinting those requirement rows. Not a
 *  certification — see the disclaimer. */
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
              failed: totals.failed,
              review: totals.review,
              total: totals.total,
            })}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="whitespace-nowrap py-1.5 pr-3 font-medium">{t("crosswalk.thFramework")}</th>
                <th className="whitespace-nowrap py-1.5 px-2 text-right font-medium tabular-nums">{t("crosswalk.present")}</th>
                <th className="whitespace-nowrap py-1.5 px-2 text-right font-medium tabular-nums">{t("crosswalk.gap")}</th>
                <th className="whitespace-nowrap py-1.5 px-2 text-right font-medium tabular-nums">{t("crosswalk.failed")}</th>
                <th className="whitespace-nowrap py-1.5 px-2 text-right font-medium tabular-nums">{t("crosswalk.review")}</th>
                <th className="whitespace-nowrap py-1.5 pl-2 text-right font-medium tabular-nums">{t("crosswalk.thTotal")}</th>
              </tr>
            </thead>
            <tbody>
              {crosswalk.frameworks.map((fw) => (
                <tr key={fw.id} className="border-b last:border-0 align-top">
                  <td className="py-1.5 pr-3">
                    <div className="text-foreground">{fw.title}</div>
                    <div className="text-xs text-muted-foreground">{fw.source}</div>
                  </td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-foreground">{fw.present}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-foreground">{fw.gap}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-foreground">{fw.failed ?? 0}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums text-foreground">{fw.review}</td>
                  <td className="py-1.5 pl-2 text-right tabular-nums text-foreground">{fw.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-muted-foreground">{t("crosswalk.disclaimer")}</p>
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
  const { t, i18n } = useTranslation();
  const { Icon, color, key } = statusOf(check.status);
  // A registry check carries a cluster, a data source, and — where the locale has
  // one — a plain-language "what this is" line and a "how to satisfy" hint. This
  // used to be gated on the id starting with "g7-", which meant the 2026 minimum
  // elements were rendered as three bare lines while the block above them showed
  // the same kind of element in full. The gate is what the check IS, not what it
  // is called: the checks the scripts write themselves carry no cluster.
  const isKo = (i18n.language ?? "").startsWith("ko");
  const fromRegistry = isRegistryCheck(check);
  const what = fromRegistry
    ? t(`g7.help.${check.id}.what`, { defaultValue: "" })
    : "";
  // Regulatory references ride with the requirement they belong to: "BSI
  // TR-03183-2 Section 5.2.2 · CISA 2026 Component Producer". The crosswalk
  // section stays a per-framework roll-up rather than reprinting these.
  const regText = (check.regulations ?? [])
    .map((r) => `${(isKo ? r.short_ko : r.short) || r.framework} ${r.ref}`)
    .join(" · ");
  const notMet = check.status !== "pass";
  const fix =
    fromRegistry && notMet
      ? t(`g7.help.${check.id}.fix`, { defaultValue: "" })
      : "";
  // Evidence: the real values pulled from the SBOM (purl, license id, hash alg…)
  // — shown only when the element is present, so it reads as "met with these".
  const evidence = fromRegistry && !notMet ? (check.evidence ?? []) : [];
  // What a person has to establish. Shown for an element no scan can settle, and
  // for one that is checkable in a form this report cannot see — a signature
  // delivered beside the SBOM reads as "not present" without it.
  const reviewHow = notMet
    ? (isKo ? check.reviewGuide?.howKo || check.reviewGuide?.how : check.reviewGuide?.how) ?? ""
    : "";
  // The registry's own Korean label, when the reader is reading Korean. The
  // contract stays English; this is the translation riding alongside it.
  const label = (isKo && check.labelKo) || check.label;
  const missing = dedupeMissing(check.missing ?? []);
  const overflow = missingOverflow(check);
  // Supplied by the report itself (validate-sbom.sh joins docker/lib/g7-guidance.json),
  // so the CLI artifacts and this panel show the same fragment. Runs from before
  // the guidance registry carry none.
  const guidance = check.guidance;
  return (
    <li className="flex items-start gap-2.5 px-3 py-2.5">
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", color)} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-foreground">{label}</span>
          {check.required ? (
            <Badge variant="muted">{t("g7.required")}</Badge>
          ) : null}
          {fromRegistry ? <SourceBadge source={check.source} /> : null}
          <span className="sr-only">{t(key)}</span>
        </div>
        {regText ? (
          <div className="mt-0.5 text-xs text-muted-foreground">
            <span className="font-medium">{t("crosswalk.refs")}</span> {regText}
          </div>
        ) : null}
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
            {missing.map(({ name, count }: { name: string; count: number }) => (
              <code
                key={name}
                className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
              >
                {count > 1 ? `${name} ×${count}` : name}
              </code>
            ))}
            {overflow > 0 ? (
              <span className="tabular-nums">{t("g7.missingMore", { count: overflow })}</span>
            ) : null}
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
        {reviewHow ? (
          <div className="mt-1 rounded-md bg-muted/50 px-2.5 py-1.5 text-xs leading-relaxed text-foreground">
            <span className="font-medium">{t("g7.needsPerson")}</span> {reviewHow}
          </div>
        ) : null}
        {notMet && guidance?.snippet ? (
          // Folded away: a page that shows every fragment open runs to twelve
          // thousand pixels, and the fragment is only wanted once a reader has
          // decided to act on that row.
          <details className="mt-1">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
              {t("g7.example")}
            </summary>
            <pre className="mt-0.5 overflow-x-auto rounded-md bg-muted px-2.5 py-2 text-[11px] leading-relaxed text-foreground">
              <code className="font-mono">{guidance.snippet}</code>
            </pre>
          </details>
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

  const { base, cisa, g7 } = splitChecks(checks);
  const g7t = registryTally(g7);
  const g7groups = groupG7ByCluster(g7);
  const cisaT = registryTally(cisa);
  const cisaGroups = groupByCluster(cisa, CISA_CLUSTER_ORDER);
  const verdict = verdictTally(checks);
  const pass = conformance.result === "pass";

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {conformance.format ? (
            <span className="font-medium text-foreground">{conformance.format}</span>
          ) : null}
          <Badge tone={pass ? "success" : "critical"}>
            {pass ? t("result.verdictPass") : t("result.verdictFail")}
          </Badge>
        </div>
        {/* Says what "conformance" here measures — SBOM format/submission
            requirements, not regulatory compliance — so the section title is not
            read as a compliance verdict. */}
        <p className="max-w-3xl text-sm text-muted-foreground">{t("g7.panelIntro")}</p>
        {/* What blocks this SBOM, before anything else. The mandatory checks
            decide the verdict on their own — an advisory baseline can be wholly
            unmet without changing it — and they used to sit below every advisory
            row, which on an AI SBOM meant the bottom of a very long page. */}
        <p className="text-sm text-foreground">
          <span className="font-medium">
            {t("g7.verdictFailed", { count: verdict.mandatoryFailed })}
          </span>
          {verdict.advisoryGap > 0 ? (
            <span className="text-muted-foreground">
              {" · "}
              {t("g7.verdictGap", { count: verdict.advisoryGap })}
            </span>
          ) : null}
          {verdict.review > 0 ? (
            <span className="text-muted-foreground">
              {" · "}
              {t("g7.verdictReview", { count: verdict.review })}
            </span>
          ) : null}
        </p>
      </div>

      {base.length > 0 && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <div className="text-sm font-semibold text-foreground">{t("g7.formatTitle")}</div>
            <span className="text-xs text-muted-foreground">
              {t("g7.baseMandatory", {
                passed: verdict.mandatoryPassed,
                total: verdict.mandatoryTotal,
              })}
            </span>
          </div>
          <ul className="divide-y rounded-md border">
            {sortByAttention(base).map((c) => (
              <CheckRow key={c.id} check={c} />
            ))}
          </ul>
        </div>
      )}

      {conformance.regulatoryCrosswalk &&
      conformance.regulatoryCrosswalk.frameworks.length > 0 ? (
        <CrosswalkBlock crosswalk={conformance.regulatoryCrosswalk} />
      ) : null}

      {cisa.length > 0 && (
        <Card>
          <CardContent className="space-y-4 p-4">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <div className="text-sm font-semibold text-foreground">{t("cisa.subtitle")}</div>
              <div className="text-2xl font-semibold tabular-nums text-foreground">
                {t("g7.present", { present: cisaT.present, total: cisaT.autoTotal })}
              </div>
              {cisaT.review > 0 && (
                <span className="text-xs text-muted-foreground">
                  · {t("g7.review", { count: cisaT.review })}
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t("cisa.allAdvisory")}</p>
            <div className="space-y-4">
              {cisaGroups.map((group) => (
                <div key={group.cluster} className="space-y-2">
                  <div className="text-xs font-semibold text-foreground">
                    {t(`cisa.cluster.${group.cluster}`, { defaultValue: group.cluster })}
                  </div>
                  <ul className="divide-y rounded-md border">
                    {sortByAttention(group.checks).map((c) => (
                      <CheckRow key={c.id} check={c} />
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

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


    </div>
  );
}
