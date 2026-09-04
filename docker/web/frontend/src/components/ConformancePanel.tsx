// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CircleAlert, CircleCheck, CircleMinus, CircleX, Download } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/state";
import {
  fileUrl,
  type AiProfile,
  type ConformanceCheck,
  type ConformanceSummary,
  type ResultFile,
} from "@/lib/api";
import {
  checkKind,
  type CheckKind,
  CISA_CLUSTER_ORDER,
  crosswalkTotals,
  dedupeMissing,
  groupByCluster,
  groupG7ByCluster,
  isNotApplicable,
  isRegistryCheck,
  kindTally,
  matchesQuery,
  registryTally,
  missingOverflow,
  profileCard,
  sortByAttention,
  splitChecks,
  verdictTally,
} from "@/lib/conformance";
import { Disclosure } from "@/components/ui/disclosure";
import { cn } from "@/lib/utils";

const STATUS = {
  pass: { Icon: CircleCheck, color: "text-risk-low", key: "g7.sPass" },
  fail: { Icon: CircleX, color: "text-risk-critical", key: "g7.sFail" },
  warn: { Icon: CircleAlert, color: "text-risk-medium", key: "g7.sWarn" },
  // Nothing in this document to judge. Muted on purpose: it is neither a gap the
  // reader can close nor something met, so it must not read as either.
  na: { Icon: CircleMinus, color: "text-muted-foreground", key: "g7.sNa" },
} as const;

function statusOf(check: ConformanceCheck) {
  if (isNotApplicable(check)) return STATUS.na;
  return statusOfValue(check.status);
}

/** For rows that carry a status without the rest of a check (crosswalk elements). */
function statusOfValue(s: string) {
  return STATUS[s as keyof typeof STATUS] ?? STATUS.warn;
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
                    {/* The counts said how many requirements were met and left
                        the reader to work out which. The rows are already in the
                        payload; folding them under the framework answers the
                        question the table raises. */}
                    <Disclosure
                      summaryClassName="text-foreground"
                      summary={<span>{fw.title}</span>}
                    >
                      <ul className="mt-1 space-y-0.5">
                        {fw.elements.map((el, i) => {
                          const { Icon, color } = statusOfValue(el.status);
                          return (
                            <li key={`${el.label}-${i}`} className="flex items-start gap-1.5 text-xs">
                              <Icon className={cn("mt-0.5 h-3 w-3 shrink-0", color)} aria-hidden />
                              <span className="text-muted-foreground">
                                {el.label}
                                {el.refs.length > 0 ? (
                                  <span className="text-muted-foreground"> — {el.refs.join(" · ")}</span>
                                ) : null}
                              </span>
                            </li>
                          );
                        })}
                      </ul>
                    </Disclosure>
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
function SourceBadge({ source, naKind }: { source?: string; naKind?: string }) {
  const { t } = useTranslation();
  if (!source) return null;
  const notApplicable = naKind === "not-applicable";
  const label = notApplicable
    ? t("g7.source.notApplicable", { defaultValue: "" })
    : t(`g7.source.${source}`, { defaultValue: "" });
  if (notApplicable && label) return <Badge variant="muted">{label}</Badge>;
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
  const { Icon, color, key } = statusOf(check);
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
  // Same rule for the measurement line. A Korean requirement name followed by
  // "no packages to measure" was the shape the conformance screen had for every
  // check this pipeline writes itself.
  const detail = (isKo && check.detailKo) || check.detail;
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
          {fromRegistry ? <SourceBadge source={check.source} naKind={check.naKind} /> : null}
          {detail && !notMet ? (
            <span className="text-xs tabular-nums text-muted-foreground">{detail}</span>
          ) : null}
          <span className="sr-only">{t(key)}</span>
        </div>
        {regText ? (
          <div className="mt-0.5 text-xs text-muted-foreground">
            <span className="font-medium">{t("crosswalk.refs")}</span> {regText}
          </div>
        ) : null}
        {detail && notMet ? (
          <div className="mt-0.5 text-xs tabular-nums text-muted-foreground">{detail}</div>
        ) : null}
        {what && notMet ? (
          // Only where there is something to do. A met element's description is
          // read once and then re-read on every visit: forty of them turned a
          // list a reader scans into a page a reader scrolls.
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
          // Folded: the values that satisfied an element are worth having, and
          // worth having on request. Open by default they made every met row as
          // tall as an unmet one.
          <Disclosure
            className="mt-1"
            summaryClassName="text-xs font-medium text-muted-foreground"
            summary={<span>{t("g7.evidence")}</span>}
          >
            <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
              {evidence.map((e, i) => (
                <code
                  key={`${e}-${i}`}
                  className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
                >
                  {e}
                </code>
              ))}
            </div>
          </Disclosure>
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
          <Disclosure
            className="mt-1"
            summaryClassName="text-xs font-medium text-muted-foreground"
            summary={<span>{t("g7.example")}</span>}
          >
            <pre className="mt-0.5 overflow-x-auto rounded-md bg-muted px-2.5 py-2 text-[11px] leading-relaxed text-foreground">
              <code className="font-mono">{guidance.snippet}</code>
            </pre>
          </Disclosure>
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

const KIND_TONE: Record<CheckKind, "success" | "medium" | "info" | "none"> = {
  pass: "success",
  actionable: "medium",
  review: "info",
  na: "none",
};

/**
 * One filter chip. Built like the severity legend so the two screens are read
 * the same way, but with no bar above it: these four are a classification, not a
 * scale, and a bar would give most of its width to "passed", the one band
 * nobody came here to look at.
 */
function KindChip({
  kind,
  count,
  selected,
  onSelect,
}: {
  kind: CheckKind;
  count: number;
  selected: CheckKind | null;
  onSelect: (k: CheckKind) => void;
}) {
  const { t } = useTranslation();
  const isSel = selected === kind;
  return (
    <button
      type="button"
      disabled={count === 0}
      aria-pressed={isSel}
      onClick={() => onSelect(kind)}
      className={cn(
        "rounded-full transition duration-fast ease-out-soft",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        count === 0 ? "cursor-not-allowed opacity-40" : "cursor-pointer hover:opacity-80",
        isSel && "ring-2 ring-foreground ring-offset-1",
        Boolean(selected) && !isSel && "opacity-60",
      )}
    >
      <Badge tone={KIND_TONE[kind]} variant={kind === "na" ? "muted" : undefined}>
        {t(`conf.kind.${kind}`)} {count}
      </Badge>
    </button>
  );
}

/** A named group of checks, folded away when it holds nothing to act on. */
function CheckGroup({
  title,
  checks,
  defaultOpen,
  trailing,
}: {
  title: string;
  checks: ConformanceCheck[];
  defaultOpen: boolean;
  trailing?: React.ReactNode;
}) {
  if (checks.length === 0) return null;
  return (
    <Disclosure
      defaultOpen={defaultOpen}
      summaryClassName="text-xs font-semibold text-foreground"
      summary={
        <span className="flex flex-wrap items-baseline gap-x-2">
          <span>{title}</span>
          <span className="text-xs font-normal tabular-nums text-muted-foreground">
            {checks.length}
          </span>
          {trailing}
        </span>
      }
    >
      <ul className="mt-2 divide-y rounded-md border">
        {sortByAttention(checks).map((c) => (
          <CheckRow key={c.id} check={c} />
        ))}
      </ul>
    </Disclosure>
  );
}

/**
 * SBOM conformance: the supplier-SBOM verdict, the base CycloneDX format
 * checks, the 2026 SBOM minimum elements and (when the SBOM carries a model) the
 * G7 AI minimum elements.
 *
 * Ninety-one checks over twelve groups ran to twelve screens with no filter, no
 * search and nothing folded, and drew every unmet check the same way, so the
 * twelve a reader can act on sat among fourteen only a person can settle and
 * seven this document has nothing to measure for. The chips split those four
 * apart and start on the actionable ones; the groups fold; the search covers the
 * requirement names and the regulation references.
 */
export function ConformancePanel({
  conformance,
  aiProfile,
  scanId,
  results = [],
}: {
  conformance: ConformanceSummary;
  /** AI compliance profile card (AI SBOMs only); null otherwise. */
  aiProfile?: AiProfile | null;
  /** Scoping for the report download links; omit to hide them. */
  scanId?: string | null;
  /** This scan's artifacts, to offer the same report as a file. */
  results?: ResultFile[];
}) {
  const { t } = useTranslation();
  const checks = conformance.checks ?? [];
  const tally = useMemo(() => kindTally(checks), [checks]);
  // Open on the checks a reader can do something about. When there are none,
  // opening on an empty list would say "nothing here" about a document that has
  // plenty to show, so the unfiltered list is the honest start.
  const [kind, setKind] = useState<CheckKind | null>(
    tally.actionable > 0 ? "actionable" : null,
  );
  const [query, setQuery] = useState("");

  const reports = useMemo(
    () =>
      results
        .filter((r) => r.name.includes("_conformance.") && !r.name.endsWith(".json"))
        .sort((a, b) => a.name.localeCompare(b.name)),
    [results],
  );

  if (checks.length === 0) {
    return <EmptyState>{t("g7.empty")}</EmptyState>;
  }

  const keep = (c: ConformanceCheck) =>
    (kind === null || checkKind(c) === kind) && matchesQuery(c, query);
  const shown = checks.filter(keep);
  // Coverage of each advisory baseline, always over ALL of its checks: "32/41
  // present" answers how much of G7 this SBOM documents, which a filtered view
  // must not change.
  const all = splitChecks(checks);
  const cisaT = registryTally(all.cisa);
  const g7t = registryTally(all.g7);
  // A search that finds nothing because a chip is narrowing it should say so:
  // the reader typed a requirement they expect to exist, and "no match" alone
  // reads as "this SBOM has no such check".
  const hiddenByChip =
    kind !== null && query
      ? checks.filter((c) => matchesQuery(c, query)).length - shown.length
      : 0;
  const { base, cisa, g7 } = splitChecks(shown);
  const g7groups = groupG7ByCluster(g7);
  const cisaGroups = groupByCluster(cisa, CISA_CLUSTER_ORDER);
  const verdict = verdictTally(checks);
  const pass = conformance.result === "pass";
  // Re-mount the folds when the filter changes so their default open state is
  // recomputed; Disclosure captures it once, on purpose.
  const foldKey = `${kind ?? "all"}:${query}`;
  const openByDefault = kind !== null || Boolean(query);

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
          <div className="flex-1" />
          {scanId
            ? reports.map((r) => (
                <Button key={r.name} variant="outline" size="sm" asChild>
                  <a href={fileUrl(scanId, r.name)} download={r.name}>
                    <Download className="h-3.5 w-3.5" />
                    {t("conf.report", { ext: r.name.split(".").pop()?.toUpperCase() })}
                  </a>
                </Button>
              ))
            : null}
        </div>
        {/* Says what "conformance" here measures — SBOM format/submission
            requirements, not regulatory compliance — so the section title is not
            read as a compliance verdict. */}
        <p className="max-w-3xl text-sm text-muted-foreground">{t("g7.panelIntro")}</p>
        <p className="text-sm text-foreground">
          <span className="font-medium">
            {t("g7.verdictFailed", { count: verdict.mandatoryFailed })}
          </span>
        </p>
      </div>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {(["actionable", "review", "na", "pass"] as const).map((k) => (
            <KindChip
              key={k}
              kind={k}
              count={tally[k]}
              selected={kind}
              onSelect={(picked) => setKind((cur) => (cur === picked ? null : picked))}
            />
          ))}
          <div className="flex-1" />
          <Input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("conf.searchPlaceholder")}
            aria-label={t("conf.searchPlaceholder")}
            className="h-8 w-full max-w-xs text-sm"
          />
        </div>
        <p className="text-xs text-muted-foreground">
          {kind === null && !query
            ? t("conf.showingAll", { count: checks.length })
            : t("conf.showingFiltered", { count: shown.length, total: checks.length })}
          {hiddenByChip > 0 && shown.length > 0
            ? ` ${t("conf.hiddenByFilter", { count: hiddenByChip })}`
            : null}
        </p>
      </div>

      {shown.length === 0 ? (
        <EmptyState
          hint={
            hiddenByChip > 0
              ? t("conf.hiddenByFilter", { count: hiddenByChip })
              : undefined
          }
        >
          {t("conf.noMatch")}
        </EmptyState>
      ) : (
        <div className="space-y-6" key={foldKey}>
          <CheckGroup
            title={t("g7.formatTitle")}
            checks={base}
            defaultOpen={openByDefault || base.some((c) => checkKind(c) === "actionable")}
            trailing={
              <span className="text-xs font-normal text-muted-foreground">
                {t("g7.baseMandatory", {
                  passed: verdict.mandatoryPassed,
                  total: verdict.mandatoryTotal,
                })}
              </span>
            }
          />

          {conformance.regulatoryCrosswalk &&
          conformance.regulatoryCrosswalk.frameworks.length > 0 &&
          kind === null &&
          !query ? (
            <CrosswalkBlock crosswalk={conformance.regulatoryCrosswalk} />
          ) : null}

          {cisa.length > 0 && (
            <Card>
              <CardContent className="space-y-4 p-4">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <div className="text-sm font-semibold text-foreground">{t("cisa.subtitle")}</div>
                  <div className="text-lg font-semibold tabular-nums text-foreground">
                    {t("g7.present", { present: cisaT.present, total: cisaT.autoTotal })}
                  </div>
                  <p className="text-xs text-muted-foreground">{t("cisa.allAdvisory")}</p>
                </div>
                <div className="space-y-3">
                  {cisaGroups.map((group) => (
                    <CheckGroup
                      key={group.cluster}
                      title={t(`cisa.cluster.${group.cluster}`, { defaultValue: group.cluster })}
                      checks={group.checks}
                      defaultOpen={
                        openByDefault || group.checks.some((c) => checkKind(c) === "actionable")
                      }
                    />
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {aiProfile && kind === null && !query ? <AiProfileCard profile={aiProfile} /> : null}

          {g7.length > 0 && (
            <Card>
              <CardContent className="space-y-4 p-4">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <div className="text-sm font-semibold text-foreground">{t("g7.subtitle")}</div>
                  <div className="text-lg font-semibold tabular-nums text-foreground">
                    {t("g7.present", { present: g7t.present, total: g7t.autoTotal })}
                  </div>
                  <p className="text-xs text-muted-foreground">{t("g7.allAdvisory")}</p>
                </div>
                <div className="space-y-3">
                  {g7groups.map((group) => (
                    <CheckGroup
                      key={group.cluster}
                      title={t(`g7.cluster.${group.cluster}`, { defaultValue: group.cluster })}
                      checks={group.checks}
                      defaultOpen={
                        openByDefault || group.checks.some((c) => checkKind(c) === "actionable")
                      }
                    />
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
