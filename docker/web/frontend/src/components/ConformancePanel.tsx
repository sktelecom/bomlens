// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChecklistIcon, DownloadIcon, SearchIcon } from "@primer/octicons-react";
import { Button, Label, Link, TextInput } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";

import { type Completeness, fileUrl, type ConformanceCheck, type ConformanceSummary, type ResultFile } from "@/lib/api";
import { gradeLabel, gradeVariant, isIncomplete } from "@/lib/completeness";
import {
  checkKind,
  type CheckKind,
  CISA_CLUSTER_ORDER,
  conformanceReports,
  groupByCluster,
  groupG7ByCluster,
  kindTally,
  matchesQuery,
  profileLabelKey,
  registryTally,
  resultQuality,
  splitChecks,
  verdictTally,
} from "@/lib/conformance";
import { buildQuery, parseQuery, type RouteQuery } from "@/lib/route";
import { conformanceFromQuery, conformanceToQuery } from "@/lib/section-query";
import { useToast } from "@/lib/toast";
import { NARROW_QUERY, useMediaQuery } from "@/lib/useMediaQuery";

import { BaselineBox, Count, FormatBox } from "./conformance/CheckRow";
import { Crosswalk } from "./conformance/Crosswalk";
import { EmptyNotices, PipelineNote, QualityNote } from "./conformance/Notices";
import "./conformance/conformance.css";

export { CheckGroup } from "./conformance/CheckRow";

/** The result header's slot for the report downloads. */
export const CONFORMANCE_ACTIONS_SLOT = "bl-conformance-actions";

const KINDS: CheckKind[] = ["actionable", "review", "na", "pass"];

/**
 * SBOM conformance: this SBOM's own fields against the CycloneDX format and the
 * regulatory baselines (the 2026 minimum elements and, when the SBOM carries a
 * model, the G7 AI minimum elements). It is not a verdict on the scanned software.
 *
 * Ninety-one checks over twelve groups ran to twelve screens with no filter, so
 * the twelve a reader can act on sat among fourteen only a person can settle and
 * seven this document has nothing to measure for. The tabs split those four
 * apart and start on the actionable ones; the groups fold; the search covers the
 * requirement names and the regulation references. Tab and search ride in the URL.
 */
export function ConformancePanel({
  conformance,
  scanId,
  results = [],
  isSuppliedDocument = false,
  isAiDocument = false,
  completeness = null,
  profile = null,
  query,
  onQueryChange,
}: {
  conformance: ConformanceSummary;
  /** The conformance profile the scan ran with (scanConfig.conformanceProfile);
   *  named in the summary box so a pass is read against the right criteria. */
  profile?: string | null;
  /** Scoping for the report download links; omit to hide them. */
  scanId?: string | null;
  /** This scan's artifacts, to offer the same report as a file. */
  results?: ResultFile[];
  /** An ANALYZE run against an uploaded SBOM the reader did not generate, so a
   *  failed-step note suggests asking the supplier instead of re-scanning. */
  isSuppliedDocument?: boolean;
  /** `isAiScan(result)`: the empty-result and license warnings do not apply. */
  isAiDocument?: boolean;
  /** The engine's completeness result; when it is not complete its grade leads the summary and its reasons explain an empty result. */
  completeness?: Completeness | null;
  /** The tab and the search, as carried in the URL hash. */
  query?: RouteQuery;
  onQueryChange?: (query: RouteQuery) => void;
}) {
  const { t, i18n } = useTranslation();
  const { toast } = useToast();
  const checks = useMemo(() => conformance.checks ?? [], [conformance.checks]);
  const tally = useMemo(() => kindTally(checks), [checks]);
  // Open on the checks a reader can do something about. When there are none,
  // opening on an empty list would say "nothing here" about a document that has
  // plenty to show, so the unfiltered list is the honest start.
  const defaultKind: CheckKind | null = tally.actionable > 0 ? "actionable" : null;
  const [kind, setKind] = useState<CheckKind | null>(() => conformanceFromQuery(query, defaultKind, tally).kind);
  const [term, setTerm] = useState(() => conformanceFromQuery(query, defaultKind, tally).term);

  // The URL is the source; see ComponentsTable for why this compares strings.
  const urlQuery = buildQuery(query);
  const appliedRef = useRef(urlQuery);
  useEffect(() => {
    if (appliedRef.current === urlQuery) return;
    appliedRef.current = urlQuery;
    const next = conformanceFromQuery(parseQuery(urlQuery), defaultKind, tally);
    setKind(next.kind);
    setTerm(next.term);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlQuery]);
  useEffect(() => {
    const next = buildQuery(conformanceToQuery(kind, term, defaultKind));
    if (next === appliedRef.current) return;
    appliedRef.current = next;
    onQueryChange?.(parseQuery(next));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, term]);

  // The report downloads live in the result header when it has a slot for them.
  const [actionsHost, setActionsHost] = useState<HTMLElement | null>(null);
  useLayoutEffect(() => {
    const host = document.getElementById(CONFORMANCE_ACTIONS_SLOT);
    if (host !== actionsHost) setActionsHost(host);
  });
  // On a narrow window the title leaves no room beside the buttons, so they sit
  // at the top of the screen instead of in the header.
  const narrow = useMediaQuery(NARROW_QUERY);
  const reports = useMemo(() => conformanceReports(results), [results]);
  const reportButtons = scanId
    ? reports.map((r) => (
        <Button
          key={r.name}
          as="a"
          href={fileUrl(scanId, r.name)}
          download={r.name}
          title={r.name}
          leadingVisual={DownloadIcon}
          onClick={() => toast(t("result.downloadStarted"))}
        >
          {t("conf.report", { ext: r.name.split(".").pop()?.toUpperCase() })}
        </Button>
      ))
    : null;
  const actions =
    reportButtons && reportButtons.length > 0
      ? actionsHost && !narrow
        ? createPortal(reportButtons, actionsHost)
        : <div className="bl-cf-actions">{reportButtons}</div>
      : null;

  const quality = resultQuality(conformance, isAiDocument);
  const incomplete = !isAiDocument && isIncomplete(completeness);
  const pass = conformance.result === "pass";
  const warnPass = pass && (quality.empty || quality.noLicenses);
  const profileKey = profileLabelKey(profile);

  if (checks.length === 0) {
    return (
      <div className="bl-cf bl-cf-notes">
        {actions}
        <EmptyNotices conformance={conformance} quality={quality} supplied={isSuppliedDocument} completeness={completeness} />
        <div className="bl-cf-box">
          <Blankslate>
            <Blankslate.Visual>
              <ChecklistIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("g7.empty")}</Blankslate.Heading>
          </Blankslate>
        </div>
      </div>
    );
  }

  const write = (k: CheckKind | null, q: string) => {
    setKind(k);
    setTerm(q);
  };
  const keep = (c: ConformanceCheck) => (kind === null || checkKind(c) === kind) && matchesQuery(c, term);
  const shown = checks.filter(keep);
  // Coverage of each advisory baseline, always over ALL of its checks: "32/41
  // present" answers how much of G7 this SBOM documents, which a filtered view
  // must not change.
  const all = splitChecks(checks);
  const cisaT = registryTally(all.cisa);
  const g7t = registryTally(all.g7);
  // A search that finds nothing because a tab is narrowing it should say so: the
  // reader typed a requirement they expect to exist, and "no match" alone reads
  // as "this SBOM has no such check".
  const hiddenByKind = kind !== null && term ? checks.filter((c) => matchesQuery(c, term)).length - shown.length : 0;
  const { base, cisa, g7 } = splitChecks(shown);
  const verdict = verdictTally(checks);
  // A filter opens every group; unfiltered, only the ones holding something to act on.
  const openAll = kind !== null || Boolean(term);
  const actionable = (cs: ConformanceCheck[]) => openAll || cs.some((c) => checkKind(c) === "actionable");
  // Re-mount the folds when the filter changes so their open state is recomputed.
  const foldKey = `${kind ?? "all"}:${term}`;
  const crosswalk = conformance.regulatoryCrosswalk;

  return (
    <div className="bl-cf bl-stack">
      {actions}
      <PipelineNote
        steps={conformance.pipelineStepsFailed ?? []}
        more={conformance.pipelineStepsFailedMore ?? 0}
        supplied={isSuppliedDocument}
      />
      {conformance.submissionJudgedAs && (
        <p className="bl-muted bl-small bl-flat" data-testid="conformance-judged-as">
          {t("conf.submissionJudgedAs", { mode: conformance.submissionJudgedAs })}
        </p>
      )}
      {/* From 1536px the summary stays in a narrow column at the right while the
          checks run beside it; below that the order is summary, tabs, checks. */}
      <div className="bl-cf-grid">
        <div className="bl-cf-side">
          <section className="bl-cf-box" aria-labelledby="bl-cf-sum">
            <div className="bl-cf-head">
              <h2 id="bl-cf-sum">{conformance.format || t("nav.conformance")}</h2>
              {/* A result that is not complete says so before it says "pass". */}
              {incomplete && (
                <Label variant={gradeVariant(completeness.grade)} data-testid="conformance-completeness-grade">
                  {t("completeness.badge", { grade: gradeLabel(completeness, i18n.language ?? "en") })}
                </Label>
              )}
              <Label variant={!pass ? "danger" : warnPass ? "attention" : "success"}>
                {!pass ? t("result.verdictFail") : warnPass ? t("conf.qualityPassWarn") : t("result.verdictPass")}
              </Label>
            </div>
            <div className="bl-cf-body">
              {profileKey && (
                <p className="bl-small" data-testid="conformance-profile">
                  {t("options.conformanceProfile")}: <span className="bl-strong">{t(profileKey)}</span>
                </p>
              )}
              {/* What a pass and a fail mean: this SBOM's own fields against the
                  selected profile's format requirements, not a judgment of the
                  scanned software and not a legal compliance determination. */}
              <p className="bl-muted bl-small">{t("g7.panelIntro")}</p>
              <p className="bl-strong">{t("g7.verdictFailed", { count: verdict.mandatoryFailed })}</p>
              {(quality.empty || quality.noLicenses) && <QualityNote quality={quality} supplied={isSuppliedDocument} completeness={completeness} />}
            </div>
          </section>
        </div>
        <div className="bl-cf-main">
          <div className="bl-cf-bar">
            <div className="bl-cf-tabs" role="group" aria-label={t("conf.kinds")}>
              <button type="button" className="bl-cf-tab" aria-pressed={kind === null} onClick={() => write(null, term)}>
                {t("conf.kind.all")}
                <Count n={checks.length} />
              </button>
              {KINDS.map((k) => (
                <button
                  key={k}
                  type="button"
                  className="bl-cf-tab"
                  aria-pressed={kind === k}
                  disabled={tally[k] === 0}
                  onClick={() => write(k, term)}
                >
                  {t(`conf.kind.${k}`)}
                  <Count n={tally[k]} />
                </button>
              ))}
            </div>
            <TextInput
              type="search"
              leadingVisual={SearchIcon}
              value={term}
              onChange={(e) => write(kind, e.target.value)}
              placeholder={t("conf.searchPlaceholder")}
              aria-label={t("conf.searchPlaceholder")}
              className="bl-cf-search"
            />
            <p className="bl-cf-status" aria-live="polite">
              {kind === null && !term
                ? t("conf.showingAll", { count: checks.length })
                : t("conf.showingFiltered", { count: shown.length, total: checks.length })}
              {hiddenByKind > 0 && shown.length > 0 ? ` ${t("conf.hiddenByFilter", { count: hiddenByKind })}` : null}
            </p>
          </div>
          <div className="bl-stack" key={foldKey}>
            {shown.length === 0 ? (
              <div className="bl-cf-box bl-cf-nomatch">
                <Blankslate>
                  <Blankslate.Visual>
                    <SearchIcon size={24} />
                  </Blankslate.Visual>
                  <Blankslate.Heading as="h2">{t("conf.noMatch")}</Blankslate.Heading>
                </Blankslate>
                {hiddenByKind > 0 && (
                  <p>
                    {t("conf.hiddenByFilter", { count: hiddenByKind })}{" "}
                    <Link as="button" onClick={() => write(null, term)}>
                      {t("conf.searchAllKinds")}
                    </Link>
                  </p>
                )}
              </div>
            ) : (
              <>
                {base.length > 0 && (
                  <FormatBox checks={base} open={actionable(base)} />
                )}
                {cisa.length > 0 && (
                  <BaselineBox
                    title={t("cisa.subtitle")}
                    present={cisaT.present}
                    total={cisaT.autoTotal}
                    note={t("cisa.allAdvisory")}
                    groups={groupByCluster(cisa, CISA_CLUSTER_ORDER).map((g) => ({
                      key: g.cluster,
                      title: t(`cisa.cluster.${g.cluster}`, { defaultValue: g.cluster }),
                      checks: g.checks,
                    }))}
                    open={actionable}
                  />
                )}
                {g7.length > 0 && (
                  <BaselineBox
                    title={t("g7.subtitle")}
                    present={g7t.present}
                    total={g7t.autoTotal}
                    note={t("g7.allAdvisory")}
                    groups={groupG7ByCluster(g7).map((g) => ({
                      key: g.cluster,
                      title: t(`g7.cluster.${g.cluster}`, { defaultValue: g.cluster }),
                      checks: g.checks,
                    }))}
                    open={actionable}
                  />
                )}
              </>
            )}
          </div>
          {/* A roll-up of the whole document: shown whatever the tab, so the default view has it. */}
          {crosswalk && crosswalk.frameworks.length > 0 && <Crosswalk crosswalk={crosswalk} />}
        </div>
      </div>
    </div>
  );
}
