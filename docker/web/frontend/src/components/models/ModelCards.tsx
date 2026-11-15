// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  AlertIcon,
  CheckCircleIcon,
  CircleIcon,
  CpuIcon,
  DatabaseIcon,
  InfoIcon,
  LinkExternalIcon,
  ServerIcon,
} from "@primer/octicons-react";
import { Label, Link } from "@primer/react";
import { Table } from "@primer/react/experimental";
import { type ReactNode, useMemo } from "react";
import { useTranslation } from "react-i18next";

import type { ConformanceSummary } from "@/lib/api";
import { groupG7ByCluster, registryTally, splitChecks } from "@/lib/conformance";
import { formatNumber } from "@/lib/format";
import { renderLocalized } from "@/lib/localized";
import { localizeReasons } from "@/lib/modelReasons";
import {
  type AssessmentGrade,
  type DatasetRef,
  type DeclaredService,
  datasetTreeRows,
  GRADE_LABEL_KEY,
  GRADE_LABEL_VARIANT,
  type ModelAssessment,
  type ModelCard,
  USAGE_LABEL_KEY,
} from "@/lib/models";

import { CheckGroup } from "../conformance/CheckRow";
import "../conformance/conformance.css";
import "./models.css";

/** A stamped grade as a word on a Label; the colour only reinforces the word. */
export function GradeLabel({ grade }: { grade: AssessmentGrade }) {
  const { t } = useTranslation();
  return <Label variant={GRADE_LABEL_VARIANT[grade]}>{t(GRADE_LABEL_KEY[grade])}</Label>;
}

/** A link whose text is the host and path; the whole address is the tooltip. The
 *  icon stays with the last characters, so it never sits alone on a line. */
function ExternalLink({ url }: { url: string }) {
  const text = shortUrl(url);
  const cut = Math.max(0, text.length - 6);
  return (
    <Link href={url} target="_blank" rel="noreferrer" title={url} className="bl-md-link">
      {text.slice(0, cut)}
      <span className="bl-md-tail">
        {text.slice(cut)}
        <LinkExternalIcon size={12} />
      </span>
    </Link>
  );
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname === "/" ? "" : u.pathname}${u.search}`;
  } catch {
    return url;
  }
}

/** External references by their type, in first-seen order, each address once. */
function groupRefs(refs: Array<{ type: string; url: string }>): Array<{ type: string; urls: string[] }> {
  const out: Array<{ type: string; urls: string[] }> = [];
  for (const r of refs) {
    const g = out.find((x) => x.type === r.type) ?? out[out.push({ type: r.type, urls: [] }) - 1];
    if (!g.urls.includes(r.url)) g.urls.push(r.url);
  }
  return out;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="bl-md-field">
      <div className="bl-md-flabel">{label}</div>
      <div>{children}</div>
    </div>
  );
}

/**
 * The pipeline's stamped verdict: per-axis grades (an unevaluated axis says so),
 * the grounds, the custom-license excerpt and the lineage warning. Pure display:
 * every value comes verbatim from the SBOM properties.
 */
function Assessment({
  assessment: a,
  customLicenseQuote,
  lineageConflictWith,
}: {
  assessment: ModelAssessment;
  customLicenseQuote?: string;
  lineageConflictWith?: string;
}) {
  const { t } = useTranslation();
  const axes: Array<{ key: string; label: string; grade?: AssessmentGrade }> = [
    { key: "license", label: t("models.assessLicense"), grade: a.license },
    { key: "security", label: t("models.assessSecurity"), grade: a.security },
    { key: "datasets", label: t("models.assessDatasets"), grade: a.datasets },
    { key: "trainingData", label: t("models.assessTrainingData"), grade: a.trainingData },
  ];
  const reasons = useMemo(() => localizeReasons(a.reasons), [a.reasons]);
  return (
    <div className="bl-md-inset">
      <div className="bl-md-axes">
        <span className="bl-muted bl-small">{t("models.assessment")}</span>
        {axes.map(({ key, label, grade }) => (
          <span key={key} className="bl-md-axis">
            {label}
            {grade ? (
              <GradeLabel grade={grade} />
            ) : (
              <span className="bl-muted" title={t("models.assessNotEvaluated")}>
                {t("models.noVerdict")}
                <span className="sr-only"> ({t("models.assessNotEvaluated")})</span>
              </span>
            )}
          </span>
        ))}
      </div>
      {a.usageContext && <Field label={t("models.usageContext")}>{t(USAGE_LABEL_KEY[a.usageContext])}</Field>}
      {a.reasons.length > 0 && (
        <Field label={t("models.reasons")}>
          <ul className="bl-md-list">
            {/* Stamped in the scan's language; an English sentence the scanner
                writes is shown in the UI language, with the stamped text kept
                as the tooltip. Anything else stays verbatim. */}
            {reasons.map(({ text, key }, i) =>
              key ? (
                <li key={i} title={text}>
                  {renderLocalized(t, key)}
                </li>
              ) : (
                <li key={i}>{text}</li>
              ),
            )}
          </ul>
        </Field>
      )}
      {customLicenseQuote && (
        <Field label={t("models.customLicenseQuote")}>
          <p className="bl-md-quote">{customLicenseQuote}</p>
        </Field>
      )}
      {lineageConflictWith && (
        <p className="bl-md-conflict">
          <span className="bl-md-warn" aria-hidden>
            <AlertIcon size={14} />
          </span>
          {t("models.lineageConflict", { name: lineageConflictWith })}
        </p>
      )}
    </div>
  );
}

export function ModelCardBox({ model: m }: { model: ModelCard }) {
  const { t } = useTranslation();
  const axes: Array<{ key: keyof ModelCard["disclosure"]; label: string }> = [
    { key: "weights", label: t("models.axisWeights") },
    { key: "architecture", label: t("models.axisArchitecture") },
    { key: "trainingData", label: t("models.axisTrainingData") },
    { key: "trainingProcess", label: t("models.axisTrainingProcess") },
  ];
  return (
    <section className="bl-box" aria-label={m.name} data-testid="model-card">
      <div className="bl-box-head">
        <span className="bl-md-icon" aria-hidden>
          <CpuIcon size={16} />
        </span>
        <h2 className="bl-mono">
          {m.group ? `${m.group} / ` : ""}
          {m.name}
          {m.version && <span className="bl-muted bl-md-light"> {m.version}</span>}
        </h2>
        {m.assessment && <GradeLabel grade={m.assessment.overall} />}
        {/* Neutral, not a grade colour: a licence id is a fact about the model,
            and next to the verdict the two would read as one kind of thing. */}
        {m.licenses.map((l) => (
          <Label key={l} variant="secondary">
            {l}
          </Label>
        ))}
      </div>
      <div className="bl-box-body bl-md-body">
        {m.assessment && (
          <Assessment
            assessment={m.assessment}
            customLicenseQuote={m.customLicenseQuote}
            lineageConflictWith={m.lineageConflictWith}
          />
        )}
        {m.description && <p className="bl-md-text">{m.description}</p>}
        <div className="bl-md-facts">
          {m.architecture && <Field label={t("models.architecture")}>{m.architecture}</Field>}
          {m.task && <Field label={t("models.task")}>{m.task}</Field>}
          {m.supplier && <Field label={t("models.supplier")}>{m.supplier}</Field>}
          <Field label={t("models.integrity")}>
            <span className={m.hasIntegrity ? undefined : "bl-muted"}>
              {m.hasIntegrity ? t("models.integrityYes") : t("models.integrityNo")}
            </span>
          </Field>
        </div>
        {m.purl && (
          <Field label={t("models.identifier")}>
            <span className="bl-mono bl-breakall">{m.purl}</span>
          </Field>
        )}
        {m.localScan && (
          <Field label={t("models.localScan")}>
            <span
              className={
                m.localScan === "unsafe" ? "bl-md-unsafe" : m.localScan === "clean" || m.localScan === "not-applicable" ? "bl-muted" : undefined
              }
            >
              {t(`models.localScan_${m.localScan.replace("-", "_")}`)}
            </span>
            {m.localScanFindings && <span className="bl-mono bl-muted bl-breakall"> {m.localScanFindings}</span>}
            {m.localScanTool && <span className="bl-muted bl-small"> ({m.localScanTool})</span>}
          </Field>
        )}
        <div className="bl-md-field">
          <div className="bl-md-flabel" title={t("models.disclosureHint")}>
            {t("models.disclosure")}
          </div>
          <div className="bl-md-axes bl-md-axes-gap">
            {axes.map(({ key, label }) => {
              const on = m.disclosure[key];
              return (
                <span
                  key={key}
                  className="bl-md-axis"
                  data-on={on}
                  title={on ? t("models.documented") : t("models.notDocumented")}
                >
                  <span className={on ? "bl-md-on" : "bl-md-off"} aria-hidden>
                    {on ? <CheckCircleIcon size={14} /> : <CircleIcon size={14} />}
                  </span>
                  {label}
                  <span className="sr-only">: {on ? t("models.documented") : t("models.notDocumented")}</span>
                </span>
              );
            })}
          </div>
        </div>
        {m.limitations.length > 0 && (
          <Field label={t("models.limitations")}>
            <ul className="bl-md-list">
              {m.limitations.map((l, i) => (
                <li key={i}>{l}</li>
              ))}
            </ul>
          </Field>
        )}
        {m.externalRefs.length > 0 && (
          <Field label={t("models.references")}>
            <ul className="bl-md-plain bl-md-refs">
              {groupRefs(m.externalRefs).map(({ type, urls }) => (
                <li key={type}>
                  <span className="bl-muted bl-md-reftype">{t(`models.refType.${type}`, { defaultValue: type })}</span>
                  <ul className="bl-md-plain">
                    {urls.map((url) => (
                      <li key={url}>
                        <ExternalLink url={url} />
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </Field>
        )}
      </div>
    </section>
  );
}

/**
 * The service (an app or API) the publisher declared the model runs in, read
 * from the CycloneDX SBOM. Every value is the publisher's word: the label and
 * the note say so, so it is not read as something the scan found.
 */
export function ServiceBox({ service: s }: { service: DeclaredService }) {
  const { t } = useTranslation();
  const none = <span className="bl-muted">{t("models.service.notStated")}</span>;
  return (
    <section className="bl-box" data-testid="declared-service">
      <div className="bl-box-head">
        <span className="bl-md-icon" aria-hidden>
          <ServerIcon size={16} />
        </span>
        <span className="bl-muted bl-small">{t("models.service.kind")}</span>
        <h2>
          {s.name}
          {s.version && <span className="bl-muted bl-md-light"> {s.version}</span>}
        </h2>
        <Label variant="secondary">{t("models.service.declared")}</Label>
      </div>
      <div className="bl-box-body bl-md-body">
        <p className="bl-md-text">{t("models.service.note")}</p>
        {s.description && <p className="bl-md-text">{s.description}</p>}
        <div className="bl-md-facts">
          <Field label={t("models.service.provider")}>{s.provider ?? none}</Field>
          <Field label={t("models.service.runs")}>
            {s.models.length ? <span className="bl-mono bl-breakall">{s.models.join(", ")}</span> : none}
          </Field>
          <Field label={t("models.service.dataFlows")}>
            <span className="bl-num">{t("models.service.dataFlowCount", { count: s.dataFlows })}</span>
          </Field>
          {s.endpoint && (
            <Field label={t("models.service.endpoint")}>
              <span className="bl-mono bl-breakall">{s.endpoint}</span>
            </Field>
          )}
        </div>
        <Field label={t("models.service.externalModels")}>
          {s.externalModels.length ? (
            <ul className="bl-md-list" data-testid="declared-external-models">
              {s.externalModels.map((m, i) => (
                <li key={`${m.name}-${i}`}>
                  <span className="bl-strong">{m.name}</span>
                  {(m.provider || m.version) && (
                    <span className="bl-muted"> {[m.provider, m.version].filter(Boolean).join(", ")}</span>
                  )}
                  {m.endpoint && <span className="bl-mono bl-muted bl-breakall"> {m.endpoint}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <span className="bl-muted">{t("models.service.noExternal")}</span>
          )}
        </Field>
      </div>
    </section>
  );
}

/**
 * The "Derived from" cell. When the pipeline traced sources, the traced ones are
 * rows of their own beneath this one, so the cell only counts them and adds what
 * the rows cannot show: a card that calls the data original, sources named in
 * words (kept verbatim, never looked up, so marked for checking), and why the
 * walk stopped here. Without tracing it lists the card's values as before.
 */
function DatasetSources({ dataset: d }: { dataset: DatasetRef }) {
  const { t } = useTranslation();
  if (d.depth === undefined) {
    return d.sources.length > 0 ? (
      <span className="bl-breakall">{d.sources.join(", ")}</span>
    ) : (
      <span className="bl-muted">{"-"}</span>
    );
  }
  const original = d.sources.some((s) => s.trim().toLowerCase() === "original");
  if (d.derivedFrom.length + d.unverifiedSources.length + (original ? 1 : 0) === 0 && !d.trace) {
    return <span className="bl-muted">{"-"}</span>;
  }
  return (
    <div className="bl-md-sources">
      {d.derivedFrom.length > 0 && <div>{t("models.dsSourceCount", { count: d.derivedFrom.length })}</div>}
      {original && <div>{t("models.dsSourceOriginal")}</div>}
      {d.unverifiedSources.map((s) => (
        <div key={s} className="bl-md-source">
          <span className="bl-breakall">{s}</span>
          {/* The pipeline grades such a source "review"; same tone as that grade. */}
          <Label variant="severe">{t("models.dsSourceUnverified")}</Label>
        </div>
      ))}
      {d.trace === "depth-limit" && <div className="bl-muted">{t("models.dsTraceDepthLimit")}</div>}
      {d.trace === "cycle" && <div className="bl-muted">{t("models.dsTraceCycle")}</div>}
    </div>
  );
}

export function DatasetsBox({ datasets }: { datasets: DatasetRef[] }) {
  const { t, i18n } = useTranslation();
  const hasAssessment = datasets.some((d) => d.assessment);
  const columns = hasAssessment
    ? "minmax(14rem, 1.4fr) fit-content(10rem) minmax(8rem, 0.7fr) fit-content(9rem) minmax(10rem, 1fr)"
    : "minmax(14rem, 1.4fr) minmax(8rem, 0.7fr) fit-content(9rem) minmax(10rem, 1fr)";
  return (
    <section className="bl-box" aria-labelledby="bl-md-datasets">
      <div className="bl-box-head">
        <span className="bl-md-icon" aria-hidden>
          <DatabaseIcon size={16} />
        </span>
        <h2 id="bl-md-datasets">{t("models.datasets")}</h2>
        <span className="bl-muted bl-num">{formatNumber(datasets.length, i18n.language)}</span>
      </div>
      <Table.Container className="bl-md-table">
        <Table gridTemplateColumns={columns} cellPadding="condensed" aria-labelledby="bl-md-datasets">
          <Table.Head>
            <Table.Row>
              <Table.Header>{t("models.dsName")}</Table.Header>
              {hasAssessment && <Table.Header>{t("models.dsAssessment")}</Table.Header>}
              <Table.Header>{t("models.dsLicense")}</Table.Header>
              <Table.Header>{t("models.dsIntegrity")}</Table.Header>
              <Table.Header>{t("models.dsSource")}</Table.Header>
            </Table.Row>
          </Table.Head>
          <Table.Body>
            {datasetTreeRows(datasets).map(({ dataset: d, level, relation, repeat }, i) => (
              <Table.Row key={`${d.ref ?? d.name}-${i}`}>
                {/* A traced source sits under the dataset it came from. */}
                <Table.Cell
                  scope="row"
                  style={level > 0 ? { paddingInlineStart: `calc(var(--base-size-12) + ${level * 1.25}rem)` } : undefined}
                >
                  <div className="bl-md-dsname">
                    {level > 0 && (
                      <span className="bl-md-tree" aria-hidden>
                        {"└ "}
                      </span>
                    )}
                    {relation && (
                      <span className="sr-only">
                        {t("models.dsSourceOf", { relation: t(`models.dsRelation.${relation}`, relation) })}
                      </span>
                    )}
                    <span className="bl-mono">{d.name}</span>
                    {d.version && <span className="bl-muted bl-mono">@{d.version}</span>}{" "}
                    {d.collectedBy && <Label variant="secondary">{d.collectedBy}</Label>}{" "}
                    {relation && <Label variant="secondary">{t(`models.dsRelation.${relation}`, relation)}</Label>}
                    {repeat && <span className="bl-muted bl-small"> {t("models.dsListedAbove")}</span>}
                    {d.url && (
                      <div className="bl-md-dsurl">
                        <ExternalLink url={d.url} />
                      </div>
                    )}
                  </div>
                </Table.Cell>
                {hasAssessment && (
                  <Table.Cell>
                    {d.assessment ? <GradeLabel grade={d.assessment} /> : <span className="bl-muted">{t("models.noVerdict")}</span>}
                  </Table.Cell>
                )}
                <Table.Cell>
                  {/* An unreadable repository is said so, rather than shown as a
                      dataset with no license: the two mean different things. */}
                  {d.unresolved ? (
                    <Label variant="attention">{t("models.dsUnresolved")}</Label>
                  ) : d.licenses.some((l) => l.trim().toLowerCase() !== "unknown") ? (
                    <span className="bl-mono bl-breakall">{d.licenses.join(", ")}</span>
                  ) : (
                    <span className="bl-muted">{t("models.dsLicenseNotStated")}</span>
                  )}
                </Table.Cell>
                <Table.Cell>
                  <span
                    className="bl-md-nowrap"
                    title={d.hasIntegrity ? t("models.dsHashed") : t("models.dsNotHashed")}
                  >
                    <span className={d.hasIntegrity ? "bl-success" : "bl-muted bl-inline"} aria-hidden>
                      {d.hasIntegrity ? <CheckCircleIcon size={16} /> : <CircleIcon size={16} />}
                    </span>
                    <span className={d.hasIntegrity ? undefined : "bl-muted"}>
                      {d.hasIntegrity ? t("models.integrityYes") : t("models.integrityNo")}
                    </span>
                  </span>
                </Table.Cell>
                <Table.Cell>
                  {/* A repeat row's sources are on its full row above. */}
                  {repeat ? <span className="bl-muted">{"-"}</span> : <DatasetSources dataset={d} />}
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      </Table.Container>
    </section>
  );
}

/** The model-card disclaimer shown once any grade is on screen. */
export function Disclaimer() {
  const { t } = useTranslation();
  return (
    <p className="bl-md-disclaimer">
      <InfoIcon size={14} />
      <span>{t("models.disclaimer")}</span>
    </p>
  );
}

/**
 * What this model's own card/listing discloses, measured against the G7 minimum
 * elements, for an AI SBOM BomLens generated itself (AIBOM, a model file scan, a
 * dataset scan). It uses the Conformance screen's baseline box, so the data and
 * its grouping match what an uploaded AI SBOM shows there. A gap here is the
 * model's publisher not having disclosed something in the card BomLens read, a
 * real finding about the model, so it keeps its checklist framing. The headline
 * rollup is AiSummaryCard's job (top of Overview); this is only the detail.
 */
export function G7Disclosure({ conformance }: { conformance: ConformanceSummary }) {
  const { t } = useTranslation();
  const { g7 } = splitChecks(conformance.checks ?? []);
  if (g7.length === 0) return null;
  const tally = registryTally(g7);
  return (
    <section className="bl-cf-box" data-testid="g7-disclosure" aria-labelledby="bl-md-g7">
      <div className="bl-cf-head">
        <h2 id="bl-md-g7">{t("models.g7SectionTitle")}</h2>
        <span className="bl-strong bl-num">{t("g7.present", { present: tally.present, total: tally.autoTotal })}</span>
        <span className="bl-muted bl-small">{t("g7.allAdvisory")}</span>
        <p className="bl-md-headintro bl-muted">{t("models.g7SectionIntro")}</p>
      </div>
      <div className="bl-cf-groups">
        {groupG7ByCluster(g7).map((group) => (
          <CheckGroup
            key={group.cluster}
            title={t(`g7.cluster.${group.cluster}`, { defaultValue: group.cluster })}
            checks={group.checks}
            // Folded: forty-odd rows would run the page long. A group's head
            // carries its count, and the met elements fold inside it.
            defaultOpen={false}
            foldMet
          />
        ))}
      </div>
    </section>
  );
}
