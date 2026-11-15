// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, FileBadgeIcon, PencilIcon } from "@primer/octicons-react";
import { Banner, Button, Label } from "@primer/react";
import { Table } from "@primer/react/experimental";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { Spdx3Summary } from "@/lib/api";
import {
  bandSegments,
  formatDay,
  missingByElement,
  parseFlowDisplay,
  readDisplay,
  rolesNotStated,
  type CheckElement,
  type FieldStatus,
  type Spdx3Check,
} from "@/lib/aiDeclaration";
import { formatNumber } from "@/lib/format";

import "./models/models.css";

/**
 * The SPDX 3.0.1 AI document's state on the Models & datasets screen: draft or
 * complete, how its fields were filled, and the way into the questions that
 * fill the rest. A scan from before the document existed gets a button that
 * writes it instead.
 */
export function Spdx3StatusBand({
  summary,
  available,
  busy,
  onFill,
  onWrite,
  focusFill,
  check,
  publisher = false,
  onRescan,
}: {
  summary: Spdx3Summary | null | undefined;
  /** This server can write the document and save a declaration. */
  available: boolean;
  /** A write or a save is in flight. */
  busy: boolean;
  onFill: () => void;
  onWrite: () => void;
  /** The question flow just closed: give focus back to the button that opened it. */
  focusFill?: boolean;
  /** The per-field detail, to say where the open required fields are. */
  check?: Spdx3Check | null;
  /** The person reading is the model's publisher (a model described from a
   *  declaration). Otherwise they scanned someone else's model, and filling
   *  the document matters only if they publish it themselves. */
  publisher?: boolean;
  /** Open the scan again with its settings (the top bar's re-scan), offered
   *  when a declared service is not in the CycloneDX SBOM yet. */
  onRescan?: () => void;
}) {
  const { t, i18n } = useTranslation();
  const fillRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (focusFill) fillRef.current?.focus();
  }, [focusFill]);

  if (!summary) {
    return (
      <section className="bl-box" data-testid="spdx3-band" aria-labelledby="bl-md-spdx-title">
        <div className="bl-box-head">
          <span className="bl-md-icon" aria-hidden>
            <FileBadgeIcon size={16} />
          </span>
          <h2 id="bl-md-spdx-title">{t("spdx3.band.title")}</h2>
          {available && (
            <span className="bl-box-head-end">
              <Button size="small" leadingVisual={FileBadgeIcon} onClick={onWrite} loading={busy}>
                {t("spdx3.band.write")}
              </Button>
            </span>
          )}
        </div>
        <div className="bl-box-body bl-muted">{available ? t("spdx3.band.none") : t("spdx3.band.unavailable")}</div>
      </section>
    );
  }

  const segments = bandSegments(summary.counts);
  const total = segments.reduce((n, s) => n + s.count, 0) || 1;
  const missing = summary.counts.missingRequired ?? 0;
  const refused = summary.declaration?.state === "refused";
  // What was declared after the scan (a service, or the model's input and
  // output kinds and regulatory values) is in this document already, but the
  // CycloneDX SBOM and its G7 checks get it only from a new scan. The check
  // says so with or without a service, so the note names the service only
  // when the document has one.
  const servicePending = summary.service?.state === "pendingScan";
  const hasService = Boolean(check?.elements.some((e) => e.type === "service"));
  const where = check && missing > 0 ? missingByElement(check) : [];

  return (
    <section className="bl-box" data-testid="spdx3-band" aria-labelledby="bl-md-spdx-title">
      <div className="bl-box-head">
        <span className="bl-md-icon" aria-hidden>
          <FileBadgeIcon size={16} />
        </span>
        <h2 id="bl-md-spdx-title">{t("spdx3.band.title")}</h2>
        <Label variant={summary.draft ? "attention" : "success"}>{summary.draft ? t("spdx3.draft") : t("spdx3.complete")}</Label>
        {available && (
          <span className="bl-box-head-end">
            <Button ref={fillRef} variant="primary" size="small" leadingVisual={PencilIcon} onClick={onFill} loading={busy}>
              {t("spdx3.band.fill")}
            </Button>
          </span>
        )}
      </div>
      <div className="bl-box-body bl-md-stack">
        <div className="bl-md-bar" aria-hidden>
          {segments.map((s) => (s.count > 0 ? <span key={s.key} data-seg={s.key} style={{ flex: s.count / total }} /> : null))}
        </div>
        <ul className="bl-md-legend">
          {segments.map((s) => (
            <li key={s.key} data-segment={s.key}>
              <span className="bl-md-dot" data-seg={s.key} aria-hidden />
              {t(`spdx3.segment.${s.key}`)}
              <span className="bl-strong bl-num">{formatNumber(s.count, i18n.language)}</span>
            </li>
          ))}
        </ul>
        <p className="bl-md-p bl-muted">
          {summary.draft ? t("spdx3.band.draftNote", { count: missing }) : t("spdx3.band.completeNote")}
          {summary.draft && !publisher && <> {t("spdx3.band.consumerNote")}</>}
        </p>
        {where.length > 0 && (
          <p className="bl-md-p" data-testid="spdx3-missing-where">
            {t("spdx3.band.missingAt", {
              list: where
                .map((e) =>
                  t("spdx3.band.missingItem", {
                    label:
                      e.type === "CreationInfo"
                        ? t("spdx3.band.documentLabel")
                        : e.type === "service"
                          ? t("spdx3.band.serviceLabel", { name: e.label })
                          : e.label,
                    count: e.count,
                  }),
                )
                .join(", "),
            })}
          </p>
        )}
        {servicePending && (
          <Banner
            variant="info"
            role="status"
            data-testid="spdx3-service-pending"
            title={t(hasService ? "spdx3.band.servicePending" : "spdx3.band.declarationPending")}
            primaryAction={
              onRescan ? (
                <Banner.PrimaryAction onClick={onRescan} title={t("result.rescanHint")}>
                  {t("result.rescan")}
                </Banner.PrimaryAction>
              ) : undefined
            }
          />
        )}
        {refused && (
          <Banner variant="warning" role="status">
            <Banner.Title as="h3">{t("spdx3.band.refused")}</Banner.Title>
            <Banner.Description>
              <ul className="bl-md-reasons">
                {(summary.declaration?.reasons ?? []).slice(0, 5).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </Banner.Description>
          </Banner>
        )}
      </div>
    </section>
  );
}

const STATUS_VARIANT: Record<FieldStatus, "success" | "secondary" | "primary" | "accent" | "attention"> = {
  auto: "success",
  declared: "primary",
  noAssertion: "secondary",
  missingRequired: "attention",
  judgment: "accent",
  optional: "secondary",
  omitted: "secondary",
  review: "secondary",
};

export function Spdx3StatusBadge({ status }: { status: FieldStatus }) {
  const { t } = useTranslation();
  return <Label variant={STATUS_VARIANT[status]}>{t(`spdx3.status.${status}`)}</Label>;
}

/** The translation namespace for an element type's field names. The check
 *  names a declared service and its external models by their mapping keys. */
export function fieldNamespace(type: string): "document" | "model" | "dataset" | "service" | "externalModel" {
  switch (type) {
    case "CreationInfo":
      return "document";
    case "ai_AIPackage":
      return "model";
    case "service":
      return "service";
    case "externalModel":
      return "externalModel";
    default:
      return "dataset";
  }
}

const SHOWN: FieldStatus[] = ["auto", "declared", "noAssertion", "missingRequired", "judgment"];

type ExtraRow = { key: string; label: string; value: string | null; status: FieldStatus; statusLabel?: string };

/**
 * One element's fields in the SPDX 3.0.1 document: the value and where it came
 * from. Optional fields nobody filled are counted under the table instead of
 * listed, so the rows that need attention are not lost among them.
 */
export function Spdx3FieldTable({
  element,
  extraRows = [],
  trailingRows = [],
}: {
  element: CheckElement;
  /** Rows from the document as a whole (its author), shown before the fields. */
  extraRows?: ExtraRow[];
  /** Rows from a relationship (how the model used a dataset), shown after them. */
  trailingRows?: ExtraRow[];
}) {
  const { t } = useTranslation();
  const ns = fieldNamespace(element.type);
  const rows = element.fields.filter((f) => SHOWN.includes(f.status) || (f.status === "optional" && f.display));
  const hidden = element.fields.filter((f) => f.status === "optional" && !f.display).length;
  return (
    <>
      <Table.Container className="bl-md-fieldtable">
        <Table gridTemplateColumns="minmax(10rem, 0.8fr) minmax(0, 2fr) fit-content(12rem)" cellPadding="condensed" aria-label={element.label}>
          <Table.Head>
            <Table.Row>
              <Table.Header>{t("spdx3.table.field")}</Table.Header>
              <Table.Header>{t("spdx3.table.value")}</Table.Header>
              <Table.Header>{t("spdx3.table.status")}</Table.Header>
            </Table.Row>
          </Table.Head>
          <Table.Body>
            {extraRows.map((r) => (
              <ExtraTableRow key={r.key} row={r} />
            ))}
            {rows.map((f) => (
              <Table.Row key={f.id} data-field={f.id}>
                <Table.Cell>{t(`aiDecl.${ns}.${f.id}.label`, { defaultValue: f.id })}</Table.Cell>
                <Table.Cell>
                  <span className="bl-breakall">
                    {f.display !== undefined ? (
                      <DisplayText ns={ns} fieldId={f.id} display={f.display} />
                    ) : (
                      <span className="bl-muted">{t("spdx3.table.notFilled")}</span>
                    )}
                    {f.meaning === "huggingface-publisher" && (
                      <span className="bl-muted"> {t("spdx3.table.hubPublisher")}</span>
                    )}
                  </span>
                </Table.Cell>
                <Table.Cell>
                  <Spdx3StatusBadge status={f.status} />
                </Table.Cell>
              </Table.Row>
            ))}
            {trailingRows.map((r) => (
              <ExtraTableRow key={r.key} row={r} />
            ))}
          </Table.Body>
        </Table>
      </Table.Container>
      {hidden > 0 && <p className="bl-md-fieldnote">{t("spdx3.table.optionalHidden", { count: hidden })}</p>}
    </>
  );
}

/** A value from the check as the questions word it: a date in the reader's
 *  locale, a choice by its label; anything else as written. */
function DisplayText({ ns, fieldId, display }: { ns: string; fieldId: string; display: string }) {
  const { t, i18n } = useTranslation();
  // A service's data flows: the direction in the words the questions use.
  if (ns === "service" && fieldId === "dataFlows") {
    return (
      <>
        {parseFlowDisplay(display)
          .map((p) =>
            p.flow ? `${t(`aiDecl.dataFlow.flow.option.${p.flow}`, { defaultValue: p.flow })}: ${p.text}` : p.text,
          )
          .join(", ")}
      </>
    );
  }
  const v = readDisplay(fieldId, display);
  if (v.kind === "date") {
    return <time dateTime={display}>{formatDay(display, i18n.language)}</time>;
  }
  if (v.kind === "enum") {
    // A service's autonomy reads as the question asked it: is a person involved.
    const key = ns === "service" && fieldId === "autonomyType" ? "aiDecl.service.autonomyType.option" : "aiDecl.enum";
    return <>{v.values.map((x) => t(`${key}.${x}`, { defaultValue: x })).join(", ")}</>;
  }
  return <>{v.text}</>;
}

function ExtraTableRow({ row }: { row: ExtraRow }) {
  const { t } = useTranslation();
  return (
    <Table.Row>
      <Table.Cell>{row.label}</Table.Cell>
      <Table.Cell>
        <span className="bl-breakall">{row.value ?? <span className="bl-muted">{t("spdx3.table.notFilled")}</span>}</span>
      </Table.Cell>
      <Table.Cell>
        {row.statusLabel ? <Label variant="secondary">{row.statusLabel}</Label> : <Spdx3StatusBadge status={row.status} />}
      </Table.Cell>
    </Table.Row>
  );
}

function Sub({ title, caption, children }: { title: ReactNode; caption?: string | null; children: ReactNode }) {
  return (
    <div className="bl-md-sub">
      <div className="bl-md-subhead">
        <span className="bl-strong">{title}</span>
        {caption && <span className="bl-muted bl-small">{caption}</span>}
      </div>
      {children}
    </div>
  );
}

/** The SPDX 3.0.1 view of the scan: the model's fields (with the document's
 *  author and the datasets whose role is open), then each dataset's, folded.
 *  The whole table folds too: someone who scanned another publisher's model
 *  reads the model card first; the publisher of a declared model sees it open. */
export function Spdx3Fields({ check, defaultOpen = false }: { check: Spdx3Check; defaultOpen?: boolean }) {
  const { t } = useTranslation();
  const doc = check.elements.find((e) => e.type === "CreationInfo");
  const model = check.elements.find((e) => e.type === "ai_AIPackage");
  const datasets = check.elements.filter((e) => e.type === "dataset_DatasetPackage");
  const service = check.elements.find((e) => e.type === "service");
  const externals = check.elements.filter((e) => e.type === "externalModel");
  const author = doc?.fields.find((f) => f.id === "createdBy");
  const extra = author
    ? [{ key: "createdBy", label: t("aiDecl.document.createdBy.label"), value: author.display ?? null, status: author.status }]
    : [];
  // Datasets whose role is open, by where they were named: the scanned
  // model's card, or the publisher's own declaration.
  const roles = rolesNotStated(check);
  const roleRow = (key: string, label: string, names: string[]) => ({
    key,
    label,
    value: names.join(", ") || null,
    status: "review" as FieldStatus,
    statusLabel: t("spdx3.table.roleOpen"),
  });
  const roleRows = [
    ...(roles.card.length ? [roleRow("roles", t("spdx3.table.cardDatasets"), roles.card)] : []),
    ...(roles.declared.length ? [roleRow("declaredRoles", t("spdx3.table.declaredDatasets"), roles.declared)] : []),
  ];
  const folded = datasets.slice(model ? 0 : 1);
  const foldedMissing = folded.reduce(
    (n, d) => n + d.fields.filter((f) => f.status === "missingRequired").length,
    0,
  );
  // Captured once so React never fights the person's own open and close.
  const [initialOpen] = useState(defaultOpen);
  const [foldOpen] = useState(foldedMissing > 0);
  return (
    <details className="bl-box" open={initialOpen || undefined}>
      <summary className="bl-box-head bl-md-sum">
        <span className="bl-md-chev" aria-hidden>
          <ChevronRightIcon size={16} />
        </span>
        <span className="bl-strong">{t("spdx3.table.toggle")}</span>
      </summary>
      <div data-testid="spdx3-fields">
        {model && (
          <Sub title={model.label} caption={t("spdx3.table.caption")}>
            <Spdx3FieldTable element={model} extraRows={extra} trailingRows={roleRows} />
          </Sub>
        )}
        {service && (
          <div data-testid="spdx3-service-fields">
            <Sub
              title={
                <>
                  {service.label} <Label variant="secondary">{t("spdx3.table.publisherDeclared")}</Label>
                </>
              }
              caption={t("spdx3.table.serviceCaption")}
            >
              <Spdx3FieldTable element={service} />
              {externals.map((e) => (
                <div key={e.declarationKey ?? e.label} className="bl-md-ext" data-testid="spdx3-external-model">
                  <div className="bl-md-extname">{t("spdx3.table.externalModel", { name: e.label })}</div>
                  <Spdx3FieldTable element={e} />
                </div>
              ))}
            </Sub>
          </div>
        )}
        {!model && doc && datasets[0] && (
          <Sub title={datasets[0].label}>
            <Spdx3FieldTable element={datasets[0]} extraRows={extra} />
          </Sub>
        )}
        {folded.length > 0 && (
          // Opens by itself when it holds required fields still empty, so they
          // are not hidden behind a fold.
          <details className="bl-md-folded" open={foldOpen || undefined}>
            <summary className="bl-md-sum" data-testid="spdx3-dataset-fields">
              <span className="bl-md-chev" aria-hidden>
                <ChevronRightIcon size={16} />
              </span>
              <span className="bl-strong">{t("spdx3.table.datasetFields", { count: folded.length })}</span>
              {foldedMissing > 0 && (
                <span className="bl-md-danger">{t("spdx3.table.datasetMissing", { count: foldedMissing })}</span>
              )}
            </summary>
            {folded.map((d) => (
              <Sub key={d.declarationKey ?? d.label} title={d.label}>
                <Spdx3FieldTable element={d} />
              </Sub>
            ))}
          </details>
        )}
        <p className="bl-md-legal">{t("spdx3.table.notLegalAdvice")}</p>
      </div>
    </details>
  );
}
