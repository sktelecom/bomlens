// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FileCheck2, Info, Loader2, PencilLine, RotateCw, TriangleAlert } from "lucide-react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
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
import { cn } from "@/lib/utils";

const SEGMENT_COLOR: Record<string, string> = {
  filled: "bg-risk-low",
  optional: "bg-muted-foreground/40",
  judgment: "bg-risk-medium",
  missingRequired: "bg-risk-critical",
};

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
  const { t } = useTranslation();
  const fillRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (focusFill) fillRef.current?.focus();
  }, [focusFill]);

  if (!summary) {
    return (
      <Card data-testid="spdx3-band">
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
          <div className="min-w-0">
            <div className="text-body-sm font-semibold">{t("spdx3.band.title")}</div>
            <p className="mt-0.5 text-body-sm text-muted-foreground">
              {available ? t("spdx3.band.none") : t("spdx3.band.unavailable")}
            </p>
          </div>
          {available && (
            <Button variant="outline" size="sm" onClick={onWrite} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileCheck2 className="h-4 w-4" />}
              {t("spdx3.band.write")}
            </Button>
          )}
        </CardContent>
      </Card>
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
    <Card data-testid="spdx3-band">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-body-sm font-semibold">{t("spdx3.band.title")}</span>
            {summary.draft ? (
              <Badge tone="warning">{t("spdx3.draft")}</Badge>
            ) : (
              <Badge tone="success">{t("spdx3.complete")}</Badge>
            )}
          </div>
          {available && (
            <Button ref={fillRef} size="sm" onClick={onFill} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PencilLine className="h-4 w-4" />}
              {t("spdx3.band.fill")}
            </Button>
          )}
        </div>
        <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden>
          {segments.map((s) =>
            s.count > 0 ? (
              <div
                key={s.key}
                className={SEGMENT_COLOR[s.key]}
                style={{ width: `${(s.count / total) * 100}%` }}
              />
            ) : null,
          )}
        </div>
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-label">
          {segments.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5" data-segment={s.key}>
              <span className={cn("h-2 w-2 rounded-full", SEGMENT_COLOR[s.key])} aria-hidden />
              {t(`spdx3.segment.${s.key}`)}
              <span className="tabular-nums font-medium">{s.count}</span>
            </li>
          ))}
        </ul>
        <p className="text-body-sm text-muted-foreground">
          {summary.draft ? t("spdx3.band.draftNote", { count: missing }) : t("spdx3.band.completeNote")}
          {summary.draft && !publisher && <> {t("spdx3.band.consumerNote")}</>}
        </p>
        {where.length > 0 && (
          <p className="text-body-sm text-foreground" data-testid="spdx3-missing-where">
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
          <div
            role="status"
            data-testid="spdx3-service-pending"
            className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/40 p-3 text-label text-foreground"
          >
            <span className="flex items-start gap-1.5">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
              {t(hasService ? "spdx3.band.servicePending" : "spdx3.band.declarationPending")}
            </span>
            {onRescan && (
              <Button variant="outline" size="sm" onClick={onRescan} title={t("result.rescanHint")}>
                <RotateCw className="h-4 w-4" aria-hidden />
                {t("result.rescan")}
              </Button>
            )}
          </div>
        )}
        {refused && (
          <div
            role="status"
            className="space-y-1 rounded-md border border-warning/40 bg-warning-surface p-3 text-label text-warning dark:bg-warning-surface/15"
          >
            <div className="flex items-center gap-1.5 font-medium">
              <TriangleAlert className="h-3.5 w-3.5" aria-hidden />
              {t("spdx3.band.refused")}
            </div>
            <ul className="list-disc space-y-0.5 pl-5 font-mono">
              {(summary.declaration?.reasons ?? []).slice(0, 5).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

const STATUS_BADGE: Record<FieldStatus, { tone?: "low" | "info" | "critical" | "medium"; key: string }> = {
  auto: { tone: "low", key: "auto" },
  declared: { tone: "info", key: "declared" },
  noAssertion: { key: "noAssertion" },
  missingRequired: { tone: "critical", key: "missingRequired" },
  judgment: { tone: "medium", key: "judgment" },
  optional: { key: "optional" },
  omitted: { key: "omitted" },
  review: { key: "review" },
};

export function Spdx3StatusBadge({ status }: { status: FieldStatus }) {
  const { t } = useTranslation();
  const b = STATUS_BADGE[status];
  return b.tone ? (
    <Badge tone={b.tone}>{t(`spdx3.status.${b.key}`)}</Badge>
  ) : (
    <Badge variant="muted">{t(`spdx3.status.${b.key}`)}</Badge>
  );
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

/**
 * One element's fields in the SPDX 3.0.1 document: the value and where it came
 * from. Optional fields nobody filled are counted under the table instead of
 * listed, so the rows that need attention are not lost among them.
 */
type ExtraRow = { key: string; label: string; value: string | null; status: FieldStatus; statusLabel?: string };

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
    <div className="space-y-1">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-left text-label">
          <thead className="border-b bg-muted/40 text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.field")}</th>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.value")}</th>
              <th scope="col" className="px-3 py-2 font-medium">{t("spdx3.table.status")}</th>
            </tr>
          </thead>
          <tbody>
            {extraRows.map((r) => <ExtraTableRow key={r.key} row={r} />)}
            {rows.map((f) => (
              <tr key={f.id} className="border-b last:border-0" data-field={f.id}>
                <td className="px-3 py-2 align-top">{t(`aiDecl.${ns}.${f.id}.label`, { defaultValue: f.id })}</td>
                <td className="px-3 py-2 align-top break-all">
                  {f.display !== undefined ? (
                    <DisplayText ns={ns} fieldId={f.id} display={f.display} />
                  ) : (
                    <span className="text-muted-foreground">{t("spdx3.table.notFilled")}</span>
                  )}
                  {f.meaning === "huggingface-publisher" && (
                    <span className="ml-1 text-muted-foreground">{t("spdx3.table.hubPublisher")}</span>
                  )}
                </td>
                <td className="px-3 py-2 align-top">
                  <Spdx3StatusBadge status={f.status} />
                </td>
              </tr>
            ))}
            {trailingRows.map((r) => <ExtraTableRow key={r.key} row={r} />)}
          </tbody>
        </table>
      </div>
      {hidden > 0 && <p className="text-body-sm text-muted-foreground">{t("spdx3.table.optionalHidden", { count: hidden })}</p>}
    </div>
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
    <tr className="border-b last:border-0">
      <td className="px-3 py-2 align-top">{row.label}</td>
      <td className="px-3 py-2 align-top break-all">
        {row.value ?? <span className="text-muted-foreground">{t("spdx3.table.notFilled")}</span>}
      </td>
      <td className="px-3 py-2 align-top">
        {row.statusLabel ? <Badge variant="muted">{row.statusLabel}</Badge> : <Spdx3StatusBadge status={row.status} />}
      </td>
    </tr>
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
  return (
    <Disclosure
      defaultOpen={defaultOpen}
      summary={<span className="text-body-sm font-medium">{t("spdx3.table.toggle")}</span>}
      className="rounded-lg border bg-card p-3"
    >
      <div className="mt-3 space-y-3" data-testid="spdx3-fields">
        {model && (
          <Card>
            <CardContent className="space-y-2 p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="text-body-sm font-semibold">{model.label}</span>
                <span className="text-label text-muted-foreground">{t("spdx3.table.caption")}</span>
              </div>
              <Spdx3FieldTable element={model} extraRows={extra} trailingRows={roleRows} />
            </CardContent>
          </Card>
        )}
        {service && (
          <Card data-testid="spdx3-service-fields">
            <CardContent className="space-y-2 p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="flex items-center gap-2 text-body-sm font-semibold">
                  {service.label}
                  <Badge tone="info">{t("spdx3.table.publisherDeclared")}</Badge>
                </span>
                <span className="text-label text-muted-foreground">{t("spdx3.table.serviceCaption")}</span>
              </div>
              <Spdx3FieldTable element={service} />
              {externals.map((e) => (
                <div key={e.declarationKey ?? e.label} className="space-y-1 pt-2" data-testid="spdx3-external-model">
                  <div className="text-label font-semibold">
                    {t("spdx3.table.externalModel", { name: e.label })}
                  </div>
                  <Spdx3FieldTable element={e} />
                </div>
              ))}
            </CardContent>
          </Card>
        )}
        {!model && doc && datasets[0] && (
          <Card>
            <CardContent className="space-y-2 p-4">
              <span className="text-body-sm font-semibold">{datasets[0].label}</span>
              <Spdx3FieldTable element={datasets[0]} extraRows={extra} />
            </CardContent>
          </Card>
        )}
        {folded.length > 0 && (
          // Opens by itself when it holds required fields still empty, so they
          // are not hidden behind a fold.
          <Disclosure
            defaultOpen={foldedMissing > 0}
            summary={
              <span className="text-body-sm font-medium" data-testid="spdx3-dataset-fields">
                {t("spdx3.table.datasetFields", { count: folded.length })}
                {foldedMissing > 0 && (
                  <span className="ml-2 font-normal text-risk-critical-fg">
                    {t("spdx3.table.datasetMissing", { count: foldedMissing })}
                  </span>
                )}
              </span>
            }
          >
            <div className="mt-2 space-y-3">
              {folded.map((d) => (
                <div key={d.declarationKey ?? d.label} className="space-y-1">
                  <div className="text-label font-semibold">{d.label}</div>
                  <Spdx3FieldTable element={d} />
                </div>
              ))}
            </div>
          </Disclosure>
        )}
        <p className="text-body-sm text-muted-foreground">{t("spdx3.table.notLegalAdvice")}</p>
      </div>
    </Disclosure>
  );
}
