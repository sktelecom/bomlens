// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Button, CounterLabel, Label } from "@primer/react";
import { Table } from "@primer/react/experimental";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { PackageCoordinate } from "@/components/primer";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { conflictGroups, conflictReasonGroups, type ConflictVerdict } from "@/lib/licenses";
import { conflictWhyKey } from "@/lib/licenseWhy";
import { renderLocalized } from "@/lib/localized";

const CONFLICT_LABEL: Record<ConflictVerdict, string> = {
  incompatible: "licenses.conflictIncompatible",
  conditional: "licenses.conflictConditional",
  unknown: "licenses.conflictUnknown",
  compatible: "licenses.conflictCompatible",
};

/** Cannot be met is a real problem (danger); depends-on-shipping needs a look
 *  (attention); cannot judge is grey. The word always carries the meaning. */
const CONFLICT_VARIANT: Record<ConflictVerdict, "danger" | "attention" | "secondary"> = {
  incompatible: "danger",
  conditional: "attention",
  unknown: "secondary",
  compatible: "secondary",
};

/** Rows shown per verdict group before the "show all" button. */
export const CONFLICT_ROWS_TOP = 5;

/** One group's table. The column headers stay when the rows are folded. */
function ConflictRows({
  verdict,
  components,
  label,
}: {
  verdict: ConflictVerdict;
  components: ComponentItem[];
  /** Names the table: the verdict and, when there is one, its reason. */
  label: string;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const id = useId();
  const [all, setAll] = useState(false);
  const folded = components.length > CONFLICT_ROWS_TOP;
  const shown = folded && !all ? components.slice(0, CONFLICT_ROWS_TOP) : components;
  return (
    <>
      <Table.Container className="bl-lic-table">
        <Table id={id} gridTemplateColumns="minmax(0, 1fr) fit-content(14rem) minmax(0, 20rem)" cellPadding="condensed" aria-label={label}>
          <Table.Head>
            <Table.Row>
              <Table.Header>{t("result.colName")}</Table.Header>
              <Table.Header>{t("result.colVersion")}</Table.Header>
              <Table.Header>{t("result.colLicense")}</Table.Header>
            </Table.Row>
          </Table.Head>
          <Table.Body>
            {shown.map((c, i) => (
              <Table.Row key={c.purl || `${c.name}-${i}`}>
                <Table.Cell scope="row">
                  <PackageCoordinate group={c.group || undefined} name={c.name} strongName className="bl-breakall" />
                </Table.Cell>
                <Table.Cell>
                  <span className="bl-mono bl-muted bl-breakall">{c.version || "-"}</span>
                </Table.Cell>
                <Table.Cell>
                  <span className="bl-mono bl-breakall">{c.licenses.join(", ")}</span>
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      </Table.Container>
      {folded && (
        <div className="bl-lic-foot">
          <Button
            size="small"
            aria-expanded={all}
            aria-controls={id}
            data-testid={`license-conflict-toggle-${verdict}`}
            onClick={() => setAll((v) => !v)}
          >
            {all ? t("licenses.conflictShowLess") : t("licenses.conflictShowAll", { count: components.length })}
          </Button>
        </div>
      )}
    </>
  );
}

/**
 * Components whose license sits badly against the license the project ships
 * under, grouped by verdict (worst first). Most components in one verdict share
 * a reason (it comes from the license class pair), so the reason is said once
 * above the rows it applies to.
 */
export function Conflicts({ components, outbound }: { components: ComponentItem[]; outbound: string }) {
  const { t, i18n } = useTranslation();
  const fmt = useFormatNumber();
  const groups = conflictGroups(components);
  if (groups.length === 0) return null;
  // The scanner records the reason in English; show it in the UI language when
  // it is one of the sentences BomLens writes, verbatim otherwise.
  // A sentence this build has no translation for is shown as written only in
  // English; in another language a plain notice stands in and the original is
  // kept in the tooltip.
  const localize = (why: string) => {
    const key = conflictWhyKey(why);
    if (key) return renderLocalized(t, key);
    return i18n.language.startsWith("en") ? why : t("licenses.whyUntranslated");
  };
  const total = groups.reduce((n, g) => n + g.components.length, 0);
  return (
    <section className="bl-box" aria-labelledby="lic-conflict" data-testid="license-conflicts">
      <div className="bl-box-head">
        <h2 id="lic-conflict">{t("licenses.conflictTitle", { license: outbound })}</h2>
        <CounterLabel aria-label={t("licenses.obligationsComponentCount", { count: total })}>{fmt(total)}</CounterLabel>
      </div>
      <p className="bl-muted bl-lic-hint">{t("licenses.conflictHint")}</p>
      {groups.map((g) =>
        conflictReasonGroups(g.components).map((r, ri) => (
          <div key={`${g.verdict}-${r.why}`}>
            <div className="bl-lic-sub">
              {ri === 0 && (
                <>
                  <Label variant={CONFLICT_VARIANT[g.verdict]}>{t(CONFLICT_LABEL[g.verdict])}</Label>
                  <CounterLabel aria-label={t("licenses.obligationsComponentCount", { count: g.components.length })}>
                    {fmt(g.components.length)}
                  </CounterLabel>
                </>
              )}
              {r.why && (
                <span className="bl-muted" title={r.why}>
                  {localize(r.why)}
                </span>
              )}
            </div>
            <ConflictRows
              verdict={g.verdict}
              components={r.components}
              label={
                r.why
                  ? t("licenses.conflictTableLabel", { verdict: t(CONFLICT_LABEL[g.verdict]), reason: localize(r.why) })
                  : t(CONFLICT_LABEL[g.verdict])
              }
            />
          </div>
        )),
      )}
    </section>
  );
}
