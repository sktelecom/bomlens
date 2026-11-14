// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, LinkExternalIcon } from "@primer/octicons-react";
import { CounterLabel, Label, Link } from "@primer/react";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { SeverityLabel } from "@/components/primer";
import type { AdvisoryRecord } from "@/lib/api";
import { formatLookupDate, formatRange } from "@/lib/lookup";

import "./lookup.css";

/** One advisory as a row: id, grade, title with the affected range, date. The
 *  rest of the record opens inside the row. */
function AdvisoryRow({ advisory: a, open }: { advisory: AdvisoryRecord; open?: boolean }) {
  const { t, i18n } = useTranslation();
  const base = useId();
  const affected = a.affected
    .map((x) => `${x.name}${x.ranges?.length ? ` ${x.ranges.map(formatRange).filter(Boolean).join("; ")}` : ""}`)
    .join(", ");
  return (
    <li className="bl-lk-row" data-testid="lookup-advisory">
      <details open={open || undefined}>
        <summary
          className="bl-lk-sum"
          aria-labelledby={`${base}-id ${base}-sev ${base}-title`}
          aria-describedby={affected ? `${base}-aff` : undefined}
        >
          <span className="bl-lk-chev" aria-hidden>
            <ChevronRightIcon size={16} />
          </span>
          <span id={`${base}-id`} className="bl-mono bl-lk-id">{a.id}</span>
          <span id={`${base}-sev`}>
            {/* A missing grade is Unknown, never a reassuring None. */}
            <SeverityLabel severity={a.severity === "NONE" ? "UNKNOWN" : a.severity} />
          </span>
          <span className="bl-lk-titlecell">
            <span id={`${base}-title`} className="bl-lk-title">
              {a.withdrawn && (
                <Label variant="attention" className="bl-lk-lbl bl-lk-withdrawn">
                  {t("lookup.withdrawn")}
                </Label>
              )}
              <span className={a.withdrawn ? "bl-lk-struck" : undefined}>{a.title || a.id}</span>
            </span>
            {affected && (
              <span id={`${base}-aff`} className="bl-mono bl-lk-aff">
                {affected}
              </span>
            )}
          </span>
          <span className="bl-lk-date">{a.published ? formatLookupDate(a.published, i18n.language) : ""}</span>
        </summary>
        <div className="bl-lk-body">
          <dl className="bl-lk-kv">
            {a.cvss != null && (
              <>
                <dt>{t("lookup.cvss")}</dt>
                <dd>
                  <span className="bl-num bl-strong">{a.cvss}</span>{" "}
                  {a.cvssVector && <span className="bl-mono bl-muted">{a.cvssVector}</span>}
                </dd>
              </>
            )}
            {a.published && (
              <>
                <dt>{t("lookup.published")}</dt>
                <dd>{formatLookupDate(a.published, i18n.language)}</dd>
              </>
            )}
            {a.modified && (
              <>
                <dt>{t("lookup.modified")}</dt>
                <dd>{formatLookupDate(a.modified, i18n.language)}</dd>
              </>
            )}
            {a.aliases.length > 0 && (
              <>
                <dt>{t("lookup.aliases")}</dt>
                <dd className="bl-lk-aliases">
                  {a.aliases.map((x, i) => (
                    <span key={`${i}-${x}`} className="bl-mono">
                      {x}
                    </span>
                  ))}
                </dd>
              </>
            )}
            {a.affected.length > 0 && (
              <>
                <dt>{t("lookup.affected")}</dt>
                <dd>
                  <ul className="bl-lk-list">
                    {a.affected.map((x, i) => (
                      <li key={`${x.ecosystem}-${x.name}-${i}`} className="bl-mono">
                        {x.ecosystem ? `${x.ecosystem}: ` : ""}
                        {x.name}
                        {x.versions && x.versions.length > 0 && ` @ ${x.versions.join(", ")}`}
                        {x.ranges && x.ranges.length > 0 && (
                          <span className="bl-muted"> ({x.ranges.map(formatRange).filter(Boolean).join("; ")})</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
          </dl>
          {a.description && <p className="bl-lk-desc">{a.description}</p>}
          {a.refs.length > 0 && (
            <div>
              <div className="bl-lk-sub">{t("lookup.references")}</div>
              <ul className="bl-lk-reflist">
                {a.refs.map((href, i) => (
                  <li key={`${i}-${href}`}>
                    <Link href={href} target="_blank" rel="noreferrer">
                      <LinkExternalIcon size={12} className="bl-lk-ext" /> {href}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </details>
    </li>
  );
}

/** The results box: a count in the head and one row per advisory. */
export function AdvisoryList({ items, open }: { items: AdvisoryRecord[]; open?: boolean }) {
  const { t } = useTranslation();
  const heading = useId();
  return (
    <section className="bl-box" aria-labelledby={heading} data-testid="lookup-results">
      <div className="bl-box-head">
        <h2 id={heading}>{t("lookup.results")}</h2>
        <CounterLabel>{items.length}</CounterLabel>
      </div>
      <ul className="bl-rows">
        {items.map((a, i) => (
          <AdvisoryRow key={`${a.id}-${i}`} advisory={a} open={open} />
        ))}
      </ul>
    </section>
  );
}
