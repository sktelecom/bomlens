// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon } from "@primer/octicons-react";
import { VisuallyHidden } from "@primer/react";
import { useTranslation } from "react-i18next";

import type { ConformanceSummary } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";

import { statusOfValue } from "./CheckRow";
import "./conformance.css";

const COLUMNS = ["present", "gap", "failed", "review"] as const;

/**
 * Regulatory crosswalk: one row per framework, present for any SBOM that carries
 * `conformance.regulatoryCrosswalk`. It answers only how much of each framework
 * this SBOM documents; each mapped requirement carries its own reference in the
 * check rows. The rows are folded under the framework so the counts can be traced
 * to the requirements. Not a certification: see the disclaimer.
 */
export function Crosswalk({ crosswalk }: { crosswalk: NonNullable<ConformanceSummary["regulatoryCrosswalk"]> }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const cell = (n: number, danger = false) => (
    <td className={`bl-cf-numcell${n === 0 ? " bl-cf-zero" : danger ? " bl-cf-bad" : ""}`}>{fmt(n)}</td>
  );
  return (
    <section className="bl-cf-box" data-testid="crosswalk">
      <div className="bl-cf-head">
        <h2>{t("crosswalk.title")}</h2>
      </div>
      <div className="bl-cf-xscroll">
        <table className="bl-cf-xwalk">
          <thead>
            <tr>
              <th scope="col">{t("crosswalk.thFramework")}</th>
              {COLUMNS.map((c) => (
                <th scope="col" key={c} className="bl-cf-numcell">
                  {t(`crosswalk.${c}`)}
                </th>
              ))}
              <th scope="col" className="bl-cf-numcell">
                {t("crosswalk.thTotal")}
              </th>
            </tr>
          </thead>
          <tbody>
            {crosswalk.frameworks.map((fw) => (
              <tr key={fw.id}>
                <td>
                  <details>
                    <summary className="bl-cf-sum">
                      <span className="bl-cf-chev">
                        <ChevronRightIcon size={16} />
                      </span>
                      <span>{t(`crosswalk.fw.${fw.id}.title`, { defaultValue: fw.title })}</span>
                    </summary>
                    <ul className="bl-cf-xlist">
                      {fw.elements.map((el, i) => {
                        const { Icon, tone, key } = statusOfValue(el.status);
                        return (
                          <li key={`${el.label}-${i}`}>
                            <span className={`bl-cf-ico ${tone}`} aria-hidden>
                              <Icon size={12} />
                            </span>
                            <VisuallyHidden>{t(key)}</VisuallyHidden>
                            <span className="bl-muted">
                              {el.label}
                              {el.refs.length > 0 && <> ({el.refs.join(" · ")})</>}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  </details>
                  <div className="bl-cf-xsrc">{t(`crosswalk.fw.${fw.id}.source`, { defaultValue: fw.source })}</div>
                </td>
                {cell(fw.present)}
                {cell(fw.gap)}
                {cell(fw.failed ?? 0, true)}
                {cell(fw.review)}
                <td className="bl-cf-numcell">{fmt(fw.total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="bl-cf-disclaimer">{t("crosswalk.disclaimer")}</p>
    </section>
  );
}
