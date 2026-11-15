// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Button, CounterLabel, Label } from "@primer/react";
import { useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { licenseObligations, type ObligationTag, type ObligationTerm } from "@/lib/licenseObligations";
import { licenseGroups } from "@/lib/licenses";

/** Rows shown before the "show all" button. */
const TOP = 8;

const TAG_LABEL: Record<ObligationTag, string> = {
  "include-copyright": "licenses.obligation.includeCopyright",
  "include-copyright--source": "licenses.obligation.includeCopyrightSource",
  "document-changes": "licenses.obligation.documentChanges",
  "disclose-source": "licenses.obligation.discloseSource",
  "network-use-disclose": "licenses.obligation.networkUseDisclose",
  "same-license": "licenses.obligation.sameLicense",
  "same-license--file": "licenses.obligation.sameLicenseFile",
  "same-license--library": "licenses.obligation.sameLicenseLibrary",
};

function Chips({ tags }: { tags: ObligationTag[] | null }) {
  const { t } = useTranslation();
  if (tags === null) return <Label variant="attention">{t("licenses.obligationsUnknown")}</Label>;
  if (tags.length === 0) return <Label variant="secondary">{t("licenses.obligationsNone")}</Label>;
  return (
    <>
      {tags.map((tag) => (
        <Label key={tag} variant="secondary">
          {t(TAG_LABEL[tag])}
        </Label>
      ))}
    </>
  );
}

function Terms({ terms }: { terms: ObligationTerm[] }) {
  return (
    <ul className="bl-lic-terms">
      {terms.map((x) => (
        <li key={x.term}>
          <span className="bl-mono bl-breakall">{x.term}</span>
          <Chips tags={x.tags} />
        </li>
      ))}
    </ul>
  );
}

/**
 * What each license in the scan asks of someone who redistributes the
 * component, as chips next to the license id. The data is a fixed, public
 * summary; a license it does not cover (or one with an exception clause) is
 * shown as "Needs checking" rather than filled in. An SPDX expression lists
 * each term: pick one of the alternatives of an OR, meet all the terms of an AND.
 */
export function Obligations({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const listId = useId();
  const [all, setAll] = useState(false);
  const groups = useMemo(() => licenseGroups(components).groups, [components]);
  if (groups.length === 0) return null;
  const shown = all ? groups : groups.slice(0, TOP);
  return (
    <section className="bl-box" aria-labelledby="lic-obl" data-testid="license-obligations">
      <div className="bl-box-head">
        <h2 id="lic-obl">{t("licenses.obligationsTitle")}</h2>
        <CounterLabel aria-hidden>{fmt(groups.length)}</CounterLabel>
      </div>
      <p className="bl-muted bl-lic-hint bl-lic-hint-rule">{t("licenses.obligationsHint")}</p>
      <ul id={listId} className="bl-lic-list">
        {shown.map((g) => {
          const r = licenseObligations(g.name);
          return (
            <li key={g.name} className="bl-lic-item bl-lic-item-col">
              <div className="bl-lic-line">
                <span className="bl-mono bl-strong bl-breakall">{g.name}</span>
                <span className="bl-muted bl-small bl-num bl-lic-count" aria-hidden="true">
                  {fmt(g.count)}
                </span>
                <span className="bl-visually-hidden">{t("licenses.obligationsComponentCount", { count: g.count })}</span>
                {r.kind === "known" && <Chips tags={r.tags} />}
                {r.kind === "unknown" && <Chips tags={null} />}
              </div>
              {r.kind === "expression" && (
                <div className="bl-lic-expr">
                  {r.alternatives.length > 1 && <span className="bl-muted bl-small">{t("licenses.obligationsChooseOne")}</span>}
                  {r.alternatives.map((terms, i) => (
                    <div key={i}>
                      {terms.length > 1 && <span className="bl-muted bl-small">{t("licenses.obligationsAll")}</span>}
                      <Terms terms={terms} />
                    </div>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {groups.length > TOP && (
        <div className="bl-lic-foot">
          <Button
            size="small"
            aria-expanded={all}
            aria-controls={listId}
            data-testid="license-obligations-toggle"
            onClick={() => setAll((v) => !v)}
          >
            {all ? t("licenses.obligationsShowLess") : t("licenses.obligationsShowAll", { count: groups.length })}
          </Button>
        </div>
      )}
    </section>
  );
}
