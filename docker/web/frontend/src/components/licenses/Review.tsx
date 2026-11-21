// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CounterLabel, Label } from "@primer/react";
import { useTranslation } from "react-i18next";

import { PackageCoordinate } from "@/components/primer";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { type LicenseReview, reviewGroups } from "@/lib/licenses";

const FLAG_LABEL: Record<LicenseReview, string> = {
  "behavioral-use": "licenses.flagBehavioral",
  "non-commercial": "licenses.flagNonCommercial",
  "no-derivatives": "licenses.flagNoDerivatives",
  proprietary: "licenses.flagProprietary",
};

/** Terms that need a person to read them: AI behavioral-use, non-commercial,
 *  no-derivatives and commercial or proprietary licenses, flagged from the bomlens:licenseReview property so the box matches
 *  the NOTICE review section. */
export function Review({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const groups = reviewGroups(components);
  if (groups.length === 0) return null;
  return (
    <section className="bl-box" aria-labelledby="lic-review" data-testid="license-review">
      <div className="bl-box-head">
        <h2 id="lic-review">{t("licenses.reviewTitle")}</h2>
      </div>
      <p className="bl-muted bl-lic-hint">{t("licenses.reviewHint")}</p>
      {groups.map((g) => (
        <div key={g.flag} className="bl-lic-group">
          <div className="bl-lic-grouphead">
            <Label variant="attention">{t(FLAG_LABEL[g.flag])}</Label>
            <CounterLabel aria-label={t("licenses.obligationsComponentCount", { count: g.components.length })}>
              {fmt(g.components.length)}
            </CounterLabel>
          </div>
          <ul className="bl-lic-list">
            {g.components.map((c, i) => (
              <li key={c.purl || `${c.name}-${i}`} className="bl-lic-item bl-lic-item-wrap">
                <span className="bl-breakall">
                  <PackageCoordinate group={c.group || undefined} name={c.name} strongName />
                  {c.version && <span className="bl-mono bl-muted"> {c.version}</span>}
                </span>
                {c.licenses.map((l) => (
                  <Label key={l} variant="secondary">
                    {l}
                  </Label>
                ))}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
