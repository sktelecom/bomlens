// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import {
  licenseObligations,
  type ObligationTag,
  type ObligationTerm,
} from "@/lib/licenseObligations";
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
  if (tags === null) return <Badge variant="outline">{t("licenses.obligationsUnknown")}</Badge>;
  if (tags.length === 0) return <Badge variant="muted" className="hover:bg-muted">{t("licenses.obligationsNone")}</Badge>;
  return (
    <>
      {tags.map((tag) => (
        <Badge key={tag} variant="muted" className="hover:bg-muted">
          {t(TAG_LABEL[tag])}
        </Badge>
      ))}
    </>
  );
}

function Terms({ terms }: { terms: ObligationTerm[] }) {
  return (
    <ul className="space-y-1">
      {terms.map((x) => (
        <li key={x.term} className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-label">{x.term}</span>
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
 * shown as "Needs checking" rather than filled in. The wording says this is a
 * documentation aid, matching the conformance screens.
 */
export function LicenseObligations({ components }: { components: ComponentItem[] }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const [all, setAll] = useState(false);
  const groups = useMemo(() => licenseGroups(components).groups, [components]);
  if (groups.length === 0) return null;

  const shown = all ? groups : groups.slice(0, TOP);
  return (
    <Card data-testid="license-obligations">
      <CardContent className="space-y-3 p-4">
        <div className="text-body-sm font-semibold text-foreground">
          {t("licenses.obligationsTitle")}
        </div>
        <p className="text-body-sm text-muted-foreground">{t("licenses.obligationsHint")}</p>
        <ul id="license-obligations-list" className="divide-y rounded-md border bg-card">
          {shown.map((g) => {
            const r = licenseObligations(g.name);
            return (
              <li key={g.name} className="space-y-1.5 px-3 py-2 text-body-sm">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-mono">{g.name}</span>
                  <span className="tabular-nums text-label text-muted-foreground" aria-hidden="true">
                    {fmt(g.count)}
                  </span>
                  <span className="sr-only">{t("licenses.obligationsComponentCount", { count: g.count })}</span>
                  {r.kind === "known" && <Chips tags={r.tags} />}
                  {r.kind === "unknown" && <Chips tags={null} />}
                </div>
                {r.kind === "expression" && (
                  <div className="space-y-1.5 pl-2">
                    {r.alternatives.length > 1 && (
                      <div className="text-label text-muted-foreground">
                        {t("licenses.obligationsChooseOne")}
                      </div>
                    )}
                    {r.alternatives.map((terms, i) => (
                      <div key={i} className="space-y-1">
                        {terms.length > 1 && (
                          <div className="text-label text-muted-foreground">
                            {t("licenses.obligationsAll")}
                          </div>
                        )}
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
          <Button
            variant="outline"
            size="sm"
            aria-expanded={all}
            aria-controls="license-obligations-list"
            onClick={() => setAll((v) => !v)}
          >
            {all ? t("licenses.obligationsShowLess") : t("licenses.obligationsShowAll", { count: groups.length })}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
