// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ArrowRightIcon } from "@primer/octicons-react";
import { Button, Link } from "@primer/react";
import { useTranslation } from "react-i18next";

import type { RecentScan } from "@/lib/api";
import { pickComparedScan, pickStartScans, scanTypeLabelKey } from "@/lib/recent";
import { scanHash } from "@/lib/route";

/**
 * The demo's "start here" strip: one sentence on what the list is and what to
 * do, then up to three scans (a source project, a container image, an AI model)
 * as links straight into that scan's Overview. The picks are derived from the
 * loaded list by type, so nothing here names a scan; with none of the three
 * types present the strip is not rendered at all.
 */
export function DemoStartHere({ scans }: { scans: RecentScan[] }) {
  const { t } = useTranslation();
  const picks = pickStartScans(scans);
  const compared = pickComparedScan(scans);
  if (picks.length === 0) return null;
  return (
    <section className="bl-box" data-testid="demo-start-here" style={{ marginTop: "var(--base-size-16)" }}>
      <div className="bl-box-body bl-demostart">
        <p>{t("recent.demoStart")}</p>
        <ul>
          {picks.map((s) => (
            <li key={s.id}>
              <Button as="a" href={scanHash(s.id)} trailingVisual={ArrowRightIcon}>
                <span className="bl-muted">{t(scanTypeLabelKey(s))}</span> <span className="bl-demoname" title={s.project}>{s.project}</span>
              </Button>
            </li>
          ))}
        </ul>
        {compared && (
          <Link href={scanHash(compared.id)} data-testid="demo-compare-link">
            {t("recent.demoCompare", { project: compared.project, version: compared.version })}
          </Link>
        )}
      </div>
    </section>
  );
}
