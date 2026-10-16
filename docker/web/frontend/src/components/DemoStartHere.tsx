// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ArrowRight } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { RecentScan } from "@/lib/api";
import { pickStartScans, scanTypeLabelKey } from "@/lib/recent";
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
  if (picks.length === 0) return null;
  return (
    <Card data-testid="demo-start-here">
      <CardContent className="flex flex-col gap-3 p-4 md:flex-row md:items-center md:gap-5">
        <p className="text-body-sm text-foreground md:max-w-sm">
          {t("recent.demoStart")}
        </p>
        <ul className="flex min-w-0 flex-1 flex-col gap-2 md:flex-row md:flex-wrap">
          {picks.map((s) => (
            <li key={s.id} className="min-w-0">
              <a
                href={scanHash(s.id)}
                className="group inline-flex max-w-full items-center gap-2 rounded-md border bg-background px-3 py-2 text-body-sm text-foreground transition-colors duration-fast ease-out-soft hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              >
                <span className="shrink-0 text-label text-muted-foreground">
                  {t(scanTypeLabelKey(s))}
                </span>
                <span className="min-w-0 truncate font-medium" title={s.project}>{s.project}</span>
                <ArrowRight
                  className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
                  aria-hidden
                />
              </a>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
