// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRight, FileCheck2, Flame, type LucideIcon, Wrench } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { DoneEvent } from "@/lib/api";
import { formatDateTime, useFormatNumber } from "@/lib/format";
import { type FirstCheck, firstChecks } from "@/lib/overview";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

const ICON: Record<FirstCheck["id"], LucideIcon> = {
  knownExploited: Flame,
  fixableSevere: Wrench,
  requiredItems: FileCheck2,
};

/**
 * "Items to check first": up to three links into the scan, each with the count
 * it rests on, where the count came from and when the scan was made. It is a
 * reference order for reading the scan, worded as such. It is not a verdict and
 * not a ranking, so the icons stay neutral and the block has no alarm colour.
 * Renders nothing when no item applies.
 */
export function FirstChecks({
  result,
  scanId,
  generatedAt,
}: {
  result: DoneEvent;
  scanId: string | null;
  /** Unix seconds when the scan was made; the line leaves the time out until known. */
  generatedAt?: number;
}) {
  const { t, i18n } = useTranslation();
  const fmt = useFormatNumber();
  const items = firstChecks(result);
  if (items.length === 0) return null;
  const asOf = generatedAt
    ? t("overview.firstChecks.asOf", { time: formatDateTime(generatedAt, i18n.language) })
    : "";
  return (
    <Card data-testid="first-checks">
      <CardContent className="p-4">
        <div className="mb-2">
          <div className="text-body-sm font-semibold text-foreground">
            {t("overview.firstChecks.title")}
          </div>
          <p className="text-label text-muted-foreground">{t("overview.firstChecks.note")}</p>
        </div>
        <ol className="flex flex-col gap-1">
          {items.map((item) => {
            const Icon = ICON[item.id];
            const source =
              item.source === "conformance"
                ? t("overview.firstChecks.sourceConformance")
                : item.rowsListed !== undefined
                  ? t("overview.firstChecks.sourceVulnsPartial", {
                      listed: fmt(item.rowsListed),
                      total: fmt(item.rowsTotal ?? 0),
                    })
                  : t("overview.firstChecks.sourceVulns");
            return (
              <li key={item.id}>
                <a
                  href={scanId ? scanHash(scanId, item.target, item.query) : undefined}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left",
                    "transition-colors duration-fast ease-out-soft hover:bg-muted",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                  )}
                >
                  <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block text-body-sm text-foreground">
                      {t(`overview.firstChecks.${item.id}`)}
                    </span>
                    <span className="block text-label text-muted-foreground">
                      {asOf ? `${source}, ${asOf}` : source}
                    </span>
                  </span>
                  <span className="shrink-0 text-body-sm font-semibold tabular-nums text-foreground">
                    {fmt(item.count)}
                  </span>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                </a>
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
