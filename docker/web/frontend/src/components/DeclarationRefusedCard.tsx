// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Download, ExternalLink, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { type DeclarationRefused, fileUrl } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The failed-scan card for a refused declaration file (sbom-declared.cdx.json,
 * or a Yocto build directory's file of that name). The scan stopped before the
 * SBOM was finished and kept what it had written as `_bom.refused.json`; this
 * card says so, lists each reason the declaration step gave (file, component
 * and rule), and offers that file, in place of the generic failure text.
 */
export function DeclarationRefusedCard({
  refused,
  scanId,
  errorMessage,
}: {
  refused: DeclarationRefused;
  scanId: string | null;
  /** The scan's own [ERROR] text, shown when the step gave no reasons (it
   *  failed rather than refused the file). */
  errorMessage?: string | null;
}) {
  const { t } = useTranslation();
  const href = fileUrl(scanId, refused.file);
  return (
    <Card role="alert" className="border-destructive/40 bg-destructive/5" data-testid="declaration-refused">
      <CardContent className="space-y-3 p-4">
        <div className="flex items-center gap-2 text-body-sm font-semibold text-foreground">
          <TriangleAlert className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
          {t("run.declarationRefusedTitle")}
        </div>
        <p className="text-body-sm text-muted-foreground">
          {t("run.declarationRefusedBody", { file: refused.file })}
        </p>
        {refused.reasons.length === 0 && errorMessage && (
          <p className="whitespace-pre-wrap break-words font-mono text-label text-muted-foreground">
            {errorMessage}
          </p>
        )}
        {refused.reasons.length > 0 && (
          <ul className="list-disc space-y-1 pl-5 text-body-sm text-foreground">
            {refused.reasons.map((reason) => (
              <li key={reason} className="break-words font-mono text-label">
                {reason}
              </li>
            ))}
          </ul>
        )}
        <p className="text-body-sm text-muted-foreground">{t("run.declarationRefusedFix")}</p>
        <div className="flex flex-wrap gap-2">
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
          >
            <ExternalLink className="h-4 w-4" aria-hidden />
            {t("run.declarationRefusedView")}
          </a>
          <a
            href={href}
            download={refused.file}
            className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
          >
            <Download className="h-4 w-4" aria-hidden />
            {t("run.declarationRefusedDownload")}
          </a>
        </div>
      </CardContent>
    </Card>
  );
}
