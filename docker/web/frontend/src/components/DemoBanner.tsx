// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { FlaskConical } from "lucide-react";
import { useTranslation } from "react-i18next";

import { demoInstallUrl } from "@/lib/demo";

/**
 * The strip the read-only demo shows under the top bar.
 *
 * It says two things a visitor needs before they read anything else: the
 * numbers on screen came from a real scan (not mock data), and the actions
 * that would change something are off. Rendered only when the bundle is the
 * demo — `AppShell` gates it, so a normal build never mounts this.
 */
export function DemoBanner() {
  const { t, i18n } = useTranslation("common");
  return (
    <div
      role="region"
      aria-label={t("shell.demoBannerTitle")}
      data-testid="demo-banner"
      className="flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b bg-muted/50 px-4 py-2 text-label text-muted-foreground"
    >
      <FlaskConical
        className="h-3.5 w-3.5 shrink-0 self-center text-muted-foreground"
        aria-hidden
      />
      <span className="font-medium text-foreground">
        {t("shell.demoBannerTitle")}
      </span>
      {/* The explanation is the long part; on a phone it would fill the first
          screen, so only the title and the install link remain there. */}
      <span className="hidden min-w-0 flex-1 md:block">
        {t("shell.demoBannerBody")}
      </span>
      <a
        href={demoInstallUrl(i18n.language)}
        target="_blank"
        rel="noreferrer"
        className="ml-auto shrink-0 font-medium text-foreground underline underline-offset-2 hover:no-underline"
      >
        {t("shell.demoBannerCta")}
      </a>
    </div>
  );
}
