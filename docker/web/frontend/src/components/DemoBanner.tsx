import { FlaskConical } from "lucide-react";
import { useTranslation } from "react-i18next";

import { DEMO_INSTALL_URL } from "@/lib/demo";

/**
 * The strip the read-only demo shows under the top bar.
 *
 * It says two things a visitor needs before they read anything else: the
 * numbers on screen came from a real scan (not mock data), and the actions
 * that would change something are off. Rendered only when the bundle is the
 * demo — `AppShell` gates it, so a normal build never mounts this.
 */
export function DemoBanner() {
  const { t } = useTranslation("common");
  return (
    <div
      role="note"
      data-testid="demo-banner"
      className="flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b border-brand/25 bg-brand/5 px-4 py-2 text-xs text-muted-foreground"
    >
      <FlaskConical
        className="h-3.5 w-3.5 shrink-0 self-center text-brand"
        aria-hidden
      />
      <span className="font-medium text-foreground">
        {t("shell.demoBannerTitle")}
      </span>
      <span className="min-w-0 flex-1">{t("shell.demoBannerBody")}</span>
      <a
        href={DEMO_INSTALL_URL}
        target="_blank"
        rel="noreferrer"
        className="shrink-0 font-medium text-brand underline underline-offset-2 hover:no-underline"
      >
        {t("shell.demoBannerCta")}
      </a>
    </div>
  );
}
