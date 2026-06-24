import { FileSearch } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "./AppShell";
import { EmptyState } from "./ui/state";
import { EMPTY_SCAN, type SectionId } from "@/lib/nav";

/**
 * Phase 0 deliverable: the empty application shell behind the `?ui=next` flag.
 *
 * It wires the rail, top bar, theme and language toggles together and lets you
 * move between (still empty) sections so the frame, tokens and light/dark
 * behaviour can be reviewed in isolation. Real section content is migrated into
 * this shell in later phases; until then each section shows a placeholder.
 */
export function ShellPreview() {
  const { t } = useTranslation();
  const [activeSection, setActiveSection] = useState<SectionId>("overview");

  return (
    <AppShell
      scan={EMPTY_SCAN}
      activeSection={activeSection}
      onSelectSection={setActiveSection}
    >
      <div className="mx-auto max-w-5xl px-6 py-8">
        <div className="mb-6 flex items-center gap-3">
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            {t(`nav.${activeSection}`)}
          </h1>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-brand/10 px-2 py-0.5 text-xs font-medium text-foreground">
            <span className="h-1.5 w-1.5 rounded-full bg-brand" aria-hidden />
            {t("shell.previewBadge")}
          </span>
        </div>
        <div className="rounded-lg border border-dashed bg-card/40 p-10">
          <EmptyState icon={FileSearch}>
            <span className="font-medium text-foreground">
              {t("shell.placeholderTitle")}
            </span>
            <span className="mt-1 block max-w-md text-muted-foreground">
              {t("shell.placeholderBody")}
            </span>
          </EmptyState>
        </div>
      </div>
    </AppShell>
  );
}
