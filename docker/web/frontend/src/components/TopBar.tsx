import { useTranslation } from "react-i18next";

import { LangToggle } from "./LangToggle";
import { ThemeToggle } from "./ThemeToggle";

interface TopBarProps {
  /** Current project context, e.g. "my-app · 1.0.0". Hidden when absent. */
  projectLabel?: string;
  /** Optional action node rendered before the toggles (e.g. New scan). */
  actions?: React.ReactNode;
}

/**
 * Application top bar: product mark + active project context on the left,
 * global controls (language, theme) on the right. Sticky, token-driven.
 */
export function TopBar({ projectLabel, actions }: TopBarProps) {
  const { t } = useTranslation();
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-4 border-b bg-card/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      <img
        src="/logo.svg"
        alt={t("appTitle")}
        className="h-7 w-auto shrink-0"
      />
      {projectLabel && (
        <>
          <span className="h-5 w-px shrink-0 bg-border" aria-hidden />
          <span className="truncate text-sm font-medium text-foreground">
            {projectLabel}
          </span>
        </>
      )}
      <div className="ml-auto flex shrink-0 items-center gap-2">
        {actions}
        <LangToggle />
        <ThemeToggle />
      </div>
    </header>
  );
}
