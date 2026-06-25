import { useTranslation } from "react-i18next";

import { LangToggle } from "./LangToggle";
import { ThemeToggle } from "./ThemeToggle";

interface TopBarProps {
  /** Current project context, e.g. "my-app · 1.0.0". Hidden when absent. */
  projectLabel?: string;
  /** Optional action node rendered before the toggles (e.g. New scan). */
  actions?: React.ReactNode;
  /** Clicking the logo goes home (new scan). Omit to leave it static. */
  onHome?: () => void;
}

/**
 * Application top bar: product mark + active project context on the left,
 * global controls (language, theme) on the right. Sticky, token-driven.
 */
export function TopBar({ projectLabel, actions, onHome }: TopBarProps) {
  const { t } = useTranslation();
  const logo = (
    <img src="/logo.svg" alt={t("appTitle")} className="h-7 w-auto shrink-0" />
  );
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-4 border-b bg-card/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      {onHome ? (
        <button
          type="button"
          onClick={onHome}
          title={t("appTitle")}
          aria-label={t("appTitle")}
          className="shrink-0 rounded transition-opacity duration-fast ease-out-soft hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        >
          {logo}
        </button>
      ) : (
        logo
      )}
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
