import { type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { LangToggle } from "./LangToggle";
import { ThemeToggle } from "./ThemeToggle";

interface TopBarProps {
  /**
   * Active project context. The name truncates (long firmware filenames) with
   * the full value on hover; the version shows muted beside it. Hidden absent.
   */
  project?: { name: string; version?: string };
  /** Optional global-search control, rendered between the project and controls. */
  search?: ReactNode;
  /** Hash for the home (Recent scans) screen — the logo links here. */
  homeHref: string;
  /** Render the logo as a link home (off on the Recent home screen itself). */
  showHomeLink?: boolean;
}

/**
 * Application top bar: product mark + active project context on the left,
 * global controls (language, theme) on the right. Sticky, token-driven.
 *
 * The logo is a real `<a href="#/">` link so the home screen can be opened in a
 * new tab (Cmd/Ctrl/middle click); the hash router handles same-tab navigation.
 */
export function TopBar({ project, search, homeHref, showHomeLink }: TopBarProps) {
  const { t } = useTranslation();
  const logo = (
    <img src="/logo.svg" alt={t("appTitle")} className="h-7 w-auto shrink-0" />
  );
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-4 border-b bg-card/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      {showHomeLink ? (
        <a
          href={homeHref}
          title={t("appTitle")}
          aria-label={t("appTitle")}
          className="shrink-0 rounded transition-opacity duration-fast ease-out-soft hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        >
          {logo}
        </a>
      ) : (
        logo
      )}
      {project && (
        <>
          <span className="h-5 w-px shrink-0 bg-border" aria-hidden />
          <div className="flex min-w-0 items-baseline gap-2">
            <span
              className="truncate text-sm font-medium text-foreground"
              title={project.name}
            >
              {project.name}
            </span>
            {project.version && (
              <span className="shrink-0 text-sm text-muted-foreground">
                {project.version}
              </span>
            )}
          </div>
        </>
      )}
      <div className="ml-auto flex shrink-0 items-center gap-2">
        {search}
        <LangToggle />
        <ThemeToggle />
      </div>
    </header>
  );
}
