import { Plus } from "lucide-react";
import { useTranslation } from "react-i18next";

import { LangToggle } from "./LangToggle";
import { ThemeToggle } from "./ThemeToggle";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface TopBarProps {
  /** Current project context, e.g. "my-app · 1.0.0". Hidden when absent. */
  projectLabel?: string;
  /** Hash for the home (New scan) screen — the logo and New scan link target. */
  homeHref: string;
  /** Render the logo + a New scan link home. Off on the idle screen itself
   *  (the logo stays static, no New scan action), so we don't link home to home. */
  showHomeLink?: boolean;
}

/**
 * Application top bar: product mark + active project context on the left,
 * global controls (language, theme) on the right. Sticky, token-driven.
 *
 * The logo and the New scan action are real `<a href="#/">` links so the New
 * scan screen can be opened in a new tab (Cmd/Ctrl/middle click); the hash
 * router handles same-tab navigation.
 */
export function TopBar({ projectLabel, homeHref, showHomeLink }: TopBarProps) {
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
      {projectLabel && (
        <>
          <span className="h-5 w-px shrink-0 bg-border" aria-hidden />
          <span className="truncate text-sm font-medium text-foreground">
            {projectLabel}
          </span>
        </>
      )}
      <div className="ml-auto flex shrink-0 items-center gap-2">
        {showHomeLink && (
          <a
            href={homeHref}
            className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
          >
            <Plus className="mr-1.5 h-4 w-4" />
            {t("shell.newScan")}
          </a>
        )}
        <LangToggle />
        <ThemeToggle />
      </div>
    </header>
  );
}
