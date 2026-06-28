import { Clock, Plus, RotateCw, X } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button, buttonVariants } from "@/components/ui/button";
import { type RecentScanLink } from "@/lib/nav";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

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
  /** Re-run this scan with the same target and toggles (prefills the New scan
   *  form). Shown only when the loaded scan carries a config; absent otherwise. */
  onRescan?: () => void;
  /** Hash for the home (Recent scans) screen — the logo links here. */
  homeHref: string;
  /** Render the logo as a link home (off on the Recent home screen itself). */
  showHomeLink?: boolean;
  /** Hash for the New scan screen — the primary global action. */
  newHref: string;
  /** Past scans for the Recent menu (newest first). */
  recent?: RecentScanLink[];
  /** Delete a past scan from the Recent list (removes its artifacts). */
  onDeleteRecent?: (id: string) => void;
}

const SEVERITY_DOT: Record<NonNullable<RecentScanLink["topSeverity"]>, string> = {
  CRITICAL: "bg-risk-critical",
  HIGH: "bg-risk-high",
  MEDIUM: "bg-risk-medium",
  LOW: "bg-risk-low",
  NONE: "bg-risk-info",
};

/**
 * Application top bar: product mark + active project context on the left,
 * global actions (New scan, Recent) and controls (language, theme) on the
 * right. Sticky, token-driven.
 *
 * New scan and Recent live here — the chrome, not the section rail — so the left
 * rail stays purely the current scan's sections. The logo is a real
 * `<a href="#/">` link so the home screen can be opened in a new tab.
 */
export function TopBar({
  project,
  search,
  onRescan,
  homeHref,
  showHomeLink,
  newHref,
  recent = [],
  onDeleteRecent,
}: TopBarProps) {
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
        {onRescan && (
          <Button
            variant="outline"
            size="sm"
            onClick={onRescan}
            className="gap-1.5"
            title={t("result.rescanHint")}
          >
            <RotateCw className="h-4 w-4 text-brand" aria-hidden />
            <span>{t("result.rescan")}</span>
          </Button>
        )}
        <a
          href={newHref}
          aria-label={t("shell.newScan")}
          className={cn(buttonVariants({ size: "sm" }), "shrink-0")}
        >
          <Plus className="h-4 w-4" aria-hidden />
          <span className="hidden sm:inline">{t("shell.newScan")}</span>
        </a>
        <RecentMenu
          recent={recent}
          homeHref={homeHref}
          onDeleteRecent={onDeleteRecent}
        />
        <LangToggle />
        <ThemeToggle />
      </div>
    </header>
  );
}

/**
 * Recent-scans popover: the Clock button opens a panel listing past scans
 * (severity dot + label, optional delete) with a link to the full Recent home.
 * Closes on outside pointer-down or Escape, mirroring GlobalSearch.
 */
function RecentMenu({
  recent,
  homeHref,
  onDeleteRecent,
}: {
  recent: RecentScanLink[];
  homeHref: string;
  onDeleteRecent?: (id: string) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const panelId = useId();

  useEffect(() => {
    if (!open) return;
    const onPointer = (e: PointerEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={wrapRef} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        aria-label={t("nav.recentScans")}
        title={t("nav.recentScans")}
        className={cn(
          "inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground",
          "transition-colors duration-fast ease-out-soft hover:bg-muted hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          open && "bg-muted text-foreground",
        )}
      >
        <Clock className="h-4 w-4" aria-hidden />
      </button>
      {open && (
        <div
          id={panelId}
          className="absolute right-0 top-full z-30 mt-1 w-72 max-w-[90vw] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-lg"
        >
          <a
            href={homeHref}
            onClick={() => setOpen(false)}
            className="flex items-center gap-2 border-b px-3 py-2 text-sm font-medium hover:bg-muted focus-visible:bg-muted focus-visible:outline-none"
          >
            <Clock className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            {t("nav.recentScans")}
          </a>
          {recent.length === 0 ? (
            <p className="px-3 py-3 text-sm text-muted-foreground">
              {t("nav.recentEmpty")}
            </p>
          ) : (
            <ul className="max-h-80 overflow-auto py-1">
              {recent.map((scanItem) => (
                <li key={scanItem.id} className="group/recent relative">
                  <a
                    href={scanHash(scanItem.id)}
                    onClick={() => setOpen(false)}
                    className={cn(
                      "flex w-full items-center gap-2 px-3 py-1.5 text-sm text-muted-foreground",
                      "transition-colors duration-fast ease-out-soft hover:bg-muted hover:text-foreground",
                      "focus-visible:bg-muted focus-visible:text-foreground focus-visible:outline-none",
                      onDeleteRecent && "pr-8",
                    )}
                  >
                    <span
                      className={cn(
                        "h-2 w-2 shrink-0 rounded-full",
                        SEVERITY_DOT[scanItem.topSeverity ?? "NONE"],
                      )}
                      aria-hidden
                    />
                    <span className="truncate">{scanItem.label}</span>
                  </a>
                  {onDeleteRecent && (
                    <button
                      type="button"
                      onClick={() => onDeleteRecent(scanItem.id)}
                      aria-label={t("nav.recentDelete")}
                      title={t("nav.recentDelete")}
                      className={cn(
                        "absolute right-1.5 top-1/2 inline-flex h-5 w-5 -translate-y-1/2 items-center justify-center rounded",
                        "text-muted-foreground opacity-0 transition-opacity duration-fast",
                        "hover:bg-muted hover:text-foreground group-hover/recent:opacity-100",
                        "focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                      )}
                    >
                      <X className="h-3 w-3" aria-hidden />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
