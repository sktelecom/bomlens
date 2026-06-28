import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  EMPTY_SCAN,
  type ScanContext,
  type SectionId,
  visibleGroups,
} from "@/lib/nav";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

interface SidebarProps {
  scan?: ScanContext;
  activeSection: SectionId;
  /** The current scan's id, so section links resolve to `#/scan/<id>/<section>`. */
  activeScanId?: string | null;
  /**
   * Per-section counts shown as a trailing badge (e.g. components, vulns).
   * Mostly numbers; dependencies is a `direct/transitive` string.
   */
  counts?: Partial<Record<SectionId, number | string>>;
  /** Icon-only rail when collapsed (narrow widths / user toggle). */
  collapsed?: boolean;
  onToggleCollapsed?: () => void;
}

/**
 * Left rail: the current scan's grouped sections, adapting to the scan type (AI
 * surfaces appear only for AI/ANALYZE scans). Purely intra-scan navigation —
 * the global actions (New scan, Recent scans) live in the TopBar, so the rail
 * stays one altitude. Tokens only; the brand accent marks the active section.
 * Collapses to an icon rail on narrow widths or via the header toggle.
 */
export function Sidebar({
  scan = EMPTY_SCAN,
  activeSection,
  activeScanId,
  counts = {},
  collapsed = false,
  onToggleCollapsed,
}: SidebarProps) {
  const { t } = useTranslation();
  const groups = visibleGroups(scan);

  return (
    <nav
      aria-label={t("nav.label")}
      data-collapsed={collapsed}
      className={cn(
        "flex shrink-0 flex-col gap-1 border-r border-sidebar-border bg-sidebar",
        "overflow-y-auto py-3 transition-[width] duration-base ease-out-soft",
        collapsed ? "w-[3.75rem] px-2" : "w-60 px-3",
      )}
    >
      <div className={cn("mb-1 flex items-center", collapsed ? "justify-center" : "justify-end")}>
        <button
          type="button"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? t("nav.expand") : t("nav.collapse")}
          title={collapsed ? t("nav.expand") : t("nav.collapse")}
          className={cn(
            "inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground",
            "transition-colors duration-fast ease-out-soft hover:bg-muted hover:text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
          )}
        >
          {collapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </button>
      </div>

      {groups.map((group) => (
        <div key={group.id} className="mb-2">
          {!collapsed && (
            <p className="px-2 pb-1 pt-2 text-[0.6875rem] font-semibold uppercase tracking-wider text-muted-foreground">
              {t(group.labelKey)}
            </p>
          )}
          <ul className="flex flex-col gap-0.5">
            {group.sections.map((section) => {
              const Icon = section.icon;
              const active = section.id === activeSection;
              const label = t(section.labelKey);
              const count = counts[section.id];
              return (
                <li key={section.id}>
                  <a
                    href={activeScanId ? scanHash(activeScanId, section.id) : undefined}
                    aria-current={active ? "page" : undefined}
                    title={collapsed ? label : undefined}
                    className={cn(
                      "group relative flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-sm",
                      "transition-colors duration-fast ease-out-soft",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
                      collapsed && "justify-center",
                      // Label stays at foreground contrast (AA); the brand accent
                      // lives in the icon + left indicator, not the text.
                      active
                        ? "bg-brand/10 font-semibold text-foreground"
                        : "font-medium text-muted-foreground hover:bg-muted hover:text-foreground",
                    )}
                  >
                    <Icon
                      className={cn("h-4 w-4 shrink-0", active && "text-brand")}
                      aria-hidden
                    />
                    {!collapsed && <span className="truncate">{label}</span>}
                    {!collapsed && count !== undefined && (
                      <span
                        className="ml-auto shrink-0 tabular-nums text-xs text-muted-foreground"
                        title={
                          section.id === "dependencies"
                            ? t("nav.depSplitTitle")
                            : undefined
                        }
                      >
                        {count}
                      </span>
                    )}
                  </a>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
