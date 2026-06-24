import { Clock, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  EMPTY_SCAN,
  type RecentScanLink,
  type ScanContext,
  type SectionId,
  visibleGroups,
} from "@/lib/nav";
import { cn } from "@/lib/utils";

interface SidebarProps {
  scan?: ScanContext;
  activeSection: SectionId;
  onSelect: (id: SectionId) => void;
  recent?: RecentScanLink[];
  /** Per-section counts shown as a trailing badge (e.g. components, vulns). */
  counts?: Partial<Record<SectionId, number>>;
  /** Hide the section groups (e.g. before any scan); the Recent area stays. */
  showSections?: boolean;
  /** Icon-only rail when collapsed (narrow widths / user toggle). */
  collapsed?: boolean;
  onToggleCollapsed?: () => void;
}

const SEVERITY_DOT: Record<NonNullable<RecentScanLink["topSeverity"]>, string> = {
  CRITICAL: "bg-risk-critical",
  HIGH: "bg-risk-high",
  MEDIUM: "bg-risk-medium",
  LOW: "bg-risk-low",
  NONE: "bg-risk-info",
};

/**
 * Left rail: grouped result sections that adapt to the scan type (AI surfaces
 * appear only for AI/ANALYZE scans), plus a Recent scans area. Tokens only;
 * the brand accent marks the active section. Collapses to an icon rail on
 * narrow widths or via the header toggle.
 */
export function Sidebar({
  scan = EMPTY_SCAN,
  activeSection,
  onSelect,
  recent = [],
  counts = {},
  showSections = true,
  collapsed = false,
  onToggleCollapsed,
}: SidebarProps) {
  const { t } = useTranslation();
  const groups = showSections ? visibleGroups(scan) : [];

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
                  <button
                    type="button"
                    onClick={() => onSelect(section.id)}
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
                    {active && (
                      <span
                        className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-brand"
                        aria-hidden
                      />
                    )}
                    <Icon
                      className={cn("h-4 w-4 shrink-0", active && "text-brand")}
                      aria-hidden
                    />
                    {!collapsed && <span className="truncate">{label}</span>}
                    {!collapsed && count !== undefined && (
                      <span className="ml-auto shrink-0 tabular-nums text-xs text-muted-foreground">
                        {count}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}

      <div className="mt-auto border-t border-sidebar-border pt-2">
        {!collapsed && (
          <p className="flex items-center gap-1.5 px-2 pb-1 pt-1 text-[0.6875rem] font-semibold uppercase tracking-wider text-muted-foreground">
            <Clock className="h-3 w-3" aria-hidden />
            {t("nav.recent")}
          </p>
        )}
        {recent.length === 0 ? (
          !collapsed && (
            <p className="px-2 py-1 text-xs text-muted-foreground">
              {t("nav.recentEmpty")}
            </p>
          )
        ) : (
          <ul className="flex flex-col gap-0.5">
            {recent.map((scanItem) => (
              <li key={scanItem.id}>
                <button
                  type="button"
                  title={collapsed ? scanItem.label : undefined}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted-foreground",
                    "transition-colors duration-fast ease-out-soft hover:bg-muted hover:text-foreground",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
                    collapsed && "justify-center",
                  )}
                >
                  <span
                    className={cn(
                      "h-2 w-2 shrink-0 rounded-full",
                      SEVERITY_DOT[scanItem.topSeverity ?? "NONE"],
                    )}
                    aria-hidden
                  />
                  {!collapsed && <span className="truncate">{scanItem.label}</span>}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </nav>
  );
}
