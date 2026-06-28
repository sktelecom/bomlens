import { type ReactNode, useEffect, useState } from "react";

import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import {
  EMPTY_SCAN,
  type RecentScanLink,
  type ScanContext,
  type SectionId,
} from "@/lib/nav";
import { newHash } from "@/lib/route";

interface AppShellProps {
  scan?: ScanContext;
  activeSection: SectionId;
  /** The current scan's id, so the rail can build `#/scan/<id>/<section>` links. */
  activeScanId?: string | null;
  recent?: RecentScanLink[];
  /** Delete a past scan from the Recent list. */
  onDeleteRecent?: (id: string) => void;
  /** Per-section counts shown as trailing rail badges (dependencies is a split string). */
  counts?: Partial<Record<SectionId, number | string>>;
  /** Show the section rail (a scan is loaded); hidden on the idle home screens. */
  showSections?: boolean;
  /** Project context shown in the top bar (name + optional version). */
  project?: { name: string; version?: string };
  /** Optional top-bar content (the global search), shown when a scan is loaded. */
  search?: ReactNode;
  /** Hash for the home (Recent scans) screen — the logo links here. */
  homeHref: string;
  /** Show the logo as a link home (hidden on the Recent home screen itself). */
  showHomeLink?: boolean;
  /** The active section's content fills the canvas. */
  children: ReactNode;
}

/** Below this width the rail auto-collapses to an icon strip. */
const COLLAPSE_QUERY = "(max-width: 1024px)";

/**
 * The application frame: a sticky top bar over a left rail + scrolling canvas.
 * The top bar carries the global actions (New scan, Recent); the left rail is
 * purely the current scan's sections and only appears once a scan is loaded. The
 * rail adapts to the scan type and collapses automatically on narrow viewports
 * (and via the in-rail toggle).
 */
export function AppShell({
  scan = EMPTY_SCAN,
  activeSection,
  activeScanId,
  recent,
  onDeleteRecent,
  counts,
  showSections,
  project,
  search,
  homeHref,
  showHomeLink,
  children,
}: AppShellProps) {
  // `null` until the user toggles manually; until then we follow the viewport.
  const [manualCollapsed, setManualCollapsed] = useState<boolean | null>(null);
  const [narrow, setNarrow] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia(COLLAPSE_QUERY);
    const sync = () => setNarrow(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);

  const collapsed = manualCollapsed ?? narrow;

  return (
    <div className="flex h-screen flex-col bg-background">
      <TopBar
        project={project}
        search={search}
        homeHref={homeHref}
        showHomeLink={showHomeLink}
        newHref={newHash()}
        recent={recent}
        onDeleteRecent={onDeleteRecent}
      />
      <div className="flex min-h-0 flex-1">
        {showSections && (
          <Sidebar
            scan={scan}
            activeSection={activeSection}
            activeScanId={activeScanId}
            counts={counts}
            collapsed={collapsed}
            onToggleCollapsed={() => setManualCollapsed(!collapsed)}
          />
        )}
        {/* tabIndex makes the scrollable region keyboard-accessible (axe
            scrollable-region-focusable / WCAG 2.1.1): a mouse-free user can
            focus it and scroll with the arrow keys. */}
        <main tabIndex={0} className="min-w-0 flex-1 overflow-y-auto animate-fade-in">
          {children}
        </main>
      </div>
    </div>
  );
}
