// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { DemoBanner } from "./DemoBanner";
import { type NavPlace, Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { EMPTY_SCAN, type RecentScanLink, type ScanContext, type SectionId } from "@/lib/nav";
import { newHash } from "@/lib/route";
import { type ProjectName } from "@/lib/scanTitle";
import { useMediaQuery } from "@/lib/useMediaQuery";

interface AppShellProps {
  scan?: ScanContext;
  /** Which navigation entry is the current page. */
  current: NavPlace;
  /** The open scan's id, so the navigation can build `#/scan/<id>/<section>`
   *  links; absent when no scan is open. */
  activeScanId?: string | null;
  recent?: RecentScanLink[];
  /** Delete a past scan from the Recent menu. */
  onDeleteRecent?: (id: string) => void;
  /** The running image's version, passed through to the help menu. */
  version?: string;
  /** Per-section counts shown in the navigation. */
  counts?: Partial<Record<SectionId, number | string>>;
  /** The open or running scan, shown as the path in the top bar. */
  project?: ProjectName;
  /** Where that path links to (the open scan's Overview). */
  projectHref?: string;
  /** The global search, shown when a scan is loaded. */
  search?: (width: number) => ReactNode;
  /** Re-run the loaded scan (prefills the New scan form). */
  onRescan?: () => void;
  /** Hash for the home (Scan management) screen; the logo links here. */
  homeHref: string;
  /** Show the logo as a link home (off on the home screen itself). */
  showHomeLink?: boolean;
  /** Hide the top bar's New scan button (on Scan management, which has its
   *  own, and on New scan itself). */
  hideTopBarNewScan?: boolean;
  /** Hash for the External lookup screen; absent hides the entry point. */
  lookupHref?: string;
  /** Leave a running scan and open External lookup (see `NextApp.goToLookup`). */
  onLookup?: () => void;
  /** External lookup is the current screen. */
  lookupCurrent?: boolean;
  /** Reset to a blank New scan form (see `NextApp.goToNewScan`). */
  onNewScan?: () => void;
  /** A scan is running or opening; the navigation shows placeholders for
   *  its sections. */
  loadingSections?: boolean;
  children: ReactNode;
}

/** Below this width the navigation starts as an icon strip. */
const COLLAPSE_QUERY = "(max-width: 1024px)";

/**
 * The application frame: a sticky top bar, the left navigation and the screen
 * content. The page itself scrolls. Every screen has the navigation, so Scan
 * management and New scan are one click away from anywhere; the open scan's
 * sections appear under them.
 */
export function AppShell({
  scan = EMPTY_SCAN,
  current,
  activeScanId,
  recent,
  onDeleteRecent,
  counts,
  project,
  projectHref,
  search,
  onRescan,
  homeHref,
  showHomeLink,
  hideTopBarNewScan,
  lookupHref,
  onLookup,
  lookupCurrent,
  onNewScan,
  loadingSections,
  children,
  version,
}: AppShellProps) {
  const { t } = useTranslation();
  const mainRef = useRef<HTMLElement>(null);
  const narrow = useMediaQuery(COLLAPSE_QUERY);
  // `null` until the reader toggles; until then the viewport decides.
  const [manualCollapsed, setManualCollapsed] = useState<boolean | null>(null);
  const collapsed = manualCollapsed ?? narrow;

  return (
    <div className="bl-shell">
      {/* The first Tab stop: jumps past the top bar and the navigation (WCAG
          2.4.1). Visible only while focused. The route lives in the URL hash,
          so a real in-page anchor would rewrite it: the click moves focus to
          the content instead. */}
      <a
        href="#main-content"
        className="bl-skip"
        onClick={(e) => {
          e.preventDefault();
          mainRef.current?.focus();
        }}
      >
        {t("shell.skipToMain")}
      </a>
      <TopBar
        project={project}
        projectHref={projectHref}
        search={search}
        onRescan={onRescan}
        homeHref={homeHref}
        showHomeLink={showHomeLink}
        newHref={hideTopBarNewScan || IS_STATIC_DEMO ? undefined : newHash()}
        onNewScan={onNewScan}
        recent={recent}
        onDeleteRecent={onDeleteRecent}
        version={version}
        lookupHref={lookupHref}
        onLookup={onLookup}
        lookupCurrent={lookupCurrent}
        currentScanId={activeScanId}
      />
      <div className="bl-body">
        <Sidebar
          scan={scan}
          current={current}
          activeScanId={activeScanId}
          counts={counts}
          collapsed={collapsed}
          onToggleCollapsed={() => setManualCollapsed(!collapsed)}
          homeHref={homeHref}
          newHref={newHash()}
          onNewScan={onNewScan}
          hideNewScan={IS_STATIC_DEMO}
          loading={loadingSections}
        />
        <main id="main-content" ref={mainRef} tabIndex={-1} className="bl-main animate-fade-in">
          {/* The demo notice opens every screen, inside the page so the top
              bar and the navigation keep their fixed geometry. */}
          {IS_STATIC_DEMO && <DemoBanner />}
          {children}
        </main>
      </div>
    </div>
  );
}
