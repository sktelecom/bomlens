// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  BookIcon,
  LinkExternalIcon,
  ListUnorderedIcon,
  CommandPaletteIcon,
  GlobeIcon,
  HistoryIcon,
  IssueOpenedIcon,
  MegaphoneIcon,
  PlayIcon,
  PlusIcon,
  QuestionIcon,
  RocketIcon,
  SyncIcon,
  TrashIcon,
} from "@primer/octicons-react";
import {
  ActionList,
  ActionMenu,
  AnchoredOverlay,
  Button,
  IconButton,
} from "@primer/react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Marker } from "@/components/ui/marker";
import { severityShape } from "@/components/primer/display";
import { demoInstallUrl, demoUrl, docsUrl, IS_STATIC_DEMO, releaseNotesUrl } from "@/lib/demo";
import { ISSUE_FORM_URL } from "@/lib/diagnostics";
import { type RecentScanLink } from "@/lib/nav";
import { scanHash } from "@/lib/route";
import { type ProjectName } from "@/lib/scanTitle";
import { useMediaQuery } from "@/lib/useMediaQuery";

import { LANGUAGES, LangToggle, useCurrentLanguage } from "./LangToggle";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { ThemeToggle } from "./ThemeToggle";

/** Below this width the top bar packs tighter: a shorter search box, Re-scan
 *  as an icon, and the language choice inside the help menu. */
const COMPACT_QUERY = "(max-width: 1199px)";
/** Below this width the path and the search leave the top bar (the left
 *  navigation and each screen's own heading still name the scan). */
const NARROW_QUERY = "(max-width: 767px)";

interface TopBarProps {
  /** The open or running scan: shown as the path after the logo. */
  project?: ProjectName;
  /** Where the project in the path links to (the open scan's Overview);
   *  absent while a scan is still running and has no address yet. */
  projectHref?: string;
  /** The global search, rendered only with a scan loaded. Called with the
   *  width the box should take. */
  search?: (width: number) => ReactNode;
  /** Re-run this scan with the same target and toggles (prefills the New scan
   *  form). Shown only when the loaded scan carries a config. */
  onRescan?: () => void;
  /** Hash for the home (Scan management) screen; the logo links here. */
  homeHref: string;
  /** Render the logo as a link home (off on the home screen itself). */
  showHomeLink?: boolean;
  /** Hash for the New scan screen; absent hides the top-bar button (the home
   *  screen has its own New scan button). */
  newHref?: string;
  /** Reset to a blank New scan form, in addition to the `#/new` navigation
   *  `newHref` already carries: a scan started from `#/new` that fails leaves
   *  the hash unchanged, so the link's navigation is a no-op then. */
  onNewScan?: () => void;
  /** Past scans for the Recent menu (newest first). */
  recent?: RecentScanLink[];
  /** Delete a past scan from the Recent menu (removes its artifacts). */
  onDeleteRecent?: (id: string) => void;
  /** The running image's version, from `capabilities`. Absent on a local build,
   *  where the help menu says the build carries no version rather than blank. */
  version?: string;
  /** Hash for the External lookup screen. Absent hides the entry point:
   *  `capabilities.externalLookup` is off, or this is the static demo. */
  lookupHref?: string;
  /** Leave a running scan and open External lookup, in addition to the
   *  `#/lookup` navigation `lookupHref` carries (the hash router ignores
   *  navigation while a scan runs; see `NextApp.goToLookup`). */
  onLookup?: () => void;
  /** External lookup is the current screen (its entry shows as pressed). */
  lookupCurrent?: boolean;
  /** The open scan's id, marked in the Recent menu. */
  currentScanId?: string | null;
  /** A finished scan is open: "Report a problem" opens the diagnostics dialog
   *  for it instead of going straight to the issue form. */
  onReportProblem?: () => void;
}

/**
 * The top bar: logo and the open scan's path on the left; the global search,
 * Re-scan, New scan, External lookup, Recent scans, Help, language and theme
 * on the right. Sticky at the top of the page (56px).
 */
export function TopBar({
  project,
  projectHref,
  search,
  onRescan,
  homeHref,
  showHomeLink,
  newHref,
  onNewScan,
  recent = [],
  onDeleteRecent,
  version,
  lookupHref,
  onLookup,
  lookupCurrent,
  currentScanId,
  onReportProblem,
}: TopBarProps) {
  const { t } = useTranslation();
  const compact = useMediaQuery(COMPACT_QUERY);
  const narrow = useMediaQuery(NARROW_QUERY);
  // BASE_URL, not "/": the demo is served from a sub-path, where a rooted src
  // would look outside the deployment. It is "/" in a normal build.
  const logo = (
    <img src={`${import.meta.env.BASE_URL}logo.svg`} alt={t("appTitle")} className="bl-topbar-logo" />
  );
  return (
    <header className="bl-topbar">
      {showHomeLink ? (
        <a href={homeHref} className="bl-topbar-home">
          {logo}
        </a>
      ) : (
        <span className="bl-topbar-home">{logo}</span>
      )}
      {project && !narrow && (
        <nav className="bl-path" data-testid="topbar-path" aria-label={t("nav.pathLabel")}>
          <span className="bl-path-sep" aria-hidden>
            /
          </span>
          {projectHref ? (
            <a href={projectHref} className="bl-path-name" title={projectTitle(project)}>
              <PathName project={project} />
            </a>
          ) : (
            <span className="bl-path-name" title={projectTitle(project)}>
              <PathName project={project} />
            </span>
          )}
        </nav>
      )}
      <span className="bl-topbar-spacer" />
      <div className="bl-topbar-actions">
        {search && !narrow && search(compact ? 200 : 300)}
        {/* Re-scan parks the finished scan's config in the form, which the demo
            cannot run. */}
        {onRescan &&
          !IS_STATIC_DEMO &&
          (compact ? (
            <IconButton
              icon={SyncIcon}
              variant="invisible"
              aria-label={t("result.rescan")}
              description={t("result.rescanHint")}
              onClick={onRescan}
            />
          ) : (
            <Button leadingVisual={SyncIcon} onClick={onRescan} title={t("result.rescanHint")}>
              {t("result.rescan")}
            </Button>
          ))}
        {newHref && (
          <IconButton
            as="a"
            href={newHref}
            onClick={onNewScan}
            icon={PlusIcon}
            variant="invisible"
            aria-label={t("shell.newScan")}
          />
        )}
        {lookupHref && (
          <IconButton
            as="a"
            href={lookupHref}
            onClick={onLookup}
            icon={GlobeIcon}
            variant="invisible"
            aria-current={lookupCurrent ? "page" : undefined}
            aria-label={t("nav.lookupTitle")}
            data-testid="external-lookup-link"
          />
        )}
        <RecentMenu
          recent={recent}
          homeHref={homeHref}
          onDeleteRecent={onDeleteRecent}
          currentScanId={currentScanId}
        />
        <HelpMenu version={version} withLanguage={compact} onReportProblem={onReportProblem} />
        {!compact && <LangToggle />}
        <ThemeToggle />
      </div>
    </header>
  );
}

function projectTitle(p: ProjectName) {
  return p.version ? `${p.name} ${p.version}` : p.name;
}

function PathName({ project }: { project: ProjectName }) {
  return (
    <>
      {project.name}
      {project.version && <span className="bl-path-version"> {project.version}</span>}
    </>
  );
}

/** Text colour of a severity's shape in the Recent menu. */
const SEVERITY_FG: Record<NonNullable<RecentScanLink["topSeverity"]>, string> = {
  CRITICAL: "var(--fgColor-danger)",
  HIGH: "var(--fgColor-severe)",
  MEDIUM: "var(--fgColor-attention)",
  LOW: "var(--fgColor-muted)",
  NONE: "var(--fgColor-muted)",
};

/**
 * Recent scans: each past scan with the shape and name of its worst severity
 * and a delete button (not in the demo), then a link to the full list.
 */
function RecentMenu({
  recent,
  homeHref,
  onDeleteRecent,
  currentScanId,
}: {
  recent: RecentScanLink[];
  homeHref: string;
  onDeleteRecent?: (id: string) => void;
  currentScanId?: string | null;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const canDelete = Boolean(onDeleteRecent) && !IS_STATIC_DEMO;
  return (
    <AnchoredOverlay
      open={open}
      onOpen={() => setOpen(true)}
      onClose={() => setOpen(false)}
      renderAnchor={(p) => (
        <IconButton {...p} icon={HistoryIcon} variant="invisible" aria-label={t("nav.recent")} />
      )}
      overlayProps={{ width: "medium", maxHeight: "large" }}
      focusZoneSettings={{ disabled: false }}
    >
      <ActionList aria-label={t("nav.recent")}>
        {recent.length === 0 && <ActionList.Item disabled>{t("nav.recentEmpty")}</ActionList.Item>}
        {recent.map((s) => {
          const sev = s.topSeverity ?? "NONE";
          // No severity means nothing was found, not an unknown grade.
          const sevName = t(`severity.${sev}`);
          const current = s.id === currentScanId;
          return (
            <ActionList.LinkItem
              key={s.id}
              href={scanHash(s.id)}
              onClick={() => setOpen(false)}
              active={current}
              aria-current={current ? "page" : undefined}
            >
              <ActionList.LeadingVisual>
                <span aria-hidden style={{ display: "inline-flex", color: SEVERITY_FG[sev] }}>
                  <Marker shape={severityShape(sev === "NONE" ? "UNKNOWN" : sev)} />
                </span>
              </ActionList.LeadingVisual>
              {/* The item is named by its label, so the worst severity goes in
                  the label too (visually hidden); the shape alone says it
                  only to sighted readers. */}
              <span className="bl-recent-name">
                <span className="bl-recent-project">
                  {s.name}
                  {!s.version && <span className="bl-visually-hidden">, {sevName}</span>}
                </span>
                {/* The flex gap separates name and version on screen; this
                    space separates them in the accessible name. */}
                {s.version && <span className="bl-visually-hidden">{"\u00a0"}</span>}
                {s.version && (
                  <span className="bl-recent-version">
                    {s.version}
                    <span className="bl-visually-hidden">, {sevName}</span>
                  </span>
                )}
              </span>
              {canDelete && (
                <ActionList.TrailingAction
                  label={t("nav.recentDelete")}
                  icon={TrashIcon}
                  onClick={() => {
                    setOpen(false);
                    onDeleteRecent?.(s.id);
                  }}
                />
              )}
            </ActionList.LinkItem>
          );
        })}
        {/* An action, not a scan: it leads to the full list. Named apart from
            the navigation's "Scan management" so the two are not confused. */}
        <ActionList.Divider />
        <ActionList.LinkItem href={homeHref} onClick={() => setOpen(false)}>
          <ActionList.LeadingVisual>
            <ListUnorderedIcon />
          </ActionList.LeadingVisual>
          {t("nav.recentAll")}
        </ActionList.LinkItem>
      </ActionList>
    </AnchoredOverlay>
  );
}

/**
 * Getting started, documentation, the demo, the keyboard shortcuts, what
 * changed, reporting a problem, and which version is running. On a compact top
 * bar it also carries the language choice.
 */
function HelpMenu({
  version,
  withLanguage,
  onReportProblem,
}: {
  version?: string;
  withLanguage: boolean;
  onReportProblem?: () => void;
}) {
  const { t, i18n } = useTranslation();
  const current = useCurrentLanguage();
  const [menuOpen, setMenuOpen] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  const anchorRef = useRef<HTMLButtonElement>(null);
  const ext = { target: "_blank", rel: "noreferrer noopener" } as const;
  // Every entry but the shortcuts list leaves the app in a new tab: say so.
  const external = (
    <ActionList.TrailingVisual>
      <LinkExternalIcon />
      <span className="bl-visually-hidden">{t("nav.opensNewTab")}</span>
    </ActionList.TrailingVisual>
  );

  // "?" lists the keys, the way most web tools do. Not while typing: a question
  // mark in a field is text, and a modifier means some other shortcut. With
  // this menu open, it closes the menu first.
  useEffect(() => {
    const onQuestion = (e: KeyboardEvent) => {
      if (e.key !== "?" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = e.target as HTMLElement | null;
      if (el?.closest("input, textarea, select, [contenteditable='true']")) return;
      e.preventDefault();
      setMenuOpen(false);
      setShortcuts(true);
    };
    window.addEventListener("keydown", onQuestion);
    return () => window.removeEventListener("keydown", onQuestion);
  }, []);

  return (
    <>
      <ActionMenu anchorRef={anchorRef} open={menuOpen} onOpenChange={setMenuOpen}>
        <ActionMenu.Anchor>
          <IconButton
            ref={anchorRef}
            icon={QuestionIcon}
            variant="invisible"
            aria-label={t("nav.help")}
            data-testid="help-menu"
          />
        </ActionMenu.Anchor>
        <ActionMenu.Overlay width="medium">
          <ActionList>
            <ActionList.LinkItem href={demoInstallUrl(i18n.language)} {...ext} data-testid="help-start">
              <ActionList.LeadingVisual>
                <RocketIcon />
              </ActionList.LeadingVisual>
              {t("nav.helpStart")}
              {external}
            </ActionList.LinkItem>
            <ActionList.LinkItem href={docsUrl(i18n.language)} {...ext}>
              <ActionList.LeadingVisual>
                <BookIcon />
              </ActionList.LeadingVisual>
              {t("nav.helpDocs")}
              {external}
            </ActionList.LinkItem>
            <ActionList.LinkItem href={demoUrl()} {...ext}>
              <ActionList.LeadingVisual>
                <PlayIcon />
              </ActionList.LeadingVisual>
              {t("nav.helpDemo")}
              {external}
            </ActionList.LinkItem>
            <ActionList.Divider />
            <ActionList.Item onSelect={() => setShortcuts(true)} data-testid="help-shortcuts">
              <ActionList.LeadingVisual>
                <CommandPaletteIcon />
              </ActionList.LeadingVisual>
              {t("nav.helpShortcuts")}
              <ActionList.TrailingVisual>
                <kbd className="bl-kbd" aria-hidden>
                  ?
                </kbd>
              </ActionList.TrailingVisual>
            </ActionList.Item>
            <ActionList.Divider />
            <ActionList.LinkItem href={releaseNotesUrl(version)} {...ext} data-testid="help-whats-new">
              <ActionList.LeadingVisual>
                <MegaphoneIcon />
              </ActionList.LeadingVisual>
              {t("nav.helpWhatsNew")}
              <ActionList.Description variant="block">
                <span data-testid="app-version">
                  {version ? t("nav.helpVersion", { version }) : t("nav.helpVersionUnknown")}
                </span>
              </ActionList.Description>
              {external}
            </ActionList.LinkItem>
            {onReportProblem ? (
              // With a finished scan open, the entry shows what would be copied
              // (the diagnostics summary) before anything leaves the app.
              <ActionList.Item onSelect={onReportProblem} data-testid="help-report">
                <ActionList.LeadingVisual>
                  <IssueOpenedIcon />
                </ActionList.LeadingVisual>
                {t("nav.helpReport")}
              </ActionList.Item>
            ) : (
              <ActionList.LinkItem href={ISSUE_FORM_URL} {...ext} data-testid="help-report">
                <ActionList.LeadingVisual>
                  <IssueOpenedIcon />
                </ActionList.LeadingVisual>
                {t("nav.helpReport")}
                {external}
              </ActionList.LinkItem>
            )}
            {withLanguage && (
              <>
                <ActionList.Divider />
                <ActionList.Group selectionVariant="single">
                  <ActionList.GroupHeading>{t("lang.label")}</ActionList.GroupHeading>
                  {LANGUAGES.map((l) => (
                    <ActionList.Item
                      key={l.code}
                      lang={l.code}
                      selected={current === l.code}
                      onSelect={() => void i18n.changeLanguage(l.code)}
                    >
                      {l.name}
                    </ActionList.Item>
                  ))}
                </ActionList.Group>
              </>
            )}
          </ActionList>
        </ActionMenu.Overlay>
      </ActionMenu>
      {shortcuts && <ShortcutsDialog onClose={() => setShortcuts(false)} returnFocusRef={anchorRef} />}
    </>
  );
}
