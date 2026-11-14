// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  ChecklistIcon,
  CpuIcon,
  FileDirectoryIcon,
  FileIcon,
  FileZipIcon,
  GitBranchIcon,
  GraphIcon,
  ListUnorderedIcon,
  type Icon,
  LawIcon,
  PackageIcon,
  PlusIcon,
  ShieldIcon,
  SidebarCollapseIcon,
  SidebarExpandIcon,
} from "@primer/octicons-react";
import { IconButton, NavList } from "@primer/react";
import { SkeletonText } from "@primer/react/experimental";
import { Fragment } from "react";
import { useTranslation } from "react-i18next";

import { useFormatNumber } from "@/lib/format";
import { EMPTY_SCAN, type ScanContext, type SectionId, visibleGroups } from "@/lib/nav";
import { scanHash } from "@/lib/route";

/** Where the reader is: one of the two global screens, a scan section, or
 *  neither (External lookup, a running scan). */
export type NavPlace = "recent" | "new" | SectionId | null;

interface SidebarProps {
  scan?: ScanContext;
  current: NavPlace;
  /** The open scan's id, so section links resolve to `#/scan/<id>/<section>`;
   *  absent when no scan is open, which hides the sections. */
  activeScanId?: string | null;
  /** Per-section counts shown after the label (dependencies is a
   *  `direct/transitive` string, conformance `passed/measured`). */
  counts?: Partial<Record<SectionId, number | string>>;
  /** Icon-only rail (narrow widths, or the reader's toggle). */
  collapsed: boolean;
  onToggleCollapsed: () => void;
  homeHref: string;
  newHref: string;
  /** Reset to a blank New scan form, in addition to the `#/new` navigation the
   *  link carries: a scan started from `#/new` that fails leaves the hash
   *  unchanged, so the link's own navigation is a no-op then. */
  onNewScan?: () => void;
  /** Hide New scan (the read-only demo cannot scan). */
  hideNewScan?: boolean;
  /** A scan is running or opening: its sections are on the way. */
  loading?: boolean;
}

const SECTION_ICON: Record<SectionId, Icon> = {
  overview: GraphIcon,
  components: PackageIcon,
  dependencies: GitBranchIcon,
  sourceTree: FileDirectoryIcon,
  inputSbom: FileIcon,
  vulnerabilities: ShieldIcon,
  licenses: LawIcon,
  conformance: ChecklistIcon,
  models: CpuIcon,
  artifacts: FileZipIcon,
};

/**
 * The left navigation, on every screen: Scan management and New scan, then the
 * open scan's sections grouped as lib/nav.ts describes, each with its count.
 * Collapses to an icon strip on narrow widths or by the toggle at its top.
 */
export function Sidebar({
  scan = EMPTY_SCAN,
  current,
  activeScanId,
  counts = {},
  collapsed,
  onToggleCollapsed,
  homeHref,
  newHref,
  onNewScan,
  hideNewScan,
  loading,
}: SidebarProps) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const groups = activeScanId ? visibleGroups(scan) : [];
  const globals: Array<{ key: "recent" | "new"; href: string; label: string; icon: Icon; onClick?: () => void }> = [
    { key: "recent", href: homeHref, label: t("nav.recentScans"), icon: ListUnorderedIcon },
    { key: "new", href: newHref, label: t("shell.newScan"), icon: PlusIcon, onClick: onNewScan },
  ];
  if (hideNewScan) globals.pop();
  const sectionHref = (id: SectionId) => (activeScanId ? scanHash(activeScanId, id) : homeHref);
  // Two of the counts are pairs ("6/65"). The pointer gets the meaning as a
  // tooltip; a screen reader hears the pair spelled out instead of "6 slash 65".
  const countNote = (id: SectionId) =>
    id === "dependencies"
      ? t("nav.depSplitTitle")
      : id === "conformance"
        ? t("nav.conformanceSplitTitle")
        : undefined;
  const said = (id: SectionId, count: string): string | undefined => {
    const [a, b] = count.split("/");
    if (b === undefined) return undefined;
    if (id === "dependencies") return t("nav.depsSaid", { direct: a, transitive: b });
    if (id === "conformance") return t("nav.confSaid", { passed: a, total: b });
    return undefined;
  };

  const toggle = (
    <div className="bl-pane-toggle">
      <IconButton
        icon={collapsed ? SidebarCollapseIcon : SidebarExpandIcon}
        variant="invisible"
        size="small"
        aria-label={collapsed ? t("nav.expand") : t("nav.collapse")}
        onClick={onToggleCollapsed}
        tooltipDirection="e"
      />
    </div>
  );

  if (collapsed) {
    return (
      <div className="bl-pane" data-collapsed="true">
        {toggle}
        <nav aria-label={t("nav.mainLabel")}>
          <ul className="bl-pane-icons">
            {globals.map((g) => (
              <li key={g.key}>
                <IconButton
                  as="a"
                  href={g.href}
                  onClick={g.onClick}
                  icon={g.icon}
                  variant="invisible"
                  aria-label={g.label}
                  aria-current={current === g.key ? "page" : undefined}
                  tooltipDirection="e"
                />
              </li>
            ))}
            {/* A rule between the global links and the first group, and one
                at every group boundary, as the expanded list draws them. */}
            {groups.map((group) => (
              <Fragment key={group.id}>
                <li aria-hidden className="bl-pane-icons-rule" />
                {group.sections.map((s) => (
                  <li key={s.id}>
                    <IconButton
                      as="a"
                      href={sectionHref(s.id)}
                      icon={SECTION_ICON[s.id]}
                      variant="invisible"
                      aria-label={t(s.labelKey)}
                      aria-current={current === s.id ? "page" : undefined}
                      tooltipDirection="e"
                    />
                  </li>
                ))}
              </Fragment>
            ))}
          </ul>
        </nav>
      </div>
    );
  }

  return (
    <div className="bl-pane" data-collapsed="false">
      {toggle}
      <NavList aria-label={t("nav.mainLabel")}>
        {globals.map((g) => {
          const GlobalIcon = g.icon;
          return (
            <NavList.Item
              key={g.key}
              href={g.href}
              onClick={g.onClick}
              aria-current={current === g.key ? "page" : undefined}
            >
              <NavList.LeadingVisual>
                <GlobalIcon />
              </NavList.LeadingVisual>
              {g.label}
            </NavList.Item>
          );
        })}
        {/* Each group draws its own rule above it; without groups, one rule
            separates the hint from the global links. */}
        {groups.length === 0 && <NavList.Divider />}
        {groups.length === 0 &&
          (loading ? (
            <li className="bl-pane-hint" aria-hidden data-testid="nav-loading">
              <SkeletonText lines={3} />
            </li>
          ) : (
            <li className="bl-pane-hint">{t("nav.sectionsHint")}</li>
          ))}
        {groups.map((group) => (
          <NavList.Group key={group.id} title={t(group.labelKey)}>
            {group.sections.map((s) => {
              const SectionIcon = SECTION_ICON[s.id];
              const count = counts[s.id];
              const note = countNote(s.id);
              return (
                <NavList.Item
                  key={s.id}
                  href={sectionHref(s.id)}
                  aria-current={current === s.id ? "page" : undefined}
                >
                  <NavList.LeadingVisual>
                    <SectionIcon />
                  </NavList.LeadingVisual>
                  <span data-nav-label={s.id}>{t(s.labelKey)}</span>
                  {count !== undefined && (
                    <NavList.TrailingVisual>
                      <span className="bl-count" title={note} data-testid={`nav-count-${s.id}`}>
                        {typeof count === "number" ? (
                          fmt(count)
                        ) : said(s.id, count) ? (
                          <>
                            <span aria-hidden>{count}</span>
                            <span className="bl-visually-hidden">{said(s.id, count)}</span>
                          </>
                        ) : (
                          count
                        )}
                      </span>
                    </NavList.TrailingVisual>
                  )}
                </NavList.Item>
              );
            })}
          </NavList.Group>
        ))}
      </NavList>
    </div>
  );
}
