// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  AiModelIcon,
  AlertIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  ContainerIcon,
  CpuIcon,
  FileCodeIcon,
  FileDirectoryIcon,
  FileIcon,
  FileSubmoduleIcon,
  type Icon,
  KebabHorizontalIcon,
  LawIcon,
  LinkExternalIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  TrashIcon,
} from "@primer/octicons-react";
import { ActionList, ActionMenu, Button, IconButton, Label, Link, TextInput, VisuallyHidden } from "@primer/react";
import { Blankslate, Table } from "@primer/react/experimental";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { ActiveFilters, FilterMenu, ScreenHeader, SeverityLabel, SortHeader } from "@/components/primer";
import { DemoStartHere } from "@/components/DemoStartHere";
import type { RecentScan } from "@/lib/api";
import { demoUrl, IS_STATIC_DEMO } from "@/lib/demo";
import { useFormatNumber } from "@/lib/format";
import {
  filterRecent,
  formatRelativeTime,
  middleEllipsis,
  presentTypes,
  type RecentSortDir,
  type RecentSortKey,
  type ScanType,
  scanComparison,
  scanType,
  scanTypeLabelKey,
  scanTypeLabelKeyFor,
  sortRecent,
  summarizeRecent,
} from "@/lib/recent";
import { scanHash } from "@/lib/route";
import { NARROW_QUERY, useMediaQuery } from "@/lib/useMediaQuery";

interface Props {
  scans: RecentScan[];
  /** Hash for the New scan screen (empty-state CTA). */
  newHref: string;
  /** Ask to delete a past scan (the confirm dialog in NextApp does the work). */
  onDelete: (id: string) => void;
}

/** One icon per scan type, the same ones the New scan tiles use for that input. */
const TYPE_ICON: Record<ScanType, Icon> = {
  source: FileDirectoryIcon,
  container: ContainerIcon,
  rootfs: FileSubmoduleIcon,
  firmware: CpuIcon,
  ai: AiModelIcon,
  sbom: FileCodeIcon,
};

/** Longest name shown in full before the middle is replaced with an ellipsis. */
const NAME_MAX = 40;

/**
 * A scan's name and version as one link. A long name (a firmware image's file
 * name, say) is shortened in the middle so the start and the end both stay
 * readable and the version is never pushed out; the full text is the tooltip
 * and is what assistive technology reads.
 */
function ScanName({ scan }: { scan: RecentScan }) {
  const shown = middleEllipsis(scan.project, NAME_MAX);
  const cut = shown !== scan.project;
  const full = scan.version ? `${scan.project} @${scan.version}` : scan.project;
  // One line: when the column is narrow the end of the line (the version first)
  // gives way to an ellipsis, and the tooltip always holds both in full.
  return (
    <Link href={scanHash(scan.id)} title={full} className="bl-scanname">
      <span aria-hidden={cut || undefined}>{shown}</span>
      {cut && <VisuallyHidden>{scan.project}</VisuallyHidden>}
      {scan.version && (
        <span className="bl-scanname-version">
          {" @"}
          {scan.version}
        </span>
      )}
    </Link>
  );
}

/** The type label, shared by the table and the stacked rows. */
function TypeLabel({ scan }: { scan: RecentScan }) {
  const { t } = useTranslation();
  const TypeIcon = TYPE_ICON[scanType(scan)];
  return (
    <Label variant="secondary" className="bl-lbl">
      <TypeIcon size={12} />
      {t(scanTypeLabelKey(scan))}
    </Label>
  );
}

/** Which way the worst severity moved since the previous run of this project.
 *  The arrow is paired with a label read aloud and shown as a tooltip. */
function Trend({ up }: { up: boolean }) {
  const { t } = useTranslation();
  const label = t(up ? "recent.sevUp" : "recent.sevDown");
  return (
    <span title={label} className={`bl-trend ${up ? "bl-trend-up" : "bl-trend-down"}`}>
      {up ? <ArrowUpIcon size={16} /> : <ArrowDownIcon size={16} />}
      <VisuallyHidden>{label}</VisuallyHidden>
    </span>
  );
}

function SeverityCell({ scan, all }: { scan: RecentScan; all: RecentScan[] }) {
  const { t } = useTranslation();
  const cmp = scanComparison(all, scan.id);
  return (
    <span className="bl-lbl-wrap">
      {scan.refused && (
        <Label variant="attention" title={t("recent.refusedHint")}>
          {t("recent.refused")}
        </Label>
      )}
      {scan.maxSeverity ? <SeverityLabel severity={scan.maxSeverity} /> : <span className="bl-muted">—</span>}
      {cmp && cmp.severityDir !== "same" && <Trend up={cmp.severityDir === "up"} />}
    </span>
  );
}

/** Component count and, against the previous run of the same project, the
 *  change. A project scanned once has nothing to compare against and shows no
 *  change at all, rather than a "0" that would read as "unchanged". */
function ComponentsCell({ scan, all }: { scan: RecentScan; all: RecentScan[] }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const cmp = scanComparison(all, scan.id);
  return (
    <span className="bl-num bl-compcell">
      {fmt(scan.components)}
      {/* A fixed slot, filled or not, so the counts share one right edge. */}
      <span className="bl-muted bl-small bl-delta" title={cmp && cmp.componentsDelta !== 0 ? t("recent.vsPrevious") : undefined}>
        {cmp && cmp.componentsDelta !== 0 && (
          <>
            {cmp.componentsDelta > 0 ? "+" : ""}
            {fmt(cmp.componentsDelta)}
            <VisuallyHidden> ({t("recent.vsPrevious")})</VisuallyHidden>
          </>
        )}
      </span>
    </span>
  );
}

/** The row's actions. Delete is the only one today; it asks first. */
function RowMenu({ scan, onDelete }: { scan: RecentScan; onDelete: (id: string) => void }) {
  const { t } = useTranslation();
  const name = [scan.project, scan.version].filter(Boolean).join(" ");
  return (
    <ActionMenu>
      <ActionMenu.Anchor>
        <IconButton icon={KebabHorizontalIcon} variant="invisible" size="small" aria-label={t("recent.moreActions", { name })} />
      </ActionMenu.Anchor>
      <ActionMenu.Overlay width="small">
        <ActionList>
          <ActionList.Item variant="danger" onSelect={() => onDelete(scan.id)}>
            <ActionList.LeadingVisual>
              <TrashIcon />
            </ActionList.LeadingVisual>
            {t("recent.delete")}
          </ActionList.Item>
        </ActionList>
      </ActionMenu.Overlay>
    </ActionMenu>
  );
}

function RecentHeader({ newHref, withAction }: { newHref: string; withAction: boolean }) {
  const { t } = useTranslation();
  return (
    <ScreenHeader
      title={t("recent.title")}
      description={t(IS_STATIC_DEMO ? "recent.demoSubtitle" : "recent.subtitle")}
      actions={
        // The empty list carries its own New scan call to action. The demo shows
        // the form too; only its last step, running the scan, is refused.
        withAction ? (
          <Button as="a" href={newHref} variant="primary" leadingVisual={PlusIcon} data-testid="recent-new-scan">
            {t("shell.newScan")}
          </Button>
        ) : undefined
      }
    />
  );
}

/**
 * First-run screen: the empty list is what a new user sees first, so orient
 * them: what BomLens does, how to start, and what it produces.
 */
function RecentEmpty({ newHref }: { newHref: string }) {
  const { t } = useTranslation();
  return (
    <div className="bl-scanmgmt">
      <RecentHeader newHref={newHref} withAction={false} />
      <div className="bl-box" style={{ marginTop: "var(--base-size-16)" }}>
        <Blankslate spacious>
          <Blankslate.Visual>
            <ShieldIcon size={32} />
          </Blankslate.Visual>
          <Blankslate.Heading as="h2">{t("recent.emptyTitle")}</Blankslate.Heading>
          <Blankslate.Description>{t("recent.emptyBody")}</Blankslate.Description>
          <Blankslate.PrimaryAction href={newHref}>{t("shell.newScan")}</Blankslate.PrimaryAction>
          {/* A second way in for someone who wants to see a result before
              scanning anything of their own. */}
          {!IS_STATIC_DEMO && (
            <div style={{ marginTop: "var(--base-size-16)" }}>
              <Link href={demoUrl()} target="_blank" rel="noreferrer noopener" data-testid="empty-demo-link" className="bl-extlink">
                {t("recent.emptyDemo")} <LinkExternalIcon size={12} />
              </Link>
            </div>
          )}
          <ul className="bl-emptyouts">
            {[
              { Icon: FileIcon, label: t("recent.emptyOutSbom") },
              { Icon: LawIcon, label: t("recent.emptyOutNotice") },
              { Icon: ShieldIcon, label: t("recent.emptyOutSecurity") },
            ].map(({ Icon, label }) => (
              <li key={label}>
                <Label variant="secondary" className="bl-lbl">
                  <Icon size={12} />
                  {label}
                </Label>
              </li>
            ))}
          </ul>
        </Blankslate>
      </div>
    </div>
  );
}

interface RecentSort {
  key: RecentSortKey;
  dir: RecentSortDir;
}

/**
 * Scan management, the home screen (logo / `#/` target): the past local scans
 * with search, an at-risk toggle, a type filter and sortable columns. Every
 * figure is computed from the real `/scans` list; Type is derived only from
 * signals the data carries (see lib/recent.ts).
 */
export function RecentScans({ scans, newHref, onDelete }: Props) {
  const { t, i18n } = useTranslation();
  const fmt = useFormatNumber();
  const narrow = useMediaQuery(NARROW_QUERY);
  const now = Date.now();
  const [sort, setSort] = useState<RecentSort>({ key: "generated", dir: "desc" });
  const [query, setQuery] = useState("");
  const [type, setType] = useState<ScanType | "all">("all");
  const [atRisk, setAtRisk] = useState(false);
  const summary = useMemo(() => summarizeRecent(scans), [scans]);
  const types = useMemo(() => presentTypes(scans), [scans]);
  const filtering = query.trim() !== "" || type !== "all" || atRisk;
  const rows = useMemo(
    () => sortRecent(filterRecent(scans, { query, type, atRisk }), sort.key, sort.dir),
    [scans, query, type, atRisk, sort],
  );
  const onSort = (key: RecentSortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" }));
  const sortHeader = (key: RecentSortKey, label: string, align?: "end") => (
    <SortHeader label={label} active={sort.key === key} dir={sort.dir} onSort={() => onSort(key)} align={align} />
  );

  if (scans.length === 0) return <RecentEmpty newHref={newHref} />;

  const chips = [
    ...(query.trim() ? [{ key: "q", label: t("recent.searchChip", { query: query.trim() }), onRemove: () => setQuery("") }] : []),
    ...(atRisk ? [{ key: "risk", label: t("recent.atRisk"), onRemove: () => setAtRisk(false) }] : []),
    ...(type !== "all" ? [{ key: "type", label: t(scanTypeLabelKeyFor(type)), onRemove: () => setType("all") }] : []),
  ];
  const clearAll = () => {
    setQuery("");
    setAtRisk(false);
    setType("all");
  };

  return (
    <div className="bl-scanmgmt">
      <RecentHeader newHref={newHref} withAction />
      {IS_STATIC_DEMO && <DemoStartHere scans={scans} />}
      <div className="bl-filterbar">
        <TextInput
          type="search"
          leadingVisual={SearchIcon}
          placeholder={t("recent.searchPlaceholder")}
          aria-label={t("recent.searchPlaceholder")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="bl-filterbar-search"
        />
        {/* The at-risk filter is a toggle with its count on it. It stays while
            active so it can be turned off. */}
        {(summary.atRisk > 0 || atRisk) && (
          <Button
            aria-pressed={atRisk}
            onClick={() => setAtRisk((v) => !v)}
            leadingVisual={AlertIcon}
            count={fmt(summary.atRisk)}
            className={atRisk ? "bl-toggle-on" : undefined}
          >
            {t("recent.atRisk")}
          </Button>
        )}
        {/* The type filter only when there is more than one type to choose between. */}
        {types.length > 1 && (
          <FilterMenu
            name={t("recent.colType")}
            allLabel={t("result.allTypes")}
            value={type === "all" ? "" : type}
            onChange={(v) => setType((v || "all") as ScanType | "all")}
            options={types.map((ty) => ({
              value: ty,
              text: t(scanTypeLabelKeyFor(ty)),
              count: scans.filter((s) => scanType(s) === ty).length,
            }))}
          />
        )}
        <span className="bl-grow" />
        {/* Totals: plain text, not controls. */}
        <span className="bl-totals bl-muted bl-num">
          <span>
            {t("recent.total")} <strong>{fmt(summary.total)}</strong>
          </span>
          <span aria-hidden>·</span>
          <span>
            {t("recent.projects")} <strong>{fmt(summary.projects)}</strong>
          </span>
        </span>
      </div>
      <ActiveFilters
        chips={chips}
        onClear={clearAll}
        summary={filtering && rows.length > 0 ? t("recent.shown", { shown: rows.length, total: scans.length }) : undefined}
      />

      {rows.length === 0 ? (
        <div className="bl-box">
          <Blankslate>
            <Blankslate.Visual>
              <SearchIcon size={24} />
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("recent.noMatch")}</Blankslate.Heading>
            <Blankslate.Description>{t("recent.noMatchHint")}</Blankslate.Description>
            <Button onClick={clearAll}>{t("result.clearFilters")}</Button>
          </Blankslate>
        </div>
      ) : narrow ? (
        <ul className="bl-box bl-rows">
          {rows.map((s) => (
            <li key={s.id} className="bl-row">
              <div className="bl-row-main">
                <ScanName scan={s} />
                <span className="bl-row-tags">
                  <TypeLabel scan={s} />
                  <SeverityCell scan={s} all={scans} />
                </span>
                <span className="bl-muted bl-small bl-num">
                  {t("recent.rowMeta", { count: s.components, date: formatRelativeTime(s.generatedAt, now, i18n.language) })}
                </span>
              </div>
              {/* The demo's data is fixed, so nothing there can be deleted. */}
              {!IS_STATIC_DEMO && <RowMenu scan={s} onDelete={onDelete} />}
            </li>
          ))}
        </ul>
      ) : (
        <Table.Container className="bl-scantbl">
          <Table
            aria-label={t("recent.title")}
            gridTemplateColumns={`minmax(15rem, 1fr) auto auto auto auto${IS_STATIC_DEMO ? "" : " 3.5rem"}`}
          >
            <Table.Head>
              <Table.Row>
                {sortHeader("scan", t("recent.colScan"))}
                <Table.Header>{t("recent.colType")}</Table.Header>
                {sortHeader("generated", t("recent.colGenerated"))}
                {sortHeader("components", t("recent.colComponents"), "end")}
                {sortHeader("severity", t("recent.colSeverity"))}
                {/* The demo's data is fixed, so the whole column goes, header
                    included, or the row would gain a blank cell. */}
                {!IS_STATIC_DEMO && (
                  <Table.Header>
                    <VisuallyHidden>{t("recent.colActions")}</VisuallyHidden>
                  </Table.Header>
                )}
              </Table.Row>
            </Table.Head>
            <Table.Body>
              {rows.map((s) => (
                <Table.Row key={s.id}>
                  <Table.Cell>
                    <ScanName scan={s} />
                  </Table.Cell>
                  <Table.Cell>
                    <TypeLabel scan={s} />
                  </Table.Cell>
                  <Table.Cell>
                    <time
                      dateTime={new Date(s.generatedAt * 1000).toISOString()}
                      title={new Date(s.generatedAt * 1000).toLocaleString(i18n.language)}
                      className="bl-muted bl-nowrap"
                    >
                      {formatRelativeTime(s.generatedAt, now, i18n.language)}
                    </time>
                  </Table.Cell>
                  <Table.Cell align="end">
                    <ComponentsCell scan={s} all={scans} />
                  </Table.Cell>
                  <Table.Cell>
                    <SeverityCell scan={s} all={scans} />
                  </Table.Cell>
                  {!IS_STATIC_DEMO && (
                    <Table.Cell align="end">
                      <RowMenu scan={s} onDelete={onDelete} />
                    </Table.Cell>
                  )}
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </Table.Container>
      )}

      {/* Where the list comes from: true of a local run, false of the demo,
          whose list is a fixed capture and not a folder on disk. */}
      {!IS_STATIC_DEMO && (
        <p className="bl-muted bl-small bl-sourcenote">
          <FileDirectoryIcon size={14} />
          <code className="bl-code">~/sbom-output</code>
          <span>{t("recent.source")}</span>
        </p>
      )}
    </div>
  );
}
