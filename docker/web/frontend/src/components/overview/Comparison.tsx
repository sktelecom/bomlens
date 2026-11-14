// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, HistoryIcon, TriangleDownIcon, TriangleUpIcon } from "@primer/octicons-react";
import { Link, Spinner } from "@primer/react";
import { type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { loadScan, type DoneEvent, type RecentScan } from "@/lib/api";
import { formatRelativeTime, scanComparison } from "@/lib/recent";
import { scanHash } from "@/lib/route";
import { type ComponentDiff, diffComponents, diffVulnerabilities, type VulnDiff } from "@/lib/scanDiff";
import { PackageCoordinate, splitPackage } from "@/components/primer";

import { OvBox } from "./parts";

/** Rows shown per change list; the rest is a "+N more" line. */
const DIFF_LIST_CAP = 8;

function capList<T>(items: T[]): { shown: T[]; more: number } {
  return { shown: items.slice(0, DIFF_LIST_CAP), more: Math.max(0, items.length - DIFF_LIST_CAP) };
}

const compLabel = (c: { group: string; name: string }) => (c.group ? `${c.group}/${c.name}` : c.name);

interface DiffRow {
  key: string;
  href?: string;
  main: ReactNode;
  aside: ReactNode;
  note?: string;
}

/**
 * One change list of the comparison: a full-width disclosure whose rows read
 * like the riskiest-components list. The summary line is always shown; the
 * rows (each a link into the section it names) open below it.
 */
function DiffSection({
  testId,
  label,
  summary,
  groups,
  all,
}: {
  testId: string;
  label: string;
  summary: string;
  groups: { heading: string; more: number; rows: DiffRow[] }[];
  all?: { href: string; label: string; testId: string };
}) {
  const { t } = useTranslation();
  return (
    <details className="bl-ovdiff">
      <summary>
        <span className="bl-chev">
          <ChevronRightIcon size={16} />
        </span>
        <span className="bl-ovdiff-label">{label}</span>
        <span className="bl-ovdiff-summary" data-testid={`${testId}-summary`}>
          {summary}
        </span>
      </summary>
      <div data-testid={`${testId}-details`}>
        {groups
          .filter((g) => g.rows.length > 0)
          .map((g) => (
            <div key={g.heading}>
              <div className="bl-box-sub">{g.heading}</div>
              <ul className="bl-ovlist">
                {g.rows.map((r) => {
                  const inner = (
                    <>
                      <span className="bl-ovdiff-main">{r.main}</span>
                      <span className="bl-ovdiff-aside">{r.aside}</span>
                      {r.note && <span className="bl-muted bl-small bl-nowrap">{r.note}</span>}
                      {r.href && (
                        <span className="bl-ovrow-chev">
                          <ChevronRightIcon size={16} />
                        </span>
                      )}
                    </>
                  );
                  return (
                    <li key={r.key}>
                      {r.href ? (
                        <a className="bl-ovdiff-row" href={r.href}>
                          {inner}
                        </a>
                      ) : (
                        <div className="bl-ovdiff-row">{inner}</div>
                      )}
                    </li>
                  );
                })}
              </ul>
              {g.more > 0 && <div className="bl-ovdiff-more">{t("overview.diffMore", { count: g.more })}</div>}
            </div>
          ))}
        {all && (
          <div className="bl-ovdiff-foot">
            <Link href={all.href} data-testid={all.testId}>
              {all.label}
            </Link>
          </div>
        )}
      </div>
    </details>
  );
}

/**
 * How this run moved against the last one of the same project. The first part
 * (component count change, worst-severity direction) renders at once from the
 * Recent-scans summary. Which components and which CVEs actually moved needs
 * the previous scan's full lists, which the summary does not carry, so they
 * load in a second pass and fill the box in. Absent entirely when there is no
 * earlier run to compare against.
 */
export function ComparisonBox({
  result,
  scanId,
  recent,
}: {
  result: DoneEvent;
  scanId: string | null;
  recent: RecentScan[];
}) {
  const { t, i18n } = useTranslation();
  const comparison = scanId ? scanComparison(recent, scanId) : null;
  const [changes, setChanges] = useState<{
    components: ComponentDiff;
    vulns: VulnDiff;
    /** Either scan's component list was capped server-side, so the diff may
     *  be missing rows outside what was actually shown. */
    partial: boolean;
  } | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setChanges(null);
    if (!comparison) return;
    let cancelled = false;
    setLoading(true);
    loadScan(comparison.prev.id).then((prev) => {
      if (cancelled) return;
      setLoading(false);
      if (!prev) return;
      setChanges({
        components: diffComponents(prev.sbom?.componentList ?? [], result.sbom?.componentList ?? []),
        vulns: diffVulnerabilities(prev.security?.vulnerabilities ?? [], result.security?.vulnerabilities ?? []),
        partial: Boolean(prev.sbom?.truncated || result.sbom?.truncated),
      });
    });
    return () => {
      cancelled = true;
    };
    // result and scanId change together (a new scan replaces both); comparison
    // is derived from scanId + recent, so scanId is the one stable dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, comparison?.prev.id]);

  if (!comparison || !scanId) return null;

  const label =
    comparison.prev.version || formatRelativeTime(comparison.prev.generatedAt, Date.now(), i18n.language);
  const dir = comparison.severityDir;
  const prevName = `${comparison.prev.project} ${comparison.prev.version}`.trim();
  const cLink = (name: string) => scanHash(scanId, "components", { q: name });

  const added = changes && capList(changes.components.added);
  const removed = changes && capList(changes.components.removed);
  const changed = changes && capList(changes.components.changed);
  const news = changes && capList(changes.vulns.new);
  const resolved = changes && capList(changes.vulns.resolved);

  return (
    <OvBox
      testId="comparison"
      icon={HistoryIcon}
      title={t("overview.vsPrevious", { label: `${comparison.prev.project} ${label}`.trim() })}
      head={
        <>
          <span className="bl-muted bl-small">
            {comparison.componentsDelta === 0
              ? t("overview.compSame")
              : t("overview.compDelta", {
                  delta: comparison.componentsDelta > 0 ? `+${comparison.componentsDelta}` : `${comparison.componentsDelta}`,
                })}
          </span>
          {loading && (
            <span className="bl-muted bl-small bl-inline" role="status" data-testid="diff-loading">
              <Spinner size="small" srText={null} />
              {t("overview.diffLoading")}
            </span>
          )}
          <span className="bl-box-head-end">
            <span className="bl-muted">{t("overview.sevTrendLabel")}</span>
            <span
              className={`bl-ovtrend ${dir === "up" ? "bl-ovtrend-up" : dir === "down" ? "bl-ovtrend-down" : ""}`}
            >
              {dir === "up" && <TriangleUpIcon size={16} />}
              {dir === "down" && <TriangleDownIcon size={16} />}
              {t(dir === "up" ? "overview.sevValueUp" : dir === "down" ? "overview.sevValueDown" : "overview.sevValueSame")}
            </span>
          </span>
        </>
      }
    >
      {changes && (
        <>
          <DiffSection
            testId="comp-change"
            label={t("overview.compChangeLabel")}
            summary={t("overview.compChangeSummary", {
              added: changes.components.added.length,
              removed: changes.components.removed.length,
              changed: changes.components.changed.length,
            })}
            groups={[
              {
                heading: t("overview.compAddedHeading"),
                more: added!.more,
                rows: added!.shown.map((c) => ({
                  key: compLabel(c),
                  href: cLink(compLabel(c)),
                  main: <PackageCoordinate group={c.group || undefined} name={c.name} />,
                  aside: c.version,
                })),
              },
              {
                heading: t("overview.compRemovedHeading"),
                more: removed!.more,
                rows: removed!.shown.map((c) => ({
                  key: compLabel(c),
                  href: cLink(compLabel(c)),
                  main: <PackageCoordinate group={c.group || undefined} name={c.name} />,
                  aside: c.version,
                })),
              },
              {
                heading: t("overview.compChangedHeading"),
                more: changed!.more,
                rows: changed!.shown.map((c) => ({
                  key: compLabel(c),
                  href: cLink(compLabel(c)),
                  main: <PackageCoordinate group={c.group || undefined} name={c.name} />,
                  aside: t("overview.compChangedSuffix", { from: c.from, to: c.to }),
                })),
              },
            ]}
            all={{ href: scanHash(scanId, "components"), label: t("overview.topRiskAll"), testId: "comp-diff-all-link" }}
          />
          <DiffSection
            testId="vuln-change"
            label={t("overview.vulnChangeLabel")}
            summary={t("overview.vulnChangeSummary", {
              added: changes.vulns.new.length,
              resolved: changes.vulns.resolved.length,
            })}
            groups={[
              {
                heading: t("overview.vulnNewHeading"),
                more: news!.more,
                rows: news!.shown.map((v) => ({
                  key: `${v.id}:${v.pkg}`,
                  href: scanHash(scanId, "vulnerabilities", { q: v.id }),
                  main: v.id,
                  aside: <PackageCoordinate {...splitPackage(v.pkg)} />,
                })),
              },
              {
                heading: t("overview.vulnResolvedHeading"),
                more: resolved!.more,
                // A resolved CVE is gone from this scan, so its link opens it in
                // the previous scan, where the row still is.
                rows: resolved!.shown.map((v) => ({
                  key: `${v.id}:${v.pkg}`,
                  href: scanHash(comparison.prev.id, "vulnerabilities", { q: v.id }),
                  main: v.id,
                  aside: <PackageCoordinate {...splitPackage(v.pkg)} />,
                  note: t("overview.prevScanLink", { scan: prevName }),
                })),
              },
            ]}
            all={{ href: scanHash(scanId, "vulnerabilities"), label: t("overview.allVulnerabilities"), testId: "vuln-diff-all-link" }}
          />
        </>
      )}
      {changes?.partial && (
        <div className="bl-ovdiff-foot bl-muted" style={{ borderTop: "var(--borderWidth-thin) solid var(--borderColor-muted)" }}>
          {t("overview.diffPartial")}
        </div>
      )}
    </OvBox>
  );
}
