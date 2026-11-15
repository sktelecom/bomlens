// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDownIcon, ChevronRightIcon } from "@primer/octicons-react";
import { Label, Link } from "@primer/react";
import { Table } from "@primer/react/experimental";
import { Fragment, memo, type MouseEvent } from "react";
import { useTranslation } from "react-i18next";

import { LicenseTierLabel, LicenseTierMark, PackageCoordinate, SeverityLabel } from "@/components/primer";
import { TIER_LABEL_KEY } from "@/components/primer/display";
import type { ComponentItem } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { componentRiskTier, worstLicense } from "@/lib/licenses";
import { scanHash } from "@/lib/route";

/** Which optional columns the table is showing right now. */
export interface ShownColumns {
  version: boolean;
  type: boolean;
  scope: boolean;
  risk: boolean;
  license: boolean;
}

export interface RowProps {
  item: ComponentItem;
  /** Stable key of the row (purl, or name and position). */
  rowKey: string;
  /** Position in the filtered list; names the detail row for aria-controls. */
  index: number;
  isOpen: boolean;
  onToggle: (rowKey: string) => void;
  shown: ShownColumns;
  scanId?: string | null;
  /** When the End of life or Outdated filter is on, the second line leaves out the word the filter already says. */
  eolFilter: boolean;
  outdatedFilter: boolean;
  onPickVulns?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
}

/** EOL and outdated, as a muted second line under the name. */
function NameMeta({ c, eolFilter, outdatedFilter }: { c: ComponentItem; eolFilter: boolean; outdatedFilter: boolean }) {
  const { t } = useTranslation();
  const parts: { key: string; text: string; title: string }[] = [];
  if (c.eol === "true") {
    const text = eolFilter
      ? c.eolDate
        ? t("result.eolSince", { date: c.eolDate })
        : ""
      : c.eolDate
        ? t("result.eolWithDate", { date: c.eolDate })
        : t("result.eolBadge");
    parts.push({ key: "eol", title: t("result.eolBadgeHint"), text });
  }
  if (c.outdated === "true") {
    const latest = c.latestVersion ? t("result.outdatedLatest", { version: c.latestVersion }) : "";
    const text = outdatedFilter ? latest : latest ? `${t("result.outdatedBadge")} · ${latest}` : t("result.outdatedBadge");
    parts.push({ key: "out", title: t("result.outdatedBadgeHint"), text });
  }
  const shown = parts.filter((p) => p.text);
  if (!shown.length) return null;
  return (
    <div className="bl-comp-meta bl-muted bl-small">
      {shown.map((p, i) => (
        <span key={p.key} title={p.title}>
          {i > 0 && " · "}
          {p.text}
        </span>
      ))}
    </div>
  );
}

/** Where a component came from or what is wrong with it, as Labels after the name. */
function NameLabels({ c }: { c: ComponentItem }) {
  const { t } = useTranslation();
  return (
    <>
      {/* Leads the labels: a package to remove outranks anything else. */}
      {c.malicious && (
        <Label
          variant="danger"
          title={
            c.maliciousId
              ? `${t("result.maliciousBadgeHint")} (${c.maliciousId}${c.maliciousSource ? `, ${c.maliciousSource}` : ""})`
              : t("result.maliciousBadgeHint")
          }
        >
          {t("result.maliciousBadge")}
        </Label>
      )}
      {c.vendored && (
        <Label
          variant="secondary"
          title={
            c.matchConfidence
              ? `${t("result.vendoredBadgeHint")} (${t("result.vendoredMatch", { pct: c.matchConfidence })})`
              : t("result.vendoredBadgeHint")
          }
        >
          {t("result.vendoredBadge")}
        </Label>
      )}
      {/* Added from a declaration file, not found by the scan. Neutral tones:
          where a component came from is not a risk signal. */}
      {c.declaredOrigin && (
        <Label
          variant={c.declaredOrigin === "first-party" ? "default" : "secondary"}
          data-testid="declared-origin"
          title={t(c.declaredOrigin === "first-party" ? "result.declaredFirstPartyHint" : "result.declaredThirdPartyHint")}
        >
          {t(c.declaredOrigin === "first-party" ? "result.declaredFirstParty" : "result.declaredThirdParty")}
        </Label>
      )}
    </>
  );
}

/** A link into another section of this scan. A plain click goes through the shell's own navigation (it keeps
 *  the term and version it needs); a modified click and "open in a new tab" use the href. */
function SectionLink({
  href,
  onPick,
  children,
}: {
  href?: string;
  onPick: () => void;
  children: string;
}) {
  const onClick = (e: MouseEvent<HTMLElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
    e.preventDefault();
    onPick();
  };
  return (
    <Link as={href ? "a" : "button"} href={href} onClick={onClick}>
      {children}
    </Link>
  );
}

function Detail({
  c,
  scanId,
  onPickVulns,
  onPickDependency,
}: {
  c: ComponentItem;
  scanId?: string | null;
  onPickVulns?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
}) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  return (
    <div className="bl-comp-detailbody">
      <dl className="bl-comp-kv">
        {c.purl ? (
          <>
            <dt>purl</dt>
            <dd className="bl-mono">{c.purl}</dd>
          </>
        ) : null}
        {c.source ? (
          <>
            <dt>{t("result.colSource")}</dt>
            <dd>
              <Link href={c.source} target="_blank" rel="noreferrer">
                {c.source}
              </Link>
            </dd>
          </>
        ) : null}
        {c.copyright ? (
          <>
            <dt>{t("result.colCopyright")}</dt>
            <dd>{c.copyright}</dd>
          </>
        ) : null}
        {c.licenses.length > 0 ? (
          <>
            <dt>{t("result.colLicense")}</dt>
            <dd className="bl-comp-licdd">
              <span>{c.licenses.join(", ")}</span>
              <LicenseTierLabel tier={componentRiskTier(c)} size="small" />
            </dd>
          </>
        ) : null}
        {c.eol === "true" ? (
          <>
            <dt>{t("result.colEol")}</dt>
            <dd>
              {t("result.eolBadge")}
              {c.eolDate ? ` (${c.eolDate})` : ""}
            </dd>
          </>
        ) : null}
        {c.outdated === "true" ? (
          <>
            <dt>{t("result.colCurrency")}</dt>
            <dd>
              {c.latestVersion ? t("result.outdatedLatest", { version: c.latestVersion }) : t("result.outdatedBadge")}
              {typeof c.releasesBehind === "number" ? ` · ${t("result.outdatedReleasesBehind", { count: c.releasesBehind })}` : ""}
              {c.lastReleased ? ` · ${t("result.outdatedLastReleased", { date: c.lastReleased })}` : ""}
            </dd>
          </>
        ) : null}
        {c.vulnCount ? (
          <>
            <dt>{t("nav.vulnerabilities")}</dt>
            <dd className="bl-comp-vulndd">
              {c.maxSeverity ? <SeverityLabel severity={c.maxSeverity} count={c.vulnCount} size="small" /> : <span>{fmt(c.vulnCount)}</span>}
              {onPickVulns && (
                <SectionLink
                  href={scanId ? scanHash(scanId, "vulnerabilities", { q: c.name }) : undefined}
                  onPick={() => onPickVulns(c.name)}
                >
                  {t("result.viewInVulns", { name: c.name })}
                </SectionLink>
              )}
            </dd>
          </>
        ) : null}
        {onPickDependency && (
          <>
            <dt>{t("nav.dependencies")}</dt>
            <dd>
              <SectionLink
                href={scanId ? scanHash(scanId, "dependencies", { q: c.name, ...(c.version ? { version: c.version } : {}) }) : undefined}
                onPick={() => onPickDependency(c.name, c.version)}
              >
                {t("result.viewInDependencies", { name: c.name })}
              </SectionLink>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

/** One component row and, when open, the detail row it expands into. */
function ComponentRowImpl({
  item: c,
  rowKey,
  index,
  isOpen,
  onToggle,
  shown,
  scanId,
  eolFilter,
  outdatedFilter,
  onPickVulns,
  onPickDependency,
}: RowProps) {
  const { t } = useTranslation();
  const detailId = `cd-${index}`;
  // The one license shown is the most concerning one; the rest fold into "+N" that names them all.
  const shownLicense = worstLicense(c.licenses);
  const otherLicenses = c.licenses.length - 1;
  const tier = componentRiskTier(c);
  const tierName = t(TIER_LABEL_KEY[tier]);
  const toggle = () => onToggle(rowKey);
  const coord = c.group ? `${c.group}/${c.name}` : c.name;
  return (
    <Fragment>
      <Table.Row data-open={isOpen} onClick={toggle} className="bl-comp-row">
        <Table.Cell scope="row">
          <div className="bl-comp-namecell">
            <div className="bl-comp-line1">
              {/* The disclosure is a real button, so Tab, Enter and Space work and a
                  screen reader hears the state; a click anywhere on the row does the same for a pointer. */}
              <button
                type="button"
                className="bl-comp-disclose"
                aria-expanded={isOpen}
                aria-controls={isOpen ? detailId : undefined}
                aria-label={`${t("result.componentRowToggle")}: ${coord}`}
                onClick={(e) => {
                  e.stopPropagation();
                  toggle();
                }}
              >
                <span className="bl-muted bl-comp-chev" aria-hidden>
                  {isOpen ? <ChevronDownIcon size={16} /> : <ChevronRightIcon size={16} />}
                </span>
                <PackageCoordinate group={c.group || undefined} name={c.name} strongName className="bl-comp-name" />
              </button>
              <span className="bl-comp-labels">
                <NameLabels c={c} />
              </span>
            </div>
            <NameMeta c={c} eolFilter={eolFilter} outdatedFilter={outdatedFilter} />
          </div>
        </Table.Cell>
        {shown.version && (
          <Table.Cell>
            {/* A presence-only row has no version by construction: a dash here would read as a gap in the
                data rather than as the finding it is. */}
            <span className="bl-mono bl-muted bl-comp-ver">
              {c.version ||
                (c.presenceOnly ? (
                  <span className="bl-comp-sans" title={t("result.presenceOnlyHint")}>
                    {t("result.presenceOnlyVersion")}
                  </span>
                ) : (
                  "-"
                ))}
            </span>
          </Table.Cell>
        )}
        {shown.type && (
          <Table.Cell>
            <span className="bl-muted">{c.type || "-"}</span>
          </Table.Cell>
        )}
        {shown.scope && (
          <Table.Cell>
            {c.scope ? (
              <span className={c.scope === "direct" ? "bl-strong" : "bl-muted"}>
                {t(c.scope === "direct" ? "result.scopeDirect" : "result.scopeTransitive")}
              </span>
            ) : (
              <span className="bl-muted">-</span>
            )}
          </Table.Cell>
        )}
        {shown.risk && (
          <Table.Cell>
            {c.maxSeverity ? <SeverityLabel severity={c.maxSeverity} count={c.vulnCount || undefined} /> : <span className="bl-muted">-</span>}
          </Table.Cell>
        )}
        {shown.license && (
          <Table.Cell>
            {c.licenses.length ? (
              <div className="bl-comp-lic">
                <span
                  role="img"
                  aria-label={t("result.componentsTierOf", { tier: tierName })}
                  title={t("result.componentsTierOf", { tier: tierName })}
                  className="bl-comp-tier"
                >
                  <LicenseTierMark tier={tier} />
                </span>
                <Label variant="secondary" className="bl-comp-liclabel" title={shownLicense}>
                  {shownLicense}
                </Label>
                {otherLicenses > 0 && (
                  <span
                    role="img"
                    className="bl-muted bl-small bl-nowrap"
                    title={c.licenses.join(", ")}
                    aria-label={c.licenses.join(", ")}
                  >
                    {t("result.licenseMore", { count: otherLicenses })}
                  </span>
                )}
              </div>
            ) : (
              <span className="bl-muted">{t("result.licenseNone")}</span>
            )}
          </Table.Cell>
        )}
      </Table.Row>
      {isOpen && (
        <Table.Row id={detailId}>
          <Table.Cell className="bl-comp-detail">
            <Detail c={c} scanId={scanId} onPickVulns={onPickVulns} onPickDependency={onPickDependency} />
          </Table.Cell>
        </Table.Row>
      )}
    </Fragment>
  );
}

export const ComponentRow = memo(ComponentRowImpl);
