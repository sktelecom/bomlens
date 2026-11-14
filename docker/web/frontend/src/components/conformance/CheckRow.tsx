// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  AlertIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  LinkExternalIcon,
  SkipIcon,
  XCircleIcon,
} from "@primer/octicons-react";
import { CounterLabel, Label, Link, VisuallyHidden } from "@primer/react";
import { useId, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import type { ConformanceCheck } from "@/lib/api";
import {
  checkKind,
  dedupeMissing,
  explainedEntries,
  formatMeasure,
  isNotApplicable,
  isRegistryCheck,
  missingOverflow,
  sortByAttention,
} from "@/lib/conformance";
import { useFormatNumber } from "@/lib/format";

import "./conformance.css";

export const STATUS = {
  pass: { Icon: CheckCircleIcon, tone: "bl-cf-ok", key: "g7.sPass" },
  fail: { Icon: XCircleIcon, tone: "bl-cf-bad", key: "g7.sFail" },
  warn: { Icon: AlertIcon, tone: "bl-cf-warn", key: "g7.sWarn" },
  na: { Icon: SkipIcon, tone: "bl-cf-na", key: "g7.sNa" },
} as const;

/** For rows that carry a status without the rest of a check (crosswalk elements). */
export const statusOfValue = (s: string) => STATUS[s as keyof typeof STATUS] ?? STATUS.warn;
const statusOf = (c: ConformanceCheck) => (isNotApplicable(c) ? STATUS.na : statusOfValue(c.status));

export function Count({ n }: { n: number }) {
  const fmt = useFormatNumber();
  return <CounterLabel>{fmt(n)}</CounterLabel>;
}

/**
 * Where a satisfied value comes from. The word carries the meaning; colour only
 * backs it. Green only on a met check: "checked automatically" beside an unmet
 * one is not good news. A met element whose source is "declared" holds the
 * publisher's declaration, which the tool did not check, and says so.
 */
function SourceLabel({ source, naKind, met }: { source?: string; naKind?: string; met?: boolean }) {
  const { t } = useTranslation();
  if (!source) return null;
  if (naKind === "not-applicable") {
    const l = t("g7.source.notApplicable", { defaultValue: "" });
    return l ? <Label variant="secondary">{l}</Label> : null;
  }
  // No automated source is exactly what puts a check under the "Needs a person" tab.
  if (source === "na") return <Label variant="secondary">{t("conf.kind.review")}</Label>;
  const label = source === "declared" && met ? t("g7.source.declaredMet") : t(`g7.source.${source}`, { defaultValue: "" });
  if (!label) return null;
  return <Label variant={source === "auto" && met ? "success" : "secondary"}>{label}</Label>;
}

const Chip = ({ children }: { children: ReactNode }) => <code className="bl-cf-chip">{children}</code>;

function Line({ children }: { children: ReactNode }) {
  return <div className="bl-cf-line">{children}</div>;
}

/** One check: a one-line summary, the detail folded inside the row; how to satisfy stays visible. */
function CheckRow({ check }: { check: ConformanceCheck }) {
  const { t, i18n } = useTranslation();
  const { Icon, tone, key } = statusOf(check);
  const isKo = (i18n.language ?? "").startsWith("ko");
  // A registry check carries a cluster, a data source and, where the locale has
  // one, a plain-language "what this is" line and a "how to satisfy" hint. The
  // gate is what the check IS, not what it is called: the checks the scripts
  // write themselves carry no cluster.
  const fromRegistry = isRegistryCheck(check);
  const notMet = check.status !== "pass";
  const what = fromRegistry && notMet ? t(`g7.help.${check.id}.what`, { defaultValue: "" }) : "";
  const fix = fromRegistry && notMet ? t(`g7.help.${check.id}.fix`, { defaultValue: "" }) : "";
  const regText = (check.regulations ?? [])
    .map((r) => `${(isKo ? r.short_ko : r.short) || r.framework} ${r.ref}`)
    .join(" · ");
  // The real values pulled from the SBOM (purl, license id, hash alg): shown on
  // a met element, so it reads as "met with these".
  const evidence = fromRegistry && !notMet ? (check.evidence ?? []) : [];
  // What a person has to establish, for an element no scan can settle or one
  // checkable in a form this report cannot see (a signature delivered beside the SBOM).
  const reviewHow = notMet ? ((isKo ? check.reviewGuide?.howKo || check.reviewGuide?.how : check.reviewGuide?.how) ?? "") : "";
  const label = (isKo && check.labelKo) || check.label;
  const fmt = useFormatNumber();
  const detail = formatMeasure((isKo && check.detailKo) || check.detail, fmt, (n) => t("conf.unit", { count: n }));
  const fixId = useId();
  const missing = dedupeMissing(check.missing ?? []);
  const overflow = missingOverflow(check);
  // Components the supplier explained instead of versioning. Shown on a passing
  // row too: the count passed, but each reason is still the reviewer's call.
  const explained = explainedEntries(check);
  const guidance = check.guidance;

  const body: ReactNode[] = [
    what && (
      <Line key="what">
        <span className="bl-muted">{what}</span>
      </Line>
    ),
    notMet && missing.length > 0 && (
      <Line key="missing">
        <span className="bl-muted bl-strong">{t("g7.missing")}</span>
        {missing.map(({ name, count }) => (
          <Chip key={name}>{count > 1 ? `${name} ×${count}` : name}</Chip>
        ))}
        {overflow > 0 && <span className="bl-muted">{t("g7.missingMore", { count: overflow })}</span>}
      </Line>
    ),
    explained.length > 0 && (
      <Line key="explained">
        <span className="bl-muted bl-strong">{t("g7.explained")}</span>
        {explained.map(({ name, reason }, i) => (
          <Chip key={`${name}-${i}`}>
            {name} <span className="bl-muted">({t(`g7.explainedReason.${reason}`)})</span>
          </Chip>
        ))}
      </Line>
    ),
    evidence.length > 0 && (
      <Line key="evidence">
        <span className="bl-muted bl-strong">{t("g7.evidence")}</span>
        {evidence.map((e, i) => (
          <Chip key={`${e}-${i}`}>{e}</Chip>
        ))}
      </Line>
    ),
    reviewHow && (
      <Line key="how">
        <span>
          <span className="bl-strong">{t("g7.needsPerson")}</span> {reviewHow}
        </span>
      </Line>
    ),
    notMet && guidance?.snippet && (
      <details key="example" className="bl-cf-more">
        <summary>
          <span className="bl-cf-chev">
            <ChevronRightIcon size={16} />
          </span>
          <span className="bl-strong">{t("conf.exampleShow")}</span>
        </summary>
        <pre className="bl-cf-pre">{guidance.snippet}</pre>
      </details>
    ),
    guidance?.docUrl && (
      <div key="doc" className="bl-cf-more">
        <Link href={guidance.docUrl} target="_blank" rel="noreferrer">
          {t("g7.learnMore")} <LinkExternalIcon size={12} />
        </Link>
      </div>
    ),
  ].filter(Boolean);

  const lead =
    body.length > 0 ? (
      <span className="bl-cf-chev">
        <ChevronRightIcon size={16} />
      </span>
    ) : (
      <span className="bl-cf-spacer" />
    );
  const head = (
    <span className="bl-cf-rowhead">
      {lead}
      <span className={`bl-cf-ico ${tone}`} aria-hidden>
        <Icon size={16} />
      </span>
      <span className="bl-cf-name">{label}</span>
      {check.required && <Label variant="secondary" className="bl-cf-nowrap">{t("g7.required")}</Label>}
      {fromRegistry && <SourceLabel source={check.source} naKind={check.naKind} met={!notMet} />}
      <VisuallyHidden>{t(key)}</VisuallyHidden>
      <span className="bl-cf-meas bl-muted bl-small bl-num">{detail}</span>
    </span>
  );
  // The references stay visible, short and muted; how to satisfy sits under the
  // name, open or folded; the rest opens below it.
  const sub = (
    <>
      {regText && (
        <span className="bl-small bl-muted bl-cf-sub">
          <span className="bl-strong">{t("crosswalk.refs")}</span> {regText}
        </span>
      )}
      {fix && (
        <span className="bl-small bl-cf-sub" id={fixId}>
          <span className="bl-strong">{t("g7.howToFix")}</span> {fix}
        </span>
      )}
    </>
  );
  return (
    <li className="bl-cf-row" data-check={check.id}>
      {body.length > 0 ? (
        <details>
          <summary className="bl-cf-rowsum" aria-describedby={fix ? fixId : undefined}>
            {head}
            {sub}
          </summary>
          <div className="bl-cf-rowbody">{body}</div>
        </details>
      ) : (
        <div className="bl-cf-rowsum bl-cf-plain">
          {head}
          {sub}
        </div>
      )}
    </li>
  );
}

function Rows({ checks }: { checks: ConformanceCheck[] }) {
  return (
    <ul className="bl-cf-rows">
      {sortByAttention(checks).map((c) => (
        <CheckRow key={c.id} check={c} />
      ))}
    </ul>
  );
}

/**
 * A named group of checks in a fold. With `foldMet`, the met checks of an open
 * group sit in their own closed fold below the rest, so opening a group shows
 * what needs filling first.
 */
export function CheckGroup({
  title,
  checks,
  defaultOpen,
  trailing,
  foldMet = false,
}: {
  title: string;
  checks: ConformanceCheck[];
  defaultOpen: boolean;
  trailing?: ReactNode;
  foldMet?: boolean;
}) {
  const { t } = useTranslation();
  if (checks.length === 0) return null;
  // A group of met checks only is already closed; folding them a second time
  // would take two clicks to see anything.
  const pass = checks.filter((c) => checkKind(c) === "pass");
  const split = foldMet && pass.length > 0 && pass.length < checks.length;
  const rest = split ? checks.filter((c) => checkKind(c) !== "pass") : checks;
  return (
    <details className="bl-cf-group" open={defaultOpen || undefined}>
      <summary className="bl-cf-sum bl-cf-grouphead">
        <span className="bl-cf-chev">
          <ChevronRightIcon size={16} />
        </span>
        <span className="bl-strong">{title}</span>
        <Count n={checks.length} />
        {trailing}
      </summary>
      {rest.length > 0 && <Rows checks={rest} />}
      {split && (
        <details className="bl-cf-metfold">
          <summary className="bl-cf-sum">
            <span className="bl-cf-chev">
              <ChevronRightIcon size={16} />
            </span>
            <span className="bl-muted bl-small bl-strong">{t("g7.metFold", { count: pass.length })}</span>
          </summary>
          <Rows checks={pass} />
        </details>
      )}
    </details>
  );
}

/** Format conformance: the same box and head row as a baseline, the checks directly under it. */
export function FormatBox({ checks, open }: { checks: ConformanceCheck[]; open: boolean }) {
  const { t } = useTranslation();
  const [isOpen, setOpen] = useState(open);
  const listId = useId();
  return (
    <section className="bl-cf-box">
      <div className="bl-cf-head">
        <h2>
          <button type="button" className="bl-cf-hbtn" aria-expanded={isOpen} aria-controls={listId} onClick={() => setOpen((o) => !o)}>
            <span className="bl-cf-chev" data-open={isOpen || undefined}>
              <ChevronRightIcon size={16} />
            </span>
            {t("g7.formatTitle")}
          </button>
        </h2>
        <Count n={checks.length} />
      </div>
      <div id={listId} hidden={!isOpen}>
        <Rows checks={checks} />
      </div>
    </section>
  );
}

/** A baseline (2026 minimum elements, AI G7): one box, its coverage in the head, clusters as folds. */
export function BaselineBox({
  title,
  present,
  total,
  note,
  groups,
  open,
}: {
  title: string;
  present: number;
  total: number;
  note: string;
  groups: { key: string; title: string; checks: ConformanceCheck[] }[];
  open: (checks: ConformanceCheck[]) => boolean;
}) {
  const { t } = useTranslation();
  return (
    <section className="bl-cf-box">
      <div className="bl-cf-head">
        <h2>{title}</h2>
        <span className="bl-strong bl-num">{t("g7.present", { present, total })}</span>
        <span className="bl-muted bl-small">{note}</span>
      </div>
      <div className="bl-cf-groups">
        {groups.map((g) => (
          <CheckGroup key={g.key} title={g.title} checks={g.checks} defaultOpen={open(g.checks)} />
        ))}
      </div>
    </section>
  );
}
