// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "@primer/react";
import { useTranslation } from "react-i18next";

import { LicenseTierMark, PackageCoordinate, SeverityLabel, severityFg, severityFill, severityShape, tierFill, TIER_LABEL_KEY } from "@/components/primer";
import { Marker } from "@/components/ui/marker";
import { SEVERITY_ORDER, type DoneEvent, type SecuritySummary, type Severity } from "@/lib/api";
import { useFormatNumber } from "@/lib/format";
import { LICENSE_TIER_ORDER, type LicenseRiskTier, licenseRiskSummary } from "@/lib/licenses";
import { riskyComponentCount, topRiskComponents } from "@/lib/overview";
import { scanHash } from "@/lib/route";

import { OvBox, OvRow } from "./parts";
import { useTierHint } from "../LicenseRiskBar";

/**
 * The handful of components carrying the most risk, as a short list that links
 * to the vulnerabilities of the component it names. Not a replacement for the
 * Components table (six rows, no filtering); renders nothing when no component
 * carries a vulnerability.
 */
export function RiskyBox({ result, scanId }: { result: DoneEvent; scanId: string | null }) {
  const { t } = useTranslation();
  const rows = topRiskComponents(result);
  const total = riskyComponentCount(result);
  if (rows.length === 0) return null;
  return (
    <OvBox
      testId="top-risk"
      title={t("overview.topRisk")}
      head={
        <>
          {/* On an OS image the worst six can all be variants of one kernel
              package. True, but it reads as the whole story unless the size of
              what sits behind it is stated. */}
          <span className="bl-muted bl-small">{t("overview.topRiskOf", { shown: rows.length, total })}</span>
          {scanId && (
            <span className="bl-box-head-end">
              <Link href={scanHash(scanId, "components")}>{t("overview.topRiskAll")}</Link>
            </span>
          )}
        </>
      }
    >
      <ul className="bl-ovlist">
        {rows.map((c) => (
          <li key={c.purl || `${c.group}-${c.name}-${c.version}`}>
            <OvRow href={scanId ? scanHash(scanId, "vulnerabilities", { q: c.name }) : undefined}>
              <span className="bl-flat" style={{ display: "flex", alignItems: "center", gap: "var(--base-size-12)" }}>
                <PackageCoordinate group={c.group || undefined} name={c.name} className="bl-ovrisk-name" />
                <span className="bl-ovrisk-version" title={c.version}>
                  {c.version}
                </span>
                <span className="bl-ovrisk-sev">
                  {c.maxSeverity && <SeverityLabel severity={c.maxSeverity} count={c.vulnCount || undefined} quiet />}
                </span>
              </span>
            </OvRow>
          </li>
        ))}
      </ul>
    </OvBox>
  );
}

/**
 * The severity axis. A proportional bar (display only: its smallest segments are
 * a few pixels wide, below the 24px target size), and under it one cell per grade
 * that links to the vulnerabilities of that grade. A grade with none is disabled.
 */
export function SeverityPanel({ security, scanId }: { security: SecuritySummary; scanId: string | null }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const total = security.TOTAL;
  return (
    <OvBox
      testId="severity-panel"
      title={t("result.severityTitle")}
      head={total > 0 && scanId ? <span className="bl-muted bl-small bl-box-head-end">{t("result.severityFilterHint")}</span> : undefined}
    >
      <div className="bl-box-body">
        {total === 0 ? (
          <p className="bl-muted bl-flat">
            {security.uncheckedCount
              ? t("result.noVulnsSomeUnchecked", { count: security.uncheckedCount })
              : security.notReachableCount
                ? t("result.noVulnsSomeNotReachable", { count: security.notReachableCount })
                : t("result.noVulns")}
          </p>
        ) : (
          <>
            <div
              className="bl-ovbar"
              role="img"
              aria-label={`${t("result.severityTitle")}: ${SEVERITY_ORDER.map((s) => `${t(`severity.${s}`)} ${fmt(security[s])}`).join(", ")}`}
            >
              {SEVERITY_ORDER.map((s) =>
                security[s] ? (
                  <span
                    key={s}
                    title={`${t(`severity.${s}`)}: ${fmt(security[s])}`}
                    style={{ flex: security[s] / total, background: severityFill(s) }}
                  />
                ) : null,
              )}
            </div>
            <div className="bl-sevgrid">
              {SEVERITY_ORDER.map((s) => {
                const inner = (
                  <>
                    <span className="bl-sevcell-num" style={{ color: severityFg(s) }}>
                      <Marker shape={severityShape(s)} />
                      <b>{fmt(security[s])}</b>
                    </span>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{t(`severity.${s}`)}</span>
                  </>
                );
                if (security[s] === 0)
                  return (
                    // A disabled link: a grade with no findings has nothing to open.
                    <span key={s} className="bl-sevcell" role="link" aria-disabled="true">
                      {inner}
                    </span>
                  );
                if (!scanId)
                  return (
                    <span key={s} className="bl-sevcell">
                      {inner}
                    </span>
                  );
                return (
                  <a
                    key={s}
                    className="bl-sevcell"
                    href={scanHash(scanId, "vulnerabilities", { severity: s as Severity })}
                    aria-label={`${t(`severity.${s}`)} ${fmt(security[s])}`}
                  >
                    {inner}
                  </a>
                );
              })}
            </div>
          </>
        )}
      </div>
    </OvBox>
  );
}

/**
 * The license axis: a bar of the six classes and their legend, both linking to
 * the Licenses section filtered to the class. An unknown license shows as
 * uncategorized, never folded into permissive, so the bar never overstates how
 * safe the bill of materials is.
 */
export function LicensePanel({ result, scanId }: { result: DoneEvent; scanId: string | null }) {
  const { t } = useTranslation();
  const fmt = useFormatNumber();
  const tierHint = useTierHint();
  const summary = licenseRiskSummary(result.sbom?.componentList ?? []);
  const total = summary.TOTAL;
  if (total === 0) return null;
  const href = (tier: LicenseRiskTier) => (scanId ? scanHash(scanId, "licenses", { tier }) : undefined);
  const present = LICENSE_TIER_ORDER.filter((tier) => summary[tier] > 0);
  return (
    <OvBox
      testId="license-panel"
      title={t("result.licenseClassTitle")}
      head={scanId ? <span className="bl-muted bl-small bl-box-head-end">{t("result.licenseClassFilterHint")}</span> : undefined}
    >
      <div className="bl-box-body">
        <div className="bl-ovbar bl-ovbar-lic" role="group" aria-label={t("result.licenseClassTitle")}>
          {present.map((tier) => {
            const common = {
              title: `${t(TIER_LABEL_KEY[tier])}: ${fmt(summary[tier])}. ${tierHint(tier)}`,
              style: { flex: summary[tier] / total, background: tierFill(tier) },
            };
            const h = href(tier);
            // A link needs its own name; a plain segment is described by the legend.
            return h ? (
              <a key={tier} {...common} href={h} aria-label={`${t(TIER_LABEL_KEY[tier])} ${fmt(summary[tier])}`} />
            ) : (
              <span key={tier} {...common} />
            );
          })}
        </div>
        <div className="bl-tierlegend">
          {present.map((tier) => {
            const inner = (
              <>
                <LicenseTierMark tier={tier} />
                {t(TIER_LABEL_KEY[tier])}
                <span className="bl-muted bl-num">{fmt(summary[tier])}</span>
              </>
            );
            const h = href(tier);
            return h ? (
              <a key={tier} className="bl-tierchip" href={h} title={tierHint(tier)}>
                {inner}
              </a>
            ) : (
              <span key={tier} className="bl-tierchip" title={tierHint(tier)}>
                {inner}
              </span>
            );
          })}
        </div>
      </div>
    </OvBox>
  );
}
