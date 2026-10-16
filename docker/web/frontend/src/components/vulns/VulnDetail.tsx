// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import {
  ApiError,
  saveVexVerdict,
  VEX_STATES,
  type VexReceived,
  type VexState,
  type VulnItem,
} from "@/lib/api";
import { useToast } from "@/lib/toast";
import { IS_STATIC_DEMO } from "@/lib/demo";

import { VEX_LABEL_KEY, VEX_TONE } from "./vulnStatus";

/** Primary advisory URL first, then references, de-duplicated. */
export function vulnLinks(v: VulnItem): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of [v.url, ...(v.refs ?? [])]) {
    if (u && !seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

/** Human-readable publish date; falls back to the raw string if it doesn't parse. */
function formatPublishedDate(iso: string, locale: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(locale, { dateStyle: "medium" });
}

/** Expanded detail for one CVE: CVSS, description, reference links, and the
 *  supplier's own judgement (VexJudgement below). */
export function VulnDetail({
  vuln,
  links,
  onPickComponent,
  onPickDependency,
  scanId,
  vex,
  received,
  onVexSaved,
}: {
  vuln: VulnItem;
  links: string[];
  onPickComponent?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
  scanId?: string | null;
  vex: VexFields;
  received?: VexReceived;
  onVexSaved: (saved: VexFields) => void;
}) {
  const { t, i18n } = useTranslation();
  const noOriginalDetail =
    vuln.cvss == null && !vuln.description && links.length === 0 && !vuln.publishedDate;
  if (noOriginalDetail && !scanId && !vex.state && !received) {
    return <p className="text-muted-foreground">{t("result.vulnNoDetail")}</p>;
  }
  return (
    <div className="space-y-3">
      {noOriginalDetail && <p className="text-muted-foreground">{t("result.vulnNoDetail")}</p>}
      {vuln.cvss != null && (
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-medium">{t("result.vulnCvss")}</span>
          <span className="tabular-nums">{vuln.cvss}</span>
          {vuln.cvssVector ? (
            <span className="font-mono text-label text-muted-foreground">
              {vuln.cvssVector}
            </span>
          ) : null}
        </div>
      )}
      {vuln.publishedDate && (
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-medium">{t("result.vulnPublished")}</span>
          <span className="tabular-nums text-muted-foreground">
            {formatPublishedDate(vuln.publishedDate, i18n.language)}
          </span>
        </div>
      )}
      {vuln.description ? (
        <div className="space-y-1">
          <div className="font-medium">{t("result.vulnDescription")}</div>
          <p className="max-w-3xl leading-relaxed text-muted-foreground">
            {vuln.description}
          </p>
        </div>
      ) : null}
      {links.length > 0 ? (
        <div className="space-y-1">
          <div className="font-medium">{t("result.vulnReferences")}</div>
          <ul className="space-y-0.5">
            {links.map((href) => (
              <li key={href}>
                <a
                  href={href}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 break-all text-primary underline-offset-2 hover:underline"
                >
                  <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                  {href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {/* Back to the package this CVE is against, in the component inventory.
          It lives in the expanded detail because the row itself is the toggle
          control, and a control nested in a control is not announced reliably. */}
      {onPickComponent && vuln.pkg ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onPickComponent(vuln.pkg);
          }}
          className="rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {t("result.viewInComponents", { name: vuln.pkg })}
        </button>
      ) : null}
      {onPickDependency && vuln.pkg ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onPickDependency(vuln.pkg, vuln.installed);
          }}
          className="ml-3 rounded text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {t("result.viewInDependencies", { name: vuln.pkg })}
        </button>
      ) : null}
      {received && (
        <div className="space-y-1 border-t pt-3">
          <div className="font-medium">{t("result.vexReceivedTitle")}</div>
          <p className="text-body-sm text-muted-foreground">
            {received.source
              ? t("result.vexReceivedFrom", { product: received.source })
              : t("result.vexReceivedHint")}
          </p>
          <Badge tone={VEX_TONE[received.state]}>{t(VEX_LABEL_KEY[received.state])}</Badge>
          {received.justification && (
            <p className="text-muted-foreground">
              {t("result.vexReceivedJustification", { value: received.justification })}
            </p>
          )}
          {received.detail && <p className="text-muted-foreground">{received.detail}</p>}
        </div>
      )}
      <VexJudgement scanId={scanId} vuln={vuln} vex={vex} onSaved={onVexSaved} />
    </div>
  );
}

/** Judgement input for one CVE against one component: state select, an
 *  optional note, and Save. Read-only (state only, no editing) in the static
 *  demo build, which has no server to save to. */
function VexJudgement({
  scanId,
  vuln,
  vex,
  onSaved,
}: {
  scanId?: string | null;
  vuln: VulnItem;
  vex: VexFields;
  onSaved: (saved: VexFields) => void;
}) {
  const { t, i18n } = useTranslation();
  const { toast } = useToast();
  const [pendingState, setPendingState] = useState<VexState | "">(vex.state ?? "");
  const [pendingDetail, setPendingDetail] = useState(vex.detail ?? "");
  const [saving, setSaving] = useState(false);

  // The same component instance is reused across rows as the open panel
  // switches (React diffs by the surrounding Fragment's key, not this one's
  // props), so the form has to resync when the row underneath it changes.
  useEffect(() => {
    setPendingState(vex.state ?? "");
    setPendingDetail(vex.detail ?? "");
  }, [vuln.id, vuln.purl, vuln.pkg, vex.state, vex.detail]);

  if (IS_STATIC_DEMO) {
    if (!vex.state) return null;
    return (
      <div className="space-y-1 border-t pt-3">
        <div className="font-medium">{t("result.vexSectionTitle")}</div>
        <Badge tone={VEX_TONE[vex.state]}>{t(VEX_LABEL_KEY[vex.state])}</Badge>
        {vex.detail && <p className="text-muted-foreground">{vex.detail}</p>}
      </div>
    );
  }
  if (!scanId) return null;

  const save = async () => {
    if (!pendingState) return;
    setSaving(true);
    try {
      const verdict = await saveVexVerdict(scanId, {
        cve: vuln.id,
        state: pendingState,
        detail: pendingDetail || undefined,
        purl: vuln.purl,
        pkg: vuln.purl ? undefined : vuln.pkg,
        installed: vuln.purl ? undefined : vuln.installed,
      });
      onSaved({ state: verdict.state, detail: verdict.detail, updatedAt: verdict.updatedAt });
      toast(t("result.vexSaved"));
    } catch (e) {
      toast(e instanceof ApiError ? e.message : t("result.vexSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-2 border-t pt-3">
      <div className="font-medium">{t("result.vexSectionTitle")}</div>
      <p className="text-body-sm text-muted-foreground">{t("result.vexSectionHint")}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Select
          aria-label={t("result.vexStateLabel")}
          value={pendingState}
          onChange={(e) => setPendingState(e.target.value as VexState | "")}
          onClick={(e) => e.stopPropagation()}
        >
          <option value="">{t("result.vexStatePlaceholder")}</option>
          {VEX_STATES.map((s) => (
            <option key={s} value={s}>
              {t(VEX_LABEL_KEY[s])}
            </option>
          ))}
        </Select>
        <Button
          type="button"
          size="sm"
          variant="secondary"
          disabled={!pendingState || saving}
          onClick={(e) => {
            e.stopPropagation();
            void save();
          }}
        >
          {saving ? t("result.vexSaving") : t("result.vexSaveButton")}
        </Button>
      </div>
      <textarea
        value={pendingDetail}
        onChange={(e) => setPendingDetail(e.target.value)}
        onClick={(e) => e.stopPropagation()}
        placeholder={t("result.vexDetailPlaceholder")}
        aria-label={t("result.vexDetailLabel")}
        rows={2}
        maxLength={2000}
        className="w-full max-w-lg rounded-lg border border-input bg-background px-2 py-1.5 text-body-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
      />
      {vex.updatedAt && (
        <p className="text-body-sm text-muted-foreground">
          {t("result.vexUpdatedAt", { date: formatPublishedDate(vex.updatedAt, i18n.language) })}
        </p>
      )}
    </div>
  );
}

/** A row's own saved fields, or a not-yet-persisted local edit overriding
 *  them (set right after a successful save, before the next full reload). */
export interface VexFields {
  state?: VexState;
  detail?: string;
  updatedAt?: string;
}

/** Same identity a saved verdict is keyed by: purl when the row has one,
 *  otherwise pkg+installed (matching the server's own purl-then-fallback
 *  join in security_summary/_vex_verdict_index). */
export function vexKey(v: VulnItem): string {
  return `${v.purl || `${v.pkg}@${v.installed}`}::${v.id}`;
}
