// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon, LinkExternalIcon } from "@primer/octicons-react";
import { Button, Dialog, FormControl, Label, Link, Select, Textarea } from "@primer/react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { DialogHeader } from "@/components/ShortcutsDialog";
import { SeverityLabel } from "@/components/primer";
import { vulnAliases } from "@/lib/advisories";
import { ApiError, saveVexVerdict, VEX_STATES, type VexReceived, type VexState, type VulnItem } from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { useToast } from "@/lib/toast";

import { FixedVersions, StatusLabels, VEX_VARIANT } from "./cells";
import { vulnLinks, type VexFields } from "./vexFields";
import { VEX_LABEL_KEY } from "./vulnStatus";

/** References shown before the rest fold behind "N more". */
const REF_SHOWN = 3;

/** Human-readable date; falls back to the raw string if it does not parse. */
function formatDate(iso: string, locale: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(locale, { dateStyle: "medium" });
}

/**
 * The detail of one vulnerability in a side panel: package, the supplier's
 * judgement (editable), links into Components and Dependencies, a received VEX
 * statement, CVSS, dates, the fixed versions, the description and references.
 * The panel is the one open detail; its id is in the URL (`open=`).
 */
export function VulnPanel({
  vuln: v,
  scanId,
  vex,
  received,
  onVexSaved,
  onClose,
  onPickComponent,
  onPickDependency,
}: {
  vuln: VulnItem;
  scanId?: string | null;
  vex: VexFields;
  received?: VexReceived;
  onVexSaved: (saved: VexFields) => void;
  onClose: () => void;
  onPickComponent?: (name: string) => void;
  onPickDependency?: (name: string, version?: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const bodyRef = useRef<HTMLDivElement>(null);
  const links = vulnLinks(v);
  const aliases = vulnAliases(v);
  const title = v.title || v.id;
  const noDetail = v.cvss == null && !v.description && links.length === 0 && !v.publishedDate;
  const refItem = (href: string) => (
    <li key={href}>
      <Link href={href} target="_blank" rel="noreferrer">
        <LinkExternalIcon size={12} />
        <span className="bl-breakall">{href}</span>
      </Link>
    </li>
  );
  return (
    <Dialog
      position="right"
      width="xlarge"
      title={title}
      onClose={onClose}
      initialFocusRef={bodyRef}
      renderHeader={({ dialogLabelId }) => <DialogHeader id={dialogLabelId} title={title} onClose={onClose} />}
    >
      {/* Initial focus goes to the body, not the close button, so the first Escape closes the panel. */}
      <div ref={bodyRef} tabIndex={-1} className="bl-vp" data-testid="vuln-detail">
        <div className="bl-vp-ids">
          <SeverityLabel severity={v.severity} quiet />
          <StatusLabels vuln={v} vex={vex} received={received} everyStatus />
          <span className="bl-mono bl-muted bl-breakall">{v.id}</span>
        </div>
        <dl className="bl-vp-kv">
          <dt>{t("result.vulnPackageUrl")}</dt>
          <dd className="bl-mono bl-breakall">{v.purl || `${v.pkg}@${v.installed}`}</dd>
          {aliases.length > 0 && (
            <>
              <dt>{t("result.vulnAliases")}</dt>
              <dd className="bl-mono bl-breakall">{aliases.join(", ")}</dd>
            </>
          )}
        </dl>
        {(onPickComponent || onPickDependency) && v.pkg && (
          <div className="bl-vp-links">
            {onPickComponent && (
              <Link as="button" type="button" onClick={() => onPickComponent(v.pkg)}>
                {t("result.viewInComponents", { name: v.pkg })}
              </Link>
            )}
            {onPickDependency && (
              <Link as="button" type="button" onClick={() => onPickDependency(v.pkg, v.installed)}>
                {t("result.viewInDependencies", { name: v.pkg })}
              </Link>
            )}
          </div>
        )}
        <section className="bl-vp-facts">
          {noDetail && <p className="bl-muted bl-flat">{t("result.vulnNoDetail")}</p>}
          <dl className="bl-vp-kv">
            {v.cvss != null && (
              <>
                <dt>{t("result.vulnCvss")}</dt>
                <dd>
                  <span className="bl-num bl-strong">{v.cvss}</span>{" "}
                  {v.cvssVector && <span className="bl-mono bl-muted bl-breakall">{v.cvssVector}</span>}
                </dd>
              </>
            )}
            {v.nvdSeverity && (
              <>
                <dt>{t("result.colNvdSeverity")}</dt>
                <dd>
                  <SeverityLabel severity={v.nvdSeverity} quiet />
                </dd>
              </>
            )}
            {v.publishedDate && (
              <>
                <dt>{t("result.vulnPublished")}</dt>
                <dd>{formatDate(v.publishedDate, i18n.language)}</dd>
              </>
            )}
            <dt>{t("result.colInstalled")}</dt>
            <dd className="bl-mono">{v.installed || "-"}</dd>
            <dt>{t("result.colFixed")}</dt>
            <dd>
              <FixedVersions vuln={v} />
            </dd>
          </dl>
        </section>
        {v.description && (
          <section>
            <h3 className="bl-vp-h">{t("result.vulnDescription")}</h3>
            <p className="bl-muted bl-vp-desc">{v.description.replace(/\n{3,}/g, "\n\n").trim()}</p>
          </section>
        )}
        {links.length > 0 && (
          <section>
            <h3 className="bl-vp-h">{t("result.vulnReferences")}</h3>
            <ul className="bl-vp-refs">{links.slice(0, REF_SHOWN).map(refItem)}</ul>
            {links.length > REF_SHOWN && (
              <details className="bl-vp-more">
                <summary>
                  <span className="bl-chev">
                    <ChevronRightIcon size={16} />
                  </span>
                  {t("result.vulnRefsMore", { count: links.length - REF_SHOWN })}
                </summary>
                <ul className="bl-vp-refs">{links.slice(REF_SHOWN).map(refItem)}</ul>
              </details>
            )}
          </section>
        )}
        {received && (
          <section data-testid="vex-received">
            <h3 className="bl-vp-h">{t("result.vexReceivedTitle")}</h3>
            <p className="bl-muted bl-small bl-vp-p">
              {received.source ? t("result.vexReceivedFrom", { product: received.source }) : t("result.vexReceivedHint")}
            </p>
            <Label variant={VEX_VARIANT[received.state]}>{t(VEX_LABEL_KEY[received.state])}</Label>
            {received.justification && (
              <p className="bl-muted bl-vp-p">{t("result.vexReceivedJustification", { value: received.justification })}</p>
            )}
            {received.detail && <p className="bl-muted bl-vp-p">{received.detail}</p>}
          </section>
        )}
        <VexJudgement scanId={scanId} vuln={v} vex={vex} onSaved={onVexSaved} />
      </div>
    </Dialog>
  );
}

/** Judgement input for one CVE against one component: state, an optional note
 *  and Save. In the static demo it only shows a judgement that already exists. */
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
  const [state, setState] = useState<VexState | "">(vex.state ?? "");
  const [detail, setDetail] = useState(vex.detail ?? "");
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    setState(vex.state ?? "");
    setDetail(vex.detail ?? "");
  }, [vuln.id, vuln.purl, vuln.pkg, vex.state, vex.detail]);

  if (IS_STATIC_DEMO) {
    if (!vex.state) return null;
    return (
      <section>
        <h3 className="bl-vp-h">{t("result.vexSectionTitle")}</h3>
        <Label variant={VEX_VARIANT[vex.state]}>{t(VEX_LABEL_KEY[vex.state])}</Label>
        {vex.detail && <p className="bl-muted bl-vp-p">{vex.detail}</p>}
      </section>
    );
  }
  if (!scanId) return null;

  const save = async () => {
    if (!state) return;
    setSaving(true);
    try {
      const verdict = await saveVexVerdict(scanId, {
        cve: vuln.id,
        state,
        detail: detail || undefined,
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
    <section>
      <h3 className="bl-vp-h">{t("result.vexSectionTitle")}</h3>
      <p className="bl-muted bl-small bl-vp-p">{t("result.vexSectionHint")}</p>
      <div className="bl-vp-vexrow">
        <FormControl>
          <FormControl.Label>{t("result.vexStateLabel")}</FormControl.Label>
          <Select value={state} onChange={(e) => setState(e.target.value as VexState | "")}>
            <Select.Option value="">{t("result.vexStatePlaceholder")}</Select.Option>
            {VEX_STATES.map((s) => (
              <Select.Option key={s} value={s}>
                {t(VEX_LABEL_KEY[s])}
              </Select.Option>
            ))}
          </Select>
        </FormControl>
        <Button disabled={!state || saving} onClick={() => void save()}>
          {saving ? t("result.vexSaving") : t("result.vexSaveButton")}
        </Button>
      </div>
      <FormControl className="bl-vp-note">
        <FormControl.Label>{t("result.vexDetailLabel")}</FormControl.Label>
        <Textarea
          value={detail}
          onChange={(e) => setDetail(e.target.value)}
          placeholder={t("result.vexDetailPlaceholder")}
          rows={2}
          maxLength={2000}
          block
        />
      </FormControl>
      {vex.updatedAt && (
        <p className="bl-muted bl-small bl-vp-p">{t("result.vexUpdatedAt", { date: formatDate(vex.updatedAt, i18n.language) })}</p>
      )}
    </section>
  );
}
