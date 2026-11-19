// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Table } from "@primer/react/experimental";
import { memo, type MouseEvent } from "react";
import { useTranslation } from "react-i18next";

import { PackageCoordinate, SeverityLabel, splitPackage } from "@/components/primer";
import { vulnAliases } from "@/lib/advisories";
import type { VulnItem } from "@/lib/api";
import { receivedFor, type ReceivedIndex } from "@/lib/vexReceived";

import { FixedVersions, IntroducedBy, StatusLabels } from "./cells";
import type { VexFields } from "./vexFields";

interface Props {
  vuln: VulnItem;
  /** The id the URL carries when this row's panel is open. */
  openId: string;
  isOpen: boolean;
  onToggle: (id: string) => void;
  showEpss: boolean;
  showNvd: boolean;
  /** The "Introduced by" column is on. */
  showIntroduced: boolean;
  /** Inside a package block the package is in the block's head, not in the row. */
  inGroup: boolean;
  /** A verdict saved this session, overriding what the scan payload carried. */
  override?: VexFields;
  /** The VEX document imported this session; wins over the scan payload. */
  imported: ReceivedIndex | null;
}

/**
 * One vulnerability. The first line is the title (the control that opens the
 * detail panel) and its labels; the second is the package and installed
 * version, the CVE id and the other ids it is filed under. The second line is
 * one line high: an id that does not fit is not drawn at all (all of them stay
 * in the tooltip and the panel), so a row never ends in half an id.
 */
export const VulnRow = memo(function VulnRow({ vuln: v, openId, isOpen, onToggle, showEpss, showNvd, showIntroduced, inGroup, override, imported }: Props) {
  const { t } = useTranslation();
  const vex: VexFields = override ?? { state: v.vexState, detail: v.vexDetail, updatedAt: v.vexUpdatedAt };
  const received = imported ? receivedFor(imported, v) : v.vexReceived;
  const aliases = vulnAliases(v);
  const toggle = () => onToggle(openId);
  const title = v.title || v.id;
  return (
    <Table.Row data-open={isOpen ? "true" : undefined} onClick={toggle} className="bl-v-row">
      <Table.Cell>
        <SeverityLabel severity={v.severity} quiet />
      </Table.Cell>
      <Table.Cell align="end">
        <span className="bl-num">{v.cvss ?? <span className="bl-muted">-</span>}</span>
      </Table.Cell>
      {showEpss && (
        <Table.Cell align="end">
          <span className="bl-num bl-muted">{typeof v.epss === "number" ? `${(v.epss * 100).toFixed(1)}%` : "-"}</span>
        </Table.Cell>
      )}
      {showNvd && (
        <Table.Cell>{v.nvdSeverity ? <SeverityLabel severity={v.nvdSeverity} quiet /> : <span className="bl-muted">-</span>}</Table.Cell>
      )}
      <Table.Cell scope="row">
        <div className="bl-v-cell">
          <div className="bl-v-line1">
            <button
              type="button"
              className="bl-v-title"
              data-open-id={openId}
              aria-expanded={isOpen}
              aria-haspopup="dialog"
              title={title}
              onClick={(e: MouseEvent) => {
                e.preventDefault();
                e.stopPropagation();
                toggle();
              }}
            >
              {title}
            </button>
            <span className="bl-v-labels">
              <StatusLabels vuln={v} vex={vex} received={received} />
            </span>
          </div>
          <div className="bl-v-line2 bl-muted" title={[v.id, ...aliases].join(", ")}>
            {!inGroup && (
              <span className="bl-v-pkg">
                <PackageCoordinate {...splitPackage(v.pkg)} title={v.purl || v.pkg} shrink className="bl-mono" />
                <span className="bl-mono">{v.installed}</span>
                {v.buildTool && (
                  <span className="bl-v-buildtool" title={t("result.buildToolHint")} data-testid="vuln-build-tool">
                    {t("result.buildToolTag")}
                  </span>
                )}
              </span>
            )}
            {/* With no title the id is already the first line. */}
            {v.title && <span className="bl-v-id bl-mono">{v.id}</span>}
            {aliases.length > 0 && (
              <span className="bl-v-aliases">
                {aliases.map((a) => (
                  <span key={a} className="bl-v-alias bl-mono">
                    {a}
                  </span>
                ))}
              </span>
            )}
          </div>
        </div>
      </Table.Cell>
      <Table.Cell>
        <FixedVersions vuln={v} />
      </Table.Cell>
      {showIntroduced && (
        <Table.Cell>
          <IntroducedBy vuln={v} />
        </Table.Cell>
      )}
    </Table.Row>
  );
});
