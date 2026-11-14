// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon } from "@primer/octicons-react";
import { Label, PageHeader } from "@primer/react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { formatDateTime, formatNumber } from "@/lib/format";

export type ResultStatus = "ok" | "failed" | "partial";

/**
 * The top of every result section: the title, then one line saying what was
 * scanned (project and version, scan type, when). The status label is shown
 * only when the scan did not simply complete, so a normal result carries no
 * "complete" label on every screen.
 *
 * The title is the page's h1 (`.bl-result-title`); NextApp moves focus to it
 * when the section changes, so a keyboard or screen-reader user lands on the
 * new content.
 */
export function ResultHeader({
  name,
  version,
  kind,
  generatedAt,
  status,
  title,
  projectTitle = false,
  components,
  extra,
  actions,
}: {
  name?: string;
  version?: string;
  /** Already translated scan type ("Source", "Firmware", ...). */
  kind: string;
  /** Unix seconds; absent until the scan list has the scan. */
  generatedAt?: number;
  status: ResultStatus;
  title: string;
  /** Use the project and version as the title (the Overview), so the meta
   *  line under it does not repeat them. */
  projectTitle?: boolean;
  /** Number of components in the SBOM; absent when the scan made none. */
  components?: number;
  /** More lines under the meta line (the Overview's input source and how it was read). */
  extra?: ReactNode;
  /** Buttons at the end of the title row. */
  actions?: ReactNode;
}) {
  const { t, i18n } = useTranslation();
  const when = generatedAt ? formatDateTime(generatedAt, i18n.language) : "";
  const asProject = projectTitle && Boolean(name);
  return (
    <PageHeader>
      <PageHeader.TitleArea>
        <PageHeader.Title as="h1" className="bl-result-title">
          {asProject ? (
            <span style={{ overflowWrap: "anywhere" }}>
              {name}
              {version && (
                <span style={{ fontWeight: 400, color: "var(--fgColor-muted)" }}> {version}</span>
              )}
            </span>
          ) : (
            title
          )}
        </PageHeader.Title>
      </PageHeader.TitleArea>
      <PageHeader.Description>
        <div style={{ display: "flex", flexDirection: "column" }}>
        <span
          data-testid="result-meta"
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            columnGap: "var(--base-size-8)",
            rowGap: "var(--base-size-4)",
            fontSize: "var(--text-body-size-small)",
            color: "var(--fgColor-muted)",
          }}
        >
          {!asProject && name && (
            <span
              title={version ? `${name} ${version}` : name}
              style={{
                maxWidth: "28rem",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                fontWeight: 600,
                color: "var(--fgColor-default)",
              }}
            >
              {name}
              {version && <span style={{ fontWeight: 400 }}> {version}</span>}
            </span>
          )}
          {!asProject && name && <Dot />}
          <span data-testid="result-kind" title={t("result.metaScanType")}>
            {kind}
          </span>
          {when && (
            <>
              <Dot />
              <time
                dateTime={new Date((generatedAt ?? 0) * 1000).toISOString()}
                title={t("result.metaGenerated")}
                style={{ fontVariantNumeric: "tabular-nums" }}
              >
                {when}
              </time>
            </>
          )}
          {components !== undefined && (
            <>
              <Dot />
              <span data-testid="result-components" style={{ fontVariantNumeric: "tabular-nums" }}>
                {t("nav.components")} {formatNumber(components, i18n.language)}
              </span>
            </>
          )}
          {status !== "ok" && (
            <Label variant={status === "failed" ? "danger" : "attention"} role="status">
              <AlertIcon size={12} />
              <span style={{ marginLeft: "var(--base-size-4)" }}>
                {t(status === "failed" ? "result.failed" : "result.partial")}
              </span>
            </Label>
          )}
        </span>
        {extra}
        </div>
      </PageHeader.Description>
      {actions && <PageHeader.Actions>{actions}</PageHeader.Actions>}
    </PageHeader>
  );
}

function Dot() {
  return <span aria-hidden>·</span>;
}
