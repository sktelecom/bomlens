// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { TriangleAlert } from "lucide-react";
import type { Ref } from "react";
import { useTranslation } from "react-i18next";

import { formatDateTime } from "@/lib/format";

export type ResultStatus = "ok" | "failed" | "partial";

/**
 * The top of every result section: one line saying what was scanned (project,
 * version, scan type, when), then the section's own title. The status badge is
 * shown only when the scan did not simply complete, so a normal result carries
 * no "complete" label on every screen.
 *
 * The title is the h1 and the focus target when the section changes, so a
 * keyboard or screen-reader user lands on the new content.
 */
export function ResultHeader({
  name,
  version,
  kind,
  generatedAt,
  status,
  title,
  headingRef,
}: {
  name?: string;
  version?: string;
  /** Already translated scan type ("Source", "Firmware", ...). */
  kind: string;
  /** Unix seconds; absent until the scan list has the scan. */
  generatedAt?: number;
  status: ResultStatus;
  title: string;
  headingRef?: Ref<HTMLHeadingElement>;
}) {
  const { t, i18n } = useTranslation();
  const when = generatedAt ? formatDateTime(generatedAt, i18n.language) : "";
  return (
    <div>
      <div
        className="flex flex-wrap items-center gap-x-2 gap-y-1 text-body-sm text-muted-foreground"
        data-testid="result-meta"
      >
        {name && (
          <span className="max-w-[28rem] truncate font-medium text-foreground" title={name}>
            {name}
          </span>
        )}
        {version && <span className="font-mono text-label">{version}</span>}
        {name && <Dot />}
        <span data-testid="result-kind" title={t("result.metaScanType")}>
          {kind}
        </span>
        {when && (
          <>
            <Dot />
            <time
              dateTime={new Date((generatedAt ?? 0) * 1000).toISOString()}
              className="tabular-nums"
              title={t("result.metaGenerated")}
            >
              {when}
            </time>
          </>
        )}
        {status !== "ok" && <StatusBadge status={status} />}
      </div>
      <h1
        ref={headingRef}
        tabIndex={-1}
        className="mt-2 text-title font-semibold tracking-tight text-foreground focus:outline-none"
      >
        {title}
      </h1>
    </div>
  );
}

function Dot() {
  return (
    <span aria-hidden className="text-muted-foreground/60">
      ·
    </span>
  );
}

function StatusBadge({ status }: { status: Exclude<ResultStatus, "ok"> }) {
  const { t } = useTranslation();
  // text-risk-critical-fg (not text-destructive): --destructive is the same value
  // in both themes, so it fails WCAG AA on its own tinted background in light
  // mode. The -fg cut is the AA-passing one. The icon means the state reads
  // without relying on colour alone.
  const tone =
    status === "failed"
      ? "bg-destructive/10 text-risk-critical-fg"
      : "border border-warning-border/60 bg-warning-surface text-warning";
  return (
    <span
      role="status"
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-label font-medium ${tone}`}
    >
      <TriangleAlert className="h-3 w-3" aria-hidden />
      {t(status === "failed" ? "result.failed" : "result.partial")}
    </span>
  );
}
