// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { ErrorState, LoadingState } from "@/components/ui/state";
import { loadScanCode, parseScanCode, type FileNode } from "@/lib/scancode";
import {
  indexLinks,
  indexSnapshot,
  loadSourceSnapshot,
  type SourceSnapshot,
} from "@/lib/sourceSnapshot";

import { SourceFileContent } from "./SourceFileContent";
import { SourceFileTree } from "./SourceFileTree";

/**
 * What the scan actually looked at: the file tree on the left, the selected
 * file's text on the right.
 *
 * Two artifacts back it, both fetched lazily when the section opens. The tree
 * comes from ScanCode output (`_scancode.json`, with per-file licenses) or the
 * structure-only `_files.json` — both share the ScanCode `files[]` shape, so
 * parseScanCode reads either, and `hasLicenses` tells the view which one it got.
 * The content comes from `_source.json`, captured during the run because the
 * scanned tree does not outlive it.
 *
 * The tree is the part that must render: a scan from before the snapshot
 * existed, or one whose files were all binary, still shows its structure while
 * the content pane explains what is missing.
 */
export function SourceTreePanel({
  scanId,
  sourceFile,
  snapshotFile,
  hasLicenses,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  sourceFile: string;
  /** The `_source.json` artifact, absent when the scan captured no content. */
  snapshotFile?: string;
  hasLicenses: boolean;
}) {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<FileNode[] | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [snapshot, setSnapshot] = useState<SourceSnapshot | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    setSelected(null);
    void loadScanCode(scanId, sourceFile)
      .then((report) => {
        if (!active) return;
        setNodes(parseScanCode(report));
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });
    return () => {
      active = false;
    };
  }, [scanId, sourceFile, reloadKey]);

  useEffect(() => {
    let active = true;
    setSnapshot(null);
    if (!snapshotFile) return;
    // A missing or broken snapshot is not a section failure — the content pane
    // says so, and the tree stays usable.
    void loadSourceSnapshot(scanId, snapshotFile)
      .then((s) => {
        if (active) setSnapshot(s);
      })
      .catch(() => {
        /* content pane falls back to its "no preview" message */
      });
    return () => {
      active = false;
    };
  }, [scanId, snapshotFile, reloadKey]);

  const byPath = useMemo(() => indexSnapshot(snapshot), [snapshot]);
  const linkTargets = useMemo(() => indexLinks(snapshot), [snapshot]);

  if (state === "loading") {
    return <LoadingState>{t("sourceTree.loading")}</LoadingState>;
  }
  if (state === "error" || !nodes) {
    return (
      <ErrorState
        onRetry={() => setReloadKey((k) => k + 1)}
        retryLabel={t("retry")}
      >
        {t("sourceTree.loadError")}
      </ErrorState>
    );
  }

  const totals = snapshot?.totals;
  const omitted = totals
    ? totals.skippedBinary + totals.skippedBudget + totals.skippedUnreadable
    : 0;

  return (
    <div className="space-y-2">
      {!hasLicenses && (
        <p className="text-xs text-muted-foreground">{t("sourceTree.noLicenseHint")}</p>
      )}
      {totals && (
        <p className="text-xs text-muted-foreground">
          {t("sourceViewer.summary", { count: totals.files })}
          {totals.links > 0 && ` ${t("sourceViewer.linksSummary", { count: totals.links })}`}
          {omitted > 0 && ` ${t("sourceViewer.summaryOmitted", { count: omitted })}`}
        </p>
      )}
      <div className="grid gap-3 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
        <SourceFileTree
          nodes={nodes}
          selected={selected}
          onSelect={setSelected}
        />
        <div className="max-h-[44rem] min-h-[16rem] overflow-hidden rounded-md border">
          <SourceFileContent
            snapshot={snapshot}
            file={selected ? (byPath.get(selected) ?? null) : null}
            linkTarget={selected ? (linkTargets.get(selected) ?? null) : null}
            path={selected}
          />
        </div>
      </div>
    </div>
  );
}
