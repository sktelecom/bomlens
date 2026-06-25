import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ErrorState, LoadingState } from "@/components/ui/state";
import { loadScanCode, parseScanCode, type FileNode } from "@/lib/scancode";

import { SourceFileTree } from "./SourceFileTree";

/**
 * Fetches the source-tree artifact (lazily, when its tab opens) and renders the
 * file tree. The artifact is either the ScanCode output (`_scancode.json`, with
 * per-file licenses) or the structure-only `_files.json` fallback — both share
 * the ScanCode `files[]` shape, so parseScanCode reads either. `hasLicenses`
 * tells the view whether license data is present (false for `_files.json`).
 */
export function SourceTreePanel({
  sourceFile,
  hasLicenses,
}: {
  sourceFile: string;
  hasLicenses: boolean;
}) {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<FileNode[] | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadScanCode(sourceFile)
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
  }, [sourceFile, reloadKey]);

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

  return (
    <div className="space-y-2">
      {!hasLicenses && (
        <p className="text-xs text-muted-foreground">{t("sourceTree.noLicenseHint")}</p>
      )}
      <SourceFileTree nodes={nodes} />
    </div>
  );
}
