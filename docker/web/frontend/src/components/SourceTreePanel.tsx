import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ErrorState, LoadingState } from "@/components/ui/state";
import { loadScanCode, parseScanCode, type FileNode } from "@/lib/scancode";

import { SourceFileTree } from "./SourceFileTree";

/**
 * Fetches the raw `_scancode.json` (lazily, when its tab opens) and renders the
 * source file tree. Only mounted when a ScanCode artifact exists.
 */
export function SourceTreePanel({ scancodeFile }: { scancodeFile: string }) {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<FileNode[] | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadScanCode(scancodeFile)
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
  }, [scancodeFile, reloadKey]);

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

  return <SourceFileTree nodes={nodes} />;
}
