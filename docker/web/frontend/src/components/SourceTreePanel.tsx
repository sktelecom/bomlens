import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

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
  }, [scancodeFile]);

  if (state === "loading") {
    return (
      <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        {t("sourceTree.loading")}
      </div>
    );
  }
  if (state === "error" || !nodes) {
    return (
      <p className="py-8 text-sm text-muted-foreground">{t("sourceTree.loadError")}</p>
    );
  }

  return <SourceFileTree nodes={nodes} />;
}
