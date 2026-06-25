import {
  Box,
  Brain,
  Cpu,
  FileArchive,
  FileJson,
  Folder,
  FolderTree,
  Github,
  type LucideIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Capabilities, ScanParams, SourceType } from "@/lib/api";
import { useScanForm } from "@/lib/useScanForm";
import { cn } from "@/lib/utils";

import {
  FormMessages,
  GenerationOptions,
  RunButton,
  ScanOptions,
  SourceControls,
} from "./ScanFormFields";

interface Props {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
}

const SOURCE_META: Record<SourceType, { labelKey: string; icon: LucideIcon }> = {
  "current-dir": { labelKey: "source.currentDir", icon: Folder },
  "rootfs-dir": { labelKey: "source.rootfsDir", icon: FolderTree },
  "git-url": { labelKey: "source.gitUrl", icon: Github },
  "zip-upload": { labelKey: "source.zipUpload", icon: FileArchive },
  "docker-image": { labelKey: "source.dockerImage", icon: Box },
  "firmware-upload": { labelKey: "source.firmwareUpload", icon: Cpu },
  "sbom-upload": { labelKey: "source.sbomUpload", icon: FileJson },
  "ai-model": { labelKey: "source.aiModel", icon: Brain },
};

// Grouped tiles: scan source code, scan a built artifact, analyze an SBOM, or
// generate an SBOM for an AI model.
const SOURCE_GROUPS: Array<{ key: string; sources: SourceType[] }> = [
  { key: "catCode", sources: ["current-dir", "rootfs-dir", "git-url", "zip-upload"] },
  { key: "catArtifact", sources: ["docker-image", "firmware-upload"] },
  { key: "catSbom", sources: ["sbom-upload"] },
  { key: "catAiModel", sources: ["ai-model"] },
];

/**
 * Two-pane New scan (shell): a grouped source-tile picker and its source-
 * specific input on the left, scan settings + outputs + the generate action on
 * the right. Shares all logic with the classic ScanForm via useScanForm.
 */
export function NewScan({ running, capabilities, onRun }: Props) {
  const { t } = useTranslation();
  const state = useScanForm({ running, capabilities, onRun });

  return (
    <div className="space-y-4">
      {/* Source picker spans the full width so the tiles sit on one balanced
          row block, and the selected source's input lands directly below. */}
      <Card className="animate-fade-in">
        <CardContent className="space-y-4 p-4">
          <Label>{t("newscan.source")}</Label>
          <div
            role="group"
            aria-label={t("newscan.source")}
            className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4"
          >
            {SOURCE_GROUPS.flatMap((group) => group.sources).map((s) => {
                    const { labelKey, icon: Icon } = SOURCE_META[s];
                    const active = state.source === s;
                    const fwLocked = s === "firmware-upload" && !capabilities.firmware;
                    const aiLocked = s === "ai-model" && !capabilities.aibom;
                    const locked = fwLocked || aiLocked;
                    return (
                      <button
                        key={s}
                        type="button"
                        aria-pressed={active}
                        disabled={state.busy || locked}
                        title={
                          fwLocked
                            ? t("source.firmwareUnavailable")
                            : aiLocked
                              ? t("source.aiModelUnavailable")
                              : undefined
                        }
                        onClick={() => state.changeSource(s)}
                        className={cn(
                          "flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-sm",
                          "transition-colors duration-fast ease-out-soft",
                          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                          "disabled:pointer-events-none disabled:opacity-50",
                          active
                            ? "border-brand/40 bg-brand/10 font-medium text-foreground"
                            : "text-foreground hover:border-brand/40 hover:bg-muted/50",
                        )}
                      >
                        <Icon
                          className={cn(
                            "h-4 w-4 shrink-0",
                            active ? "text-brand" : "text-muted-foreground",
                          )}
                          aria-hidden
                        />
                        <span className="truncate">{t(labelKey)}</span>
                      </button>
                    );
            })}
          </div>

          <SourceControls state={state} />
        </CardContent>
      </Card>

      {/* Settings below the source, as one top-to-bottom card: identity first,
          then all options side by side, then the run action — so "what to turn
          on" reads in one place instead of split left/right. */}
      <Card className="animate-fade-in">
        <CardContent className="space-y-6 p-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="project">{t("form.project")}</Label>
              <Input
                id="project"
                value={state.project}
                onChange={(e) => state.setProject(e.target.value)}
                placeholder={t("form.projectPlaceholder")}
                disabled={state.busy}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="version">{t("form.version")}</Label>
              <Input
                id="version"
                value={state.version}
                onChange={(e) => state.setVersion(e.target.value)}
                placeholder={t("form.versionPlaceholder")}
                disabled={state.busy}
              />
            </div>
          </div>

          <div
            className={cn(
              "grid gap-x-8 gap-y-5 border-t pt-5",
              state.showScanOptions && "sm:grid-cols-2",
            )}
          >
            <div className="space-y-3">
              <Label>{t("newscan.outputs")}</Label>
              <GenerationOptions state={state} />
            </div>
            {state.showScanOptions && (
              <div className="space-y-3">
                <Label>{t("newscan.scanOptions")}</Label>
                <ScanOptions state={state} />
              </div>
            )}
          </div>

          <div className="space-y-3 border-t pt-5">
            <FormMessages state={state} />
            <RunButton state={state} running={running} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
