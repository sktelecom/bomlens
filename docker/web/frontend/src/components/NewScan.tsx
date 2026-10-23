// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  Box,
  Brain,
  Cpu,
  FileArchive,
  FileBox,
  FileJson,
  Folder,
  FolderTree,
  Github,
  Lock,
  type LucideIcon,
  Package,
  PencilLine,
} from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import { FOCUS_RING, SELECTED_TILE } from "@/components/ui/selectable";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Capabilities, ScanConfig, ScanParams, SourceType } from "@/lib/api";
import { useScanForm } from "@/lib/useScanForm";
import { Disclosure } from "@/components/ui/disclosure";
import { cn } from "@/lib/utils";

import {
  FieldError,
  FormMessages,
  FormatOptions,
  GenerationOptions,
  RequiredMark,
  RunButton,
  ScanOptions,
  SourceControls,
  UploadOptions,
} from "./ScanFormFields";

interface Props {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
  /** Seed the form from a finished scan's config (the "Re-scan" flow). Consumed
   *  once on mount; see `onConfigConsumed`. */
  initialConfig?: ScanConfig | null;
  /** Called once after `initialConfig` is read so the parent can clear the
   *  pending config — a later plain New scan then starts blank. */
  onConfigConsumed?: () => void;
  /** Field to open and focus on arrival, for a prompt that sends the reader
   *  here to fill one in (the Licenses section's outbound-license notice). */
  focusField?: "license" | null;
}

const SOURCE_META: Record<SourceType, { labelKey: string; icon: LucideIcon }> = {
  "current-dir": { labelKey: "source.currentDir", icon: Folder },
  "rootfs-dir": { labelKey: "source.rootfsDir", icon: FolderTree },
  // Not shown as a tile (absent from SOURCE_GROUPS) — a submit-time variant of
  // rootfs-dir. Present only to satisfy the exhaustive SourceType record.
  "scan-target-src": { labelKey: "source.rootfsDir", icon: FolderTree },
  // Also not a tile: a folder the scanner recognized as a Yocto build directory.
  "yocto-build-dir": { labelKey: "source.yoctoBuildDir", icon: FolderTree },
  "git-url": { labelKey: "source.gitUrl", icon: Github },
  "zip-upload": { labelKey: "source.zipUpload", icon: FileArchive },
  "package-upload": { labelKey: "source.packageUpload", icon: Package },
  "docker-image": { labelKey: "source.dockerImage", icon: Box },
  "firmware-upload": { labelKey: "source.firmwareUpload", icon: Cpu },
  "sbom-upload": { labelKey: "source.sbomUpload", icon: FileJson },
  "ai-model": { labelKey: "source.aiModel", icon: Brain },
  "model-upload": { labelKey: "source.modelUpload", icon: FileBox },
  "ai-declare": { labelKey: "source.aiDeclare", icon: PencilLine },
};

// Grouped tiles: scan source code, scan a built artifact, analyze an SBOM, or
// generate an SBOM for an AI model.
const SOURCE_GROUPS: Array<{ key: string; sources: SourceType[] }> = [
  { key: "catCode", sources: ["current-dir", "rootfs-dir", "git-url", "zip-upload"] },
  { key: "catArtifact", sources: ["docker-image", "package-upload", "firmware-upload"] },
  { key: "catSbom", sources: ["sbom-upload"] },
  { key: "catAiModel", sources: ["ai-model", "model-upload", "ai-declare"] },
];

const SECTION_LABEL =
  "text-label font-semibold uppercase tracking-wider text-muted-foreground";

/** Collapsed-by-default panel section, on the shared disclosure.
 *  Keeps the settings panel within one viewport: only identity, outputs and
 *  the run action stay always-visible; advanced groups fold away. `badge`
 *  keeps the enabled state readable while the section is closed. */
function PanelDisclosure({
  label,
  badge,
  defaultOpen,
  children,
}: {
  label: string;
  badge?: string;
  defaultOpen: boolean;
  children: ReactNode;
}) {
  return (
    <Disclosure
      className="border-t pt-5"
      defaultOpen={defaultOpen}
      summary={
        <>
          <span className={SECTION_LABEL}>{label}</span>
          {badge && (
            <span className="ml-auto rounded-full bg-muted px-2 py-0.5 text-label font-medium text-foreground">
              {badge}
            </span>
          )}
        </>
      }
    >
      <div className="mt-3 space-y-3">{children}</div>
    </Disclosure>
  );
}

/**
 * Two-pane New scan: a question title, a grouped source-tile picker and the
 * selected source's input on the left, and a sticky "Scan settings" panel
 * (identity + outputs + the generate action) on the right. Shares all logic
 * with the classic form via useScanForm — only the layout changes.
 */
export function NewScan({
  running,
  capabilities,
  onRun,
  initialConfig,
  onConfigConsumed,
  focusField,
}: Props) {
  const { t } = useTranslation();
  const state = useScanForm({ running, capabilities, onRun, initialConfig });

  // The form reads `initialConfig` once (lazy state init). Tell the parent to
  // clear the pending config right after, so navigating to a plain New scan
  // later starts blank. Guarded so it fires only for the seeded mount.
  const consumedRef = useRef(false);
  useEffect(() => {
    if (initialConfig && !consumedRef.current) {
      consumedRef.current = true;
      onConfigConsumed?.();
    }
  }, [initialConfig, onConfigConsumed]);

  // How many toggles are on in each folded group (seeded by a re-scan config).
  // Drives the disclosure's initial open state and its collapsed badge.
  const scanOptionsOn = [
    state.identifyVendored,
    state.deepLicense,
    state.deepCve,
    state.reachability,
    state.byteStable,
    // On by default, so it counts only when it was turned off.
    state.showDetection && !state.readLockFile,
  ].filter(Boolean).length;
  const formatOptionsOn = [
    state.outboundLicense.trim() !== "",
    state.sbomAuthor.trim() !== "",
    state.supplier.trim() !== "",
    state.specVersion !== "1.6",
    state.conformanceProfile !== "default",
  ].filter(Boolean).length;

  // Arriving from a prompt that asks for one field: the field's group is already
  // open (see `defaultOpen` below), so only the focus is left to move.
  useEffect(() => {
    if (focusField === "license") document.getElementById("outbound-license")?.focus();
  }, [focusField]);

  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-display font-semibold tracking-tight text-foreground">
          {t("newscan.title")}
        </h1>
        <p className="text-body-sm text-muted-foreground">{t("newscan.subtitle")}</p>
      </div>

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        {/* Left: pick what to scan, then its source-specific input. */}
        <div className="space-y-4">
          <div role="group" aria-label={t("newscan.source")} className="space-y-6">
            {SOURCE_GROUPS.map((group) => {
              // Lock reason for this group (firmware/AI need the Docker sibling
              // image). Shown as visible text so keyboard/touch users — who can't
              // see a hover title — still learn why a tile is unavailable.
              const lockReason =
                group.sources.includes("firmware-upload") && !capabilities.firmware
                  ? t("source.firmwareUnavailable")
                  : group.sources.includes("ai-model") && !capabilities.aibom
                    ? t("source.aiModelUnavailable")
                    : null;
              return (
                <div key={group.key} className="space-y-2">
                  <p className={SECTION_LABEL}>{t(`newscan.${group.key}`)}</p>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-4">
                    {group.sources.map((s) => {
                      const { labelKey, icon: Icon } = SOURCE_META[s];
                      const active = state.source === s;
                      const locked =
                        (s === "firmware-upload" && !capabilities.firmware) ||
                        (s === "ai-model" && !capabilities.aibom) ||
                        (s === "ai-declare" && !capabilities.aiDeclare);
                      return (
                        <button
                          key={s}
                          type="button"
                          // The source id, not its label: a test that drives
                          // this picker in both languages needs an anchor that
                          // does not translate.
                          data-testid={`source-${s}`}
                          aria-pressed={active}
                          aria-disabled={locked || undefined}
                          disabled={state.busy}
                          onClick={() => {
                            if (!locked) state.changeSource(s);
                          }}
                          className={cn(
                            "flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-body-sm",
                            "transition-[color,border-color,background-color,box-shadow] duration-fast ease-out-soft",
                            FOCUS_RING,
                            "disabled:pointer-events-none disabled:opacity-50",
                            locked
                              ? "cursor-not-allowed border-dashed text-muted-foreground"
                              : active
                                ? SELECTED_TILE
                                : "text-foreground hover:border-foreground/30 hover:bg-muted/50 hover:shadow-md",
                          )}
                        >
                          <Icon
                            className={cn(
                              "h-4 w-4 shrink-0",
                              locked
                                ? "text-muted-foreground/60"
                                : active
                                  ? "text-foreground"
                                  : "text-muted-foreground",
                            )}
                            aria-hidden
                          />
                          <span className="truncate">{t(labelKey)}</span>
                          {locked && (
                            <Lock
                              className="ml-auto h-3.5 w-3.5 shrink-0 text-muted-foreground/60"
                              aria-hidden
                            />
                          )}
                        </button>
                      );
                    })}
                  </div>
                  {lockReason && (
                    <p className="text-body-sm text-muted-foreground">{lockReason}</p>
                  )}
                </div>
              );
            })}
          </div>

          <Card className="animate-fade-in">
            <CardContent className="space-y-4 p-4">
              <SourceControls state={state} />
            </CardContent>
          </Card>
        </div>

        {/* Right: sticky settings panel — identity, outputs, then the folded
            groups scroll inside it while the run action stays pinned below, so
            opening every group never pushes the button off screen. */}
        <Card className="flex animate-fade-in flex-col lg:sticky lg:top-6 lg:max-h-[calc(100vh-3rem)]">
          <CardContent className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5">
            <div className="space-y-3">
              <p className={SECTION_LABEL}>{t("newscan.settings")}</p>
              <div className="space-y-2">
                <Label htmlFor="project">
                  {t("form.project")}
                  <RequiredMark />
                </Label>
                <Input
                  id="project"
                  value={state.project}
                  onChange={(e) => state.setProject(e.target.value)}
                  placeholder={t("form.projectPlaceholder")}
                  disabled={state.busy}
                  autoFocus
                  aria-required
                  aria-invalid={state.errors.project ? true : undefined}
                  aria-describedby={
                    [state.errors.project && "project-error", state.source === "ai-declare" && "project-hint"]
                      .filter(Boolean)
                      .join(" ") || undefined
                  }
                />
                {/* A declared model has no hub name: the project becomes its name. */}
                {state.source === "ai-declare" && (
                  <p id="project-hint" className="text-body-sm text-muted-foreground">
                    {t("form.projectHintDeclare")}
                  </p>
                )}
                <FieldError id="project-error" msgKey={state.errors.project} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="version">
                  {t("form.version")}
                  <RequiredMark />
                </Label>
                <Input
                  id="version"
                  value={state.version}
                  onChange={(e) => state.setVersion(e.target.value)}
                  placeholder={t("form.versionPlaceholder")}
                  disabled={state.busy}
                  aria-required
                  aria-invalid={state.errors.version ? true : undefined}
                  aria-describedby={state.errors.version ? "version-error" : undefined}
                />
                <FieldError id="version-error" msgKey={state.errors.version} />
              </div>
            </div>

            <div className="space-y-3 border-t pt-5">
              <p className={SECTION_LABEL}>{t("newscan.outputs")}</p>
              <GenerationOptions state={state} />
            </div>

            {/* The result-quality group is how the scan analyzes the source, a
                different altitude from the output artifacts above — their own
                sections, folded by default so the panel fits one viewport.
                A section seeded with non-default values (re-scan) opens
                itself, and the badge keeps the state readable when closed. */}
            {state.showScanOptions && (
              <PanelDisclosure
                label={t("newscan.scanOptions")}
                badge={
                  scanOptionsOn > 0
                    ? t("newscan.enabledCount", { n: scanOptionsOn })
                    : undefined
                }
                defaultOpen={scanOptionsOn > 0}
              >
                <ScanOptions state={state} />
              </PanelDisclosure>
            )}

            {state.showFormatOptions && (
              <PanelDisclosure
                label={t("newscan.formatOptions")}
                badge={
                  formatOptionsOn > 0
                    ? t("newscan.enabledCount", { n: formatOptionsOn })
                    : undefined
                }
                defaultOpen={formatOptionsOn > 0 || focusField === "license"}
              >
                <FormatOptions state={state} />
              </PanelDisclosure>
            )}

            {state.showUpload && (
              <PanelDisclosure
                label={t("newscan.upload")}
                badge={state.uploadEnabled ? t("newscan.on") : undefined}
                defaultOpen={state.uploadEnabled}
              >
                <UploadOptions state={state} />
              </PanelDisclosure>
            )}
          </CardContent>

          <div className="space-y-3 border-t bg-card p-5">
            <FormMessages state={state} />
            <RunButton state={state} running={running} />
          </div>
        </Card>
      </div>
    </div>
  );
}
