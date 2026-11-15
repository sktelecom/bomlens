// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  AiModelIcon,
  ChevronRightIcon,
  ContainerIcon,
  CpuIcon,
  FileBinaryIcon,
  FileCodeIcon,
  FileDirectoryIcon,
  FileSubmoduleIcon,
  FileZipIcon,
  LockIcon,
  MarkGithubIcon,
  PackageIcon,
  PencilIcon,
  type Icon,
} from "@primer/octicons-react";
import { Banner, CounterLabel, FormControl, TextInput, VisuallyHidden } from "@primer/react";
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ScreenHeader } from "@/components/primer";
import type { Capabilities, ScanConfig, ScanParams, SourceType } from "@/lib/api";
import { useScanForm } from "@/lib/useScanForm";

import {
  ActionNotes,
  FormatOptions,
  OutputSwitches,
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
   *  pending config: a later plain New scan then starts blank. */
  onConfigConsumed?: () => void;
  /** Field to open and focus on arrival, for a prompt that sends the reader
   *  here to fill one in (the Licenses section's outbound-license notice). */
  focusField?: "license" | null;
}

const SOURCE_META: Record<SourceType, { labelKey: string; icon: Icon }> = {
  "current-dir": { labelKey: "source.currentDir", icon: FileDirectoryIcon },
  "rootfs-dir": { labelKey: "source.rootfsDir", icon: FileSubmoduleIcon },
  // Not shown as a tile (absent from SOURCE_GROUPS): a submit-time variant of
  // rootfs-dir. Present only to satisfy the exhaustive SourceType record.
  "scan-target-src": { labelKey: "source.rootfsDir", icon: FileSubmoduleIcon },
  // Also not a tile: a folder the scanner recognized as a Yocto build directory.
  "yocto-build-dir": { labelKey: "source.yoctoBuildDir", icon: FileSubmoduleIcon },
  "git-url": { labelKey: "source.gitUrl", icon: MarkGithubIcon },
  "zip-upload": { labelKey: "source.zipUpload", icon: FileZipIcon },
  "package-upload": { labelKey: "source.packageUpload", icon: PackageIcon },
  "docker-image": { labelKey: "source.dockerImage", icon: ContainerIcon },
  "firmware-upload": { labelKey: "source.firmwareUpload", icon: CpuIcon },
  "sbom-upload": { labelKey: "source.sbomUpload", icon: FileCodeIcon },
  "ai-model": { labelKey: "source.aiModel", icon: AiModelIcon },
  "model-upload": { labelKey: "source.modelUpload", icon: FileBinaryIcon },
  "ai-declare": { labelKey: "source.aiDeclare", icon: PencilIcon },
};

// Grouped tiles: scan source code, scan a built artifact, analyze an SBOM, or
// generate an SBOM for an AI model.
const SOURCE_GROUPS: Array<{ key: string; sources: SourceType[] }> = [
  { key: "catCode", sources: ["current-dir", "rootfs-dir", "git-url", "zip-upload"] },
  { key: "catArtifact", sources: ["docker-image", "package-upload", "firmware-upload"] },
  { key: "catSbom", sources: ["sbom-upload"] },
  { key: "catAiModel", sources: ["ai-model", "model-upload", "ai-declare"] },
];
const ALL_SOURCES: SourceType[] = SOURCE_GROUPS.flatMap((g) => g.sources);

/** A folded group of the settings. Open on arrival when something in it differs
 *  from the default (a re-scan seed); the count of such options stays readable
 *  while it is closed. Built on `<details>`: open/close state and keyboard
 *  operation come with it. */
function SettingsGroup({
  label,
  testId,
  count,
  defaultOpen,
  children,
}: {
  label: string;
  testId: string;
  count: number;
  defaultOpen: boolean;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  // Held in state so a later change of `count` never closes a group the reader
  // is working in.
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details
      className="bl-box bl-setgroup"
      data-testid={testId}
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary className="bl-setsum">
        <span className="bl-chev">
          <ChevronRightIcon size={16} />
        </span>
        <span className="bl-strong">{label}</span>
        {count > 0 && (
          <span className="bl-setcount">
            <CounterLabel aria-hidden>{count}</CounterLabel>
            <VisuallyHidden>{t("newscan.enabledCount", { n: count })}</VisuallyHidden>
          </span>
        )}
      </summary>
      <div className="bl-setbody">{children}</div>
    </details>
  );
}

/**
 * New scan: the page header, the source tiles in rows, the selected source's
 * input, the scan settings in three folded boxes, and a one-line action bar
 * pinned to the bottom of the window (project, version, the two output
 * switches and the run button). All logic is useScanForm's; only the drawing is
 * here.
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
  // Which output switch has its description open in the line above the action bar.
  const [openHint, setOpenHint] = useState<string | null>(null);
  // The notice that a re-scan filled the form outlives the pending config.
  const [seeded] = useState(() => initialConfig ?? null);

  // How many options differ from the default in each folded group (seeded by a
  // re-scan config). Drives the group's initial open state and its count.
  const scanOptionsOn = [
    state.identifyVendored,
    state.deepLicense,
    state.deepCve,
    state.reachability,
    state.byteStable,
    state.analyzeCpeIndex && state.showAnalyzeCpeIndex,
    // On by default, so it counts only when it was turned off.
    state.showDetection && !state.readLockFile,
    state.readDeclaredChanged,
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

  const isLocked = (s: SourceType) =>
    (s === "firmware-upload" && !capabilities.firmware) ||
    (s === "ai-model" && !capabilities.aibom) ||
    (s === "ai-declare" && !capabilities.aiDeclare);

  // Lock reason for a group (firmware / AI need the Docker sibling image or the
  // converter). Shown as visible text so keyboard and touch users, who cannot
  // see a hover title, still learn why a tile is unavailable.
  const lockReason = (sources: SourceType[]) =>
    sources.includes("firmware-upload") && !capabilities.firmware
      ? t("source.firmwareUnavailable")
      : sources.includes("ai-model") && !capabilities.aibom
        ? t("source.aiModelUnavailable")
        : sources.includes("ai-declare") && !capabilities.aiDeclare
          ? t("source.aiDeclareUnavailable")
          : null;

  // Arrow keys move through every tile in order and select the one they land
  // on (a radio group); a locked tile takes focus but is not selected.
  const onTileKey = (e: KeyboardEvent<HTMLButtonElement>, src: SourceType) => {
    const i = ALL_SOURCES.indexOf(src);
    const step =
      e.key === "ArrowRight" || e.key === "ArrowDown"
        ? 1
        : e.key === "ArrowLeft" || e.key === "ArrowUp"
          ? -1
          : 0;
    const to =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? ALL_SOURCES.length - 1
          : step
            ? (i + step + ALL_SOURCES.length) % ALL_SOURCES.length
            : -1;
    if (to < 0) return;
    e.preventDefault();
    const next = ALL_SOURCES[to];
    document.querySelector<HTMLButtonElement>(`[data-testid="source-${next}"]`)?.focus();
    if (!isLocked(next)) state.changeSource(next);
  };

  // The input box is named for the selected source. Sources that are not tiles
  // (a submit-time variant, a recognized Yocto folder) keep the generic name.
  const sourceLabel = t(SOURCE_META[state.source]?.labelKey ?? "newscan.source");
  // A tab stop for the group: the selected tile, or the first when the selection
  // is not a tile.
  const tabStop = ALL_SOURCES.includes(state.source) ? state.source : ALL_SOURCES[0];
  const nameDescribedBy =
    [
      (state.errors.project || state.errors.version) && "scan-alert",
      state.source === "ai-declare" && "project-hint",
    ]
      .filter(Boolean)
      .join(" ") || undefined;

  return (
    <>
      <ScreenHeader title={t("newscan.title")} description={t("newscan.subtitle")} />
      {seeded && (
        <div className="bl-ns-banner">
          <Banner
            variant="info"
            title={t("newscan.rescanSeeded", { project: seeded.project, version: seeded.version })}
            description={t("newscan.rescanSeededBody")}
          />
        </div>
      )}
      <div className="bl-ns">
        <div role="radiogroup" aria-label={t("newscan.source")} className="bl-ns-groups">
          {SOURCE_GROUPS.map((group) => {
            const reason = lockReason(group.sources);
            return (
              <div
                key={group.key}
                role="group"
                aria-labelledby={`group-${group.key}`}
                className="bl-ns-row"
              >
                <span id={`group-${group.key}`} className="bl-grouplabel">
                  {t(`newscan.${group.key}`)}
                </span>
                <div className="bl-ns-tiles">
                  {group.sources.map((s) => {
                    const { labelKey, icon: Icon } = SOURCE_META[s];
                    const locked = isLocked(s);
                    return (
                      <button
                        key={s}
                        type="button"
                        role="radio"
                        // The source id, not its label: a test that drives
                        // this picker in both languages needs an anchor that
                        // does not translate.
                        data-testid={`source-${s}`}
                        className={`bl-tile${locked ? " bl-tile-locked" : ""}`}
                        aria-checked={state.source === s}
                        aria-disabled={locked || undefined}
                        aria-describedby={locked && reason ? `lock-${group.key}` : undefined}
                        tabIndex={tabStop === s ? 0 : -1}
                        disabled={state.busy}
                        onClick={() => {
                          if (!locked) state.changeSource(s);
                        }}
                        onKeyDown={(e) => onTileKey(e, s)}
                      >
                        <Icon size={16} />
                        <span className="bl-tile-label">{t(labelKey)}</span>
                        {locked && <LockIcon size={14} />}
                      </button>
                    );
                  })}
                </div>
                {reason && (
                  <p id={`lock-${group.key}`} className="bl-muted bl-small bl-lockreason">
                    {reason}
                  </p>
                )}
              </div>
            );
          })}
        </div>

        <section className="bl-box" aria-label={sourceLabel}>
          <div className="bl-box-head">
            <h2>{sourceLabel}</h2>
          </div>
          <div className="bl-box-body">
            <SourceControls state={state} />
          </div>
        </section>

        <section className="bl-stack-8" aria-label={t("newscan.settings")}>
          <h2 className="bl-grouplabel bl-flat">{t("newscan.settings")}</h2>
          {state.showScanOptions && (
            <SettingsGroup
              label={t("newscan.scanOptions")}
              testId="settings-quality"
              count={scanOptionsOn}
              defaultOpen={scanOptionsOn > 0}
            >
              <ScanOptions state={state} />
            </SettingsGroup>
          )}
          {state.showFormatOptions && (
            <SettingsGroup
              label={t("newscan.formatOptions")}
              testId="settings-format"
              count={formatOptionsOn}
              defaultOpen={formatOptionsOn > 0 || focusField === "license"}
            >
              <FormatOptions state={state} />
            </SettingsGroup>
          )}
          {state.showUpload && (
            <div className="bl-box bl-setrow" data-testid="settings-transfer">
              <div className="bl-strong">{t("newscan.upload")}</div>
              <UploadOptions state={state} />
            </div>
          )}
        </section>

        <div className="bl-actionwrap">
          <ActionNotes state={state} openHint={openHint} />
          <div className="bl-actionbar" data-testid="action-bar">
            <div className="bl-actionrow">
              <FormControl id="project" required disabled={state.busy} className="bl-af-project">
                <FormControl.Label className="bl-af-label">{t("form.project")}</FormControl.Label>
                <TextInput
                  block
                  value={state.project}
                  onChange={(e) => state.setProject(e.target.value)}
                  placeholder={t("form.projectPlaceholder")}
                  validationStatus={state.errors.project ? "error" : undefined}
                  aria-describedby={nameDescribedBy}
                />
              </FormControl>
              <FormControl id="version" required disabled={state.busy} className="bl-af-version">
                <FormControl.Label className="bl-af-label">{t("form.version")}</FormControl.Label>
                <TextInput
                  block
                  value={state.version}
                  onChange={(e) => state.setVersion(e.target.value)}
                  placeholder={t("form.versionPlaceholder")}
                  validationStatus={state.errors.version ? "error" : undefined}
                  aria-describedby={
                    state.errors.project || state.errors.version ? "scan-alert" : undefined
                  }
                />
              </FormControl>
              <OutputSwitches state={state} openHint={openHint} onOpenHint={setOpenHint} />
              <div className="bl-af-run">
                <RunButton state={state} running={running} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
