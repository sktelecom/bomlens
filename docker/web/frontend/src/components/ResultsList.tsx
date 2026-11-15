// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  ChecklistIcon,
  CpuIcon,
  DownloadIcon,
  EyeIcon,
  FileCodeIcon,
  FileIcon,
  GraphIcon,
  LawIcon,
  LinkIcon,
  PencilIcon,
  ArrowSwitchIcon,
  ShieldIcon,
  SyncIcon,
  UploadIcon,
  VerifiedIcon,
} from "@primer/octicons-react";
import { Blankslate } from "@primer/react/experimental";
import { Button, IconButton, Label } from "@primer/react";
import { useEffect, useRef, useState, type ElementType } from "react";
import { useTranslation } from "react-i18next";

import {
  absoluteFileUrl,
  exportSpdx,
  exportSpdx3,
  fileUrl,
  getCapabilities,
  saveAiDeclaration,
  type DoneEvent,
  type ResultFile,
  type Spdx3Summary,
} from "@/lib/api";
import {
  formatLabel,
  groupArtifacts,
  isSpdx3Check,
  type ArtifactFormat,
  type LogicalArtifact,
} from "@/lib/artifacts";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { useToast } from "@/lib/toast";
import { formatBytes } from "@/lib/utils";

import { FileViewer } from "./FileViewer";
import "./results-list.css";

/** One icon per kind of artifact; an unknown kind gets the plain file icon. */
const ICON: Record<string, ElementType> = {
  riskReport: GraphIcon,
  sbom: FileCodeIcon,
  refusedSbom: FileCodeIcon,
  spdx3: CpuIcon,
  aiDeclaration: PencilIcon,
  notice: LawIcon,
  conformance: ChecklistIcon,
  aiProfile: CpuIcon,
  security: ShieldIcon,
  componentVersions: FileIcon,
  license: LawIcon,
  vex: ShieldIcon,
  signature: VerifiedIcon,
};

/** Filename shared by an artifact's formats, with the format extension dropped. */
function baseName(formats: ArtifactFormat[]): string {
  const first = formats[0]?.name ?? "";
  const i = first.lastIndexOf(".");
  return i > 0 ? first.slice(0, i) : first;
}

/** Richest viewable format for the inline viewer (HTML first). */
function preferredView(formats: ArtifactFormat[]): ArtifactFormat | null {
  return formats.find((f) => f.ext === "html" && f.viewable) ?? formats.find((f) => f.viewable) ?? null;
}

function DownloadChip({
  fmt,
  scanId,
  onDownload,
}: {
  fmt: ArtifactFormat;
  scanId: string | null;
  onDownload: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Button
      as="a"
      size="small"
      href={fileUrl(scanId, fmt.name)}
      download={fmt.name}
      title={fmt.name}
      leadingVisual={DownloadIcon}
      onClick={onDownload}
    >
      {fmt.ext === "template"
        ? t("result.emptyForm")
        : isSpdx3Check(fmt.name)
          ? t("result.checkFormat", { format: formatLabel(fmt.ext) })
          : formatLabel(fmt.ext)}{" "}
      <span className="bl-muted bl-chip-size">{formatBytes(fmt.size)}</span>
    </Button>
  );
}

function triggerDownload(scanId: string, name: string) {
  const a = document.createElement("a");
  a.href = fileUrl(scanId, name);
  a.download = name;
  a.click();
}

/**
 * Convert this scan's CycloneDX BOM to SPDX 2.3, then download it.
 *
 * SPDX is not a scan option: the BOM already exists, so the format choice
 * belongs here rather than in a toggle the user had to predict before scanning.
 * One click covers the whole intent (convert, then hand over the file) and the
 * new artifact also joins the row as an ordinary download chip.
 */
function SpdxExportButton({
  scanId,
  onExported,
}: {
  scanId: string | null;
  onExported?: (files: ResultFile[]) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [pending, setPending] = useState(false);

  const run = async () => {
    if (!scanId || pending) return;
    setPending(true);
    const res = await exportSpdx(scanId);
    setPending(false);
    if (!res) {
      toast(t("result.spdxExportFailed"));
      return;
    }
    onExported?.(res.results);
    // Hand the file over straight away: the click meant "I want the SPDX file",
    // not "prepare it and wait for me to ask again".
    triggerDownload(scanId, res.name);
    toast(t("result.downloadStarted"));
  };

  return (
    <Button
      size="small"
      onClick={run}
      disabled={pending}
      loading={pending}
      leadingVisual={pending ? undefined : ArrowSwitchIcon}
    >
      {pending ? t("result.spdxExporting") : t("result.spdxExport")}
    </Button>
  );
}

/**
 * Write the SPDX 3.0.1 AI document and download it: on a scan from before the
 * document existed this is how it first gets written ("write"), and on one
 * whose document is behind its saved declaration or this BomLens it rebuilds
 * the document ("rebuild").
 */
function Spdx3ExportButton({
  scanId,
  onPatch,
  label,
  icon,
}: {
  scanId: string | null;
  onPatch?: (patch: Partial<DoneEvent>) => void;
  label: string;
  icon: ElementType;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [pending, setPending] = useState(false);
  const run = async () => {
    if (!scanId || pending) return;
    setPending(true);
    const res = await exportSpdx3(scanId);
    setPending(false);
    if (!res.ok) {
      toast(res.status === 409 ? t("spdx3.notAi") : t("spdx3.writeFailed"));
      return;
    }
    onPatch?.({ results: res.results, spdx3: res.spdx3 });
    triggerDownload(scanId, res.name);
    toast(t("result.downloadStarted"));
  };
  return (
    <Button
      size="small"
      onClick={run}
      disabled={pending}
      loading={pending}
      leadingVisual={pending ? undefined : icon}
    >
      {label}
    </Button>
  );
}

/**
 * Send an edited declaration file back: the server checks it against this
 * scan and rewrites the SPDX 3.0.1 document with it. A refusal says why.
 */
function DeclarationUploadButton({
  scanId,
  onPatch,
}: {
  scanId: string | null;
  onPatch?: (patch: Partial<DoneEvent>) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState(false);
  const send = async (f: File) => {
    if (!scanId) return;
    setPending(true);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await f.text());
    } catch {
      setPending(false);
      toast(t("result.declarationNotJson"));
      return;
    }
    const res = await saveAiDeclaration(scanId, parsed);
    setPending(false);
    if (!res.ok) {
      toast(
        res.status === 422
          ? t("result.declarationRefused", { reason: res.reasons?.[0] ?? res.error })
          : t("aiDecl.saveFailed"),
      );
      return;
    }
    onPatch?.({ results: res.results, spdx3: res.spdx3 });
    toast(res.spdx3 && !res.spdx3.draft ? t("spdx3.savedComplete") : t("spdx3.savedDraft"));
  };
  return (
    <>
      <input
        ref={input}
        type="file"
        accept=".json,application/json"
        className="bl-visually-hidden"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (f) void send(f);
        }}
      />
      <Button
        size="small"
        onClick={() => input.current?.click()}
        disabled={pending}
        loading={pending}
        leadingVisual={pending ? undefined : UploadIcon}
      >
        {t("result.declarationUpload")}
      </Button>
    </>
  );
}

/** One artifact as a row (name, description, one download per format, view, copy link), like the asset list of a release. */
function ArtifactRow({
  artifact,
  scanId,
  onView,
  spdxAvailable,
  onExported,
  spdx3Available,
  spdx3,
  aiScan,
  uploadedSbom,
  onPatch,
}: {
  artifact: LogicalArtifact;
  scanId: string | null;
  onView: (name: string) => void;
  /** This image can convert to SPDX (syft here or a sibling scanner container). */
  spdxAvailable: boolean;
  onExported?: (files: ResultFile[]) => void;
  /** This server can write the SPDX 3.0.1 AI document and take a declaration. */
  spdx3Available: boolean;
  spdx3?: Spdx3Summary | null;
  aiScan: boolean;
  /** The scan reviewed an SBOM someone uploaded. */
  uploadedSbom: boolean;
  onPatch?: (patch: Partial<DoneEvent>) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { formats, signature } = artifact;
  const Icon = ICON[artifact.key] ?? FileIcon;
  const title = t(artifact.titleKey);
  // Rebuilding changes the document only when it is behind the saved
  // declaration or this BomLens; otherwise the button would do nothing new.
  const behind = artifact.key === "spdx3" && spdx3?.upToDate === false;
  const view = preferredView(formats);
  const onDownload = () => toast(t("result.downloadStarted"));

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(absoluteFileUrl(scanId, formats[0].name));
      toast(t("result.copied"));
    } catch {
      /* clipboard blocked (insecure context): nothing to say */
    }
  };

  return (
    <li className="bl-art-row" data-testid={`artifact-${artifact.key}`}>
      <span className="bl-art-icon bl-muted">
        <Icon size={16} />
      </span>
      <div className="bl-art-main">
        <div className="bl-art-title">
          <h2>{title}</h2>
          <span className="bl-mono bl-muted bl-breakall">{baseName(formats)}</span>
          {signature && (
            <Label variant="success">
              <VerifiedIcon size={12} />
              <span className="bl-label-text">{t("result.signed")}</span>
            </Label>
          )}
          {artifact.key === "spdx3" && spdx3 && (
            <Label variant={spdx3.draft ? "attention" : "success"}>
              {spdx3.draft ? t("spdx3.draft") : t("spdx3.complete")}
            </Label>
          )}
        </div>
        <p className="bl-art-desc">
          {t(artifact.descKey)}
          {artifact.key === "spdx3" && spdx3?.draft && (
            <> {t("result.kind.spdx3.draftNote", { count: spdx3.counts.missingRequired ?? 0 })}</>
          )}
          {artifact.key === "spdx3" && uploadedSbom && <> {t("result.kind.spdx3.uploadNote")}</>}
          {behind && <> {t("result.kind.spdx3.behindNote")}</>}
        </p>
        <div className="bl-art-chips">
          {formats.map((fmt) => (
            <DownloadChip key={fmt.name} fmt={fmt} scanId={scanId} onDownload={onDownload} />
          ))}
          {signature && (
            <DownloadChip
              fmt={{ ext: "sig", name: signature.name, size: signature.size, viewable: false }}
              scanId={scanId}
              onDownload={onDownload}
            />
          )}
          {artifact.spdxExportable && spdxAvailable && (
            <SpdxExportButton scanId={scanId} onExported={onExported} />
          )}
          {spdx3Available && behind && (
            <Spdx3ExportButton scanId={scanId} onPatch={onPatch} label={t("result.spdx3Rebuild")} icon={SyncIcon} />
          )}
          {/* An AI scan from before the document existed: write it from here. */}
          {spdx3Available && artifact.key === "sbom" && aiScan && !spdx3 && (
            <Spdx3ExportButton scanId={scanId} onPatch={onPatch} label={t("spdx3.band.write")} icon={PencilIcon} />
          )}
          {spdx3Available && artifact.key === "aiDeclaration" && (
            <DeclarationUploadButton scanId={scanId} onPatch={onPatch} />
          )}
        </div>
      </div>
      <div className="bl-art-actions">
        {view && (
          <Button size="small" variant="invisible" leadingVisual={EyeIcon} onClick={() => onView(view.name)}>
            {t("result.viewFormat", {
              format: view.ext === "template" ? t("result.formatTemplate") : formatLabel(view.ext),
            })}
          </Button>
        )}
        <IconButton
          size="small"
          variant="invisible"
          icon={LinkIcon}
          aria-label={t("result.copyLinkOf", { name: title })}
          onClick={copyLink}
        />
      </div>
    </li>
  );
}

export function ResultsList({
  results,
  scanId,
  onResultsChange,
  aiScan = false,
  uploadedSbom = false,
  spdx3,
  onResultPatch,
}: {
  results: ResultFile[];
  /** The scan's run_id, scoping artifact URLs to its run folder. */
  scanId: string | null;
  /** Called with the refreshed listing after an on-demand export. The owner
   *  holds the result, so routing the new artifact up keeps every count (this
   *  header, the sidebar badge) in agreement. */
  onResultsChange?: (files: ResultFile[]) => void;
  /** The scan describes an AI model or dataset, so it has an SPDX 3.0.1 document. */
  aiScan?: boolean;
  /** The scan reviewed an uploaded SBOM. */
  uploadedSbom?: boolean;
  spdx3?: Spdx3Summary | null;
  /** The SPDX 3.0.1 actions refresh the summary as well as the listing. */
  onResultPatch?: (patch: Partial<DoneEvent>) => void;
}) {
  const { t } = useTranslation();
  const [view, setView] = useState<string | null>(null);
  const [spdxAvailable, setSpdxAvailable] = useState(false);
  const [spdx3Available, setSpdx3Available] = useState(false);

  useEffect(() => {
    let alive = true;
    getCapabilities().then((c) => {
      if (alive) setSpdxAvailable(c.spdxExport !== false);
      if (alive) setSpdx3Available(c.spdx3 === true && !IS_STATIC_DEMO);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (results.length === 0) {
    return (
      <div className="bl-box" data-testid="empty-state">
        <Blankslate spacious>
          <Blankslate.Visual>
            <FileIcon size={24} />
          </Blankslate.Visual>
          <Blankslate.Heading as="h2">{t("result.artifactsEmpty")}</Blankslate.Heading>
        </Blankslate>
      </div>
    );
  }

  const artifacts = groupArtifacts(results);
  const totalBytes = results.reduce((sum, r) => sum + r.size, 0);
  // Files that no row offers (the raw EPSS feed, the second signature): they
  // are only in the ZIP, and the header would otherwise count them unseen.
  const listed = new Set(
    artifacts.flatMap((a) => [...a.formats.map((f) => f.name), ...(a.signature ? [a.signature.name] : [])]),
  );
  const unlisted = results.filter((r) => !listed.has(r.name)).map((r) => r.name);

  return (
    <div className="bl-stack-8">
      {/* Count what is on screen. The header said "10 artifacts" over four
          rows, because it counted files while the rows group a report's
          formats together; the file count follows, where it explains the
          chips rather than contradicting the rows. */}
      <p className="bl-art-summary" data-testid="artifact-summary">
        {t("result.artifactCount", { count: artifacts.length, size: formatBytes(totalBytes) })}{" "}
        <span className="bl-small">{t("result.artifactFiles", { count: results.length })}</span>
      </p>
      {unlisted.length > 0 && (
        <details className="bl-art-unlisted bl-small" data-testid="artifact-unlisted">
          <summary>{t("result.artifactNotListed", { count: unlisted.length })}</summary>
          <ul>
            {unlisted.map((n) => (
              <li key={n} className="bl-mono bl-breakall">
                {n}
              </li>
            ))}
          </ul>
        </details>
      )}
      <ul className="bl-box bl-art-list">
        {artifacts.map((a) => (
          <ArtifactRow
            key={a.key}
            artifact={a}
            scanId={scanId}
            onView={setView}
            spdxAvailable={spdxAvailable}
            onExported={onResultsChange}
            spdx3Available={spdx3Available}
            spdx3={spdx3}
            aiScan={aiScan}
            uploadedSbom={uploadedSbom}
            onPatch={onResultPatch ?? ((p) => p.results && onResultsChange?.(p.results))}
          />
        ))}
      </ul>
      <FileViewer
        key={view ?? "closed"}
        name={view}
        scanId={scanId}
        size={results.find((r) => r.name === view)?.size} onClose={() => setView(null)} />
    </div>
  );
}
