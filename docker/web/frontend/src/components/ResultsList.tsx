// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Download, Eye, FileSignature, FileText, Link2, Loader2, Package } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/state";
import {
  absoluteFileUrl,
  downloadAllUrl,
  exportSpdx,
  fileUrl,
  getCapabilities,
  type ResultFile,
} from "@/lib/api";
import {
  formatLabel,
  groupArtifacts,
  type ArtifactFormat,
  type LogicalArtifact,
} from "@/lib/artifacts";
import { useToast } from "@/lib/toast";
import { formatBytes } from "@/lib/utils";

import { FileViewer } from "./FileViewer";

/** Filename shared by an artifact's formats, with the format extension dropped. */
function baseName(formats: ArtifactFormat[]): string {
  const first = formats[0]?.name ?? "";
  const i = first.lastIndexOf(".");
  return i > 0 ? first.slice(0, i) : first;
}

/** Richest viewable format for the inline viewer (HTML first). */
function preferredView(formats: ArtifactFormat[]): string | null {
  const html = formats.find((f) => f.ext === "html" && f.viewable);
  return (html ?? formats.find((f) => f.viewable))?.name ?? null;
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
  return (
    <Button variant="outline" size="sm" asChild>
      <a href={fileUrl(scanId, fmt.name)} download={fmt.name} onClick={onDownload}>
        <Download className="h-3.5 w-3.5" />
        {formatLabel(fmt.ext)}
        <span className="font-normal text-muted-foreground">
          {formatBytes(fmt.size)}
        </span>
      </a>
    </Button>
  );
}

/**
 * Convert this scan's CycloneDX BOM to SPDX 2.3, then download it.
 *
 * SPDX is not a scan option: the BOM already exists, so the format choice
 * belongs here rather than in a toggle the user had to predict before scanning.
 * One click covers the whole intent — convert, then hand over the file — and the
 * new artifact also joins the card as an ordinary download chip.
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
    const a = document.createElement("a");
    a.href = fileUrl(scanId, res.name);
    a.download = res.name;
    a.click();
    toast(t("result.downloadStarted"));
  };

  return (
    <Button variant="outline" size="sm" onClick={run} disabled={pending}>
      {pending ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <Download className="h-3.5 w-3.5" />
      )}
      {pending ? t("result.spdxExporting") : t("result.spdxExport")}
    </Button>
  );
}

function ArtifactCard({
  artifact,
  scanId,
  onView,
  spdxAvailable,
  onExported,
}: {
  artifact: LogicalArtifact;
  scanId: string | null;
  onView: (name: string) => void;
  /** This image can convert to SPDX (syft here or a sibling scanner container). */
  spdxAvailable: boolean;
  onExported?: (files: ResultFile[]) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { Icon, primary, formats, signature } = artifact;
  const view = preferredView(formats);

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(absoluteFileUrl(scanId, formats[0].name));
      toast(t("result.copied"));
    } catch {
      /* clipboard blocked (insecure context) — silently ignore */
    }
  };

  return (
    <div
      className={
        "rounded-lg border bg-card p-4 transition-all duration-fast ease-out-soft hover:bg-accent/40 hover:shadow-md" +
        (primary ? " border-primary/60 ring-1 ring-primary/30 lg:col-span-2" : "")
      }
    >
      <div className="flex items-start gap-3">
        <div
          className={
            "flex shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground" +
            (primary ? " h-11 w-11" : " h-9 w-9")
          }
        >
          <Icon className={primary ? "h-5 w-5" : "h-4 w-4"} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={primary ? "font-semibold" : "text-sm font-medium"}>
              {t(artifact.titleKey)}
            </span>
            {signature && (
              <Badge tone="success" className="gap-1">
                <FileSignature className="h-3 w-3" />
                {t("result.signed")}
              </Badge>
            )}
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {t(artifact.descKey)}
          </p>
          <span className="mt-1 block truncate font-mono text-xs text-muted-foreground">
            {baseName(formats)}
          </span>
        </div>
      </div>

      {/* Downloads on one row, the two per-card actions on their own. In a
          two-column grid the spacer between them pushed View and Copy link onto
          a ragged second line whenever a card carried three format chips. */}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {formats.map((fmt) => (
          <DownloadChip
            key={fmt.name}
            fmt={fmt}
            scanId={scanId}
            onDownload={() => toast(t("result.downloadStarted"))}
          />
        ))}
        {signature && (
          <DownloadChip
            fmt={{
              ext: "sig",
              name: signature.name,
              size: signature.size,
              viewable: false,
            }}
            scanId={scanId}
            onDownload={() => toast(t("result.downloadStarted"))}
          />
        )}
        {artifact.spdxExportable && spdxAvailable && (
          <SpdxExportButton scanId={scanId} onExported={onExported} />
        )}
      </div>

      <div className="mt-2 flex items-center justify-end gap-1 border-t pt-2">
        {view && (
          <Button variant="ghost" size="sm" onClick={() => onView(view)}>
            <Eye className="h-4 w-4" />
            <span className="hidden sm:inline">{t("result.view")}</span>
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={copyLink}
          aria-label={t("result.copyLink")}
        >
          <Link2 className="h-4 w-4" />
          <span className="hidden sm:inline">{t("result.copyLink")}</span>
        </Button>
      </div>
    </div>
  );
}

export function ResultsList({
  results,
  scanId,
  onResultsChange,
}: {
  results: ResultFile[];
  /** The scan's run_id, scoping artifact URLs to its run folder. */
  scanId: string | null;
  /** Called with the refreshed listing after an on-demand export. The owner
   *  holds the result, so routing the new artifact up keeps every count (this
   *  header, the sidebar badge) in agreement. */
  onResultsChange?: (files: ResultFile[]) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [view, setView] = useState<string | null>(null);
  const [spdxAvailable, setSpdxAvailable] = useState(false);

  useEffect(() => {
    let alive = true;
    getCapabilities().then((c) => {
      if (alive) setSpdxAvailable(c.spdxExport !== false);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (results.length === 0) {
    return <EmptyState icon={FileText}>{t("result.artifactsEmpty")}</EmptyState>;
  }

  const artifacts = groupArtifacts(results);
  const totalBytes = results.reduce((sum, r) => sum + r.size, 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Package className="h-4 w-4" />
          {/* Count what is on screen. The header said "10 artifacts" over four
              cards, because it counted files while the cards group a report's
              formats together; the file count follows, where it explains the
              chips rather than contradicting the cards. */}
          {t("result.artifactCount", {
            count: artifacts.length,
            size: formatBytes(totalBytes),
          })}
          <span className="text-xs">
            {t("result.artifactFiles", { count: results.length })}
          </span>
        </div>
        <Button
          asChild
          variant="outline"
          className="text-brand-strong hover:text-brand-strong"
          onClick={() => toast(t("result.downloadStarted"))}
        >
          <a href={downloadAllUrl(scanId)} download>
            <Download className="h-4 w-4" />
            {t("result.downloadAll")}
          </a>
        </Button>
      </div>

      {/* Two columns: the cards are short and were stacked one per row, so four
          of them filled a screen and left the lower half empty. The headline
          deliverable keeps the full width. */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {artifacts.map((a) => (
          <ArtifactCard
            key={a.key}
            artifact={a}
            scanId={scanId}
            onView={setView}
            spdxAvailable={spdxAvailable}
            onExported={onResultsChange}
          />
        ))}
      </div>

      <FileViewer name={view} scanId={scanId} onClose={() => setView(null)} />
    </div>
  );
}
