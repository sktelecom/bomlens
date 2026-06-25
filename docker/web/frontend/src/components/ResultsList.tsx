import { Download, Eye, FileSignature, Link2, Package } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  absoluteFileUrl,
  downloadAllUrl,
  fileUrl,
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
  onDownload,
}: {
  fmt: ArtifactFormat;
  onDownload: () => void;
}) {
  return (
    <Button variant="outline" size="sm" asChild>
      <a href={fileUrl(fmt.name)} download={fmt.name} onClick={onDownload}>
        <Download className="h-3.5 w-3.5" />
        {formatLabel(fmt.ext)}
        <span className="font-normal text-muted-foreground">
          {formatBytes(fmt.size)}
        </span>
      </a>
    </Button>
  );
}

function ArtifactCard({
  artifact,
  onView,
}: {
  artifact: LogicalArtifact;
  onView: (name: string) => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { Icon, primary, formats, signature } = artifact;
  const view = preferredView(formats);

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(absoluteFileUrl(formats[0].name));
      toast(t("result.copied"));
    } catch {
      /* clipboard blocked (insecure context) — silently ignore */
    }
  };

  return (
    <div
      className={
        "rounded-lg border bg-card p-4 transition-all duration-fast ease-out-soft hover:bg-accent/40 hover:shadow-md" +
        (primary ? " border-primary/60 ring-1 ring-primary/30" : "")
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
          <span className="mt-1 block truncate font-mono text-xs text-muted-foreground/80">
            {baseName(formats)}
          </span>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {formats.map((fmt) => (
          <DownloadChip
            key={fmt.name}
            fmt={fmt}
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
            onDownload={() => toast(t("result.downloadStarted"))}
          />
        )}
        <div className="flex-1" />
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

export function ResultsList({ results }: { results: ResultFile[] }) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [view, setView] = useState<string | null>(null);

  if (results.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("result.artifactsEmpty")}</p>
    );
  }

  const artifacts = groupArtifacts(results);
  const totalBytes = results.reduce((sum, r) => sum + r.size, 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Package className="h-4 w-4" />
          {t("result.artifactCount", {
            count: results.length,
            size: formatBytes(totalBytes),
          })}
        </div>
        <Button
          asChild
          variant="outline"
          className="text-brand hover:text-brand"
          onClick={() => toast(t("result.downloadStarted"))}
        >
          <a href={downloadAllUrl()} download>
            <Download className="h-4 w-4" />
            {t("result.downloadAll")}
          </a>
        </Button>
      </div>

      <div className="space-y-3">
        {artifacts.map((a) => (
          <ArtifactCard key={a.key} artifact={a} onView={setView} />
        ))}
      </div>

      <FileViewer name={view} onClose={() => setView(null)} />
    </div>
  );
}
