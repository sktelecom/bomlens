import {
  Download,
  Eye,
  FileJson,
  FileSignature,
  FileText,
  ScrollText,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { fileUrl, type ResultFile } from "@/lib/api";
import { formatBytes } from "@/lib/utils";

import { FileViewer } from "./FileViewer";

function kindOf(name: string): { label: string; Icon: LucideIcon } {
  if (name.endsWith("_bom.json")) return { label: "SBOM", Icon: FileJson };
  if (name.endsWith(".sig")) return { label: "Signature", Icon: FileSignature };
  if (name.includes("_NOTICE")) return { label: "Notice", Icon: ScrollText };
  if (name.includes("_security")) return { label: "Security", Icon: ShieldCheck };
  if (name.includes("_scancode")) return { label: "License", Icon: FileText };
  return { label: "File", Icon: FileText };
}

const viewable = (n: string) =>
  /\.(html|json|txt|md)$/.test(n) && !n.endsWith(".sig");

export function ResultsList({ results }: { results: ResultFile[] }) {
  const { t } = useTranslation();
  const [view, setView] = useState<string | null>(null);

  if (results.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t("result.artifactsEmpty")}</p>
    );
  }

  return (
    <div className="space-y-2">
      {results.map((f) => {
        const { label, Icon } = kindOf(f.name);
        return (
          <div
            key={f.name}
            className="flex items-center gap-3 rounded-md border bg-card px-3 py-2.5 transition-colors duration-fast ease-out-soft hover:bg-accent/50"
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate font-mono text-xs">{f.name}</span>
                <Badge variant="muted" className="shrink-0">
                  {label}
                </Badge>
              </div>
              <span className="text-xs text-muted-foreground">
                {formatBytes(f.size)}
              </span>
            </div>
            {viewable(f.name) && (
              <Button variant="ghost" size="sm" onClick={() => setView(f.name)}>
                <Eye className="h-4 w-4" />
                <span className="hidden sm:inline">{t("result.view")}</span>
              </Button>
            )}
            <Button variant="outline" size="sm" asChild aria-label={t("result.download")}>
              <a href={fileUrl(f.name)} download={f.name}>
                <Download className="h-4 w-4" />
              </a>
            </Button>
          </div>
        );
      })}
      <FileViewer name={view} onClose={() => setView(null)} />
    </div>
  );
}
