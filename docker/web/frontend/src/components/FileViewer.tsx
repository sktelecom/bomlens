import { Download, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { fileUrl } from "@/lib/api";

interface Props {
  name: string | null;
  onClose: () => void;
}

/**
 * Lightweight modal artifact viewer. HTML reports render in an iframe (so the
 * report's own styles apply); JSON is pretty-printed; text/markdown shown raw.
 * No @radix-ui/react-dialog dependency — a focus-trapped overlay is enough for
 * this single-purpose viewer.
 */
export function FileViewer({ name, onClose }: Props) {
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const isHtml = !!name && name.endsWith(".html");

  useEffect(() => {
    if (!name || isHtml) {
      setText("");
      return;
    }
    let active = true;
    void fetch(fileUrl(name))
      .then((r) => r.text())
      .then((c) => {
        if (active) setText(c);
      });
    return () => {
      active = false;
    };
  }, [name, isHtml]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (name) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [name, onClose]);

  if (!name) return null;

  let body = text;
  if (name.endsWith(".json")) {
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      /* show raw on parse failure */
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label={name}
    >
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative z-10 flex h-[80vh] w-full max-w-4xl flex-col overflow-hidden rounded-xl border bg-card shadow-lg animate-fade-in">
        <div className="flex items-center justify-between gap-3 border-b px-4 py-3">
          <span className="truncate font-mono text-sm">{name}</span>
          <div className="flex shrink-0 items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <a href={fileUrl(name)} download={name}>
                <Download className="h-4 w-4" />
                {t("result.download")}
              </a>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              aria-label={t("viewer.close")}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="flex-1 overflow-auto">
          {isHtml ? (
            <iframe
              title={name}
              src={fileUrl(name)}
              className="h-full w-full bg-white"
            />
          ) : (
            <pre className="whitespace-pre-wrap break-all p-4 font-mono text-xs">
              {body}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
