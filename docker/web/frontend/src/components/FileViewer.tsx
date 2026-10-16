// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Download, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/dialog";
import { fileUrl } from "@/lib/api";

interface Props {
  name: string | null;
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  onClose: () => void;
}

/**
 * Lightweight modal artifact viewer. HTML reports render in an iframe (so the
 * report's own styles apply); JSON is pretty-printed; text/markdown shown raw.
 * The overlay, focus handling and Escape come from the shared Modal.
 */
export function FileViewer({ name, scanId, onClose }: Props) {
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const isHtml = !!name && name.endsWith(".html");

  useEffect(() => {
    if (!name || isHtml) {
      setText("");
      return;
    }
    let active = true;
    void fetch(fileUrl(scanId, name))
      .then((r) => r.text())
      .then((c) => {
        if (active) setText(c);
      });
    return () => {
      active = false;
    };
  }, [name, scanId, isHtml]);

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
    <Modal
      open
      onClose={onClose}
      label={name}
      className="h-[80vh] max-w-4xl"
    >
      <div className="flex items-center justify-between gap-3 border-b px-4 py-3">
        <span className="truncate font-mono text-body-sm">{name}</span>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" size="sm" asChild>
            <a href={fileUrl(scanId, name)} download={name}>
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
            src={fileUrl(scanId, name)}
            className="h-full w-full bg-white"
          />
        ) : (
          <pre className="whitespace-pre-wrap break-all p-4 font-mono text-label">
            {body}
          </pre>
        )}
      </div>
    </Modal>
  );
}
