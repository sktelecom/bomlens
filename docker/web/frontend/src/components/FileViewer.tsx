// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon, DownloadIcon, FileIcon, SyncIcon } from "@primer/octicons-react";
import { Button, Dialog, Spinner } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fileUrl } from "@/lib/api";
import { useToast } from "@/lib/toast";
import { formatBytes } from "@/lib/utils";

import { DialogHeader } from "./ShortcutsDialog";
import "./results-list.css";

interface Props {
  name: string | null;
  /** The file's size in bytes when the listing has it. */
  size?: number;
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  onClose: () => void;
}

type LoadState = "loading" | "ready" | "error" | "tooBig";

/** Above this, JSON and text are not read into the page: a 40 MB SBOM would freeze it. */
const PREVIEW_LIMIT = 2 * 1024 * 1024;

/**
 * The artifact viewer, a Primer Dialog (focus kept inside, Escape and a click
 * on the backdrop close it, focus goes back to the button that opened it). An
 * HTML report renders in a frame that runs no script (links to other sites may
 * open in a new tab); JSON is pretty-printed; text and markdown are shown as
 * they are. The file is requested first, so the dialog can say that it is
 * loading, too large, or could not be read (an error response is never shown
 * as if it were the file). Mount it with `key={name}` so a new file starts clean.
 */
export function FileViewer({ name, scanId, size, onClose }: Props) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [state, setState] = useState<LoadState>("loading");
  const [text, setText] = useState("");
  const [bytes, setBytes] = useState<number | null>(size ?? null);
  const [attempt, setAttempt] = useState(0);
  const isHtml = !!name && name.endsWith(".html");

  useEffect(() => {
    if (!name) return;
    let alive = true;
    setState("loading");
    setText("");
    void fetch(fileUrl(scanId, name))
      .then(async (r) => {
        if (!r.ok) throw new Error(String(r.status));
        const len = size ?? Number(r.headers.get("Content-Length") ?? NaN);
        if (!isHtml && Number.isFinite(len) && len > PREVIEW_LIMIT) {
          void r.body?.cancel();
          if (alive) {
            setBytes(len);
            setState("tooBig");
          }
          return;
        }
        // The report itself is loaded by the frame; this request only checked it exists.
        if (isHtml) {
          void r.body?.cancel();
          if (alive) setState("ready");
          return;
        }
        const body = await r.text();
        if (!alive) return;
        setText(body);
        setState("ready");
      })
      .catch(() => {
        if (alive) setState("error");
      });
    return () => {
      alive = false;
    };
  }, [name, scanId, size, isHtml, attempt]);

  if (!name) return null;

  let body = text;
  if (state === "ready" && name.endsWith(".json")) {
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      /* show raw on parse failure */
    }
  }

  return (
    <Dialog
      title={name}
      onClose={onClose}
      width="xlarge"
      height="large"
      // Wide enough for a report's tables, 80% of the window tall. Inline, because
      // Primer sizes the dialog with rules a class would not outrank.
      style={{ width: "min(1200px, 95vw)", maxWidth: "95vw", height: "80vh", maxHeight: "80vh" }}
      renderHeader={({ dialogLabelId }) => (
        <DialogHeader id={dialogLabelId} title={<span className="bl-mono bl-breakall">{name}</span>} onClose={onClose} />
      )}
      renderBody={() => (
        <Dialog.Body className={state === "ready" && isHtml ? "bl-viewer-body bl-viewer-body-frame" : "bl-viewer-body"}>
          {state === "loading" && (
            <div role="status" className="bl-viewer-center bl-inline">
              <Spinner size="small" srText={null} />
              <span className="bl-muted">{t("viewer.loading")}</span>
            </div>
          )}
          {state === "error" && (
            <Blankslate data-testid="viewer-error" role="alert">
              <Blankslate.Visual>
                <AlertIcon size={24} />
              </Blankslate.Visual>
              <Blankslate.Heading as="h3">{t("viewer.error")}</Blankslate.Heading>
              <div className="bl-viewer-retry">
                <Button leadingVisual={SyncIcon} onClick={() => setAttempt((n) => n + 1)}>
                  {t("retry")}
                </Button>
              </div>
            </Blankslate>
          )}
          {state === "tooBig" && (
            <Blankslate data-testid="viewer-too-big">
              <Blankslate.Visual>
                <FileIcon size={24} />
              </Blankslate.Visual>
              <Blankslate.Heading as="h3">
                {t("result.tooBig", { size: formatBytes(bytes ?? 0) })}
              </Blankslate.Heading>
              <div className="bl-viewer-retry">
                <Button
                  as="a"
                  href={fileUrl(scanId, name)}
                  download={name}
                  leadingVisual={DownloadIcon}
                  onClick={() => toast(t("result.downloadStarted"))}
                >
                  {t("result.download")}
                </Button>
              </div>
            </Blankslate>
          )}
          {state === "ready" &&
            (isHtml ? (
              // No script and no same-origin access: a report is shown, not run.
              // Links to other sites may open in a new tab.
              <iframe
                title={name}
                src={fileUrl(scanId, name)}
                sandbox="allow-popups allow-popups-to-escape-sandbox"
                className="bl-viewer-iframe"
              />
            ) : (
              <pre className="bl-viewer-pre">{body}</pre>
            ))}
        </Dialog.Body>
      )}
      renderFooter={() => (
        <Dialog.Footer>
          <Button
            as="a"
            variant="primary"
            href={fileUrl(scanId, name)}
            download={name}
            leadingVisual={DownloadIcon}
            onClick={() => toast(t("result.downloadStarted"))}
          >
            {t("result.download")}
          </Button>
          <Button onClick={onClose}>{t("viewer.close")}</Button>
        </Dialog.Footer>
      )}
    />
  );
}
