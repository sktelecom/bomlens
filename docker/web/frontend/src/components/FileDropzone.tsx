// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Paperclip, Upload, X } from "lucide-react";
import { useRef, useState, type DragEvent } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { formatBytes } from "@/lib/utils";

/**
 * File chooser for the upload sources. A drop target as well as a button,
 * because the files these sources take — firmware images, model weights,
 * installers — are things the user is already looking at in a file manager.
 *
 * The native `<input type="file">` stays in the DOM and keeps owning the
 * choice; the visible surface only forwards to it. That keeps the field's
 * validation, its label association and its keyboard behaviour exactly as they
 * were, and means a browser without drag support still works by clicking.
 *
 * Once a file is chosen the zone becomes a summary of it — name, size, and the
 * two things left to do with it — rather than staying an invitation to choose
 * one that has already been chosen.
 */
export function FileDropzone({
  id,
  accept,
  file,
  onFile,
  disabled,
  percent,
  invalid,
  describedBy,
}: {
  id: string;
  accept?: string;
  file: File | null;
  onFile: (file: File | null) => void;
  disabled?: boolean;
  /** 0-100 while this file is uploading; null when it is not. */
  percent?: number | null;
  invalid?: boolean;
  describedBy?: string;
}) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  const uploading = percent !== null && percent !== undefined;

  const open = () => inputRef.current?.click();

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setOver(false);
    if (disabled) return;
    const dropped = e.dataTransfer.files?.[0];
    if (!dropped) return;
    // Mirror the drop into the real input so the form reads one source of
    // truth, and so a submit-time check sees the same FileList a click would
    // have produced.
    if (inputRef.current) {
      const dt = new DataTransfer();
      dt.items.add(dropped);
      inputRef.current.files = dt.files;
    }
    onFile(dropped);
  };

  const dragProps = {
    onDragOver: (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      if (!disabled) setOver(true);
    },
    onDragLeave: () => setOver(false),
    onDrop,
  };

  return (
    <div className="space-y-2">
      <input
        ref={inputRef}
        id={id}
        type="file"
        accept={accept}
        disabled={disabled}
        onChange={(e) => onFile(e.target.files?.[0] ?? null)}
        aria-required
        aria-invalid={invalid ? true : undefined}
        aria-describedby={describedBy}
        className="sr-only"
      />

      {!file ? (
        <div
          {...dragProps}
          data-testid="dropzone"
          data-over={over ? "" : undefined}
          className={[
            "flex flex-col items-center gap-2 rounded-md border border-dashed px-4 py-6 text-center transition-colors duration-fast ease-out-soft",
            over ? "border-foreground/60 bg-muted" : "border-input bg-muted/30",
            disabled ? "opacity-50" : "",
          ].join(" ")}
        >
          <Upload className="h-5 w-5 text-muted-foreground" aria-hidden />
          <p className="text-body-sm text-muted-foreground">{t("source.dropHere")}</p>
          <Button type="button" variant="outline" size="sm" onClick={open} disabled={disabled}>
            {t("source.browse")}
          </Button>
        </div>
      ) : (
        <div
          {...dragProps}
          data-testid="dropzone"
          data-over={over ? "" : undefined}
          className={[
            "rounded-md border px-3 py-2.5 transition-colors duration-fast ease-out-soft",
            over ? "border-foreground/60 bg-muted" : "border-input bg-background",
          ].join(" ")}
        >
          <div className="flex items-center gap-2">
            <Paperclip className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="min-w-0 flex-1 truncate text-body-sm" data-testid="dropzone-name">
              {file.name}
            </span>
            <span className="shrink-0 text-label tabular-nums text-muted-foreground">
              {formatBytes(file.size)}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={open}
              disabled={disabled}
              className="shrink-0"
            >
              {t("source.replaceFile")}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                if (inputRef.current) inputRef.current.value = "";
                onFile(null);
              }}
              disabled={disabled}
              aria-label={t("source.removeFile")}
              className="shrink-0 px-2"
            >
              <X className="h-4 w-4" aria-hidden />
            </Button>
          </div>
          {uploading && (
            <div className="mt-2.5 space-y-1">
              <Progress
                value={percent}
                aria-label={t("source.uploading")}
                indicatorClassName={percent === 100 ? "bg-success-solid" : undefined}
              />
              <p className="text-label tabular-nums text-muted-foreground" role="status">
                {t("source.uploadingPercent", { percent })}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
