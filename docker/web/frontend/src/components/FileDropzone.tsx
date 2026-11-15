// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { PaperclipIcon, UploadIcon, XIcon } from "@primer/octicons-react";
import { Button, ProgressBar } from "@primer/react";
import { useRef, useState, type DragEvent } from "react";
import { useTranslation } from "react-i18next";

import { formatBytes } from "@/lib/utils";

/**
 * File chooser for the upload sources. A drop target as well as a button,
 * because the files these sources take (firmware images, model weights,
 * installers) are things the user is already looking at in a file manager.
 *
 * The native `<input type="file">` stays in the DOM and keeps owning the
 * choice; the visible surface only forwards to it. That keeps the field's
 * validation, its label association and its keyboard behaviour exactly as they
 * were, and means a browser without drag support still works by clicking.
 *
 * Once a file is chosen the zone becomes a summary of it (name, size, and the
 * two things left to do with it) rather than staying an invitation to choose
 * one that has already been chosen.
 *
 * A dropped file whose name does not end in one of the accepted extensions is
 * refused with a message naming the accepted types; the picker already filters
 * by `accept`, a drop does not.
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
  const [refused, setRefused] = useState<string | null>(null);

  const uploading = percent !== null && percent !== undefined;
  const extensions = (accept ?? "")
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  const accepted = (f: File) =>
    extensions.length === 0 || extensions.some((e) => f.name.toLowerCase().endsWith(e));

  const open = () => inputRef.current?.click();

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setOver(false);
    if (disabled) return;
    const dropped = e.dataTransfer.files?.[0];
    if (!dropped) return;
    if (!accepted(dropped)) {
      setRefused(dropped.name);
      return;
    }
    setRefused(null);
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
    <div>
      <input
        ref={inputRef}
        id={id}
        type="file"
        accept={accept}
        disabled={disabled}
        onChange={(e) => {
          setRefused(null);
          onFile(e.target.files?.[0] ?? null);
        }}
        aria-required
        aria-invalid={invalid ? true : undefined}
        aria-describedby={describedBy}
        className="bl-visually-hidden"
      />

      {!file ? (
        <div
          {...dragProps}
          data-testid="dropzone"
          data-over={over ? "" : undefined}
          className="bl-dz"
        >
          <UploadIcon size={20} />
          <span className="bl-muted">{t("source.dropHere")}</span>
          <Button size="small" onClick={open} disabled={disabled}>
            {t("source.browse")}
          </Button>
        </div>
      ) : (
        <div
          {...dragProps}
          data-testid="dropzone"
          data-over={over ? "" : undefined}
          className="bl-dz bl-dz-filled"
        >
          <div className="bl-dz-file">
            <PaperclipIcon size={16} />
            <span className="bl-dz-name" data-testid="dropzone-name">
              {file.name}
            </span>
            <span className="bl-muted bl-small bl-num">{formatBytes(file.size)}</span>
            <Button size="small" onClick={open} disabled={disabled}>
              {t("source.replaceFile")}
            </Button>
            <Button
              size="small"
              variant="invisible"
              aria-label={t("source.removeFile")}
              disabled={disabled}
              onClick={() => {
                if (inputRef.current) inputRef.current.value = "";
                onFile(null);
              }}
            >
              <XIcon size={16} />
            </Button>
          </div>
          {uploading && (
            <div className="bl-dz-progress">
              <ProgressBar
                progress={percent}
                aria-label={t("source.uploading")}
                bg={percent === 100 ? "success.emphasis" : undefined}
              />
              <p className="bl-muted bl-small bl-num" role="status">
                {t("source.uploadingPercent", { percent })}
              </p>
            </div>
          )}
        </div>
      )}
      {refused && (
        <p className="bl-small bl-danger bl-dz-refused" role="alert">
          {t("source.dropRefused", { name: refused, types: accept })}
        </p>
      )}
    </div>
  );
}
