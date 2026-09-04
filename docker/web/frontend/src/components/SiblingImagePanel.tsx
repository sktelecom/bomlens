// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Check, Download, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import {
  fetchImageStatus,
  pullImage,
  type ImageStatus,
  type PullImageKey,
} from "@/lib/api";

/**
 * Offer to download the image a feature needs, before the feature is used.
 *
 * Firmware analysis, AI-model SBOMs and deep CVE matching each live in their own
 * image rather than in this one: the firmware tools are GPL-family, and the AI
 * dependencies are heavy. Until now that image was pulled on the feature's first
 * use, which meant a multi-minute wait in the middle of a scan that the reader
 * could not tell apart from the analysis itself.
 *
 * One component serves all three; the caller passes which feature. The three
 * places that render it are all in the scan form, and the form shows one input at
 * a time, so component-local state is enough.
 *
 * Progress is in layers, not percent. A non-TTY `docker pull` prints no byte
 * totals and no progress bar, so a percentage would be invented.
 */
export function SiblingImagePanel({ imageKey }: { imageKey: PullImageKey }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ImageStatus | null>(null);
  const [pulling, setPulling] = useState(false);
  const [layers, setLayers] = useState<{ complete: number; total: number } | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void fetchImageStatus(imageKey).then((s) => {
      if (alive) setStatus(s);
    });
    return () => {
      alive = false;
    };
  }, [imageKey]);

  // A download in flight is stopped when this unmounts (the user switched input,
  // or closed the app). The layers already fetched stay in the daemon's cache, so
  // starting again resumes instead of restarting.
  const [stop, setStop] = useState<(() => void) | null>(null);
  useEffect(() => () => stop?.(), [stop]);

  const start = () => {
    setFailure(null);
    setLayers(null);
    setPulling(true);
    const cancel = pullImage(imageKey, {
      onProgress: setLayers,
      onDone: (d) => {
        setPulling(false);
        setStop(null);
        if (d.ok) {
          // Re-fetch rather than assume present: true tells us the freshly
          // pulled layer's own version too.
          void fetchImageStatus(imageKey).then(setStatus);
        } else {
          setFailure(d.reason ?? "unknown");
        }
      },
    });
    setStop(() => cancel);
  };

  // Already downloaded: say so and offer nothing to press.
  if (status?.present) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-brand/30 bg-brand/5 px-3 py-2 text-xs text-muted-foreground">
        <Check className="h-3.5 w-3.5 shrink-0 text-brand" aria-hidden />
        <span>{t("image.ready")}</span>
        {status.version && (
          <span
            className="font-mono text-[10px] text-muted-foreground"
            title={t("nav.helpVersion", { version: status.version })}
            data-testid="sibling-image-version"
          >
            {status.version}
          </span>
        )}
      </div>
    );
  }

  const sizeText =
    status?.downloadBytes && status.downloadBytes > 0
      ? t("image.downloadSize", {
          size: (status.downloadBytes / 1024 ** 3).toFixed(1),
        })
      : null;

  return (
    <div className="space-y-2 rounded-md border border-brand/30 bg-brand/5 px-3 py-2 text-xs text-muted-foreground">
      <p>{t("source.siblingPullNotice")}</p>
      {pulling ? (
        <p className="flex items-center gap-2" role="status" aria-live="polite">
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" aria-hidden />
          <span>
            {layers && layers.total > 0
              ? t("image.pullingLayers", { complete: layers.complete, total: layers.total })
              : t("image.pullingStart")}
          </span>
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={start}>
            <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            {t("image.download")}
          </Button>
          {sizeText && <span>{sizeText}</span>}
        </div>
      )}
      {failure && <p className="text-destructive">{t(`image.failed.${failure}`)}</p>}
    </div>
  );
}
