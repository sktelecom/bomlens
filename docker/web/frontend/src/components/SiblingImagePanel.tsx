// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { CheckCircleIcon, DownloadIcon } from "@primer/octicons-react";
import { Button, Spinner } from "@primer/react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

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
      <div className="bl-inset bl-small bl-sibling-ready">
        <span className="bl-success">
          <CheckCircleIcon size={16} />
        </span>
        <span>{t("image.ready")}</span>
        {status.version && (
          <span
            className="bl-mono bl-muted"
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
    <div className="bl-inset bl-small bl-stack-8">
      <span className="bl-muted">{t("source.siblingPullNotice")}</span>
      {pulling ? (
        <span role="status" aria-live="polite" className="bl-inline">
          <Spinner size="small" srText={null} />
          {layers && layers.total > 0
            ? t("image.pullingLayers", { complete: layers.complete, total: layers.total })
            : t("image.pullingStart")}
        </span>
      ) : (
        <span className="bl-inline bl-wrap">
          <Button size="small" leadingVisual={DownloadIcon} onClick={start}>
            {t("image.download")}
          </Button>
          {sizeText && <span className="bl-muted">{sizeText}</span>}
        </span>
      )}
      {failure && <span className="bl-danger">{t(`image.failed.${failure}`)}</span>}
    </div>
  );
}
