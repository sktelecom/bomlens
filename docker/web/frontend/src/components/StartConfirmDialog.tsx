// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useId, useRef } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/dialog";
import type { StartConfirm } from "@/lib/useScanForm";

/** How many project names the question lists before it counts the rest. */
const NAMES_SHOWN = 6;

interface Props {
  /** The question to ask, or null when none is open. */
  confirm: StartConfirm | null;
  project: string;
  version: string;
  onAnswer: (choice: "go" | "keep" | "cancel") => void;
}

/**
 * Asked before a scan starts when the folder holds several projects (they would
 * merge into one SBOM) or a finished scan of the same name would be replaced.
 * Focus opens on Cancel, so a stray Enter starts nothing.
 */
export function StartConfirmDialog({ confirm, project, version, onAnswer }: Props) {
  const { t } = useTranslation();
  const id = useId();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const merged = confirm?.merged ?? [];
  const overwrite = confirm?.overwrite ?? false;
  const shown = merged.slice(0, NAMES_SHOWN).join(", ");
  const rest = merged.length - NAMES_SHOWN;
  const title =
    merged.length > 0 && overwrite
      ? t("startConfirm.titleBoth")
      : overwrite
        ? t("startConfirm.titleOverwrite")
        : t("startConfirm.titleMerged");
  return (
    <Modal
      open={confirm !== null}
      onClose={() => onAnswer("cancel")}
      labelledBy={`${id}-title`}
      describedBy={`${id}-desc`}
      initialFocus={cancelRef}
      className="max-w-md gap-4 p-6"
    >
      <h2 id={`${id}-title`} className="text-body font-semibold">
        {title}
      </h2>
      <div id={`${id}-desc`} className="space-y-2 text-body-sm text-muted-foreground">
        {merged.length > 0 && (
          <p data-testid="confirm-merged">
            {t("startConfirm.merged", { n: merged.length, names: shown })}
            {rest > 0 && ` ${t("startConfirm.mergedMore", { n: rest })}`}
          </p>
        )}
        {overwrite && (
          <p data-testid="confirm-overwrite">
            {t("startConfirm.overwrite", { name: [project, version].filter(Boolean).join(" ") })}
          </p>
        )}
      </div>
      <div className="flex flex-wrap justify-end gap-2">
        <Button ref={cancelRef} variant="outline" size="sm" onClick={() => onAnswer("cancel")}>
          {t("dialog.cancel")}
        </Button>
        {overwrite && (
          <Button variant="outline" size="sm" onClick={() => onAnswer("keep")} data-testid="confirm-keep">
            {t("startConfirm.keepBoth")}
          </Button>
        )}
        <Button size="sm" onClick={() => onAnswer("go")} data-testid="confirm-go">
          {overwrite ? t("startConfirm.replace") : t("startConfirm.continue")}
        </Button>
      </div>
    </Modal>
  );
}
