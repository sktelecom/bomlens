// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon, SyncIcon } from "@primer/octicons-react";
import { Button, Spinner } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import type { ElementType, ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** The model SBOM is being fetched. */
export function ModelsLoading({ text }: { text: string }) {
  return (
    <div className="bl-box bl-md-loading" role="status" data-testid="loading-state">
      <Spinner size="small" srText={null} />
      <span className="bl-muted">{text}</span>
    </div>
  );
}

/** The SBOM could not be read; Retry loads it again. */
export function ModelsError({ text, onRetry }: { text: string; onRetry: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="bl-box" role="alert" data-testid="error-state">
      <Blankslate>
        <Blankslate.Visual>
          <span className="bl-danger bl-inline">
            <AlertIcon size={24} />
          </span>
        </Blankslate.Visual>
        <Blankslate.Heading as="h2">{text}</Blankslate.Heading>
        <div className="bl-md-retry">
          <Button leadingVisual={SyncIcon} onClick={onRetry}>
            {t("retry")}
          </Button>
        </div>
      </Blankslate>
    </div>
  );
}

/** The SBOM holds no model and no dataset. */
export function ModelsEmpty({ icon: Icon, title, hint }: { icon: ElementType; title: string; hint?: ReactNode }) {
  return (
    <div className="bl-box" data-testid="empty-state">
      <Blankslate>
        <Blankslate.Visual>
          <Icon size={24} />
        </Blankslate.Visual>
        <Blankslate.Heading as="h2">{title}</Blankslate.Heading>
        {hint && <Blankslate.Description>{hint}</Blankslate.Description>}
      </Blankslate>
    </div>
  );
}
