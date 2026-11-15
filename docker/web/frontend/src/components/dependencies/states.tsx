// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon, SyncIcon } from "@primer/octicons-react";
import { Button, Spinner } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import type { ElementType, ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** The SBOM is being fetched. */
export function DepLoading({ text }: { text: string }) {
  return (
    <div className="bl-box bl-dep-loading" role="status" data-testid="deps-loading">
      <Spinner size="small" srText={null} />
      <span className="bl-muted">{text}</span>
    </div>
  );
}

/** The SBOM or the graph canvas failed; Retry loads it again. */
export function DepError({ text, onRetry }: { text: string; onRetry: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="bl-box" role="alert" data-testid="deps-error">
      <Blankslate>
        <Blankslate.Visual>
          <span className="bl-danger bl-inline">
            <AlertIcon size={24} />
          </span>
        </Blankslate.Visual>
        <Blankslate.Heading as="h2">{text}</Blankslate.Heading>
        <div className="bl-dep-retry">
          <Button leadingVisual={SyncIcon} onClick={onRetry}>
            {t("retry")}
          </Button>
        </div>
      </Blankslate>
    </div>
  );
}

/** Nothing to draw: no relationships, a graph over the cap, no packages. */
export function DepEmpty({
  icon: Icon,
  title,
  hint,
  testId,
}: {
  icon: ElementType;
  title: string;
  hint?: ReactNode;
  testId?: string;
}) {
  return (
    <div className="bl-box" data-testid={testId}>
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
