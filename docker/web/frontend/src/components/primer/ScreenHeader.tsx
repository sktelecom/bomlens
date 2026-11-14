// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { PageHeader } from "@primer/react";
import type { ReactNode } from "react";

/**
 * The head of a screen that is not a scan section (Scan management, New scan,
 * External lookup): a PageHeader title at its default size, one description
 * line and, optionally, the screen's actions.
 */
export function ScreenHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <PageHeader>
      <PageHeader.TitleArea>
        <PageHeader.Title as="h1">{title}</PageHeader.Title>
      </PageHeader.TitleArea>
      {description && (
        <PageHeader.Description>
          <span style={{ fontSize: "var(--text-body-size-medium)", color: "var(--fgColor-muted)" }}>
            {description}
          </span>
        </PageHeader.Description>
      )}
      {actions && <PageHeader.Actions>{actions}</PageHeader.Actions>}
    </PageHeader>
  );
}
