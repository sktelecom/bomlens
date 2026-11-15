// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { SyncIcon } from "@primer/octicons-react";
import { Banner, Button } from "@primer/react";
import { useTranslation } from "react-i18next";

/**
 * The conflict check did not run. An empty conflict table would read as an
 * all-clear, so the screen says so, right under its title, and how to turn the
 * check on. The re-scan button is offered only where the New scan form has the
 * field and the scan can be opened again; the command-line form is folded away
 * inside the banner.
 */
export function ConflictOff({
  fieldAvailable,
  onRescan,
}: {
  /** The New scan form has an outbound-license field for this kind of scan. */
  fieldAvailable: boolean;
  onRescan?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Banner
      variant="info"
      data-testid="license-conflict-off"
    >
      <Banner.Title as={"p" as "h2"}>{t("licenses.conflictOffTitle")}</Banner.Title>
      <Banner.Description>
        {fieldAvailable ? t("licenses.conflictOffHint") : t("licenses.conflictOffNoField")}
        {/* A plain button, not the Banner's own action: that one is drawn twice
            (once per layout) and would be two buttons to a screen reader and a test. */}
        {fieldAvailable && onRescan && (
          <div className="bl-lic-action">
            <Button size="small" leadingVisual={SyncIcon} data-testid="rescan-with-license" onClick={onRescan}>
              {t("licenses.conflictOffAction")}
            </Button>
          </div>
        )}
        <details className="bl-lic-cli">
          <summary>{t("licenses.conflictOffCli")}</summary>
          <p className="bl-small">{t("licenses.conflictOffCliBody")}</p>
        </details>
      </Banner.Description>
    </Banner>
  );
}
