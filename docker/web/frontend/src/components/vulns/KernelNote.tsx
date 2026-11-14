// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon } from "@primer/octicons-react";
import { useTranslation } from "react-i18next";

/**
 * Kernel advisories are reported but kept out of the figures. An old kernel
 * carries thousands, nearly all for subsystems the image never compiled in, and
 * the SBOM cannot tell which, so counting them would bury the findings this
 * screen exists to show. One line, with the reason folded away: it is a note
 * above the table, not a finding.
 */
export function KernelNote({ count }: { count: number }) {
  const { t } = useTranslation();
  return (
    <details className="bl-box bl-v-note" data-testid="kernel-advisories-notice" data-coverage-notice="" role="note">
      <summary>
        <span className="bl-chev">
          <ChevronRightIcon size={16} />
        </span>
        <span>{t("result.kernelAdvisories", { count })}</span>
      </summary>
      <p className="bl-muted bl-flat bl-v-note-why">{t("result.kernelAdvisoriesWhy")}</p>
    </details>
  );
}
