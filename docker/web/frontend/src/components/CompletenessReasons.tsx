// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import type { Completeness } from "@/lib/api";
import { reasonLines } from "@/lib/completeness";

/**
 * The engine's reasons and how to fix each, in the UI language. The sentences
 * are the ones the reports print (the server passes them through), so they are
 * not in the locale files.
 */
export function CompletenessReasons({ completeness }: { completeness: Completeness }) {
  const { t, i18n } = useTranslation();
  const lines = reasonLines(completeness, i18n.language ?? "en");
  return (
    <ul className="bl-flat bl-cmp-reasons" data-testid="completeness-reasons">
      {lines.map((r, i) => (
        <li key={`${r.code}-${i}`} data-reason={r.code}>
          <span>{r.message}</span>
          {r.fix && (
            <span className="bl-cmp-fix">
              <span className="bl-strong">{t("completeness.fix")}</span> {r.fix}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
