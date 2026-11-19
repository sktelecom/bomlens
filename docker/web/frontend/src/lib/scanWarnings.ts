// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Warnings the scanner printed while it ran, as the result screen lists them.
 * The server puts a machine-readable code in front of the ones it recognizes
 * ("CODE: [WARN] original text"), so the screen can say them in the reader's
 * language; any other warning is shown as the scanner wrote it.
 */

/** i18n key for each code the server may send. */
const WARNING_CODE_KEY: Record<string, string> = {
  SAME_FOLDER_SCAN_RUNNING: "result.warnSameFolderScan",
};

const CODED = /^([A-Z][A-Z0-9_]+):\s*([\s\S]*)$/;

export interface ScanWarningText {
  /** i18n key to translate, or null to show `text` as is. */
  key: string | null;
  /** The scanner's own wording, without its "[WARN]" marker or the code. */
  text: string;
}

export function scanWarningText(raw: string): ScanWarningText {
  const m = CODED.exec(raw);
  const code = m?.[1];
  const rest = (m ? m[2] : raw).replace(/^\[WARN\]\s*/, "");
  if (code && code in WARNING_CODE_KEY) return { key: WARNING_CODE_KEY[code], text: rest };
  // A line that merely starts like a code but is not one stays whole.
  return { key: null, text: raw.replace(/^\[WARN\]\s*/, "") };
}
