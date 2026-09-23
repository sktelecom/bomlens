// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Helpers for the "Report a problem" path: where the issue form lives and how
 * text gets onto the clipboard. Nothing here sends data anywhere: the user
 * reads the text on screen, copies it, and pastes it into the form themselves.
 */

/** The bug-report issue form. Its required fields are defined in
 *  .github/ISSUE_TEMPLATE/bug_report.yml. */
export const ISSUE_FORM_URL =
  "https://github.com/sktelecom/bomlens/issues/new?template=bug_report.yml";

interface ClipboardEnv {
  clipboard?: { writeText?: (text: string) => Promise<void> };
}

/**
 * Put `text` on the clipboard. Returns whether it worked, so the caller can say
 * so instead of failing silently: an insecure context or a denied permission
 * makes `navigator.clipboard` unavailable, and the user then still has the text
 * on screen to select by hand.
 */
export async function copyToClipboard(
  text: string,
  nav: ClipboardEnv | undefined = typeof navigator === "undefined" ? undefined : navigator,
): Promise<boolean> {
  const write = nav?.clipboard?.writeText;
  if (typeof write !== "function") return false;
  try {
    await write.call(nav!.clipboard, text);
    return true;
  } catch {
    return false;
  }
}
