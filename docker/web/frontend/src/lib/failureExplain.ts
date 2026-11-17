// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A failed scan in words the reader can act on: what went wrong and what to do.
 * The server's own message (the end of the scanner log, often cut mid-sentence)
 * and the full log stay available in the folded run log; this is the lead.
 */
export interface FailureExplanation {
  /** i18n key of the sentence saying what went wrong. */
  causeKey: string;
  /** i18n key of the sentence saying what to do. */
  fixKey: string;
  /** Values for the two sentences. */
  vars: Record<string, string>;
  /** False when the failure was not recognised: the reader must open the run log. */
  recognised: boolean;
}

/** The i18n key a machine-readable failure code is explained by, or undefined
 *  for a code this screen has no wording for. */
export function failureKeyForCode(code: string | undefined): string | undefined {
  return code === "SCAN_TARGET_NOT_VISIBLE" ? "run.errorTargetNotVisible" : undefined;
}

const TOOLS = /\b(cdxgen|syft|trivy|grype)\b/gi;
/** Lines before the exit line that still belong to the same failing command. */
const NEAR = 4;

/** The last match of a global pattern in the text, or undefined. */
function lastMatch(re: RegExp, text: string): string | undefined {
  let found: string | undefined;
  for (const m of text.matchAll(re)) found = m[1] ?? m[0];
  return found?.toLowerCase();
}

/**
 * Classify a failure from the server's key, or from the end of the log.
 *
 * A build log is long and chatty: an earlier warning that mentions an
 * exception, another tool or Node.js says nothing about why the scan stopped.
 * So the exit code, the tool and the runtime are read only from the last
 * "exited with code N" line and the few lines just before it (or, with no such
 * line, the last few lines). An internal error needs the Python traceback
 * header, not any word that contains "Exception".
 */
export function explainFailure(
  logs: string[],
  error: string | null | undefined,
  key: string | null | undefined,
): FailureExplanation {
  if (key === "run.errorGitNotFoundOrPrivate") {
    return { causeKey: "run.failGitPrivateCause", fixKey: "run.failGitPrivateFix", vars: {}, recognised: true };
  }
  if (key === "run.errorGitNetwork") {
    return { causeKey: "run.failGitNetworkCause", fixKey: "run.failGitNetworkFix", vars: {}, recognised: true };
  }
  if (key === "run.errorTargetNotVisible") {
    return { causeKey: "run.failTargetHiddenCause", fixKey: "run.failTargetHiddenFix", vars: {}, recognised: true };
  }
  // A key this screen does not know: the server's own wording is the cause.
  if (key) return { causeKey: key, fixKey: "run.failGenericFix", vars: {}, recognised: false };

  const lines = [...logs, ...(error ?? "").split("\n")];
  let exit = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (/exited with code \d+/.test(lines[i])) {
      exit = i;
      break;
    }
  }
  const end = exit >= 0 ? exit + 1 : lines.length;
  const tail = lines.slice(Math.max(0, end - NEAR + 1), end).join("\n");
  const code = exit >= 0 ? /exited with code (\d+)/.exec(lines[exit])?.[1] : undefined;
  if (code === "126" || /cannot execute binary file|Exec format error/.test(tail)) {
    return {
      causeKey: "run.fail126Cause",
      fixKey: "run.fail126Fix",
      // An unknown tool or runtime is named by a translated phrase, set by the caller.
      vars: { tool: lastMatch(TOOLS, tail) ?? "", runtime: /\bnode(\.js)?\b/i.test(tail) ? "Node.js" : "" },
      recognised: true,
    };
  }
  if (/Traceback \(most recent call last\)/.test(lines.join("\n"))) {
    return { causeKey: "run.failInternalCause", fixKey: "run.failInternalFix", vars: {}, recognised: true };
  }
  return { causeKey: "run.failGenericCause", fixKey: "run.failGenericFix", vars: {}, recognised: false };
}
