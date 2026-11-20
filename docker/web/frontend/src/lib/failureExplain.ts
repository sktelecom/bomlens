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
  switch (code) {
    case "SCAN_TARGET_NOT_VISIBLE":
      return "run.errorTargetNotVisible";
    case "SBOM_FILE_EMPTY":
      return "run.errorSbomEmpty";
    case "SBOM_JSON_TRUNCATED":
      return "run.errorSbomTruncated";
    case "SBOM_NOT_RECOGNIZED":
      return "run.errorSbomNotRecognized";
    default:
      return undefined;
  }
}

/** The scanner's "could not read the image" failure, told apart by what the
 *  registry answered. Docker Hub answers a repository that does not exist with
 *  the same "unauthorized" as one that needs a login, so that case says both. */
const IMAGE_FAILED = /could not read the image|could not pull|pull access denied|failed to (?:pull|read) image/i;
const IMAGE_HOST = /no such host|dial tcp: lookup|name resolution|registry host could not be found/i;
const IMAGE_MISSING =
  /manifest[ _]unknown|name[ _]unknown|manifest for \S+ not found|not found: manifest|no image has that name or tag/i;
const IMAGE_AUTH = /unauthorized|denied|authentication required|requested access/i;

/** Which image failure the scanner's message and the last log lines describe,
 *  or undefined when it is not an image failure or says nothing more precise. */
export function imageFailureKind(
  error: string | null | undefined,
  logs: string[],
): "host" | "missing" | "auth" | undefined {
  const message = error ?? "";
  if (!IMAGE_FAILED.test(message)) return undefined;
  const text = [message, ...logs.slice(-30)].join("\n");
  if (IMAGE_HOST.test(text)) return "host";
  if (IMAGE_MISSING.test(text) && !IMAGE_AUTH.test(text)) return "missing";
  if (IMAGE_AUTH.test(text)) return "auth";
  return undefined;
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
  if (key === "run.errorSbomEmpty" || key === "run.errorSbomTruncated" || key === "run.errorSbomNotRecognized") {
    const causeKey =
      key === "run.errorSbomEmpty"
        ? "source.uploadErrorSbomEmpty"
        : key === "run.errorSbomTruncated"
          ? "source.uploadErrorSbomTruncated"
          : "source.uploadErrorSbomNotRecognized";
    return { causeKey, fixKey: "run.failSbomFileFix", vars: {}, recognised: true };
  }
  // A key this screen does not know: the server's own wording is the cause.
  if (key) return { causeKey: key, fixKey: "run.failGenericFix", vars: {}, recognised: false };

  // A valid JSON file that is no SBOM is let through the upload on purpose and
  // fails here, when the scanner cannot convert it.
  if (/could not convert supplier SBOM/i.test(error ?? "")) {
    return { causeKey: "run.failSbomNotSbomCause", fixKey: "run.failSbomFileFix", vars: {}, recognised: true };
  }

  const image = imageFailureKind(error, logs);
  if (image) {
    const name = image === "host" ? "Host" : image === "missing" ? "Missing" : "Auth";
    return { causeKey: `run.failImage${name}Cause`, fixKey: `run.failImage${name}Fix`, vars: {}, recognised: true };
  }

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
