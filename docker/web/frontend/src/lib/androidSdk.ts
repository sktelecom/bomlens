// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ANDROID_SDK_IMAGE_MISSING, errorCodeOf, type ScanErrorExtra } from "./api";

/**
 * What the Android SDK dialog shows, decided from what the server said. Kept out
 * of the component so the choice (ask first, build now, or only explain) is a
 * plain function with tests.
 */

/** The Google terms page the server records acceptance against. */
export const ANDROID_TERMS_URL = "https://developer.android.com/studio/terms";

export type AndroidSdkStage =
  /** Terms not accepted yet: explain, link the terms, wait for the choice. */
  | "consent"
  /** Terms already accepted: say that a build is about to start (it takes time
   *  and disk) and wait for the start button. */
  | "confirm"
  /** This run mode cannot build: show the command to run by hand. */
  | "manual";

export interface AndroidSdkNeed {
  api: number;
  image: string;
  termsUrl: string;
  consentRequired: boolean;
  buildAvailable: boolean;
  /** The host path of the launcher's own docker/android recipe, when it said
   *  so: the manual command then builds from it, as the CLI does. */
  hostBuildDir?: string;
}

/** True for the scan `error` event that asks for the Android SDK image. */
export function isAndroidSdkMissing(code: string | undefined): boolean {
  return code === ANDROID_SDK_IMAGE_MISSING;
}

/** Read the need out of the scan error event; null when it lacks what the
 *  dialog cannot do without (the API level and the image name). */
export function androidSdkNeed(extra: ScanErrorExtra | undefined): AndroidSdkNeed | null {
  if (!extra || !isAndroidSdkMissing(errorCodeOf(extra))) return null;
  if (typeof extra.api !== "number" || !extra.image) return null;
  return {
    api: extra.api,
    image: extra.image,
    termsUrl: extra.termsUrl || ANDROID_TERMS_URL,
    // Unknown means ask: the consent step is the safe default.
    consentRequired: extra.consentRequired !== false,
    // Unknown means the server did not say it cannot.
    buildAvailable: extra.buildAvailable !== false,
    ...(typeof extra.hostBuildDir === "string" && extra.hostBuildDir.trim()
      ? { hostBuildDir: extra.hostBuildDir.trim() }
      : {}),
  };
}

/** Which first screen to open. A server that cannot build (no recipe mounted) or a
 *  capabilities answer that says so both lead to the manual command. */
export function firstStage(need: AndroidSdkNeed, capabilityBuild: boolean | undefined): AndroidSdkStage {
  if (!need.buildAvailable || capabilityBuild === false) return "manual";
  return need.consentRequired ? "consent" : "confirm";
}

const RELEASE_VERSION = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

/** The git tag of this app's release (`v1.15.0`), from the version the server
 *  reports. Null when it is not a release (empty on a local build, `latest-<sha>`
 *  on a main build), because then no tag names the recipe that matches. */
export function releaseTag(version: string | undefined): string | null {
  const m = RELEASE_VERSION.exec((version ?? "").trim());
  return m ? `v${m[1]}` : null;
}

/** The branch the command reads when the release is not known, as the CLI does. */
export const DEFAULT_BRANCH = "main";

/** A path as one shell word: left as is when it holds only plain characters,
 *  otherwise in single quotes. */
function shellWord(path: string): string {
  return /^[A-Za-z0-9._/:@%+=,-]+$/.test(path) ? path : `'${path.replace(/'/g, "'\\''")}'`;
}

/** The command that builds the image by hand, runnable as shown. With the host
 *  path of the launcher's own recipe it builds from that folder, as the CLI
 *  prints it. Otherwise it reads the recipe from the GitHub repository, at the
 *  release tag, or at the main branch when this is not a release. */
export function manualBuildCommand(api: number, image: string, version?: string, hostBuildDir?: string): string {
  const ctx = hostBuildDir
    ? shellWord(hostBuildDir)
    : `https://github.com/sktelecom/bomlens.git#${releaseTag(version) ?? DEFAULT_BRANCH}:docker/android`;
  return `docker build --build-arg ANDROID_API=${api} -t ${image} ${ctx}`;
}

const REASONS = new Set([
  "no-consent",
  "no-build-files",
  "no-docker",
  "busy",
  "cancelled",
  "disk",
  "dns",
  "proxy",
  "auth",
  "notfound",
  "build-failed",
  "sdk-install",
  "connection",
]);

/** The i18n suffix for a failed build's reason; anything unlisted reads as unknown. */
export function failureReason(reason: string | undefined): string {
  return reason && REASONS.has(reason) ? reason : "unknown";
}

/** Whether a build that ended with this reason can sensibly be started again. */
export function canRetryBuild(reason: string | undefined): boolean {
  return reason !== "no-build-files" && reason !== "no-docker" && reason !== "no-consent";
}

/** The scan can be replayed on its own only when it holds no one-shot upload
 *  token or credential, the same rule the failed-scan Retry button follows. */
export function canReplayScan(p: { token?: string; cred?: string; scanossCred?: string } | null): boolean {
  return Boolean(p && !p.token && !p.cred && !p.scanossCred);
}
