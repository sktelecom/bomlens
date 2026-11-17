// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ANDROID_SDK_IMAGE_MISSING, type ScanErrorExtra } from "./api";

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
  /** Terms already accepted: the build starts without asking again. */
  | "build"
  /** This run mode cannot build: show the command to run by hand. */
  | "manual";

export interface AndroidSdkNeed {
  api: number;
  image: string;
  termsUrl: string;
  consentRequired: boolean;
  buildAvailable: boolean;
}

/** True for the scan `error` event that asks for the Android SDK image. */
export function isAndroidSdkMissing(code: string | undefined): boolean {
  return code === ANDROID_SDK_IMAGE_MISSING;
}

/** Read the need out of the scan error event; null when it lacks what the
 *  dialog cannot do without (the API level and the image name). */
export function androidSdkNeed(extra: ScanErrorExtra | undefined): AndroidSdkNeed | null {
  if (!extra || !isAndroidSdkMissing(extra.code)) return null;
  if (typeof extra.api !== "number" || !extra.image) return null;
  return {
    api: extra.api,
    image: extra.image,
    termsUrl: extra.termsUrl || ANDROID_TERMS_URL,
    // Unknown means ask: the consent step is the safe default.
    consentRequired: extra.consentRequired !== false,
    // Unknown means the server did not say it cannot.
    buildAvailable: extra.buildAvailable !== false,
  };
}

/** Which first screen to open. A server that cannot build (no recipe mounted) or a
 *  capabilities answer that says so both lead to the manual command. */
export function firstStage(need: AndroidSdkNeed, capabilityBuild: boolean | undefined): AndroidSdkStage {
  if (!need.buildAvailable || capabilityBuild === false) return "manual";
  return need.consentRequired ? "consent" : "build";
}

/** The command that builds the image by hand, run from the folder holding `docker/`. */
export function manualBuildCommand(api: number, image: string): string {
  return `docker build --build-arg ANDROID_API=${api} -t ${image} docker/android`;
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
