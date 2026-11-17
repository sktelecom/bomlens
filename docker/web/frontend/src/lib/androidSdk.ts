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

/** The tag shown in the command when the release is not known; the dialog tells
 *  the reader to replace it. */
export const TAG_PLACEHOLDER = "<release-tag>";

/** The command that builds the image by hand. It reads the recipe from the
 *  GitHub repository at the release tag, so it works where no `docker/` folder
 *  exists (the run modes that open this step have none). */
export function manualBuildCommand(api: number, image: string, version?: string): string {
  const tag = releaseTag(version) ?? TAG_PLACEHOLDER;
  return `docker build --build-arg ANDROID_API=${api} -t ${image} https://github.com/sktelecom/bomlens.git#${tag}:docker/android`;
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
