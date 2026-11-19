// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A rough time for analyzing a large supplier SBOM, so the wait is not a
 * surprise. Measured: a 14 MB CycloneDX file with 30,000 components took about
 * 5 minutes on a busy machine, which is about 20 seconds per MB. A faster
 * machine takes less, so the screen says "about" and "or more", not a promise.
 */
const SECONDS_PER_MB = 20;
/** Below this size the analysis is quick enough that no note is shown. */
export const LARGE_SBOM_BYTES = 5 * 1024 * 1024;

/** Minutes to show for an SBOM of this size, or null when it is not large. */
export function analyzeMinutesEstimate(bytes: number): number | null {
  if (!Number.isFinite(bytes) || bytes < LARGE_SBOM_BYTES) return null;
  const minutes = Math.round((bytes / (1024 * 1024)) * SECONDS_PER_MB / 60);
  return Math.max(1, minutes);
}
