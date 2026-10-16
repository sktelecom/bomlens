// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Ordering of version strings, good enough to answer "which of these fixed
 * versions is later" for the upgrade summary. It is not an ecosystem
 * comparator: Maven qualifiers, Debian epochs and PEP 440 post-releases are
 * read as plain dot-separated parts. Dots, dashes, plus signs, tildes and
 * underscores separate parts; digits compare as numbers, text as text; a text
 * part (rc1, beta) ranks below the release it precedes.
 */

function parts(version: string): string[] {
  return version
    .trim()
    .replace(/^v(?=\d)/i, "")
    .split(/[.\-+~_:]+/)
    .filter((p) => p !== "");
}

const isNumber = (p: string) => /^\d+$/.test(p);

/** Negative when a < b, positive when a > b, 0 when equal as far as we can tell. */
export function compareVersions(a: string, b: string): number {
  const pa = parts(a);
  const pb = parts(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return isNumber(y) ? -1 : 1; // 1.0 < 1.0.1, 1.0 > 1.0-rc1
    if (y === undefined) return isNumber(x) ? 1 : -1;
    if (isNumber(x) && isNumber(y)) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d;
    } else if (isNumber(x)) {
      return 1; // release part outranks a text qualifier
    } else if (isNumber(y)) {
      return -1;
    } else {
      const d = x.localeCompare(y, undefined, { sensitivity: "base" });
      if (d !== 0) return d;
    }
  }
  return 0;
}
