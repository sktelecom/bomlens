// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import data from "./license-obligations.json";
import { hasLicenseException, parseLicenseExpression } from "./licenses";

/** What a license asks of someone who redistributes the licensed material. */
export type ObligationTag =
  | "include-copyright"
  | "include-copyright--source"
  | "document-changes"
  | "disclose-source"
  | "network-use-disclose"
  | "same-license"
  | "same-license--file"
  | "same-license--library";

/** Fixed display order, so the same license always reads the same way. */
export const OBLIGATION_ORDER: ObligationTag[] = [
  "include-copyright",
  "include-copyright--source",
  "document-changes",
  "disclose-source",
  "network-use-disclose",
  "same-license",
  "same-license--file",
  "same-license--library",
];

export interface ObligationTerm {
  term: string;
  /** Null when the term is not in the data set, or carries an exception clause. */
  tags: ObligationTag[] | null;
}

/**
 * - `known`: one license found in the data set (an empty list means it attaches
 *   no conditions to redistribution).
 * - `expression`: an SPDX expression, one list of AND terms per OR alternative.
 * - `unknown`: nothing could be resolved. Never filled in by guessing.
 */
export type LicenseObligations =
  | { kind: "known"; tags: ObligationTag[] }
  | { kind: "expression"; alternatives: ObligationTerm[][] }
  | { kind: "unknown" };

const LICENSES = new Map<string, ObligationTag[]>(
  Object.entries(data.licenses as Record<string, string[]>).map(([id, tags]) => [
    id.toUpperCase(),
    OBLIGATION_ORDER.filter((t) => tags.includes(t)),
  ]),
);
const ALIASES = data.aliases as Record<string, string>;

function lookup(term: string): ObligationTag[] | null {
  // An exception clause exists to lift a condition of the base license, so the
  // base license's list would overstate what applies.
  if (hasLicenseException(term)) return null;
  const key = term.trim().toUpperCase();
  const id = (ALIASES[key] ?? key).toUpperCase();
  return LICENSES.get(id) ?? null;
}

export function licenseObligations(name: string): LicenseObligations {
  const alternatives = parseLicenseExpression(name).map((alt) =>
    alt.map((term) => ({ term, tags: lookup(term) })),
  );
  const terms = alternatives.flat();
  if (terms.length === 0 || terms.every((t) => t.tags === null)) {
    return { kind: "unknown" };
  }
  if (alternatives.length === 1 && alternatives[0].length === 1) {
    return { kind: "known", tags: alternatives[0][0].tags ?? [] };
  }
  return { kind: "expression", alternatives };
}
