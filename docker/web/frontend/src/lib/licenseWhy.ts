// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { LocalizedText } from "./localized";

/**
 * The reason a license conflict verdict carries (`bomlens:licenseConflictWhy`)
 * as an i18n key, so the Licenses section reads in the UI language.
 *
 * The scanner writes the English sentence from docker/lib/license-compat.json
 * (or one of the fixed sentences license-flags.jq and licenses.ts write around
 * it). The SBOM stays English; the translation happens here, at render time,
 * by recognising those sentences. A sentence that is not recognised (a newer
 * rules file, a hand-edited SBOM) returns null and the caller shows it as is.
 * licenseWhy.test.ts reads the rules file and fails when a sentence in it has
 * no key here.
 */

/** Key suffix (under `licenses.why.`) per fixed English sentence. */
const FIXED: Record<string, string> = {
  "Both are permissive; keep the notices.": "permissivePermissive",
  "File- or library-level reciprocity: changes to the dependency stay under its license, and static linking adds obligations. Distributing your own code under the permissive license is still fine.":
    "permissiveWeak",
  "Distributing a combined work requires the whole work to be offered under the copyleft license, which the declared permissive outbound license does not do.":
    "permissiveStrong",
  "Network copyleft extends the reciprocity to users served over a network, which the declared permissive outbound license cannot satisfy.":
    "permissiveNetwork",
  "The dependency's license was not recognised.": "unrecognised",
  "A permissive dependency imposes no reciprocal obligation.": "weakPermissive",
  "Two file- or library-level reciprocal licenses. Each keeps its own scope, so check that the boundaries do not overlap in the combined work.":
    "weakWeak",
  "The dependency requires the combined work to be offered under its terms, which a weaker reciprocal outbound license does not provide.":
    "weakStrong",
  "The dependency adds network-use reciprocity that the declared outbound license does not carry.":
    "weakNetwork",
  "Permissive terms can be met while distributing under a strong copyleft license.":
    "strongPermissive",
  "Usually absorbable into a strong copyleft work, but some file-level reciprocal licenses need an explicit compatibility clause. Check the specific pair.":
    "strongWeak",
  "Same family, but versions differ in compatibility \u2014 notably GPL-2.0-only cannot be combined with GPL-3.0 code. Check the versions.":
    "strongStrong",
  "Network copyleft adds obligations beyond the declared outbound license; combining is allowed in one direction only. Check which way this goes.":
    "strongNetwork",
  "Permissive terms can be met while distributing under a network copyleft license.":
    "networkPermissive",
  "Usually absorbable, but check whether the dependency's reciprocal scope has an explicit compatibility clause.":
    "networkWeak",
  "AGPL-3.0 and GPL-3.0 are designed to combine; older strong copyleft versions are not. Check the versions.":
    "networkStrong",
  "Same reciprocal scope.": "networkNetwork",
  "The FSF treats Apache-2.0's patent termination and indemnification terms as further restrictions that GPL-2.0 does not permit. GPL-3.0 does not have this problem.":
    "gpl2Apache2",
  "The advertising and naming clauses are further restrictions that GPL-2.0 does not permit.":
    "gpl2Apache11",
  "No rule for this combination.": "noRule",
  "The component declares no license.": "noLicense",
  "The declared license could not be parsed as an SPDX expression.": "unparsedDeclared",
};

const UNPARSED = /^The license "(.*)" could not be parsed as an SPDX expression\.$/;
const EXCEPTION =
  /^The dependency carries an exception clause, which exists to permit exactly this combination\. Confirm the exception covers your use\. \((.*)\)$/;

export function conflictWhyKey(why: string): LocalizedText | null {
  const s = why.trim();
  const fixed = FIXED[s];
  if (fixed) return { key: `licenses.why.${fixed}` };
  const unparsed = UNPARSED.exec(s);
  if (unparsed) return { key: "licenses.why.unparsedLicense", params: { license: unparsed[1] } };
  const exception = EXCEPTION.exec(s);
  if (exception) {
    const inner = conflictWhyKey(exception[1]);
    if (!inner) return null;
    return { key: "licenses.why.exception", params: { inner } };
  }
  return null;
}

/** Every key this module can return, for the locale coverage test. */
export const CONFLICT_WHY_KEYS: readonly string[] = [
  ...new Set(Object.values(FIXED)),
  "unparsedLicense",
  "exception",
].map((k) => `licenses.why.${k}`);
