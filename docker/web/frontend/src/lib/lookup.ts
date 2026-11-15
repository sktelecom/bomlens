// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure input classifier for the External lookup screen (`#/lookup`).
 *
 * One text box doubles as an advisory-id field, a purl field and a bare
 * package-name field: the screen decides which server endpoint to call
 * (`GET /advisory` vs `GET /package-advisories`, see `lib/api.ts`) from the
 * shape of what was typed, never from an explicit mode switch the user has to
 * set first. Kept free of React so the classification is unit-testable
 * without mounting anything.
 */
import { ECOSYSTEM_SLUGS, type EcosystemSlug } from "./api";

const ADVISORY_ID_PREFIXES = [
  "CVE-",
  "GHSA-",
  "GO-",
  "PYSEC-",
  "RUSTSEC-",
  "OSV-",
  "GSD-",
  "MAL-",
] as const;

/** purl `type` -> the server's ecosystem slug (server.py's `_OSV_ECOSYSTEMS`
 *  keys). A purl type outside this map has no OSV ecosystem to query. */
const PURL_TYPE_TO_ECOSYSTEM: Record<string, EcosystemSlug> = {
  npm: "npm",
  pypi: "pypi",
  maven: "maven",
  golang: "go",
  cargo: "cargo",
  gem: "rubygems",
  composer: "packagist",
  nuget: "nuget",
};

export type ParsedLookup =
  | { kind: "empty" }
  /** A known advisory-id namespace, routes to `GET /advisory`. */
  | { kind: "advisory"; id: string }
  /** Routes to `GET /package-advisories`. `ecosystem` is set when the purl
   *  named one; otherwise the screen must ask the user to pick one.
   *  `version` is "" when it still needs to be entered (a bare name, a purl
   *  with no `@version`, or a name typed with no version). */
  | { kind: "package"; ecosystem?: EcosystemSlug; name: string; version: string }
  /** A purl whose `type` has no OSV ecosystem mapping (e.g. `pkg:deb/...`). */
  | { kind: "unsupportedPurl"; type: string };

/** Re-exported for the screen's ecosystem picker (server contract order). */
export { ECOSYSTEM_SLUGS };
export type { EcosystemSlug };

/**
 * Classify one line of user input for the lookup screen. Never throws:
 * anything that isn't a recognized id or purl falls back to `package` with
 * the whole trimmed string as the name, letting the server's own validation
 * (400 `invalid id` / `invalid request`) have the final word.
 */
export function parseLookupInput(raw: string): ParsedLookup {
  const input = raw.trim();
  if (!input) return { kind: "empty" };

  const upper = input.toUpperCase();
  const prefix = ADVISORY_ID_PREFIXES.find((p) => upper.startsWith(p));
  if (prefix) {
    // Canonicalize only the prefix's casing; OSV ids are case-sensitive after
    // it (e.g. GHSA's suffix is lowercase hex-ish), so the rest is untouched.
    return { kind: "advisory", id: prefix + input.slice(prefix.length) };
  }

  if (/^pkg:/i.test(input)) return parsePurl(input);

  // A bare package name, or "name@version" / "name version". The "@" split
  // uses the *last* "@" so a scoped npm name ("@angular/core@6.6.6") keeps its
  // leading "@" as part of the name.
  const atIdx = input.lastIndexOf("@");
  if (atIdx > 0) {
    return {
      kind: "package",
      name: input.slice(0, atIdx).trim(),
      version: input.slice(atIdx + 1).trim(),
    };
  }
  const spaceIdx = input.search(/\s/);
  if (spaceIdx > 0) {
    return {
      kind: "package",
      name: input.slice(0, spaceIdx).trim(),
      version: input.slice(spaceIdx + 1).trim(),
    };
  }
  return { kind: "package", name: input, version: "" };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** `pkg:type/namespace/name@version?qualifiers#subpath`: only type, the
 *  joined namespace+name, and version matter for a lookup; qualifiers and
 *  subpath are dropped. */
function parsePurl(input: string): ParsedLookup {
  const rest = input.slice(4); // strip the leading "pkg:"
  const withoutSubpath = rest.split("#")[0];
  const withoutQualifiers = withoutSubpath.split("?")[0];
  const slashIdx = withoutQualifiers.indexOf("/");
  if (slashIdx < 0) {
    // No "/" at all: not a well-formed purl path, but still worth trying as
    // a bare name so a half-typed purl doesn't dead-end the screen.
    return { kind: "package", name: safeDecode(withoutQualifiers), version: "" };
  }
  const type = withoutQualifiers.slice(0, slashIdx).toLowerCase();
  let pathAndVersion = withoutQualifiers.slice(slashIdx + 1);
  let version = "";
  const atIdx = pathAndVersion.lastIndexOf("@");
  if (atIdx >= 0) {
    version = safeDecode(pathAndVersion.slice(atIdx + 1));
    pathAndVersion = pathAndVersion.slice(0, atIdx);
  }
  const segments = pathAndVersion.split("/").filter(Boolean).map(safeDecode);
  const name = segments.pop() ?? "";
  const namespace = segments.join("/");
  const ecosystem = PURL_TYPE_TO_ECOSYSTEM[type];
  if (!ecosystem) return { kind: "unsupportedPurl", type };
  // Maven's OSV package name is "groupId:artifactId" (colon); every other
  // mapped ecosystem here (npm scopes, Go module paths, Packagist
  // vendor/name) uses a "/"-joined namespace, matching the purl spelling.
  const fullName = !namespace
    ? name
    : type === "maven"
      ? `${namespace}:${name}`
      : `${namespace}/${name}`;
  return { kind: "package", ecosystem, name: fullName, version };
}

/** Human-readable date; falls back to the raw string if it doesn't parse. */
export function formatLookupDate(iso: string, locale: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(locale, { dateStyle: "medium" });
}

/** Best-effort summary of one OSV range object. Ranges are typed `unknown` on
 *  the wire (server.py passes them through unshaped), so this reads
 *  defensively rather than assuming every event carries every field. */
export function formatRange(range: unknown): string {
  if (!range || typeof range !== "object") return "";
  const events = (range as { events?: unknown }).events;
  if (!Array.isArray(events)) return "";
  return events
    .map((e) => {
      if (!e || typeof e !== "object") return "";
      const ev = e as Record<string, string>;
      if (ev.introduced !== undefined) return `>= ${ev.introduced || "0"}`;
      if (ev.fixed !== undefined) return `< ${ev.fixed}`;
      if (ev.last_affected !== undefined) return `<= ${ev.last_affected}`;
      if (ev.limit !== undefined) return `< ${ev.limit}`;
      return "";
    })
    .filter(Boolean)
    .join(", ");
}
