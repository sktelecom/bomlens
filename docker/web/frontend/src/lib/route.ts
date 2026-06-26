/**
 * URL-hash routing for the shell. The hash is the single source of truth for
 * what's on screen, so every navigation element can be a real `<a href>` that
 * supports open-in-new-tab (Cmd/Ctrl+click, middle click, right-click → new tab).
 *
 * Scheme:
 *   `#/`                       → Recent scans (home / logo target)
 *   `#/new`                    → the New scan screen
 *   `#/scan/<id>`              → a scan's Overview
 *   `#/scan/<id>/<section>`    → a scan's specific section
 *
 * `<id>` is the scan's run_id — the run-folder name (`DoneEvent.id`, what
 * `loadScan` takes). `<section>` is a SectionId. Ids are encoded so any run_id
 * survives a round-trip; parsing decodes and tolerates a missing leading slash.
 */
import type { SectionId } from "./nav";

export type Route =
  | { kind: "recent" }
  | { kind: "new" }
  | { kind: "scan"; id: string; section: SectionId };

const DEFAULT_SECTION: SectionId = "overview";

/** Parse a location hash (e.g. `#/scan/demo_1.0/components`) into a Route. */
export function parseHash(hash: string): Route {
  // Strip a leading "#" and an optional leading "/" so "#/scan/…" and
  // "#scan/…" both parse.
  let h = hash.startsWith("#") ? hash.slice(1) : hash;
  if (h.startsWith("/")) h = h.slice(1);
  if (!h) return { kind: "recent" };

  const parts = h.split("/");
  if (parts[0] === "new") return { kind: "new" };
  if (parts[0] === "scan" && parts[1]) {
    const id = safeDecode(parts[1]);
    if (id) {
      const section = (parts[2] ? safeDecode(parts[2]) : "") as SectionId;
      return { kind: "scan", id, section: section || DEFAULT_SECTION };
    }
  }
  return { kind: "recent" };
}

/** Build a hash for a Route. Recent (home) is the bare `#/`. */
export function buildHash(route: Route): string {
  if (route.kind === "recent") return "#/";
  if (route.kind === "new") return "#/new";
  const base = `#/scan/${encodeURIComponent(route.id)}`;
  return route.section && route.section !== DEFAULT_SECTION
    ? `${base}/${encodeURIComponent(route.section)}`
    : base;
}

/** Hash for a scan's section (Overview when omitted) — for `<a href>` targets. */
export function scanHash(id: string, section?: SectionId): string {
  return buildHash({ kind: "scan", id, section: section ?? DEFAULT_SECTION });
}

/** Hash for the home screen — Recent scans (the logo target). */
export function homeHash(): string {
  return "#/";
}

/** Hash for the New scan screen. */
export function newHash(): string {
  return "#/new";
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
