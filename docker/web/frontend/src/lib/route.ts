// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * URL-hash routing for the shell. The hash is the single source of truth for
 * what's on screen, so every navigation element can be a real `<a href>` that
 * supports open-in-new-tab (Cmd/Ctrl+click, middle click, right-click → new tab).
 *
 * Scheme:
 *   `#/`                          → Recent scans (home / logo target)
 *   `#/new`                       → the New scan screen
 *   `#/lookup`                    → the External lookup screen
 *   `#/lookup?q=<term>`           → that screen, prefilled and auto-run
 *   `#/scan/<id>`                 → a scan's Overview
 *   `#/scan/<id>/<section>`       → a scan's specific section
 *   `#/scan/<id>/<section>?…`     → that section with its filters applied
 *
 * `<id>` is the scan's run_id — the run-folder name (`DoneEvent.id`, what
 * `loadScan` takes). `<section>` is a SectionId. Ids are encoded so any run_id
 * survives a round-trip; parsing decodes and tolerates a missing leading slash.
 *
 * The query carries a section's filter and sort state, which is what makes a
 * filtered view linkable and survive a reload. This module only serialises it;
 * which keys a section uses is that section's business (see `componentsQuery`
 * and `vulnsQuery`). Keys are emitted in sorted order so that the same state
 * always produces the same string — two hashes can then be compared directly
 * to decide whether the URL needs replacing.
 */
import type { SectionId } from "./nav";

export type RouteQuery = Readonly<Record<string, string>>;

export type Route =
  | { kind: "recent" }
  | { kind: "new" }
  /** The External lookup screen. `query.q`, when present, is the term to
   *  prefill and look up immediately (a shared link or a GlobalSearch pick). */
  | { kind: "lookup"; query?: RouteQuery }
  | { kind: "scan"; id: string; section: SectionId; query?: RouteQuery };

const DEFAULT_SECTION: SectionId = "overview";

/** Parse a location hash (e.g. `#/scan/demo_1.0/components`) into a Route. */
export function parseHash(hash: string): Route {
  // Strip a leading "#" and an optional leading "/" so "#/scan/…" and
  // "#scan/…" both parse.
  let h = hash.startsWith("#") ? hash.slice(1) : hash;
  if (h.startsWith("/")) h = h.slice(1);
  if (!h) return { kind: "recent" };

  // Split the query off before the path, or a `?` inside it would be read as
  // part of the section name.
  const qAt = h.indexOf("?");
  const query = qAt >= 0 ? parseQuery(h.slice(qAt + 1)) : undefined;
  if (qAt >= 0) h = h.slice(0, qAt);
  if (!h) return { kind: "recent" };

  const parts = h.split("/");
  if (parts[0] === "new") return { kind: "new" };
  if (parts[0] === "lookup") {
    return query && Object.keys(query).length ? { kind: "lookup", query } : { kind: "lookup" };
  }
  if (parts[0] === "scan" && parts[1]) {
    const id = safeDecode(parts[1]);
    if (id) {
      const section = (parts[2] ? safeDecode(parts[2]) : "") as SectionId;
      const route: Route = { kind: "scan", id, section: section || DEFAULT_SECTION };
      return query && Object.keys(query).length ? { ...route, query } : route;
    }
  }
  return { kind: "recent" };
}

/** Build a hash for a Route. Recent (home) is the bare `#/`. */
export function buildHash(route: Route): string {
  if (route.kind === "recent") return "#/";
  if (route.kind === "new") return "#/new";
  if (route.kind === "lookup") {
    const q = buildQuery(route.query);
    return q ? `#/lookup?${q}` : "#/lookup";
  }
  const path = `#/scan/${encodeURIComponent(route.id)}`;
  const base =
    route.section && route.section !== DEFAULT_SECTION
      ? `${path}/${encodeURIComponent(route.section)}`
      : path;
  const q = buildQuery(route.query);
  return q ? `${base}?${q}` : base;
}

/**
 * Hash for a scan's section (Overview when omitted) — for `<a href>` targets.
 * Pass `query` to link straight into a filtered view.
 */
export function scanHash(id: string, section?: SectionId, query?: RouteQuery): string {
  return buildHash({ kind: "scan", id, section: section ?? DEFAULT_SECTION, query });
}

/** Parse a query string into a plain map, dropping empty values. */
export function parseQuery(search: string): RouteQuery {
  // fromEntries defines each key as an own property, so a key such as "__proto__"
  // from the address bar stays data instead of writing through to the prototype.
  return Object.fromEntries(
    [...new URLSearchParams(search)].filter(([k, v]) => k && v),
  );
}

/** Serialise a query map, dropping empty values and sorting keys. */
export function buildQuery(query?: RouteQuery): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const k of Object.keys(query).sort()) {
    const v = query[k];
    if (v) params.set(k, v);
  }
  return params.toString();
}

/** Hash for the home screen — Recent scans (the logo target). */
export function homeHash(): string {
  return "#/";
}

/** Hash for the New scan screen. */
export function newHash(): string {
  return "#/new";
}

/** Hash for the External lookup screen. Pass a term (a CVE/GHSA id, a purl, a
 *  package name) to land there prefilled and looked up immediately, which is
 *  what a GlobalSearch pick and a shared link both produce. */
export function lookupHash(term?: string): string {
  return buildHash({ kind: "lookup", query: term ? { q: term } : undefined });
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
