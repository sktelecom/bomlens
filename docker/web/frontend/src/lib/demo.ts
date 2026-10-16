// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Static-demo mode — the published read-only demo.
 *
 * The demo is the same bundle as the app, built once with VITE_DEMO_DATA_BASE
 * pointing at a folder of JSON captured from a real `server.py` run. There is
 * no server behind it: reads resolve to those files (see `api.ts`), and every
 * entry point that would write — scanning, uploading, deleting, SPDX export —
 * is hidden by the UI and refused by the API layer.
 *
 * Keeping the flag here rather than in `api.ts` lets components ask "is this
 * the demo?" without importing the network contract, and keeps `api.ts` about
 * the server contract alone.
 */

/** Where the captured JSON lives, without a trailing slash. Empty = normal build. */
export const DEMO_DATA_BASE = (import.meta.env.VITE_DEMO_DATA_BASE ?? "").replace(
  /\/+$/,
  "",
);

/** True when this bundle is the read-only demo (no server behind it). */
export const IS_STATIC_DEMO = DEMO_DATA_BASE !== "";

/**
 * Root of the documentation site, without a trailing slash. Overridable at
 * build time so a fork or a preview deploy can point at its own docs.
 */
const DOCS_BASE = (
  import.meta.env.VITE_DEMO_DOCS_BASE ?? "https://sktelecom.github.io/bomlens"
).replace(/\/+$/, "");

/**
 * Where the demo sends someone who wants to scan their own code. The demo
 * cannot run a scan, so the "New scan" action becomes this link — the one
 * thing a visitor should do next.
 *
 * The docs site keeps English at the root and Korean under `/ko/`, so the link
 * follows the UI's own language. Sending a reader of the English demo to Korean
 * install instructions (or the reverse) is a dead end, and the site's language
 * switch is too far from the moment they decided to try it.
 */
export function demoInstallUrl(language: string | undefined): string {
  // Match the subtag, not a prefix: i18next reports "ko" or "ko-KR", and a
  // bare startsWith would also claim unrelated codes such as "kor".
  const korean = /^ko(-|$)/i.test(language ?? "");
  return `${DOCS_BASE}/${korean ? "ko/" : ""}start/first-scan/`;
}

/**
 * The documentation site's home, in the reader's language.
 *
 * Shared with `demoInstallUrl` so both follow the same base: a build that
 * points the demo at a staging site points the help menu there too, rather
 * than sending one of them to production.
 */
export function docsUrl(language: string | undefined): string {
  const korean = /^ko(-|$)/i.test(language ?? "");
  return `${DOCS_BASE}/${korean ? "ko/" : ""}`;
}

/** What changed in a version: its release page, or the list when the build
 *  carries no version stamp. */
export function releaseNotesUrl(version: string | undefined): string {
  const base = "https://github.com/sktelecom/bomlens/releases";
  return version ? `${base}/tag/v${version.replace(/^v/, "")}` : base;
}

/** The public demo, for showing someone the tool without installing it. */
export function demoUrl(): string {
  return `${DOCS_BASE}/demo/`;
}

/**
 * What the primary action of the New scan form does in the demo. Running a
 * scan is refused everywhere, but the model questionnaire ("ai-declare") runs
 * in the browser and only needs a server for its last step, so it stays
 * reachable: its button opens the questions.
 */
export function demoRunAction(source: string): "questions" | "disabled" {
  return source === "ai-declare" ? "questions" : "disabled";
}
