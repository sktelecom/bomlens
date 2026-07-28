// @no-unit-test: three build-time constants read from import.meta.env — a test
// could only re-assert the literals, since Vite inlines them at build time.
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
 * Where the demo sends someone who wants to scan their own code. The demo
 * cannot run a scan, so the "New scan" action becomes this link — the one
 * thing a visitor should do next. Overridable at build time so a fork or a
 * preview deploy can point at its own docs.
 */
export const DEMO_INSTALL_URL =
  import.meta.env.VITE_DEMO_INSTALL_URL ??
  "https://sktelecom.github.io/bomlens/getting-started/";
