/// <reference types="vite/client" />

/**
 * Build-time settings for the read-only demo bundle. Both are absent in a
 * normal build, which is what keeps `IS_STATIC_DEMO` false (see lib/demo.ts).
 */
interface ImportMetaEnv {
  /** Base URL of the captured JSON the demo reads instead of calling a server. */
  readonly VITE_DEMO_DATA_BASE?: string;
  /** Docs-site root the demo links to for install instructions. */
  readonly VITE_DEMO_DOCS_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
