// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Backend API contract (docker/web/server.py) — kept stable across the UI
 * rebuild. All network access for the app flows through this module so the
 * contract lives in one place.
 *
 *   GET /results?id=<run>      → ResultFile[] (scoped to one run folder)
 *   GET /file?id=<run>&name=<n> → raw file (download / inline view)
 *   GET /scan-stream?…         → SSE: `log` (string line) + `done` (DoneEvent)
 *
 * Scans are isolated per run in OUTPUT_DIR/<run_id>/. The `id` carried by the
 * `done` event, each `/scans` entry and the `/scan` detail is the run_id (the
 * run-folder name) — every later /file, /download-all, /scan and /scan-delete
 * call must pass it. The run_id can differ from the artifact filename prefix
 * (timestamped runs are `{prefix}_{YYYYMMDD-HHMMSS}`), so address artifacts by
 * the names in `results[]` plus this `id`, never by reconstructing from
 * project/version. Omitting `id` falls back to the legacy flat layout.
 */

import { DEMO_DATA_BASE, IS_STATIC_DEMO } from "./demo";

/**
 * Map a server path to its captured file. A static host cannot answer query
 * strings, so `/scan?id=<run>` becomes `<base>/scan-<run>.json`; the capture
 * step writes the same names. Unmapped paths pass through unchanged — they
 * belong to write endpoints, which never run in demo mode.
 */
function apiUrl(path: string): string {
  if (!IS_STATIC_DEMO) return path;
  const [route, query] = path.split("?");
  const id = new URLSearchParams(query ?? "").get("id") ?? "";
  switch (route) {
    case "/capabilities":
      return `${DEMO_DATA_BASE}/capabilities.json`;
    case "/scans":
      return `${DEMO_DATA_BASE}/scans.json`;
    case "/scan":
      return `${DEMO_DATA_BASE}/scan-${encodeURIComponent(id)}.json`;
    case "/results":
      return `${DEMO_DATA_BASE}/results-${encodeURIComponent(id)}.json`;
    default:
      return path;
  }
}

/** Thrown by the write helpers when the read-only demo bundle calls them. The
 *  UI hides those entry points, so reaching this is a bug, not a user path. */
function demoWriteRefused(): never {
  throw new Error("This is a read-only demo — scanning is disabled.");
}

export interface ResultFile {
  name: string;
  size: number;
}

export interface ComponentItem {
  name: string;
  version: string;
  group: string;
  purl: string;
  type: string;
  licenses: string[];
  /** Identified by SCANOSS as open source copied (vendored) into the sources. */
  vendored?: boolean;
  /** Proved present by ELF structure with no version recovered. No version means no
   *  purl and no CPE, so no vulnerability database can be asked about it — a clean
   *  vulnerability result does not cover this row. */
  presenceOnly?: boolean;
  /** SCANOSS file-match confidence (e.g. "100%"), shown read-only on vendored rows. */
  matchConfidence?: string;
  /** Worst severity of the vulnerabilities affecting this component (Risk). */
  maxSeverity?: Severity;
  /** How many vulnerabilities affect this component. */
  vulnCount?: number;
  /** Direct dependency of the root, or transitive — from the dependency graph.
   *  Omitted when the SBOM carries no dependency graph (scope unknown). */
  scope?: "direct" | "transitive";
  /** AI-relevant restrictive license class needing human review, set by
   *  normalize-sbom.sh (shared license-flags.jq). Absent for ordinary licenses. */
  licenseReview?: "behavioral-use" | "non-commercial";
  /** A known-malicious package (bundled OSV snapshot). Not a severity: this one
   *  is removed rather than upgraded, so it is kept out of maxSeverity/vulnCount
   *  and shown as its own signal. */
  malicious?: boolean;
  /** The OSV advisory id (MAL-…) behind that flag. */
  maliciousId?: string;
  /** Which snapshot said so, e.g. "osv.dev@2026-07-28" — a clean result means
   *  "not in this snapshot", so the date is part of the answer. */
  maliciousSource?: string;
  /** How this component's license sits against the project's declared outbound
   *  license (normalize-sbom.sh, rules in docker/lib/license-compat.json).
   *  Absent when no outbound license was declared — "not assessed", not clean. */
  licenseConflict?: "compatible" | "conditional" | "incompatible" | "unknown";
  /** Why that verdict — the rule's reasoning, shown beside the badge. */
  licenseConflictWhy?: string;
  /** Source / download location (externalReferences vcs/distribution/website). */
  source?: string;
  /** Copyright holder line, when the SBOM captured one. */
  copyright?: string;
  /** End-of-life state from a bundled endoflife.date snapshot (enrich-eol.sh):
   *  "true" past upstream support, "false" still supported, "unknown" mapped but
   *  the cycle wasn't in the snapshot. Absent for unmapped components. */
  eol?: "true" | "false" | "unknown";
  /** The published end-of-life date (ISO), when known. */
  eolDate?: string;
  /** Behind the latest patch in its own release cycle ("true"/"false"), computed
   *  offline from the endoflife snapshot (enrich-eol.sh currency). */
  outdated?: "true" | "false";
  /** Newest known version — absolute latest from deps.dev (opt-in) if present,
   *  else the latest patch in-cycle from the offline snapshot. */
  latestVersion?: string;
  /** How many releases newer than the installed one — deps.dev opt-in only. */
  releasesBehind?: number;
  /** Publish date (ISO) of the newest version — deps.dev opt-in only. */
  lastReleased?: string;
}

export interface SbomSummary {
  components: number;
  /** Per-component detail rows (capped server-side; see `truncated`). */
  componentList?: ComponentItem[];
  /** True when the SBOM has more components than the server returned. */
  truncated?: boolean;
  /** Set when the scan looks like C/C++ embedded source with no package manager,
   *  hinting the user to re-run with --identify-vendored. Drives a result banner. */
  suggestIdentifyVendored?: boolean;
  /** Set when cdxgen couldn't run and the scan fell back to syft (direct deps
   *  only), e.g. "disk-space" | "cdxgen-unavailable". Drives a result banner. */
  sbomToolDegraded?: string | null;
  /** CycloneDX root component type (application/firmware/container/…) — drives
   *  the honest scan-kind subtitle, available on re-open (unlike the MODE). */
  componentType?: string | null;
  /** Direct/transitive dependency counts across the whole SBOM (0 when the SBOM
   *  has no dependency graph). Drives the Overview dependency tile. */
  directCount?: number;
  transitiveCount?: number;
  /** Components flagged past their upstream end-of-life (enrich-eol.sh). */
  eolCount?: number;
  /** EOL components that ALSO carry a vulnerability — the actionable set, since an
   *  end-of-life component has no upstream patch coming for its CVEs. */
  atRiskCount?: number;
  /** Components behind the latest patch in their own release cycle (offline
   *  currency from the endoflife snapshot). */
  outdatedCount?: number;
  /** Components that are known-malicious packages. Absent when none — the tile
   *  appears only when there is something to act on. */
  maliciousCount?: number;
  /** The outbound license the project declares on its root component. Absent
   *  when none was declared, which is what turns the conflict check off. */
  outboundLicense?: string;
  /** Conflict verdict tally across every component (not just the capped rows).
   *  Present only alongside outboundLicense. */
  conflictCounts?: {
    incompatible: number;
    conditional: number;
    unknown: number;
    compatible: number;
  };
}

export const SEVERITY_ORDER = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export interface VulnItem {
  id: string;
  severity: Severity;
  pkg: string;
  installed: string;
  fixed: string;
  title: string;
  /** Highest CVSS score across Trivy's sources (null when none scored). */
  cvss?: number | null;
  /** CVSS vector for that score, when present. */
  cvssVector?: string;
  /** Full advisory description (capped server-side). */
  description?: string;
  /** Primary advisory URL. */
  url?: string;
  /** Reference links (capped server-side). */
  refs?: string[];
  /** EPSS exploit probability (0..1), when the report was enriched. */
  epss?: number;
  /** On CISA's Known Exploited Vulnerabilities list (actively exploited). */
  kev?: boolean;
}

/** Severity counts (CRITICAL…UNKNOWN + TOTAL) plus the per-CVE detail rows. */
/** Build-time vulnerability judgements carried inside a Yocto SPDX SBOM.
 *
 *  Yocto runs its own CVE analysis during the build and records the verdict per
 *  CVE, so it knows whether the recipe applied the patch. `fixed` therefore means
 *  genuinely closed on this image — an outside scanner matching on version alone
 *  would report those same CVEs as open. Only `unresolved` reaches the security
 *  panel; the rest are shown as work the build already did. */
export interface YoctoVex {
  /** CVEs the build patched (SPDX `fixedIn`). */
  fixed: number;
  /** CVEs judged inapplicable to this image (SPDX `doesNotAffect`). */
  notAffected: number;
  /** CVEs with no verdict — these are the ones that still need attention. */
  affected: number;
  /** Rows handed to the security report; equals `affected` minus duplicates. */
  unresolved: number;
}

export type SecuritySummary = Record<Severity, number> & {
  TOTAL: number;
  vulnerabilities?: VulnItem[];
  /** Engine failure message when the scan did not complete (scan-security.sh
   *  ScanError). Present => the counts above understate the real exposure. */
  scanError?: string;
  /** Advisories filed against the kernel, counted apart from the severity figures
   *  above and from TOTAL. An old kernel carries thousands of them, nearly all
   *  for subsystems the image never compiled in, so mixing them in would make a
   *  device with two real criticals read like one with two thousand. */
  kernelCount?: number;
};

/** One conformance check (base format requirement or a G7 AI minimum element). */
export interface ConformanceCheck {
  id: string;
  label: string;
  required: boolean;
  status: "pass" | "fail" | "warn";
  detail: string;
  missing?: string[];
  /** Actual SBOM values that satisfy this check (e.g. the PURL, license id,
   *  hash algorithm). Shown as the "met with" evidence on passing G7 checks. */
  evidence?: string[];
  /** G7 cluster this element belongs to (metadata | slp | models | dp |
   *  infrastructure | sp | kpi). Empty/absent for base format checks. Drives the
   *  per-cluster grouping in the conformance panel. */
  cluster?: string;
  /** Where a satisfied value comes from: "auto" (tool read it directly),
   *  "inferred" (derived from signals), "declared" (present only if a human /
   *  manifest supplied it), "na" (no automated source — human review needed).
   *  Empty/absent for base format checks. */
  source?: string;
  /** Regulatory documentation obligations this G7 element maps to (validate-sbom.sh
   *  joins docker/lib/regulation-crosswalk.json, keyed by check id). Present only on
   *  the ~half of G7 checks with a defensible correspondence; absent otherwise.
   *  Informational — it never changes a check status or the overall result. */
  regulations?: RegulationRef[];
  /** How to satisfy this element: a CycloneDX fragment plus a reference link
   *  (validate-sbom.sh joins docker/lib/g7-guidance.json by check id, so the CLI
   *  reports show the same text). Present on the subset of G7 elements with a
   *  mapping; absent on base format checks and on runs generated before the
   *  guidance registry existed. Informational — never changes a status. */
  guidance?: G7GuidanceRef;
  /** What a person has to establish for this element, when no scan can settle it
   *  or when it is checkable in a form this report cannot see (a signature
   *  delivered beside the SBOM rather than inside it). The .md and .html reports
   *  have shown these all along. */
  reviewGuide?: ReviewGuideRef;
  /** The Korean label the registry declares for this element. The rest of this
   *  contract stays English by design, so the translation rides alongside `label`
   *  rather than replacing it. Empty for checks whose label carries a threshold
   *  or a spec version and so cannot be looked up whole. */
  labelKo?: string;
}

/** What a person has to establish for one element. */
export interface ReviewGuideRef {
  how?: string;
  howKo?: string;
  /** Authoritative documentation (absolute https URL). */
  docUrl?: string;
}

/** Fill-in guidance for one G7 element. */
export interface G7GuidanceRef {
  /** A CycloneDX fragment showing the shape that would satisfy the element. */
  snippet?: string;
  /** Authoritative documentation for providing it (absolute https URL). */
  docUrl?: string;
}

/** One regulatory-framework reference mapped onto a conformance check. */
export interface RegulationRef {
  /** Framework id (e.g. "eu-ai-act", "bsi-tr-03183-2"). */
  framework: string;
  /** The specific article / annex / section reference (e.g. "Annex IV(1)", "Section 5.2.2"). */
  ref: string;
  /** The interpretive basis for treating this check as touching that reference. */
  basis: string;
  /** Short framework name for badging a check row (e.g. "BSI TR-03183-2", "NTIA"). */
  short?: string;
  /** Korean short framework name; falls back to `short` when absent. */
  short_ko?: string;
}

/** One crosswalk element: a G7 element with its status and regulation refs, in
 *  the detailed per-framework view under `conformance.regulatoryCrosswalk`. */
export interface CrosswalkElement {
  label: string;
  status: "pass" | "warn" | "fail";
  source: string;
  refs: string[];
}

/** One framework in the detailed crosswalk under `conformance.regulatoryCrosswalk`
 *  — carries `source` and the full `elements[]` (unlike the aiProfile card view). */
export interface CrosswalkFramework {
  id: string;
  title: string;
  source: string;
  total: number;
  present: number;
  gap: number;
  review: number;
  /** Requirements this SBOM fails outright. Stated by the report; a consumer
   *  deriving it as total - present - gap - review gets the number right and the
   *  name wrong, which is what the panel used to do under the heading "advisory". */
  failed: number;
  elements: CrosswalkElement[];
}

/** The detailed regulatory crosswalk under `conformance.regulatoryCrosswalk`.
 *  Present only for AI SBOMs (validate-sbom.sh omits the key otherwise). A
 *  documentation-preparation aid, never a certification/compliance verdict. */
export interface RegulatoryCrosswalk {
  /** The no-certification / visibility disclaimer shown above the sub-block. */
  disclaimer: string;
  frameworks: CrosswalkFramework[];
}

export interface ConformanceSummary {
  result: string; // "pass" | "fail" | "unknown"
  format?: string;
  /** Per-check results; G7 checks have ids prefixed "g7-". */
  checks?: ConformanceCheck[];
  /** Regulatory crosswalk rollup with the full per-framework element detail.
   *  Present only on AI SBOMs; the key is omitted for non-AI SBOMs. Drives the
   *  "Regulatory crosswalk" sub-block inside the conformance panel. */
  regulatoryCrosswalk?: RegulatoryCrosswalk;
}

/** One G7 cluster's coverage counts in the aiProfile card. */
export interface AiProfileCluster {
  cluster: string;
  total: number;
  present: number;
  gap: number;
  review: number;
}

/** One framework's coverage in the aiProfile card's crosswalk (card view: no
 *  `source`, no `elements[]` — the light rollup for the compliance card). */
export interface AiProfileCrosswalkFramework {
  id: string;
  title: string;
  total: number;
  present: number;
  gap: number;
  review: number;
}

/**
 * AI compliance profile — a card-sized rollup gathered from a run's
 * `_ai-profile.json` (generate-ai-profile.sh re-aggregates the conformance + SBOM
 * artifacts; no new scan). Present only on AI SBOMs; null otherwise. The big
 * arrays (per-element detail) are dropped server-side — this card consumes only
 * the summary counts. Documentation-preparation, not a compliance verdict.
 */
export interface AiProfile {
  /** Overall conformance verdict: "pass" | "warn" | "fail" | "unknown". */
  conformanceResult: string;
  g7: {
    total: number;
    /** G7 elements with an automated source (the coverage base). */
    auto: number;
    present: number;
    gap: number;
    review: number;
    clusters: AiProfileCluster[];
  };
  /** Components whose license is flagged for human review (from the SBOM). */
  licenseReview: {
    total: number;
    behavioral: number;
    nonCommercial: number;
  };
  /** Card-view crosswalk coverage (no per-element detail). */
  regulatoryCrosswalk: {
    disclaimer: string;
    frameworks: AiProfileCrosswalkFramework[];
  };
}

/**
 * The settings a scan was run with, echoed back so a finished scan can be
 * re-run with the same target and toggles (the "Re-scan" action). Mirrors the
 * server's `scanConfig` keys exactly. Credentials/tokens are deliberately not
 * part of the contract — a re-scan re-prompts for them. Absent on older scans
 * (history predating this field) and on payloads that never carried a config.
 */
export interface ScanConfig {
  source: SourceType;
  /** git URL / docker image (empty for current-folder and upload sources). */
  target: string;
  /** What the user actually picked, when `target` cannot say it: the uploaded
   *  file's name, or the folder a CLI scan ran against. Shown as the scan's
   *  provenance (see lib/provenance.ts); absent on scans that predate it.
   *  Kept separate from `target` because "re-scan" refills the form from
   *  `target`, and an upload has to be chosen again rather than retyped. */
  sourceLabel?: string;
  project: string;
  version: string;
  notice: boolean;
  security: boolean;
  /** Recorded by scans run before SPDX became an on-demand export. Kept so an
   *  older sidecar still parses; the form no longer reads it. */
  spdx?: boolean;
  deepLicense: boolean;
  identifyVendored: boolean;
  includeOsv: boolean;
  byteStable: boolean;
  /** The outbound license declared for this scan (SPDX id), which switches the
   *  license-conflict check on. Empty or absent means it stayed off. */
  license?: string;
  /** SBOM-upload only: match components against NVD-only (CPE) advisories too —
   *  catches vulnerabilities in older Java (Maven) libraries other sources miss. */
  deepCve: boolean;
}

export interface DoneEvent {
  ok: boolean;
  mode?: string;
  /** The run_id (run-folder name) for this scan — used for re-opening
   *  (`loadScan`), the `#/scan/<id>` hash route, and every later /file,
   *  /download-all and /scan-delete call. Defaults to the artifact prefix;
   *  timestamped runs are `{prefix}_{YYYYMMDD-HHMMSS}` and so differ from the
   *  filename prefix. Absent on older payloads. */
  id?: string;
  results: ResultFile[];
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
  conformance?: ConformanceSummary | null;
  /** Vulnerability judgements Yocto recorded while building the image (Yocto SPDX
   *  input only; null otherwise). The security panel lists only what is still
   *  unresolved, so these counts are what distinguishes "the build already patched
   *  these" from "nothing was found". */
  yoctoVex?: YoctoVex | null;
  /** AI compliance profile card rollup (AI SBOMs only; null otherwise). Present on
   *  both the SSE `done` event and the `/scan` detail (loadScan), kept in sync
   *  server-side. Drives the AI compliance summary card. */
  aiProfile?: AiProfile | null;
  /** SCANOSS vendored-ID outcome, present only when vendored ID ran.
   *  status: "unavailable" (search blocked) | "no-match" | "matched". */
  scanoss?: { status: string | null; count: number } | null;
  /** The settings this scan ran with, for the "Re-scan" action. Absent on
   *  older payloads / history that predate the field. */
  scanConfig?: ScanConfig;
}

/** Input types the UI offers; each maps to a backend MODE in server.py. */
export type SourceType =
  | "current-dir"
  | "rootfs-dir"
  // Deep (build) source scan of a picked scan-target folder. Not a picker tile —
  // the form submits it in place of "rootfs-dir" when the transitive-resolution
  // toggle is on, so a desktop "Add folder…" scan resolves transitives like the
  // current folder does. Server clones the read-only mount into a writable tree.
  | "scan-target-src"
  // A Yocto build directory, recognized from a folder the user pointed at. Not a
  // picker tile: the CLI (and, later, the folder pickers) route to it on its own
  // when the folder turns out to be a build directory, and analyze the image
  // SBOM the build wrote. Appears in a finished scan's config, never in a
  // request.
  | "yocto-build-dir"
  | "git-url"
  | "zip-upload"
  | "package-upload"
  | "sbom-upload"
  | "firmware-upload"
  | "ai-model"
  | "docker-image";

export const SOURCE_TYPES: SourceType[] = [
  "current-dir",
  "rootfs-dir",
  "git-url",
  "zip-upload",
  "package-upload",
  "sbom-upload",
  "firmware-upload",
  "ai-model",
  "docker-image",
];

/**
 * The input a finished scan should be replayed from. "Re-scan" seeds the form
 * from a scan's config, and `yocto-build-dir` is not an input the form offers —
 * it is what a picked folder turned out to be. Replaying it means picking the
 * same folder again, so it maps back to the directory input; the scanner then
 * decides afresh whether that folder is still a Yocto build directory.
 */
export function formSourceOf(source: SourceType): SourceType {
  return source === "yocto-build-dir" ? "rootfs-dir" : source;
}

export type UploadKind = "zip" | "sbom" | "firmware" | "package";

/** How the user intends to use a scanned AI model. Sent with the scan start so
 *  the pipeline grades the license assessment against this use, and stamped
 *  back on the model as `bomlens:assessment:usageContext`. Absent = unspecified
 *  (the pipeline assesses without a usage-specific tightening). */
export type UsageContext = "internal" | "product" | "redistribute" | "outputs-only";

export const USAGE_CONTEXTS: UsageContext[] = [
  "internal",
  "product",
  "redistribute",
  "outputs-only",
];

export interface ScanParams {
  project: string;
  version: string;
  source: SourceType;
  target?: string; // git URL OR docker image name
  token?: string; // server-side token from /upload
  cred?: string; // single-use credId from /git-cred (private git URL)
  scanossCred?: string; // single-use credId for a SCANOSS/OSSKB token
  notice: boolean;
  security: boolean;
  deepLicense: boolean;
  identifyVendored: boolean;
  /** Firmware only: pull OSV.dev advisories for this run. The osv.dev database
   *  is not baked into the image, so enabling this downloads it on this run
   *  (the determinate progress bar surfaces the download). Read server-side as
   *  the exact `includeOsv` flag. */
  includeOsv: boolean;
  byteStable: boolean;
  /** Outbound license (SPDX id) the project ships under. Read server-side as the
   *  exact `license` parameter; empty leaves the license-conflict check off. */
  license?: string;
  /** AI-model scans only: the intended usage the assessment should grade
   *  against. Read server-side as the exact `usage` query parameter; omitted
   *  (sent empty) when unspecified or for any other source. */
  usage?: UsageContext;
  /** SBOM-upload only: also match against NVD-only (CPE) advisories, catching
   *  vulnerabilities in older Java (Maven) libraries other sources miss. Read
   *  server-side as the exact `deep_cve` flag. Ignored for every other source. */
  deepCve: boolean;
  /** Optional upload of the generated SBOM. "" leaves the scan generate-only. */
  uploadTarget?: "" | "dependency-track" | "trusca";
  uploadUrl?: string; // upload server base URL (API_URL)
  uploadCred?: string; // single-use credId for the upload token (API_KEY)
  truscaProjectId?: string; // required when uploadTarget === "trusca"
}

/** A determinate progress update (e.g. CVE database download). */
export interface ScanProgress {
  phase: string;
  /** Percent, for a phase that can report one (the firmware CVE DB download). */
  percent?: number;
  /** Layer counts, for an image pull. A non-TTY `docker pull` prints no byte
   *  totals and no percentage, so layers are the only honest unit and a percent
   *  here would be invented. */
  complete?: number;
  total?: number;
}

export interface ScanHandlers {
  onLog: (line: string) => void;
  onDone: (done: DoneEvent) => void;
  onError: (message?: string) => void;
  /** Optional determinate progress (e.g. firmware CVE DB download). */
  onProgress?: (p: ScanProgress) => void;
}

/** A per-feature image: whether it is already on this machine, and how many
 *  bytes the pull would download. Firmware/AI/deep-CVE each live in their own
 *  image; the download size is the compressed one the registry reports, which is
 *  not the installed size (the manifest carries no such number). */
export interface ImageStatus {
  image: string;
  present: boolean;
  downloadBytes?: number;
}

export type PullImageKey = "firmware" | "aibom" | "deep-cve";

export async function fetchImageStatus(key: PullImageKey): Promise<ImageStatus | null> {
  try {
    const res = await fetch(`/image-status?image=${encodeURIComponent(key)}`);
    if (!res.ok) return null;
    return (await res.json()) as ImageStatus;
  } catch {
    return null;
  }
}

export interface PullHandlers {
  onLog?: (line: string) => void;
  onProgress?: (p: { complete: number; total: number }) => void;
  onDone: (d: { ok: boolean; reason?: string; alreadyPresent?: boolean }) => void;
}

/** Pull a per-feature image, reporting layer progress. Returns a stop function:
 *  closing the stream stops the download, and the layers already fetched stay in
 *  the daemon's cache, so starting again resumes rather than restarting. */
export function pullImage(key: PullImageKey, handlers: PullHandlers): () => void {
  const es = new EventSource(`/pull-stream?image=${encodeURIComponent(key)}`);
  es.addEventListener("log", (e) => {
    try {
      handlers.onLog?.(String(JSON.parse((e as MessageEvent).data)));
    } catch {
      /* ignore malformed log */
    }
  });
  es.addEventListener("progress", (e) => {
    try {
      const p = JSON.parse((e as MessageEvent).data) as ScanProgress;
      if (typeof p.total === "number" && typeof p.complete === "number") {
        handlers.onProgress?.({ complete: p.complete, total: p.total });
      }
    } catch {
      /* ignore malformed progress */
    }
  });
  const finish = (d: { ok: boolean; reason?: string; alreadyPresent?: boolean }) => {
    es.close();
    handlers.onDone(d);
  };
  es.addEventListener("busy", () => {
    /* the done event carries the reason; nothing extra to do here */
  });
  es.addEventListener("done", (e) => {
    try {
      finish(JSON.parse((e as MessageEvent).data));
    } catch {
      finish({ ok: false, reason: "unknown" });
    }
  });
  es.onerror = () => finish({ ok: false, reason: "unknown" });
  return () => {
    es.close();
  };
}

export interface Capabilities {
  /** Firmware input offerable here — tools built into this image OR reachable by
   *  running the firmware image as a sibling container (docker socket). */
  firmware: boolean;
  /** scanoss-py present (built with SBOM_SCANOSS) — enables --identify-vendored. */
  scanoss?: boolean;
  docker: boolean;
  /** AI-model input offerable here — generator built in OR sibling-reachable. */
  aibom?: boolean;
  /** Firmware is satisfied by a sibling container (the desktop base UI image),
   *  so the first run pulls the (large) firmware image — show a one-time notice. */
  firmwareSibling?: boolean;
  /** AI-model is satisfied by a sibling container (first run pulls the aibom image). */
  aibomSibling?: boolean;
  /** Deep CVE matching (NVD-only advisories for uploaded SBOMs) offerable here —
   *  grype built into this image OR reachable by running the deep-cve image as a
   *  sibling container. False hides the toggle. */
  deepCve?: boolean;
  /** Deep CVE is satisfied by a sibling container, so the first run pulls the
   *  (large) deep-cve image — show the one-time notice. */
  deepCveSibling?: boolean;
  /** The results screen can convert a finished BOM to SPDX 2.3 (syft here, or a
   *  sibling scanner container). False hides the export action. */
  spdxExport?: boolean;
  /** SPDX export goes through a sibling container, so the first export may pull
   *  the scanner image — worth saying before the wait. */
  spdxSibling?: boolean;
  /** A HuggingFace credential was present in the environment that launched the
   *  UI, so private and gated model repos resolve. Never the token itself — the
   *  UI has no token field, and the server keeps no credentials. */
  hfAuth?: boolean;
  firmwareImage?: string;
  aibomImage?: string;
  deepCveImage?: string;
  hostDir?: string; // the host folder the UI was launched from (mounted as /src)
  /** Extra read-only scan targets from `--ui --mount <dir>`: container path
   *  (sent as the rootfs-dir scan target) + host path (shown to the user). */
  scanRoots?: { path: string; hostPath: string }[];
}

/** Which input types this running image supports (firmware needs the fw image). */
export async function getCapabilities(): Promise<Capabilities> {
  try {
    const res = await fetch(apiUrl("/capabilities"));
    if (!res.ok) return { firmware: false, scanoss: false, docker: true };
    return (await res.json()) as Capabilities;
  } catch {
    return { firmware: false, scanoss: false, docker: true };
  }
}

/** Error from a pre-scan POST (/upload, /git-cred): carries the HTTP status so
 *  the form can pick a human message; `message` keeps the server's raw detail. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** What the scan form shows when a pre-scan POST fails: `key` is an i18n
 *  message key (the headline the user reads), `detail` the raw server/browser
 *  text kept as secondary fine print for bug reports. */
export interface UploadErrorInfo {
  key: string;
  detail?: string;
}

/** Map an upload/stash failure to a user-facing message key. Raw error text
 *  (HTTP statuses, "Failed to fetch") never becomes the headline. */
export function describeUploadError(e: unknown): UploadErrorInfo {
  if (e instanceof ApiError) {
    if (e.status === 413) return { key: "source.uploadErrorTooLarge" };
    if (e.status >= 500)
      return { key: "source.uploadErrorServer", detail: e.message };
    return { key: "source.uploadErrorRejected", detail: e.message };
  }
  // fetch() rejects with a TypeError when the server is unreachable.
  if (e instanceof TypeError) return { key: "source.uploadErrorNetwork" };
  return {
    key: "source.uploadErrorServer",
    detail: e instanceof Error ? e.message : undefined,
  };
}

/** Upload a file (zip/sbom/firmware) and get back a server-side token. */
export async function uploadFile(
  file: File,
  kind: UploadKind,
): Promise<{ token: string; filename: string }> {
  if (IS_STATIC_DEMO) demoWriteRefused();
  const fd = new FormData();
  fd.append("kind", kind);
  fd.append("file", file);
  const res = await fetch(`/upload?kind=${encodeURIComponent(kind)}`, {
    method: "POST",
    body: fd,
  });
  if (!res.ok) {
    let msg = `upload failed (${res.status})`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch {
      /* keep default */
    }
    throw new ApiError(msg, res.status);
  }
  return (await res.json()) as { token: string; filename: string };
}

/** Stash a private-repo token; returns a single-use credId for the scan. */
export async function stashGitCred(token: string): Promise<{ credId: string }> {
  if (IS_STATIC_DEMO) demoWriteRefused();
  const res = await fetch("/git-cred", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) {
    let msg = `credential error (${res.status})`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch {
      /* keep default */
    }
    throw new ApiError(msg, res.status);
  }
  return (await res.json()) as { credId: string };
}

/**
 * URL to download / view a generated artifact. `name` is the pure basename
 * inside the run folder; `id` is the run_id that scopes it. When `id` is absent
 * the server falls back to the legacy flat layout (back-compat).
 */
export function fileUrl(id: string | null | undefined, name: string): string {
  if (IS_STATIC_DEMO) {
    // The capture step copies each run folder verbatim, so the artifact keeps
    // its own name under a folder named for the run.
    return `${DEMO_DATA_BASE}/files/${encodeURIComponent(id ?? "")}/${encodeURIComponent(name)}`;
  }
  const idPart = id ? `id=${encodeURIComponent(id)}&` : "";
  return `/file?${idPart}name=${encodeURIComponent(name)}`;
}

/**
 * Export a finished scan's SBOM as SPDX 2.3 JSON (server-side conversion of the
 * CycloneDX BOM the scan already wrote). The scan form has no SPDX toggle — the
 * choice belongs here, after the results exist, so nobody has to re-scan for a
 * format. Idempotent: an already-converted scan returns its existing file.
 * Resolves to the new artifact's name plus the refreshed listing, or null on
 * failure (the caller surfaces a toast).
 */
export async function exportSpdx(
  id: string,
): Promise<{ name: string; results: ResultFile[] } | null> {
  // The demo capture reports spdxExport: false, so the button never renders;
  // conversion needs the server. Null keeps the caller's failure path.
  if (IS_STATIC_DEMO) return null;
  try {
    const res = await fetch(`/spdx-export?id=${encodeURIComponent(id)}`);
    if (!res.ok) return null;
    return (await res.json()) as { name: string; results: ResultFile[] };
  } catch {
    return null;
  }
}

/** A past scan in the local output dir (history; no account / DB). */
export interface RecentScan {
  /** The run_id (run-folder name); pass to loadScan/deleteScan/fileUrl. */
  id: string;
  project: string;
  version: string;
  components: number;
  maxSeverity: Severity | null;
  isAiScan: boolean;
  /**
   * CycloneDX root component type as declared by the SBOM
   * (application/firmware/container/operating-system/data/…) — drives the
   * honest Type label. `null` when the SBOM omits it.
   */
  componentType: string | null;
  /**
   * What the scan was pointed at, from the run's saved config. The root
   * component type cannot separate an analyzed supplier SBOM from a source
   * scan — both declare "application" — so the Type label reads this first.
   * `null` for a scan saved before the config sidecar existed.
   */
  inputSource: SourceType | null;
  /** Unix seconds of the SBOM file mtime. */
  generatedAt: number;
}

/** List past scans (newest first). Empty on any failure — history is optional. */
export async function listScans(): Promise<RecentScan[]> {
  try {
    const res = await fetch(apiUrl("/scans"));
    if (!res.ok) return [];
    return (await res.json()) as RecentScan[];
  } catch {
    return [];
  }
}

/** Delete one past scan by run_id (removes its run folder, or legacy {id}_*). */
export async function deleteScan(id: string): Promise<boolean> {
  if (IS_STATIC_DEMO) return false; // the demo dataset is fixed; the UI hides this
  try {
    const res = await fetch(`/scan-delete?id=${encodeURIComponent(id)}`, {
      method: "POST",
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** Re-open a past scan by run_id; null if it is gone or invalid. */
export async function loadScan(id: string): Promise<DoneEvent | null> {
  try {
    const res = await fetch(apiUrl(`/scan?id=${encodeURIComponent(id)}`));
    if (!res.ok) return null;
    return (await res.json()) as DoneEvent;
  } catch {
    return null;
  }
}

/** Absolute artifact URL (origin + path) — for the "copy link" action. */
export function absoluteFileUrl(id: string | null | undefined, name: string): string {
  return new URL(fileUrl(id, name), window.location.origin).toString();
}

/** URL that streams a run's generated artifacts as a single zip (scoped by id). */
export function downloadAllUrl(id?: string | null): string {
  // The capture step zips each run folder ahead of time, so "download all"
  // stays a real download rather than a disabled button.
  if (IS_STATIC_DEMO) {
    return `${DEMO_DATA_BASE}/files/${encodeURIComponent(id ?? "")}.zip`;
  }
  return id ? `/download-all?id=${encodeURIComponent(id)}` : "/download-all";
}

/** List a run's result files (scoped by run_id; all runs when omitted). */
export async function listResults(id?: string | null): Promise<ResultFile[]> {
  try {
    const res = await fetch(
      apiUrl(id ? `/results?id=${encodeURIComponent(id)}` : "/results"),
    );
    if (!res.ok) return [];
    return (await res.json()) as ResultFile[];
  } catch {
    return [];
  }
}

/**
 * Open the scan SSE stream. Returns the EventSource so the caller can close it
 * (e.g. on unmount). The stream self-closes on `done` and on error.
 */
export function startScan(params: ScanParams, handlers: ScanHandlers): EventSource {
  const qs = new URLSearchParams({
    project: params.project,
    version: params.version,
    source: params.source,
    target: params.target ?? "",
    token: params.token ?? "",
    cred: params.cred ?? "",
    scanoss_cred: params.scanossCred ?? "",
    notice: String(params.notice),
    security: String(params.security),
    deep_license: String(params.deepLicense),
    identify_vendored: String(params.identifyVendored),
    includeOsv: String(params.includeOsv),
    byte_stable: String(params.byteStable),
    license: params.license ?? "",
    usage: params.usage ?? "",
    deep_cve: String(params.deepCve),
    upload_target: params.uploadTarget ?? "",
    upload_url: params.uploadUrl ?? "",
    upload_cred: params.uploadCred ?? "",
    trusca_project_id: params.truscaProjectId ?? "",
  });

  const es = new EventSource(`/scan-stream?${qs.toString()}`);
  let finished = false;

  es.addEventListener("log", (e) => {
    const data = (e as MessageEvent).data;
    try {
      handlers.onLog(JSON.parse(data));
    } catch {
      handlers.onLog(String(data));
    }
  });

  es.addEventListener("progress", (e) => {
    // Determinate progress (e.g. firmware CVE DB download). Best-effort: ignore
    // anything we can't parse into a numeric percent.
    const data = (e as MessageEvent).data;
    try {
      const p = JSON.parse(data) as ScanProgress;
      // Two shapes reach this channel: a percent (firmware CVE DB) and layer
      // counts (an image pull). Accept either, and still drop anything with
      // neither so a malformed event cannot render as 0%.
      if (typeof p.percent === "number" || typeof p.total === "number") {
        handlers.onProgress?.(p);
      }
    } catch {
      /* ignore malformed progress */
    }
  });

  es.addEventListener("error", (e) => {
    // Backend-emitted structured error (clone failed, bad upload, no socket…).
    const data = (e as MessageEvent).data;
    if (!data) return; // native EventSource error has no data; handled by onerror
    try {
      handlers.onError(String(JSON.parse(data)));
    } catch {
      handlers.onError(String(data));
    }
  });

  es.addEventListener("done", (e) => {
    finished = true;
    try {
      handlers.onDone(JSON.parse((e as MessageEvent).data) as DoneEvent);
    } catch {
      handlers.onError();
    }
    es.close();
  });

  es.onerror = () => {
    // The server uses HTTP/1.0 (connection closes after the stream). A close
    // after `done` is expected; only surface an error if we never finished.
    if (!finished) {
      handlers.onError();
    }
    es.close();
  };

  return es;
}
