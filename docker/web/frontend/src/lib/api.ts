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
  /** Source / download location (externalReferences vcs/distribution/website). */
  source?: string;
  /** Copyright holder line, when the SBOM captured one. */
  copyright?: string;
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
export type SecuritySummary = Record<Severity, number> & {
  TOTAL: number;
  vulnerabilities?: VulnItem[];
  /** Engine failure message when the scan did not complete (scan-security.sh
   *  ScanError). Present => the counts above understate the real exposure. */
  scanError?: string;
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
}

export interface ConformanceSummary {
  result: string; // "pass" | "fail" | "unknown"
  format?: string;
  /** Per-check results; G7 checks have ids prefixed "g7-". */
  checks?: ConformanceCheck[];
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
  project: string;
  version: string;
  notice: boolean;
  security: boolean;
  deepLicense: boolean;
  identifyVendored: boolean;
  includeOsv: boolean;
  byteStable: boolean;
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
  | "git-url"
  | "zip-upload"
  | "sbom-upload"
  | "firmware-upload"
  | "ai-model"
  | "docker-image";

export const SOURCE_TYPES: SourceType[] = [
  "current-dir",
  "rootfs-dir",
  "git-url",
  "zip-upload",
  "sbom-upload",
  "firmware-upload",
  "ai-model",
  "docker-image",
];

export type UploadKind = "zip" | "sbom" | "firmware";

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
  /** Optional upload of the generated SBOM. "" leaves the scan generate-only. */
  uploadTarget?: "" | "dependency-track" | "trusca";
  uploadUrl?: string; // upload server base URL (API_URL)
  uploadCred?: string; // single-use credId for the upload token (API_KEY)
  truscaProjectId?: string; // required when uploadTarget === "trusca"
}

/** A determinate progress update (e.g. CVE database download). */
export interface ScanProgress {
  phase: string;
  percent: number;
}

export interface ScanHandlers {
  onLog: (line: string) => void;
  onDone: (done: DoneEvent) => void;
  onError: (message?: string) => void;
  /** Optional determinate progress (e.g. firmware CVE DB download). */
  onProgress?: (p: ScanProgress) => void;
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
  firmwareImage?: string;
  aibomImage?: string;
  hostDir?: string; // the host folder the UI was launched from (mounted as /src)
}

/** Which input types this running image supports (firmware needs the fw image). */
export async function getCapabilities(): Promise<Capabilities> {
  try {
    const res = await fetch("/capabilities");
    if (!res.ok) return { firmware: false, scanoss: false, docker: true };
    return (await res.json()) as Capabilities;
  } catch {
    return { firmware: false, scanoss: false, docker: true };
  }
}

/** Upload a file (zip/sbom/firmware) and get back a server-side token. */
export async function uploadFile(
  file: File,
  kind: UploadKind,
): Promise<{ token: string; filename: string }> {
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
    throw new Error(msg);
  }
  return (await res.json()) as { token: string; filename: string };
}

/** Stash a private-repo token; returns a single-use credId for the scan. */
export async function stashGitCred(token: string): Promise<{ credId: string }> {
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
    throw new Error(msg);
  }
  return (await res.json()) as { credId: string };
}

/**
 * URL to download / view a generated artifact. `name` is the pure basename
 * inside the run folder; `id` is the run_id that scopes it. When `id` is absent
 * the server falls back to the legacy flat layout (back-compat).
 */
export function fileUrl(id: string | null | undefined, name: string): string {
  const idPart = id ? `id=${encodeURIComponent(id)}&` : "";
  return `/file?${idPart}name=${encodeURIComponent(name)}`;
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
  /** Unix seconds of the SBOM file mtime. */
  generatedAt: number;
}

/** List past scans (newest first). Empty on any failure — history is optional. */
export async function listScans(): Promise<RecentScan[]> {
  try {
    const res = await fetch("/scans");
    if (!res.ok) return [];
    return (await res.json()) as RecentScan[];
  } catch {
    return [];
  }
}

/** Delete one past scan by run_id (removes its run folder, or legacy {id}_*). */
export async function deleteScan(id: string): Promise<boolean> {
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
    const res = await fetch(`/scan?id=${encodeURIComponent(id)}`);
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
  return id ? `/download-all?id=${encodeURIComponent(id)}` : "/download-all";
}

/** List a run's result files (scoped by run_id; all runs when omitted). */
export async function listResults(id?: string | null): Promise<ResultFile[]> {
  try {
    const res = await fetch(id ? `/results?id=${encodeURIComponent(id)}` : "/results");
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
      if (typeof p.percent === "number") handlers.onProgress?.(p);
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
