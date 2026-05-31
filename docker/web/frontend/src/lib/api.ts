/**
 * Backend API contract (docker/web/server.py) — kept stable across the UI
 * rebuild. All network access for the app flows through this module so the
 * contract lives in one place.
 *
 *   GET /results            → ResultFile[]
 *   GET /file?name=<n>      → raw file (download / inline view)
 *   GET /scan-stream?…      → SSE: `log` (string line) + `done` (DoneEvent)
 */

export interface ResultFile {
  name: string;
  size: number;
}

export interface SbomSummary {
  components: number;
}

export const SEVERITY_ORDER = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export type SecuritySummary = Record<Severity, number> & { TOTAL: number };

export interface ConformanceSummary {
  result: string; // "pass" | "fail" | "unknown"
  format?: string;
}

export interface DoneEvent {
  ok: boolean;
  mode?: string;
  results: ResultFile[];
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
  conformance?: ConformanceSummary | null;
}

/** Input types the UI offers; each maps to a backend MODE in server.py. */
export type SourceType =
  | "current-dir"
  | "git-url"
  | "zip-upload"
  | "sbom-upload"
  | "firmware-upload"
  | "docker-image";

export const SOURCE_TYPES: SourceType[] = [
  "current-dir",
  "git-url",
  "zip-upload",
  "sbom-upload",
  "firmware-upload",
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
  notice: boolean;
  security: boolean;
  deepLicense: boolean;
  byteStable: boolean;
}

export interface ScanHandlers {
  onLog: (line: string) => void;
  onDone: (done: DoneEvent) => void;
  onError: (message?: string) => void;
}

export interface Capabilities {
  firmware: boolean;
  docker: boolean;
  firmwareImage?: string;
  hostDir?: string; // the host folder the UI was launched from (mounted as /src)
}

/** Which input types this running image supports (firmware needs the fw image). */
export async function getCapabilities(): Promise<Capabilities> {
  try {
    const res = await fetch("/capabilities");
    if (!res.ok) return { firmware: false, docker: true };
    return (await res.json()) as Capabilities;
  } catch {
    return { firmware: false, docker: true };
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

/** URL to download / view a generated artifact (server validates basename). */
export function fileUrl(name: string): string {
  return `/file?name=${encodeURIComponent(name)}`;
}

export async function listResults(): Promise<ResultFile[]> {
  try {
    const res = await fetch("/results");
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
    notice: String(params.notice),
    security: String(params.security),
    deep_license: String(params.deepLicense),
    byte_stable: String(params.byteStable),
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
