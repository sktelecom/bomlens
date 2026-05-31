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

export interface DoneEvent {
  ok: boolean;
  results: ResultFile[];
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
}

export interface ScanParams {
  project: string;
  version: string;
  target?: string;
  notice: boolean;
  security: boolean;
  deepLicense: boolean;
  byteStable: boolean;
}

export interface ScanHandlers {
  onLog: (line: string) => void;
  onDone: (done: DoneEvent) => void;
  onError: () => void;
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
    target: params.target ?? "",
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
