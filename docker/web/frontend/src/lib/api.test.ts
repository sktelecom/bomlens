import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  absoluteFileUrl,
  ApiError,
  deleteScan,
  describeUploadError,
  downloadAllUrl,
  fileUrl,
  exportSpdx,
  getCapabilities,
  listScans,
  loadScan,
  stashGitCred,
  startScan,
  uploadFile,
  type DoneEvent,
  type ScanHandlers,
  type ScanParams,
} from "./api";

// ---------------------------------------------------------------------------
// Pure URL builders
// ---------------------------------------------------------------------------
describe("URL builders", () => {
  it("fileUrl scopes by run id and encodes the artifact name", () => {
    expect(fileUrl("run_1.0", "app_1.0_bom.json")).toBe(
      "/file?id=run_1.0&name=app_1.0_bom.json",
    );
    expect(fileUrl("run_1.0", "a b&c.json")).toBe(
      "/file?id=run_1.0&name=a%20b%26c.json",
    );
    // No id falls back to the flat (legacy) name-only URL.
    expect(fileUrl(null, "app_1.0_bom.json")).toBe("/file?name=app_1.0_bom.json");
  });

  it("downloadAllUrl is the zip endpoint, scoped by id when given", () => {
    expect(downloadAllUrl()).toBe("/download-all");
    expect(downloadAllUrl("run_1.0")).toBe("/download-all?id=run_1.0");
  });

  it("absoluteFileUrl prefixes the window origin", () => {
    vi.stubGlobal("window", { location: { origin: "https://host:8080" } });
    expect(absoluteFileUrl("run_1.0", "x.json")).toBe(
      "https://host:8080/file?id=run_1.0&name=x.json",
    );
    vi.unstubAllGlobals();
  });
});

// ---------------------------------------------------------------------------
// fetch-backed network functions
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Upload-error mapping (pure): raw error text never becomes the headline
// ---------------------------------------------------------------------------
describe("describeUploadError", () => {
  it("maps 413 to the too-large message with no raw detail", () => {
    expect(describeUploadError(new ApiError("file too large for zip", 413))).toEqual({
      key: "source.uploadErrorTooLarge",
    });
  });

  it("maps 5xx to the server message, keeping the detail as fine print", () => {
    expect(describeUploadError(new ApiError("upload failed (500)", 500))).toEqual({
      key: "source.uploadErrorServer",
      detail: "upload failed (500)",
    });
  });

  it("maps other 4xx to the rejected message with the server detail", () => {
    expect(describeUploadError(new ApiError("unsupported kind", 400))).toEqual({
      key: "source.uploadErrorRejected",
      detail: "unsupported kind",
    });
  });

  it("maps a fetch network failure (TypeError) to the unreachable message", () => {
    expect(describeUploadError(new TypeError("Failed to fetch"))).toEqual({
      key: "source.uploadErrorNetwork",
    });
  });

  it("falls back to the server message for unknown errors", () => {
    expect(describeUploadError(new Error("boom"))).toEqual({
      key: "source.uploadErrorServer",
      detail: "boom",
    });
    expect(describeUploadError("weird")).toEqual({
      key: "source.uploadErrorServer",
      detail: undefined,
    });
  });
});

describe("network functions", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  const ok = (body: unknown) => ({ ok: true, json: async () => body });
  const fail = (status = 500, body?: unknown) => ({
    ok: false,
    status,
    json: async () => body ?? {},
  });

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("uploadFile POSTs multipart with the kind in query and body", async () => {
    fetchMock.mockResolvedValue(ok({ token: "T1", filename: "a.zip" }));
    const file = new File(["data"], "a.zip");
    const res = await uploadFile(file, "zip");
    expect(res).toEqual({ token: "T1", filename: "a.zip" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/upload?kind=zip");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get("kind")).toBe("zip");
  });

  it("uploadFile throws an ApiError carrying the status and server message", async () => {
    fetchMock.mockResolvedValue(fail(413, { error: "too big" }));
    const err = await uploadFile(new File([""], "a"), "zip").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(413);
    expect(err.message).toBe("too big");
  });

  it("stashGitCred POSTs a JSON token and returns the credId", async () => {
    fetchMock.mockResolvedValue(ok({ credId: "C9" }));
    const res = await stashGitCred("ghp_secret");
    expect(res).toEqual({ credId: "C9" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/git-cred");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body)).toEqual({ token: "ghp_secret" });
  });

  it("getCapabilities returns the payload, or a safe default on failure", async () => {
    fetchMock.mockResolvedValue(ok({ firmware: true, docker: true, aibom: true }));
    expect(await getCapabilities()).toMatchObject({ firmware: true, aibom: true });

    fetchMock.mockResolvedValue(fail(404));
    expect(await getCapabilities()).toEqual({ firmware: false, scanoss: false, docker: true });

    fetchMock.mockRejectedValue(new Error("network"));
    expect(await getCapabilities()).toEqual({ firmware: false, scanoss: false, docker: true });
  });

  it("exportSpdx converts by id, and returns null on any failure", async () => {
    const payload = {
      name: "app_1.0_bom.spdx.json",
      results: [{ name: "app_1.0_bom.spdx.json", size: 10 }],
    };
    fetchMock.mockResolvedValue(ok(payload));
    expect(await exportSpdx("app_1.0")).toEqual(payload);
    expect(fetchMock.mock.calls[0][0]).toBe("/spdx-export?id=app_1.0");

    // 503 (no syft, no docker) and a network error both fall back to null so the
    // caller can say "export unavailable" instead of throwing at the user.
    fetchMock.mockResolvedValue(fail(503));
    expect(await exportSpdx("app_1.0")).toBeNull();
    fetchMock.mockRejectedValue(new Error("network"));
    expect(await exportSpdx("app_1.0")).toBeNull();
  });

  it("listScans returns the array, or [] on any failure", async () => {
    const scans = [{ id: "s1", project: "p", version: "1" }];
    fetchMock.mockResolvedValue(ok(scans));
    expect(await listScans()).toEqual(scans);
    expect(fetchMock.mock.calls[0][0]).toBe("/scans");

    fetchMock.mockResolvedValue(fail());
    expect(await listScans()).toEqual([]);
    fetchMock.mockRejectedValue(new Error("x"));
    expect(await listScans()).toEqual([]);
  });

  it("loadScan fetches by id and returns null when gone", async () => {
    fetchMock.mockResolvedValue(ok({ ok: true }));
    expect(await loadScan("app 1")).toMatchObject({ ok: true });
    expect(fetchMock.mock.calls[0][0]).toBe("/scan?id=app%201");

    fetchMock.mockResolvedValue(fail(404));
    expect(await loadScan("gone")).toBeNull();
  });

  it("deleteScan POSTs and reports ok/failure", async () => {
    fetchMock.mockResolvedValue({ ok: true });
    expect(await deleteScan("s1")).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/scan-delete?id=s1");
    expect(init.method).toBe("POST");

    fetchMock.mockResolvedValue({ ok: false });
    expect(await deleteScan("s1")).toBe(false);
    fetchMock.mockRejectedValue(new Error("x"));
    expect(await deleteScan("s1")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// startScan (EventSource)
// ---------------------------------------------------------------------------
class FakeEventSource {
  static last: FakeEventSource | undefined;
  url: string;
  closed = false;
  onerror: (() => void) | null = null;
  private listeners = new Map<string, (e: unknown) => void>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.last = this;
  }
  addEventListener(type: string, fn: (e: unknown) => void) {
    this.listeners.set(type, fn);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data?: string) {
    this.listeners.get(type)?.({ data } as MessageEvent);
  }
}

function handlers(): ScanHandlers & {
  logs: string[];
  done: DoneEvent[];
  errors: (string | undefined)[];
  progress: { phase: string; percent: number }[];
} {
  const logs: string[] = [];
  const done: DoneEvent[] = [];
  const errors: (string | undefined)[] = [];
  const progress: { phase: string; percent: number }[] = [];
  return {
    logs, done, errors, progress,
    onLog: (l) => logs.push(l),
    onDone: (d) => done.push(d),
    onError: (m) => errors.push(m),
    onProgress: (p) => progress.push(p),
  };
}

const PARAMS: ScanParams = {
  project: "app",
  version: "1.0",
  source: "git-url",
  target: "https://example.com/r.git",
  notice: true,
  security: true,
  deepLicense: false,
  identifyVendored: false,
  includeOsv: false,
  byteStable: false,
};

describe("startScan", () => {
  beforeEach(() => vi.stubGlobal("EventSource", FakeEventSource));
  afterEach(() => vi.unstubAllGlobals());

  it("builds the scan-stream query from params", () => {
    startScan(PARAMS, handlers());
    const url = FakeEventSource.last!.url;
    expect(url.startsWith("/scan-stream?")).toBe(true);
    const qs = new URLSearchParams(url.split("?")[1]);
    expect(qs.get("project")).toBe("app");
    expect(qs.get("version")).toBe("1.0");
    expect(qs.get("source")).toBe("git-url");
    expect(qs.get("target")).toBe("https://example.com/r.git");
    expect(qs.get("security")).toBe("true");
    expect(qs.get("deep_license")).toBe("false");
    expect(qs.get("identify_vendored")).toBe("false");
    expect(qs.get("includeOsv")).toBe("false");
    expect(qs.get("byte_stable")).toBe("false");
  });

  it("parses log lines (JSON and raw fallback)", () => {
    const h = handlers();
    startScan(PARAMS, h);
    const es = FakeEventSource.last!;
    es.emit("log", JSON.stringify("scanning..."));
    es.emit("log", "not-json{");
    expect(h.logs).toEqual(["scanning...", "not-json{"]);
  });

  it("forwards numeric progress and ignores malformed", () => {
    const h = handlers();
    startScan(PARAMS, h);
    const es = FakeEventSource.last!;
    es.emit("progress", JSON.stringify({ phase: "cve-db", percent: 42 }));
    es.emit("progress", "garbage");
    es.emit("progress", JSON.stringify({ phase: "x" })); // no percent
    expect(h.progress).toEqual([{ phase: "cve-db", percent: 42 }]);
  });

  it("delivers the done event and closes the stream", () => {
    const h = handlers();
    startScan(PARAMS, h);
    const es = FakeEventSource.last!;
    const payload: DoneEvent = { ok: true, results: [], sbom: null, security: null };
    es.emit("done", JSON.stringify(payload));
    expect(h.done).toEqual([payload]);
    expect(es.closed).toBe(true);
  });

  it("surfaces a structured error event with its message", () => {
    const h = handlers();
    startScan(PARAMS, h);
    FakeEventSource.last!.emit("error", JSON.stringify("clone failed"));
    expect(h.errors).toEqual(["clone failed"]);
  });

  it("ignores a native (data-less) error event", () => {
    const h = handlers();
    startScan(PARAMS, h);
    FakeEventSource.last!.emit("error", undefined);
    expect(h.errors).toEqual([]);
  });

  it("reports onError when a connection drops before done", () => {
    const h = handlers();
    startScan(PARAMS, h);
    const es = FakeEventSource.last!;
    es.onerror!();
    expect(h.errors).toEqual([undefined]);
    expect(es.closed).toBe(true);
  });

  it("does not report onError when the connection drops after done", () => {
    const h = handlers();
    startScan(PARAMS, h);
    const es = FakeEventSource.last!;
    es.emit("done", JSON.stringify({ ok: true, results: [], sbom: null, security: null }));
    es.onerror!();
    expect(h.errors).toEqual([]);
  });
});
