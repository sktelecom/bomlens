/**
 * The source snapshot (`{prefix}_source.json`, written by source-snapshot.py):
 * the text content of the files a scan looked at, so the result screens can show
 * what was SCANNED and not only what was found.
 *
 * The scanner bounds the capture (text only, per-file and total size caps), so a
 * file in the tree may have no entry here. That is expected, not an error — the
 * viewer says why instead of showing an empty box, using the `totals` the
 * scanner reports.
 *
 * Mirrors the artifact's shape; every field is optional on the wire because an
 * older scan's folder may predate this artifact entirely.
 */
import { fileUrl } from "./api";

export interface SnapshotFile {
  /** Path relative to the scanned root, matching the file tree's `path`. */
  path: string;
  /** Size of the real file, which exceeds `content` when truncated. */
  size: number;
  content: string;
  truncated: boolean;
}

export interface SnapshotLink {
  path: string;
  /** Where the link points, exactly as recorded — absolute or relative. */
  target: string;
}

export interface SnapshotTotals {
  files: number;
  links: number;
  bytes: number;
  truncatedFiles: number;
  skippedBinary: number;
  skippedBudget: number;
  skippedUnreadable: number;
}

export interface SourceSnapshot {
  root: string;
  totals: SnapshotTotals;
  files: SnapshotFile[];
  links: SnapshotLink[];
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
}

/**
 * Normalize the raw artifact into a shape the view can trust: files with a
 * usable path and string content, totals that are always numbers. Anything
 * malformed is dropped rather than rendered as `undefined`.
 */
export function parseSnapshot(raw: unknown): SourceSnapshot {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const rawFiles = Array.isArray(obj.files) ? obj.files : [];
  const files: SnapshotFile[] = [];
  for (const entry of rawFiles) {
    const f = (entry ?? {}) as Record<string, unknown>;
    if (typeof f.path !== "string" || !f.path) continue;
    if (typeof f.content !== "string") continue;
    files.push({
      path: f.path,
      size: num(f.size),
      content: f.content,
      truncated: f.truncated === true,
    });
  }
  const rawLinks = Array.isArray(obj.links) ? obj.links : [];
  const links: SnapshotLink[] = [];
  for (const entry of rawLinks) {
    const l = (entry ?? {}) as Record<string, unknown>;
    if (typeof l.path !== "string" || !l.path) continue;
    links.push({ path: l.path, target: typeof l.target === "string" ? l.target : "" });
  }
  const rawTotals = (obj.totals ?? {}) as Record<string, unknown>;
  return {
    root: typeof obj.root === "string" ? obj.root : "",
    totals: {
      files: num(rawTotals.files) || files.length,
      links: num(rawTotals.links) || links.length,
      bytes: num(rawTotals.bytes),
      truncatedFiles: num(rawTotals.truncatedFiles),
      skippedBinary: num(rawTotals.skippedBinary),
      skippedBudget: num(rawTotals.skippedBudget),
      skippedUnreadable: num(rawTotals.skippedUnreadable),
    },
    files,
    links,
  };
}

/** Fetch and normalize the snapshot artifact (scoped to the scan's run folder). */
export async function loadSourceSnapshot(
  id: string | null | undefined,
  name: string,
): Promise<SourceSnapshot> {
  const res = await fetch(fileUrl(id, name));
  if (!res.ok) throw new Error(`source snapshot fetch failed (${res.status})`);
  return parseSnapshot(await res.json());
}

/** Path -> link target, for the tree rows that are symlinks. */
export function indexLinks(snapshot: SourceSnapshot | null): Map<string, string> {
  const map = new Map<string, string>();
  for (const l of snapshot?.links ?? []) map.set(l.path, l.target);
  return map;
}

/** Path -> file, so the tree can look up the selected row in one step. */
export function indexSnapshot(snapshot: SourceSnapshot | null): Map<string, SnapshotFile> {
  const map = new Map<string, SnapshotFile>();
  for (const f of snapshot?.files ?? []) map.set(f.path, f);
  return map;
}

/**
 * Why a file in the tree has no content to show. `null` means it does have
 * content. "budget" is a guess in the honest sense: the scanner counts how many
 * files it left out but not which ones, so when any were dropped that is the
 * likelier reason for a missing text file than an unreadable one.
 */
export type MissingReason = "binary" | "budget" | "unknown";

export function missingReason(
  snapshot: SourceSnapshot | null,
  path: string,
): MissingReason | null {
  if (!snapshot) return "unknown";
  if (snapshot.files.some((f) => f.path === path)) return null;
  if (snapshot.totals.skippedBudget > 0) return "budget";
  if (snapshot.totals.skippedBinary > 0) return "binary";
  return "unknown";
}

/**
 * Line count of a file's captured content, for the viewer's gutter. A trailing
 * newline ends the last line rather than starting an empty one.
 */
export function lineCount(content: string): number {
  if (!content) return 0;
  const body = content.endsWith("\n") ? content.slice(0, -1) : content;
  return body.split("\n").length;
}
