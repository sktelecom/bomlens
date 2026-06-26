/**
 * Parse ScanCode Toolkit output (`scancode --license --json-pp`, emitted as
 * `{prefix}_scancode.json` when --deep-license is on) into a directory tree
 * for the source file view. Each file carries its detected SPDX license(s).
 *
 * ScanCode emits a flat `files[]` list where every file and directory has a
 * POSIX-relative `path` and a `type` ("file" | "directory"); we rebuild the
 * hierarchy from the path segments.
 */
import { fileUrl } from "./api";

interface ScanCodeLicenseDetection {
  license_expression_spdx?: string;
  license_expression?: string;
}

interface ScanCodeFile {
  path?: string;
  type?: string;
  detected_license_expression_spdx?: string;
  detected_license_expression?: string;
  license_detections?: ScanCodeLicenseDetection[];
}

interface ScanCodeReport {
  files?: ScanCodeFile[];
}

export interface FileNode {
  name: string;
  path: string;
  isDir: boolean;
  licenses: string[];
  children: FileNode[];
}

/** Fetch and parse the raw ScanCode artifact (scoped to the scan's run folder).
 *  Throws on network/JSON failure. */
export async function loadScanCode(
  id: string | null | undefined,
  name: string,
): Promise<ScanCodeReport> {
  const res = await fetch(fileUrl(id, name));
  if (!res.ok) throw new Error(`ScanCode fetch failed (${res.status})`);
  return (await res.json()) as ScanCodeReport;
}

function licenseOf(f: ScanCodeFile): string[] {
  const spdx = f.detected_license_expression_spdx || f.detected_license_expression;
  if (typeof spdx === "string" && spdx) return [spdx];
  const det = Array.isArray(f.license_detections) ? f.license_detections : [];
  const out: string[] = [];
  for (const d of det) {
    const v = d?.license_expression_spdx || d?.license_expression;
    if (typeof v === "string" && v && !out.includes(v)) out.push(v);
  }
  return out;
}

function sortTree(nodes: FileNode[]): void {
  nodes.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  for (const n of nodes) if (n.children.length) sortTree(n.children);
}

export function parseScanCode(report: ScanCodeReport): FileNode[] {
  const files = Array.isArray(report.files) ? report.files : [];
  const roots: FileNode[] = [];
  // Index intermediate nodes by their full path so we can attach children.
  const byPath = new Map<string, FileNode>();

  const ensure = (path: string, isDir: boolean): FileNode => {
    const existing = byPath.get(path);
    if (existing) {
      if (isDir) existing.isDir = true;
      return existing;
    }
    const segments = path.split("/");
    const name = segments[segments.length - 1] || path;
    const node: FileNode = { name, path, isDir, licenses: [], children: [] };
    byPath.set(path, node);
    if (segments.length === 1) {
      roots.push(node);
    } else {
      const parentPath = segments.slice(0, -1).join("/");
      const parent = ensure(parentPath, true);
      parent.children.push(node);
    }
    return node;
  };

  for (const f of files) {
    if (typeof f.path !== "string" || !f.path) continue;
    const isDir = f.type === "directory";
    const node = ensure(f.path, isDir);
    if (!isDir) {
      const lics = licenseOf(f);
      if (lics.length) node.licenses = lics;
    }
  }

  sortTree(roots);
  return roots;
}
