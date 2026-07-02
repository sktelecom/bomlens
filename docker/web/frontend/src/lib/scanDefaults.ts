/**
 * Prefill heuristics for the New scan form: derive a project name — and, only
 * when the source genuinely carries one, a version — from the scan target, so
 * the user usually confirms instead of typing. Pure functions; useScanForm
 * decides when a suggestion may fill the fields (never over a user edit).
 *
 * A version is suggested only when the source states one (docker tag, a
 * `name-1.2.3` file name, SBOM metadata). No made-up defaults like "1.0":
 * they would pollute the SBOM's metadata.component and the artifact names.
 */
import type { SourceType } from "./api";

export interface IdentitySuggestion {
  project?: string;
  version?: string;
}

/** Refuse to parse unreasonably large SBOM texts (identity prefill is not
 *  worth holding megabytes of JSON.parse work on the UI thread). */
export const SBOM_PARSE_MAX_CHARS = 5 * 1024 * 1024;

/** Last non-empty path segment, tolerant of `/`, `\` and trailing slashes. */
function lastSegment(path: string): string {
  const parts = path.trim().split(/[/\\]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "";
}

/** Repo name from a git URL: last path segment minus `.git`. Also covers the
 *  scp-like `git@host:org/repo.git` form (the last `/` segment is the repo). */
function gitIdentity(target: string): IdentitySuggestion {
  let seg = lastSegment(target);
  // scp-like URLs with no slash at all: `git@host:repo.git`.
  const colon = seg.lastIndexOf(":");
  if (colon >= 0) seg = seg.slice(colon + 1);
  seg = seg.replace(/\.git$/i, "").trim();
  return seg ? { project: seg } : {};
}

/** Image name / tag from a docker reference. The digest (`@sha256:…`) pins the
 *  image but is not a human-readable version, so it is dropped, not suggested.
 *  A colon only counts as the tag separator after the last slash — so the
 *  registry port in `registry:5000/nginx` is left alone. */
function dockerIdentity(target: string): IdentitySuggestion {
  let ref = target.trim();
  if (!ref) return {};
  const at = ref.indexOf("@");
  if (at >= 0) ref = ref.slice(0, at);
  let version: string | undefined;
  const colon = ref.lastIndexOf(":");
  if (colon > ref.lastIndexOf("/")) {
    version = ref.slice(colon + 1).trim() || undefined;
    ref = ref.slice(0, colon);
  }
  const project = lastSegment(ref);
  return {
    ...(project ? { project } : {}),
    ...(version ? { version } : {}),
  };
}

// Longest-first so `.tar.gz` wins over `.gz`. Covers the upload ACCEPT lists
// (archives, firmware blobs) plus the SBOM formats used for filename fallback.
const FILE_SUFFIXES = [
  ".cdx.json",
  ".spdx.json",
  ".tar.bz2",
  ".tar.gz",
  ".tar.xz",
  ".img.gz",
  ".squashfs",
  ".ubifs",
  ".lzma",
  ".sqsh",
  ".json",
  ".spdx",
  ".bin",
  ".bz2",
  ".chk",
  ".dlf",
  ".img",
  ".rom",
  ".tar",
  ".tgz",
  ".trx",
  ".ubi",
  ".xml",
  ".zip",
  ".zst",
  ".fw",
  ".gz",
  ".xz",
];

/** Strip known archive/SBOM suffixes, repeatedly (`fw.img.gz` → `fw`). */
function stripKnownSuffixes(name: string): string {
  let base = name.trim();
  let stripped = true;
  while (stripped) {
    stripped = false;
    const lower = base.toLowerCase();
    for (const suffix of FILE_SUFFIXES) {
      if (lower.endsWith(suffix) && base.length > suffix.length) {
        base = base.slice(0, -suffix.length);
        stripped = true;
        break;
      }
    }
  }
  return base;
}

// A trailing dotted-number token (`-1.2.3`, `_v2.0`) is a version; a bare
// `-2` is too ambiguous to split on.
const NAME_VERSION = /^(.+)[-_]v?(\d+(?:\.\d+)+(?:[.-][0-9A-Za-z]+)*)$/;

/** Project/version from an uploaded file name (`openwrt-21.02.1.img.gz`). */
function fileIdentity(fileName: string): IdentitySuggestion {
  let base = stripKnownSuffixes(lastSegment(fileName));
  // Our own SBOM output naming is `{project}_{version}_bom.json` — drop the
  // `_bom` marker so re-analyzing a generated SBOM round-trips the identity.
  base = base.replace(/[-_.]bom$/i, "");
  if (!base) return {};
  const m = NAME_VERSION.exec(base);
  if (m) return { project: m[1], version: m[2] };
  return { project: base };
}

/**
 * Suggest a project (and maybe version) for the given source. Context fields:
 * `target` (free-text sources), `fileName` (uploads), `hostDir` (current-dir).
 * Returns `{}` when nothing sensible can be derived.
 */
export function suggestIdentity(
  source: SourceType,
  ctx: { target?: string; fileName?: string; hostDir?: string } = {},
): IdentitySuggestion {
  switch (source) {
    case "git-url":
      return gitIdentity(ctx.target ?? "");
    case "docker-image":
      return dockerIdentity(ctx.target ?? "");
    case "ai-model": {
      // HuggingFace `org/name` — the model name is the project.
      const project = lastSegment(ctx.target ?? "");
      return project ? { project } : {};
    }
    case "zip-upload":
    case "firmware-upload":
    case "sbom-upload":
      return fileIdentity(ctx.fileName ?? "");
    case "current-dir": {
      const project = lastSegment(ctx.hostDir ?? "");
      return project ? { project } : {};
    }
    case "rootfs-dir": {
      const project = lastSegment(ctx.target ?? "");
      return project ? { project } : {};
    }
    default:
      return {};
  }
}

/**
 * Identity from an uploaded SBOM's own metadata (the most authoritative
 * source): CycloneDX `metadata.component.{name,version}` or the SPDX
 * `documentDescribes` root package. Takes the file *text* (the hook reads the
 * File); returns null on non-JSON (`.xml`/`.spdx` tag-value), oversized input
 * or no usable identity — the caller then falls back to filename inference.
 */
export function parseSbomIdentity(jsonText: string): IdentitySuggestion | null {
  if (!jsonText || jsonText.length > SBOM_PARSE_MAX_CHARS) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(jsonText);
  } catch {
    return null;
  }
  if (typeof doc !== "object" || doc === null) return null;
  const d = doc as Record<string, unknown>;

  // CycloneDX: metadata.component names the thing the SBOM describes.
  const meta = d.metadata;
  if (typeof meta === "object" && meta !== null) {
    const comp = (meta as Record<string, unknown>).component;
    if (typeof comp === "object" && comp !== null) {
      const c = comp as Record<string, unknown>;
      const project = typeof c.name === "string" ? c.name.trim() : "";
      const version = typeof c.version === "string" ? c.version.trim() : "";
      if (project) return { project, ...(version ? { version } : {}) };
    }
  }

  // SPDX JSON: the package(s) listed in documentDescribes are the subject.
  const describes = Array.isArray(d.documentDescribes) ? d.documentDescribes : [];
  const packages = Array.isArray(d.packages) ? d.packages : [];
  const rootId = describes.find((x): x is string => typeof x === "string");
  if (rootId) {
    for (const pkg of packages) {
      if (typeof pkg !== "object" || pkg === null) continue;
      const p = pkg as Record<string, unknown>;
      if (p.SPDXID !== rootId) continue;
      const project = typeof p.name === "string" ? p.name.trim() : "";
      const version = typeof p.versionInfo === "string" ? p.versionInfo.trim() : "";
      if (project) return { project, ...(version ? { version } : {}) };
    }
  }
  return null;
}
