/**
 * Where a scan's input came from, for the Overview.
 *
 * A finished result says a lot about *what* was found and nothing about *what
 * was scanned*: two runs both read "Source, 71 components" whether they came
 * from a folder on disk, a GitHub URL or an uploaded ZIP. The scan-config
 * sidecar records the answer (see `write_scanmeta` in server.py, and the
 * `--scan-meta` writer in scan-sbom.sh), and this turns it into something to
 * print.
 *
 * Deliberately not derived from the SBOM. A CycloneDX document keeps almost
 * none of this: a container scan carries the image labels but not the reference
 * that was pulled, a source scan carries a container-internal path like
 * `/app/pom.xml` rather than the host folder, and an uploaded archive carries
 * nothing at all. Guessing from those would print something subtly wrong, which
 * is worse than printing nothing.
 */
import type { ScanConfig, SourceType } from "./api";

/** What kind of thing the input was — picks the label and the icon. */
export type ProvenanceKind =
  | "folder"
  | "git"
  | "image"
  | "file"
  | "sbom"
  | "model";

export interface Provenance {
  kind: ProvenanceKind;
  /** The input itself: a URL, an image reference, a path, a filename. */
  value: string;
  /** i18n key for the label shown beside it. */
  labelKey: string;
}

const KIND_BY_SOURCE: Record<SourceType, ProvenanceKind> = {
  "current-dir": "folder",
  "rootfs-dir": "folder",
  "scan-target-src": "folder",
  "git-url": "git",
  "docker-image": "image",
  "zip-upload": "file",
  "package-upload": "file",
  "firmware-upload": "file",
  "sbom-upload": "sbom",
  "ai-model": "model",
};

const LABEL_KEY: Record<ProvenanceKind, string> = {
  folder: "provenance.folder",
  git: "provenance.git",
  image: "provenance.image",
  file: "provenance.file",
  sbom: "provenance.sbom",
  model: "provenance.model",
};

/**
 * Read the provenance out of a scan config, or null when there is nothing
 * honest to show — an older scan with no sidecar, or one whose sidecar records
 * a source but no input value (an upload from before filenames were kept).
 */
export function provenanceOf(
  config: ScanConfig | null | undefined,
): Provenance | null {
  if (!config) return null;
  const kind = KIND_BY_SOURCE[config.source];
  if (!kind) return null;
  // sourceLabel is what the user picked (an uploaded filename, a resolved
  // folder path); target is the typed-in URL or image reference. Either can be
  // the meaningful one depending on the source, so prefer whichever is filled.
  const value = (config.sourceLabel || config.target || "").trim();
  if (!value) return null;
  return { kind, value, labelKey: LABEL_KEY[kind] };
}
