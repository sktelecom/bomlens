/**
 * Group raw artifact files into logical deliverables.
 *
 * A scan emits the same report in several formats (`_risk-report.md` +
 * `_risk-report.html`, `_security.{json,md,html}`, …). The UI shows one card
 * per logical artifact with a format chip per file, instead of one row per
 * file. The SBOM signature (`_bom.json.sig`) rides along on the SBOM card
 * rather than standing on its own.
 *
 * Titles/descriptions are i18n keys (resolved in the component); this module
 * only decides grouping, ordering and which formats exist.
 */
import {
  BadgeCheck,
  FileJson,
  FileSignature,
  FileText,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";

import type { ResultFile } from "./api";

export interface ArtifactFormat {
  /** Lowercase extension: "html" | "md" | "json" | "txt" | "sig", or the
   *  pseudo-extension "spdx" for the `.spdx.json` export. */
  ext: string;
  /** Full filename (download/view target). */
  name: string;
  size: number;
  viewable: boolean;
}

export interface LogicalArtifact {
  /** Stable group key; also the i18n namespace under `result.kind.<key>`. */
  key: string;
  titleKey: string;
  descKey: string;
  Icon: LucideIcon;
  /** Headline deliverable rendered as the hero card. */
  primary: boolean;
  rank: number;
  formats: ArtifactFormat[];
  /** Detached SBOM signature, attached to the SBOM card when present. */
  signature?: ResultFile;
}

interface GroupSpec {
  key: string;
  Icon: LucideIcon;
  primary: boolean;
  rank: number;
  match: (name: string) => boolean;
}

// Order = display order. Headline deliverable (risk report) floats to the top.
const GROUPS: GroupSpec[] = [
  {
    key: "riskReport",
    Icon: ShieldAlert,
    primary: true,
    rank: 0,
    match: (n) => n.includes("_risk-report"),
  },
  {
    key: "sbom",
    Icon: FileJson,
    primary: false,
    rank: 1,
    // The opt-in SPDX export rides on the SBOM card as an extra format chip.
    match: (n) => n.endsWith("_bom.json") || n.endsWith("_bom.spdx.json"),
  },
  {
    key: "notice",
    Icon: ScrollText,
    primary: false,
    rank: 2,
    match: (n) => n.includes("_NOTICE"),
  },
  {
    key: "conformance",
    Icon: BadgeCheck,
    primary: false,
    rank: 3,
    match: (n) => n.includes("_conformance"),
  },
  {
    key: "security",
    Icon: ShieldCheck,
    primary: false,
    rank: 4,
    // _security_epss.json is the raw EPSS feed the pipeline enriches with —
    // an internal intermediate, not a report format; listing it produced two
    // identical "JSON" chips on the card. Still in the download-all ZIP.
    match: (n) => n.includes("_security") && !n.includes("_security_epss"),
  },
  {
    key: "license",
    Icon: FileText,
    primary: false,
    rank: 5,
    match: (n) => n.includes("_scancode"),
  },
];

// Preferred chip order within a card: rich/human formats first.
const FORMAT_RANK: Record<string, number> = { html: 0, md: 1, txt: 2, json: 3, spdx: 4 };

function extOf(name: string): string {
  // The SPDX export is also .json; a distinct pseudo-extension keeps its chip
  // distinguishable from the CycloneDX one ("SPDX" vs "JSON").
  if (name.endsWith(".spdx.json")) return "spdx";
  const i = name.lastIndexOf(".");
  return i >= 0 ? name.slice(i + 1).toLowerCase() : "";
}

function toFormat(f: ResultFile): ArtifactFormat {
  const ext = extOf(f.name);
  return {
    ext,
    name: f.name,
    size: f.size,
    viewable: ext !== "sig" && ["html", "json", "txt", "md", "spdx"].includes(ext),
  };
}

function byFormatPref(a: ArtifactFormat, b: ArtifactFormat): number {
  return (FORMAT_RANK[a.ext] ?? 9) - (FORMAT_RANK[b.ext] ?? 9);
}

export function groupArtifacts(results: ResultFile[]): LogicalArtifact[] {
  // With --sign + --spdx two signatures exist; the card carries the CycloneDX
  // one (the primary SBOM). The SPDX .sig stays in the download-all ZIP.
  const sig =
    results.find((r) => r.name.endsWith("_bom.json.sig")) ??
    results.find((r) => r.name.endsWith(".sig"));
  const out: LogicalArtifact[] = [];

  for (const spec of GROUPS) {
    const members = results.filter(
      (r) => !r.name.endsWith(".sig") && spec.match(r.name),
    );
    if (members.length === 0) continue;
    out.push({
      key: spec.key,
      titleKey: `result.kind.${spec.key}.title`,
      descKey: `result.kind.${spec.key}.desc`,
      Icon: spec.Icon,
      primary: spec.primary,
      rank: spec.rank,
      formats: members.map(toFormat).sort(byFormatPref),
      signature: spec.key === "sbom" ? sig : undefined,
    });
  }

  // A signature with no SBOM card still deserves to be downloadable.
  if (sig && !out.some((a) => a.key === "sbom")) {
    out.push({
      key: "signature",
      titleKey: "result.kind.signature.title",
      descKey: "result.kind.signature.desc",
      Icon: FileSignature,
      primary: false,
      rank: 6,
      formats: [toFormat(sig)],
    });
  }

  return out.sort((a, b) => a.rank - b.rank);
}

/** Format label shown on a download chip (e.g. "HTML", "JSON"). */
export function formatLabel(ext: string): string {
  return ext.toUpperCase();
}
