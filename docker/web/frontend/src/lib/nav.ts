/**
 * Navigation model for the result shell — the single source of truth for the
 * left rail's sections, their grouping and which ones are AI-only.
 *
 * Kept free of React/JSX so the adaptation logic (`visibleGroups`) is unit
 * testable in isolation. The Sidebar component renders these descriptors; the
 * icons are plain lucide components referenced here by value.
 */
import {
  Boxes,
  Cpu,
  FileCheck2,
  FileText,
  GitBranch,
  type LucideIcon,
  LayoutDashboard,
  Package,
  ScrollText,
  ShieldAlert,
} from "lucide-react";

/** Stable identifiers for each result section (used for routing/active state). */
export type SectionId =
  | "overview"
  | "components"
  | "dependencies"
  | "sourceTree"
  | "vulnerabilities"
  | "licenses"
  | "conformance"
  | "models"
  | "artifacts";

export interface NavSection {
  id: SectionId;
  /** i18n key under `nav.*` for the visible label. */
  labelKey: string;
  icon: LucideIcon;
  /**
   * Only shown for AI/ANALYZE scans (model components or AI-SBOM analysis).
   * Non-AI scans never see these so the rail stays honest per scan type.
   */
  aiOnly?: boolean;
  /**
   * Shown only when the scan actually produced this section's data (e.g. a
   * dependency graph or a ScanCode source tree). Omit for always-present
   * sections. Mirrors the conditional tabs the classic dashboard rendered.
   */
  requires?: (ctx: ScanContext) => boolean;
}

export interface NavGroup {
  id: string;
  /** i18n key under `nav.group.*`. */
  labelKey: string;
  sections: NavSection[];
}

/**
 * Context that drives rail adaptation. `mode` is the backend MODE string
 * (SOURCE/IMAGE/ROOTFS/FIRMWARE/ANALYZE…), null before any scan. `isAiScan`
 * gates the AI surfaces (wired in Phase 3; false until then). The `has*` flags
 * mirror the data-conditional tabs the classic dashboard rendered.
 */
export interface ScanContext {
  mode: string | null;
  isAiScan: boolean;
  /** A CycloneDX SBOM artifact exists, so the dependency graph can be built. */
  hasDependencies: boolean;
  /** A ScanCode artifact exists, so the source tree can be shown. */
  hasSourceTree: boolean;
  /**
   * An SBOM conformance report exists (ANALYZE produced format/G7 checks), so
   * the conformance section applies — regardless of AI content.
   */
  hasConformance: boolean;
}

export const EMPTY_SCAN: ScanContext = {
  mode: null,
  isAiScan: false,
  hasDependencies: false,
  hasSourceTree: false,
  hasConformance: false,
};

/**
 * The full rail, grouped. `visibleGroups` filters out AI-only sections for
 * non-AI scans and data-gated sections whose data is absent. Order here is the
 * on-screen order.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    id: "inventory",
    labelKey: "nav.group.inventory",
    sections: [
      { id: "overview", labelKey: "nav.overview", icon: LayoutDashboard },
      { id: "components", labelKey: "nav.components", icon: Boxes },
      {
        id: "dependencies",
        labelKey: "nav.dependencies",
        icon: GitBranch,
        requires: (c) => c.hasDependencies,
      },
      {
        id: "sourceTree",
        labelKey: "nav.sourceTree",
        icon: FileText,
        requires: (c) => c.hasSourceTree,
      },
    ],
  },
  {
    id: "risk",
    labelKey: "nav.group.risk",
    sections: [
      // Supplier-SBOM conformance: shown whenever an ANALYZE produced a
      // conformance report, regardless of AI content. The G7 AI minimum-element
      // checks (when present) render as a sub-block inside this section.
      {
        id: "conformance",
        labelKey: "nav.conformance",
        icon: FileCheck2,
        requires: (c) => c.hasConformance,
      },
      { id: "vulnerabilities", labelKey: "nav.vulnerabilities", icon: ShieldAlert },
      { id: "licenses", labelKey: "nav.licenses", icon: ScrollText },
    ],
  },
  {
    id: "ai",
    labelKey: "nav.group.ai",
    sections: [
      { id: "models", labelKey: "nav.models", icon: Cpu, aiOnly: true },
    ],
  },
  {
    id: "outputs",
    labelKey: "nav.group.outputs",
    sections: [
      { id: "artifacts", labelKey: "nav.artifacts", icon: Package },
    ],
  },
];

/**
 * Groups to render for the given scan: AI-only sections removed for non-AI
 * scans, data-gated sections removed when their data is absent, and any group
 * left empty dropped entirely.
 */
export function visibleGroups(ctx: ScanContext): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    sections: group.sections.filter(
      (s) => (!s.aiOnly || ctx.isAiScan) && (!s.requires || s.requires(ctx)),
    ),
  })).filter((group) => group.sections.length > 0);
}

/** Flat list of visible section ids, in rail order — handy for default/active. */
export function visibleSectionIds(ctx: ScanContext): SectionId[] {
  return visibleGroups(ctx).flatMap((g) => g.sections.map((s) => s.id));
}

