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
  | "vulnerabilities"
  | "licenses"
  | "g7"
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
 * is the derived flag the AI surfaces gate on — set once a scan yields AI
 * model/dataset content (wired in a later phase; false in the empty shell).
 */
export interface ScanContext {
  mode: string | null;
  isAiScan: boolean;
}

export const EMPTY_SCAN: ScanContext = { mode: null, isAiScan: false };

/**
 * The full rail, grouped. AI-only sections are filtered out by `visibleGroups`
 * for non-AI scans. Order here is the on-screen order.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    id: "inventory",
    labelKey: "nav.group.inventory",
    sections: [
      { id: "overview", labelKey: "nav.overview", icon: LayoutDashboard },
      { id: "components", labelKey: "nav.components", icon: Boxes },
      { id: "dependencies", labelKey: "nav.dependencies", icon: GitBranch },
    ],
  },
  {
    id: "risk",
    labelKey: "nav.group.risk",
    sections: [
      { id: "vulnerabilities", labelKey: "nav.vulnerabilities", icon: ShieldAlert },
      { id: "licenses", labelKey: "nav.licenses", icon: ScrollText },
      { id: "g7", labelKey: "nav.g7", icon: FileCheck2, aiOnly: true },
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
 * Groups to render for the given scan, with AI-only sections removed for
 * non-AI scans and any group left empty dropped entirely.
 */
export function visibleGroups(ctx: ScanContext): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    sections: group.sections.filter((s) => !s.aiOnly || ctx.isAiScan),
  })).filter((group) => group.sections.length > 0);
}

/** Flat list of visible section ids, in rail order — handy for default/active. */
export function visibleSectionIds(ctx: ScanContext): SectionId[] {
  return visibleGroups(ctx).flatMap((g) => g.sections.map((s) => s.id));
}

/** A past scan entry for the Recent area (populated in a later phase). */
export interface RecentScanLink {
  id: string;
  label: string;
  topSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
}
