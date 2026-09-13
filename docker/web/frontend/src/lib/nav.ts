// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

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
  FileInput,
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
  | "inputSbom"
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
  /** The scan's input was an SBOM and its header summary was captured. */
  hasInputSbom: boolean;
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
  hasInputSbom: false,
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
      // The scanned input, when that input was itself an SBOM: what the
      // supplier sent, before the conversion to CycloneDX that everything else
      // on screen describes. Sits beside the source tree because it answers the
      // same question for a different kind of scan — what did we look at?
      {
        id: "inputSbom",
        labelKey: "nav.inputSbom",
        icon: FileInput,
        requires: (c) => c.hasInputSbom,
      },
    ],
  },
  // Security and compliance are split because they are read by different people
  // at different moments: a CVE list is triaged against a patch schedule, while
  // licence obligations are settled once per release. Grouping them together
  // made whoever needed one of them scan past the other.
  {
    id: "security",
    labelKey: "nav.group.security",
    sections: [
      { id: "vulnerabilities", labelKey: "nav.vulnerabilities", icon: ShieldAlert },
    ],
  },
  {
    id: "compliance",
    labelKey: "nav.group.compliance",
    sections: [
      { id: "licenses", labelKey: "nav.licenses", icon: ScrollText },
      // A conformance report exists for every mode (a mandatory checklist run
      // against whatever SBOM the scan ends with) and the section shows it
      // for every one of them — a self-generated SBOM's own checklist is a
      // real thing to show a reader, not a verdict BomLens passes on itself:
      // the self-grading confusion an earlier design tried to solve by
      // hiding the section here is instead solved by the section's own
      // label and intro line naming what is actually being checked (the
      // document's own fields, not the scanned software or a submission
      // review) — see nav.conformance and g7.panelIntro.
      //
      // The one case still routed elsewhere: a self-generated AI SBOM's G7
      // minimum-element rollup. That grades the model PUBLISHER's own
      // disclosure (BomLens only transcribes the model card), a real finding
      // rather than a self-grade either way, but showing it a second time
      // here would duplicate what Models & datasets already carries
      // (AiSummaryCard + this section's own CheckGroup rendering, reused
      // there) — so hasInputSbom still gates it for that one case.
      // nav.conformance ("SBOM Validation" in English) is close to the rail's
      // per-row width budget — see the RAIL_ROW comment in Sidebar.tsx —
      // check the rendered rail before lengthening it further.
      {
        id: "conformance",
        labelKey: "nav.conformance",
        icon: FileCheck2,
        requires: (c) => c.hasConformance && (c.hasInputSbom || !c.isAiScan),
      },
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

/** A past scan as shown in the top bar's Recent menu (lightweight link shape). */
export interface RecentScanLink {
  id: string;
  label: string;
  topSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
}

