// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The AI a scanned source tree uses (the SBOM summary's `aiUsage`): models and
 * AI services the code calls, MCP servers and their configuration files, and
 * agent instruction files. Listed, not measured: these items are not in
 * `componentList`, so they never reach the conformance check, the NOTICE or the
 * model risk assessment. Pure data so the grouping is unit tested; the
 * AiUsageCard component only translates and lays this out.
 */
import type { AiUsageItem, AiUsageKind, AiUsageReviewReason, SbomSummary } from "./api";

/** Display order: what the code calls at runtime first, then the editor and
 *  agent configuration. */
export const AI_USAGE_KINDS: AiUsageKind[] = [
  "model",
  "ai-service",
  "mcp-server",
  "mcp-config",
  "instruction-file",
];

export const AI_USAGE_REASONS: AiUsageReviewReason[] = [
  "broad-filesystem-access",
  "unpinned-package",
  "unencrypted-transport",
];

export const AI_USAGE_KIND_KEY: Readonly<Record<AiUsageKind, string>> = {
  model: "aiUsage.kind.model",
  "ai-service": "aiUsage.kind.aiService",
  "mcp-server": "aiUsage.kind.mcpServer",
  "mcp-config": "aiUsage.kind.mcpConfig",
  "instruction-file": "aiUsage.kind.instructionFile",
};

export const AI_USAGE_REASON_KEY: Readonly<Record<AiUsageReviewReason, string>> = {
  "broad-filesystem-access": "aiUsage.reason.broadFilesystemAccess",
  "unpinned-package": "aiUsage.reason.unpinnedPackage",
  "unencrypted-transport": "aiUsage.reason.unencryptedTransport",
};

/** The one-sentence explanation shown with a reason's label. */
export const AI_USAGE_REASON_HELP_KEY: Readonly<Record<AiUsageReviewReason, string>> = {
  "broad-filesystem-access": "aiUsage.reasonHelp.broadFilesystemAccess",
  "unpinned-package": "aiUsage.reasonHelp.unpinnedPackage",
  "unencrypted-transport": "aiUsage.reasonHelp.unencryptedTransport",
};

export function aiUsageScopeKey(scope: AiUsageItem["scope"]): string {
  return scope === "development" ? "aiUsage.scope.development" : "aiUsage.scope.runtime";
}

export interface AiUsageGroup {
  kind: AiUsageKind;
  items: AiUsageItem[];
}

export interface AiUsageView {
  groups: AiUsageGroup[];
  total: number;
  /** Items with at least one review reason. */
  reviewCount: number;
  /** Review reasons that occur at least once, in AI_USAGE_REASONS order. */
  reasons: AiUsageReviewReason[];
  /** The server capped the list (500 items). */
  truncated: boolean;
}

const isKind = (k: unknown): k is AiUsageKind => AI_USAGE_KINDS.includes(k as AiUsageKind);
const isReason = (r: unknown): r is AiUsageReviewReason =>
  AI_USAGE_REASONS.includes(r as AiUsageReviewReason);

/** One item cleaned for display: an unknown kind or a nameless item is dropped,
 *  unknown review reasons and non-string models are ignored. */
function normItem(raw: unknown): AiUsageItem | null {
  if (!raw || typeof raw !== "object") return null;
  const it = raw as Partial<AiUsageItem>;
  if (!isKind(it.kind) || typeof it.name !== "string" || !it.name) return null;
  const reasons = Array.isArray(it.reviewReasons) ? it.reviewReasons.filter(isReason) : [];
  const models = Array.isArray(it.models)
    ? it.models.filter((m): m is string => typeof m === "string" && m.length > 0)
    : undefined;
  return {
    ...it,
    kind: it.kind,
    name: it.name,
    scope: it.scope === "development" ? "development" : "runtime",
    reviewReasons: AI_USAGE_REASONS.filter((r) => reasons.includes(r)),
    ...(models ? { models } : {}),
  };
}

/** Items that need a look first, then by name. */
function compareItems(a: AiUsageItem, b: AiUsageItem): number {
  const ra = a.reviewReasons.length > 0 ? 0 : 1;
  const rb = b.reviewReasons.length > 0 ? 0 : 1;
  if (ra !== rb) return ra - rb;
  return a.name.localeCompare(b.name);
}

/** The AI usage of a scan grouped by kind, or null when it recorded none. */
export function aiUsageView(sbom: SbomSummary | null | undefined): AiUsageView | null {
  const list = Array.isArray(sbom?.aiUsage) ? sbom.aiUsage : [];
  const items = list.map(normItem).filter((i): i is AiUsageItem => i !== null);
  if (items.length === 0) return null;
  const groups = AI_USAGE_KINDS.map((kind) => ({
    kind,
    items: items.filter((i) => i.kind === kind).sort(compareItems),
  })).filter((g) => g.items.length > 0);
  return {
    groups,
    total: items.length,
    reviewCount: items.filter((i) => i.reviewReasons.length > 0).length,
    reasons: AI_USAGE_REASONS.filter((r) => items.some((i) => i.reviewReasons.includes(r))),
    truncated: sbom?.aiUsageTruncated === true,
  };
}

const HUB_PREFIX = "https://huggingface.co/";
const HF_PURL_RE = /^pkg:huggingface\/([^/@?#]+)\/([^/@?#]+)/i;
const HF_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** owner/name of a hub model from its purl, or null (not a hub model, or an
 *  id that could not be passed safely to a shell). */
export function hubModelId(purl: string | undefined): string | null {
  const m = HF_PURL_RE.exec(purl ?? "");
  if (!m) return null;
  let id: string;
  try {
    id = `${decodeURIComponent(m[1])}/${decodeURIComponent(m[2])}`;
  } catch {
    return null;
  }
  return HF_ID_RE.test(id) && !id.includes("..") ? id : null;
}

/** The hub page link, only for https://huggingface.co/ (the SBOM is untrusted input). */
export function safeHubUrl(url: string | undefined): string | undefined {
  return typeof url === "string" && url.startsWith(HUB_PREFIX) && !/\s/.test(url) ? url : undefined;
}

export interface AiUsageResolution {
  key: string;
  status?: number;
}

export interface AiUsageModelDetail {
  license?: string;
  gated?: "auto" | "manual";
  weightFormats: string[];
  pickleFiles: number;
  lineage?: string;
  verdict?: "ok" | "conditional" | "caution" | "review";
  hubUrl?: string;
  /** Why the hub data is missing, when the lookup ran and failed. */
  resolution: AiUsageResolution | null;
  modelSbom?: string;
  /** The command that builds the model's full SBOM (resolved hub models without one). */
  scanCommand?: string;
  /** Anything to show beyond the name and provider. */
  hasDetail: boolean;
}

const VERDICTS = ["ok", "conditional", "caution", "review"] as const;

/** What the hub lookup added to a model row; null for any other kind. A model
 *  the scan did not look up (no `resolved` key) has no detail. */
export function aiUsageModelDetail(it: AiUsageItem): AiUsageModelDetail | null {
  if (it.kind !== "model") return null;
  const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v : undefined);
  const resolved = it.resolved;
  const formats = Array.isArray(it.weightFormats)
    ? it.weightFormats.filter((f): f is string => typeof f === "string" && f.length > 0)
    : [];
  const pickle = typeof it.pickleFiles === "number" && it.pickleFiles > 0 ? Math.floor(it.pickleFiles) : 0;
  const modelSbom = str(it.modelSbom);
  let resolution: AiUsageResolution | null = null;
  if (resolved === "unreadable") {
    resolution =
      typeof it.resolvedStatus === "number"
        ? { key: "aiUsage.resolution.unreadable", status: it.resolvedStatus }
        : { key: "aiUsage.resolution.unreadableNoStatus" };
  } else if (resolved === "unreachable") {
    resolution = { key: "aiUsage.resolution.unreachable" };
  } else if (resolved === "not-attempted") {
    resolution = { key: "aiUsage.resolution.notAttempted" };
  }
  const id = hubModelId(it.purl);
  const detail: AiUsageModelDetail = {
    license: resolved === "huggingface" ? str(it.license) : undefined,
    gated: resolved === "huggingface" && (it.gated === "auto" || it.gated === "manual") ? it.gated : undefined,
    weightFormats: resolved === "huggingface" ? formats : [],
    pickleFiles: resolved === "huggingface" ? pickle : 0,
    lineage: resolved === "huggingface" ? str(it.lineage) : undefined,
    verdict: resolved === "huggingface" && VERDICTS.includes(it.verdict as never) ? it.verdict : undefined,
    hubUrl: resolved === undefined ? undefined : safeHubUrl(it.hubUrl),
    resolution,
    modelSbom,
    scanCommand: resolved === "huggingface" && !modelSbom && id ? `./scripts/scan-sbom.sh --model ${id}` : undefined,
    hasDetail: false,
  };
  detail.hasDetail = Boolean(
    detail.license || detail.gated || detail.weightFormats.length || detail.pickleFiles || detail.lineage ||
      detail.verdict || detail.hubUrl || detail.resolution || detail.modelSbom || detail.scanCommand,
  );
  return detail;
}
