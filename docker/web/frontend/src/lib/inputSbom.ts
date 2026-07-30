// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The supplier SBOM as it arrived (`{prefix}_input.json`, written by
 * describe-input-sbom.py before the conversion to CycloneDX).
 *
 * An ANALYZE scan converts every input to CycloneDX so one pipeline can process
 * it, which means every other screen describes the CONVERSION. The facts that
 * identify the supplier's own document — the format it was written in, the tool
 * that produced it, when, and on whose authority — survive only here.
 *
 * The component list is deliberately not repeated: the Components section does
 * that job with sorting, filters and risk, and a second half-featured table
 * beside it would only split attention.
 */
import { fileUrl } from "./api";

export interface InputRootComponent {
  name: string;
  version: string;
  type: string;
  purl: string;
  licenses: string[];
}

export interface InputSbom {
  /** "CycloneDX" | "SPDX", or "" when the format could not be established. */
  format: string;
  specVersion: string;
  documentId: string;
  documentName: string;
  /** ISO timestamp the document records as its creation time. */
  created: string;
  tools: string[];
  authors: string[];
  supplier: string;
  rootComponent: InputRootComponent;
  componentCount: number;
  originalName: string;
  originalBytes: number;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(str).filter(Boolean) : [];
}

function count(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
}

export function parseInputSbom(raw: unknown): InputSbom {
  const o = (raw ?? {}) as Record<string, unknown>;
  const root = (o.rootComponent ?? {}) as Record<string, unknown>;
  return {
    format: str(o.format),
    specVersion: str(o.specVersion),
    documentId: str(o.documentId),
    documentName: str(o.documentName),
    created: str(o.created),
    tools: strList(o.tools),
    authors: strList(o.authors),
    supplier: str(o.supplier),
    rootComponent: {
      name: str(root.name),
      version: str(root.version),
      type: str(root.type),
      purl: str(root.purl),
      licenses: strList(root.licenses),
    },
    componentCount: count(o.componentCount),
    originalName: str(o.originalName),
    originalBytes: count(o.originalBytes),
  };
}

export async function loadInputSbom(
  id: string | null | undefined,
  name: string,
): Promise<InputSbom> {
  const res = await fetch(fileUrl(id, name));
  if (!res.ok) throw new Error(`input SBOM summary fetch failed (${res.status})`);
  return parseInputSbom(await res.json());
}

/** "CycloneDX 1.6" / "SPDX 2.3", or "" when the format is unknown. */
export function formatLabel(input: InputSbom): string {
  if (!input.format) return "";
  return input.specVersion ? `${input.format} ${input.specVersion}` : input.format;
}

export interface InputFact {
  /** i18n key under `inputSbom.field.*`. */
  labelKey: string;
  value: string;
  /** Render in a monospace box — identifiers and PURLs, not prose. */
  mono?: boolean;
}

/**
 * The document header as an ordered list of facts, with the empty ones dropped.
 *
 * Nothing is invented to fill a row: a document that names no tool simply has no
 * "produced by" line. On a compliance screen, a confident-looking wrong value
 * costs more than a missing one, and the reader can tell the difference between
 * "the supplier did not say" and "we guessed".
 */
export function inputFacts(input: InputSbom): InputFact[] {
  const facts: InputFact[] = [
    { labelKey: "format", value: formatLabel(input) },
    { labelKey: "documentName", value: input.documentName },
    { labelKey: "created", value: input.created },
    { labelKey: "tools", value: input.tools.join(", ") },
    { labelKey: "supplier", value: input.supplier },
    { labelKey: "authors", value: input.authors.join(", ") },
    { labelKey: "documentId", value: input.documentId, mono: true },
    { labelKey: "rootComponent", value: rootLabel(input.rootComponent) },
    {
      labelKey: "rootLicense",
      value: input.rootComponent.licenses.join(", "),
    },
    { labelKey: "purl", value: input.rootComponent.purl, mono: true },
  ];
  return facts.filter((f) => f.value);
}

function rootLabel(root: InputRootComponent): string {
  if (!root.name) return "";
  return root.version ? `${root.name} ${root.version}` : root.name;
}
