// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The publisher's declaration for a scan's SPDX 3.0.1 AI document, as the
 * screens edit it.
 *
 * The converter (`docker/lib/convert-to-spdx3-ai.py`) owns the rules: the field
 * mapping (`spdx3-ai-map.json`), the empty declaration it writes for a scan
 * (only the fields the scan left open), and the check of a saved declaration.
 * This module reads those, keeps the answers, and repeats the converter's
 * value checks so a person sees a mistake beside the field rather than as a
 * refusal after saving. The server's check still decides.
 */
import type { Spdx3Counts } from "./api";

// ---- the mapping --------------------------------------------------------------

export interface MapField {
  id: string;
  type: string;
  min: number;
  max: number | "*";
  /** The field's vocabulary has its own "unknown" value (PresenceType, DatasetType). */
  noAssertion: boolean;
  enum?: string[];
  /** `fallback`: what the converter writes when nothing filled the field. */
  source: { kind: string; fallback?: string };
  declarable?: boolean;
  judgment?: boolean;
  /** The kinds of agent the field takes (a service's provider: Organization). */
  agentTypes?: string[];
  /** The values of a data flow's direction (CycloneDX dataFlowDirection). */
  flowEnum?: string[];
}

/** The mapping's element keys: the SPDX classes, and the declared service and
 *  the external models it calls (their SPDX classes are in the mapping's
 *  spdxType). */
export type ElementType = "document" | "ai_AIPackage" | "dataset_DatasetPackage" | "service" | "externalModel";

/** Field definitions by element type and field id. */
export type FieldIndex = Record<ElementType, Record<string, MapField>>;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read the mapping the server serves; null when it is not the expected shape. */
export function parseMap(raw: unknown): FieldIndex | null {
  if (!isObj(raw) || !isObj(raw.elements)) return null;
  const out = {} as FieldIndex;
  for (const et of ["document", "ai_AIPackage", "dataset_DatasetPackage", "service", "externalModel"] as const) {
    const el = raw.elements[et];
    // The service and external models came with v1.14; a mapping without them
    // asks no service questions.
    if ((et === "service" || et === "externalModel") && !isObj(el)) {
      out[et] = {};
      continue;
    }
    if (!isObj(el) || !Array.isArray(el.fields)) return null;
    const fields: Record<string, MapField> = {};
    for (const f of el.fields) {
      if (!isObj(f) || typeof f.id !== "string" || typeof f.type !== "string") continue;
      fields[f.id] = {
        id: f.id,
        type: f.type,
        min: typeof f.min === "number" ? f.min : 0,
        max: f.max === "*" ? "*" : typeof f.max === "number" ? f.max : 1,
        noAssertion: f.noAssertion === true,
        enum: Array.isArray(f.enum) ? f.enum.filter((x): x is string => typeof x === "string") : undefined,
        source: isObj(f.source) && typeof f.source.kind === "string"
          ? { kind: f.source.kind, ...(typeof f.source.fallback === "string" ? { fallback: f.source.fallback } : {}) }
          : { kind: "user" },
        declarable: f.declarable === true,
        judgment: f.judgment === true,
        ...(Array.isArray(f.agentTypes)
          ? { agentTypes: f.agentTypes.filter((x): x is string => typeof x === "string") }
          : {}),
        ...(Array.isArray(f.flowEnum)
          ? { flowEnum: f.flowEnum.filter((x): x is string => typeof x === "string") }
          : {}),
      };
    }
    out[et] = fields;
  }
  return out;
}

// ---- the check ------------------------------------------------------------------

export type FieldStatus = keyof Spdx3Counts;

export interface CheckField {
  id: string;
  status: FieldStatus;
  /** The written value, shortened; only on a filled field. */
  display?: string;
  /** "cdx:<what>" or "rule:<name>" for a value the scan filled. */
  source?: string;
  meaning?: string;
}

export interface CheckElement {
  type: string;
  label: string;
  /** "document", "model", "huggingface:<id>" or "local:<slug>"; absent for an
   *  element a declaration cannot address. */
  declarationKey?: string;
  fields: CheckField[];
}

export interface CheckRelationship {
  type: string;
  status: string | null;
  note?: string;
  /** The name of the element it starts from. */
  fromLabel?: string;
  /** The names of the elements it points to, where the check describes them. */
  toLabel?: string;
}

export interface Spdx3Check {
  draft: boolean;
  counts: Partial<Spdx3Counts>;
  elements: CheckElement[];
  relationships: CheckRelationship[];
  messages: { level: string; text: string }[];
}

const STATUSES: FieldStatus[] = [
  "auto",
  "declared",
  "optional",
  "judgment",
  "missingRequired",
  "noAssertion",
  "omitted",
  "review",
];

/** Read `_spdx3-check.json`; null when it is not the expected shape. */
export function parseCheck(raw: unknown): Spdx3Check | null {
  if (!isObj(raw) || !Array.isArray(raw.elements) || !isObj(raw.counts)) return null;
  const elements: CheckElement[] = [];
  const labels = new Map<string, string>();
  for (const e of raw.elements) {
    if (isObj(e) && typeof e.spdxId === "string" && typeof e.label === "string") labels.set(e.spdxId, e.label);
  }
  for (const e of raw.elements) {
    if (!isObj(e) || !Array.isArray(e.fields)) continue;
    const fields: CheckField[] = [];
    for (const f of e.fields) {
      if (!isObj(f) || typeof f.id !== "string") continue;
      const status = STATUSES.includes(f.status as FieldStatus) ? (f.status as FieldStatus) : "omitted";
      fields.push({
        id: f.id,
        status,
        display: typeof f.display === "string" ? f.display : undefined,
        source: typeof f.source === "string" ? f.source : undefined,
        meaning: typeof f.meaning === "string" ? f.meaning : undefined,
      });
    }
    elements.push({
      type: typeof e.type === "string" ? e.type : "",
      label: typeof e.label === "string" ? e.label : "",
      declarationKey: typeof e.declarationKey === "string" ? e.declarationKey : undefined,
      fields,
    });
  }
  const counts: Partial<Spdx3Counts> = {};
  for (const s of STATUSES) {
    const v = raw.counts[s];
    if (typeof v === "number" && Number.isFinite(v)) counts[s] = v;
  }
  return {
    draft: raw.draft === true,
    counts,
    elements,
    relationships: Array.isArray(raw.relationships)
      ? raw.relationships.filter(isObj).map((r) => {
          const to = (Array.isArray(r.to) ? r.to : [r.to])
            .map((x) => (typeof x === "string" ? labels.get(x) : undefined))
            .filter((x): x is string => Boolean(x));
          return {
            type: typeof r.type === "string" ? r.type : "",
            status: typeof r.status === "string" ? r.status : null,
            note: typeof r.note === "string" ? r.note : undefined,
            fromLabel: typeof r.from === "string" ? labels.get(r.from) : undefined,
            toLabel: to.length ? to.join(", ") : undefined,
          };
        })
      : [],
    messages: Array.isArray(raw.messages)
      ? raw.messages
          .filter(isObj)
          .filter((m) => typeof m.text === "string")
          .map((m) => ({ level: typeof m.level === "string" ? m.level : "info", text: m.text as string }))
      : [],
  };
}

/** The four groups the status band draws, in order. "Optional" also holds the
 *  relationships and sources to check, and the vocabulary's own "unknown". */
export interface BandSegment {
  key: "filled" | "optional" | "judgment" | "missingRequired";
  count: number;
}

/** The elements that still have required fields open, with how many each. */
export function missingByElement(check: Spdx3Check): { type: string; label: string; count: number }[] {
  return check.elements
    .map((e) => ({ type: e.type, label: e.label, count: e.fields.filter((f) => f.status === "missingRequired").length }))
    .filter((e) => e.count > 0);
}

/** The datasets the model uses with no role stated, by where they were named:
 *  on the scanned model's card, or in the publisher's own declaration (a
 *  model described from a declaration has no card). */
export function rolesNotStated(check: Spdx3Check): { card: string[]; declared: string[] } {
  const pick = (note: string) =>
    check.relationships
      .filter((r) => r.status === "review" && r.note === note)
      .map((r) => r.toLabel)
      .filter((x): x is string => Boolean(x));
  return { card: pick("card-declared dataset, role not stated"), declared: pick("declared dataset, role not stated") };
}

export function bandSegments(counts: Partial<Spdx3Counts>): BandSegment[] {
  const n = (k: FieldStatus) => counts[k] ?? 0;
  return [
    { key: "filled", count: n("auto") + n("declared") },
    { key: "optional", count: n("optional") + n("noAssertion") + n("review") },
    { key: "judgment", count: n("judgment") },
    { key: "missingRequired", count: n("missingRequired") },
  ];
}

// ---- the declaration --------------------------------------------------------------

export const DECLARATION_SCHEMA = "bomlens-ai-declaration/1";
/** "Agent" is what the converter writes for an agent of no stated kind. */
export const AGENT_TYPES = ["Organization", "Person", "Agent"] as const;
export const ROLES = ["trainedOn", "testedOn", "other"] as const;
export const URI_SCHEMES = ["http", "https", "s3", "gs", "ftp", "sftp", "git", "git+https", "git+ssh", "hf"];
export const MAX_TEXT = 4000;
const REVISION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** A hub licence tag or an SPDX licence id, as the converter takes it. */
const SPDX_ID_RE = /^(LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]{0,99})$/;
const DATE_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

export interface Agent {
  type?: string;
  name: string;
}
export interface DictEntry {
  key: string;
  value: string;
}
export type Value = string | string[] | Agent | Agent[] | DictEntry[] | null;

/** A source a publisher declares for a dataset: a hub dataset by id (read
 *  from the hub at the next scan) or one named in words with its licence. */
export interface SourceEntry {
  ref?: string;
  name?: string;
  license?: string;
  relation: "extended" | "other";
}

export const SOURCE_RELATIONS = ["extended", "other"] as const;

export interface DeclDataset {
  ref?: string;
  local?: string;
  name?: string;
  role?: string;
  sources?: SourceEntry[];
  [field: string]: Value | SourceEntry[] | undefined;
}

export interface BaseModelEntry {
  ref: string;
  revision: string;
}

/** The model's answers by field id, plus the base models' revisions and the
 *  model's own licence. */
export interface ModelAnswers {
  [field: string]: Value | BaseModelEntry[] | undefined;
  baseModels?: BaseModelEntry[];
  license?: string;
}

/**
 * The model's own licence. SPDX 3.0.1 writes a licence as a hasDeclaredLicense
 * relationship, not a property, so the mapping has no field for it; the
 * declaration takes it as `model.license`, a hub licence tag or an SPDX id.
 * The server's empty declaration asks for it only when the scan found none.
 */
export const MODEL_LICENSE_FIELD: MapField = {
  id: "license",
  type: "license",
  min: 0,
  max: 1,
  noAssertion: false,
  source: { kind: "user" },
  declarable: true,
};

/** Licence tags a model or dataset on HuggingFace most often carries, offered
 *  as suggestions where a licence is typed. Each is a hub licence tag the
 *  converter accepts (docker/lib/ai-risk-knowledge.json). */
export const COMMON_LICENSES = [
  "apache-2.0",
  "mit",
  "bsd-3-clause",
  "cc-by-4.0",
  "cc-by-sa-4.0",
  "cc-by-nc-4.0",
  "cc-by-nc-sa-4.0",
  "cc0-1.0",
  "openrail",
  "openrail++",
  "bigscience-openrail-m",
  "creativeml-openrail-m",
  "bigcode-openrail-m",
  "gpl-3.0",
  "agpl-3.0",
  "lgpl-3.0",
  "mpl-2.0",
  "llama3.1",
  "llama3.2",
  "llama3.3",
  "llama4",
  "gemma",
];

/** One flow of data in or out of the declared service, in the shape of
 *  CycloneDX serviceData. */
export interface DataFlow {
  flow: string;
  classification: string;
  name?: string;
  description?: string;
  /** Where the data comes from and goes to, as addresses. */
  source?: string[];
  destination?: string[];
}

/** The directions a data flow takes (CycloneDX dataFlowDirection). */
export const FLOWS = ["inbound", "outbound", "bi-directional", "unknown"] as const;

/** An AI model the service calls through an API: identified only. `key` names
 *  it in the declaration and follows its name. */
export interface ExternalModelEntry {
  key: string;
  name: string;
  suppliedBy?: Agent | null;
  packageVersion?: string;
  endpoint?: string;
}

/** The service (an app or API) the model runs in, by field id, with its data
 *  flows and the external models it calls. */
export interface DeclService {
  [field: string]: Value | DataFlow[] | ExternalModelEntry[] | undefined;
  dataFlows?: DataFlow[];
  externalModels?: ExternalModelEntry[];
}

/** The answer to "does this model run in a service?": only "yes" declares
 *  one. "later" and "no" keep anything typed on screen out of the file. */
export type ServiceAnswer = "yes" | "no" | "later";

export interface Declaration {
  schema: string;
  document: { createdBy?: Agent[] };
  /** Absent when the scan's root is a dataset. */
  model?: ModelAnswers;
  datasets: DeclDataset[];
  relationships: unknown[];
  /** The service the model runs in. Present (possibly blank) where one can be
   *  declared: a model's document, with a mapping that knows services. */
  service?: DeclService;
  /** The screens' answer to the service question; never saved. */
  serviceAnswer?: ServiceAnswer;
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function asService(raw: unknown): DeclService | undefined {
  if (!isObj(raw)) return undefined;
  const s = clone(raw) as DeclService;
  s.dataFlows = Array.isArray(raw.dataFlows)
    ? raw.dataFlows.filter(isObj).map((d) => ({
        ...(clone(d) as unknown as DataFlow),
        flow: typeof d.flow === "string" ? d.flow : "",
        classification: typeof d.classification === "string" ? d.classification : "",
      }))
    : [];
  s.externalModels = Array.isArray(raw.externalModels)
    ? raw.externalModels.filter(isObj).map((e) => ({
        ...(clone(e) as unknown as ExternalModelEntry),
        key: typeof e.key === "string" ? e.key : "",
        name: typeof e.name === "string" ? e.name : "",
      }))
    : [];
  return s;
}

function asDeclaration(raw: unknown): Declaration | null {
  if (!isObj(raw)) return null;
  const doc = isObj(raw.document) ? raw.document : {};
  const model = isObj(raw.model) ? (clone(raw.model) as Declaration["model"]) : undefined;
  const service = model ? asService(raw.service) : undefined;
  const out: Declaration = {
    schema: DECLARATION_SCHEMA,
    document: Array.isArray(doc.createdBy) ? { createdBy: clone(doc.createdBy) as Agent[] } : {},
    model,
    datasets: Array.isArray(raw.datasets) ? (clone(raw.datasets.filter(isObj)) as DeclDataset[]) : [],
    relationships: [],
  };
  if (service) out.service = service;
  // A declaration that holds a service answered "yes" when it was written.
  if (service && !blankDeep(service)) out.serviceAnswer = "yes";
  return out;
}

/**
 * Where a fill starts: the empty declaration the server wrote for this scan,
 * with the answers of a declaration saved earlier laid over it. A saved answer
 * for a dataset or base model the scan no longer has is dropped (the server
 * would refuse it); datasets the hub does not hold are kept as they were.
 */
export function startDeclaration(template: unknown, saved?: unknown): Declaration | null {
  const out = asDeclaration(template);
  if (!out) return null;
  const prev = saved === undefined || saved === null ? null : asDeclaration(saved);
  if (!prev) return out;
  if (prev.document.createdBy?.length) out.document.createdBy = prev.document.createdBy;
  if (out.model && prev.model) {
    const bases = out.model.baseModels ?? [];
    for (const [k, v] of Object.entries(prev.model)) {
      if (k !== "baseModels") out.model[k] = v as Value;
    }
    const revs = new Map((prev.model.baseModels ?? []).map((b) => [b.ref, b.revision ?? ""]));
    out.model.baseModels = bases.map((b) => ({ ref: b.ref, revision: revs.get(b.ref) ?? b.revision ?? "" }));
  }
  const byRef = new Map(prev.datasets.filter((d) => d.ref).map((d) => [d.ref, d]));
  out.datasets = out.datasets.map((d) => {
    const p = d.ref ? byRef.get(d.ref) : undefined;
    if (!p) return d;
    const merged: DeclDataset = { ...d };
    for (const [k, v] of Object.entries(p)) {
      // A role only where the template offers one (a dataset the card names).
      if (k === "role" && !("role" in d)) continue;
      if (k !== "ref" && k !== "name") merged[k] = v;
    }
    return merged;
  });
  if (out.model) out.datasets.push(...prev.datasets.filter((d) => d.local));
  // The service: the saved answers laid over the blank one, and the answer to
  // whether there is one kept with them.
  if (out.model && prev.service) {
    out.service = { ...(out.service ?? {}), ...prev.service };
    if (prev.serviceAnswer) out.serviceAnswer = prev.serviceAnswer;
  }
  return out;
}

/** No answer: nothing typed, an agent with no name, a setting row with neither
 *  a name nor a value. Such rows are dropped from the saved file. */
export function isEmpty(v: unknown): boolean {
  // A declared source: empty only when it names nothing at all (a licence
  // without a name is not empty; it is reported as a problem instead).
  if (isObj(v) && "relation" in v)
    return !String(v.ref ?? "").trim() && !String(v.name ?? "").trim() && !String(v.license ?? "").trim();
  return (
    v === undefined ||
    v === null ||
    (typeof v === "string" && v.trim() === "") ||
    (Array.isArray(v) && v.length === 0) ||
    (isObj(v) && "name" in v && typeof v.name === "string" && v.name.trim() === "") ||
    (isObj(v) && "key" in v && !String(v.key ?? "").trim() && !String(v.value ?? "").trim())
  );
}

/** Nothing a person wrote, all the way down: blank text, and lists and objects
 *  of only that. An agent's kind and an external model's key are not values
 *  (they come with a blank row), as the converter reads it. */
export function blankDeep(v: unknown): boolean {
  if (typeof v === "string") return !v.trim();
  if (Array.isArray(v)) return v.every(blankDeep);
  if (isObj(v)) return Object.entries(v).every(([k, x]) => k === "type" || k === "key" || blankDeep(x));
  return v === null || v === undefined;
}

/** A service is declared: the person said yes and wrote something in it. */
export function serviceDeclared(decl: Declaration): boolean {
  return decl.serviceAnswer === "yes" && decl.service !== undefined && !blankDeep(decl.service);
}

/** The model's values that also go into the CycloneDX SBOM (its input and
 *  output kinds and the regulatory fields): a scan writes them there, so
 *  saving them after one leaves the SBOM behind until the next. */
export function modelCdxValues(decl: Declaration): boolean {
  const m = decl.model;
  if (!m) return false;
  return ["inputModality", "outputModality", "trainingComputeFlops", "trainingComputeBasis", "adversarialTesting"].some(
    (k) => !isEmpty(m[k]),
  );
}

/** Text length as the converter counts it (code points, not UTF-16 units). */
function textLength(s: string): number {
  return [...s].length;
}

/** A dataset the hub does not hold that was added and left with nothing in
 *  it: neither counted nor saved. */
export function isBlankLocal(d: DeclDataset): boolean {
  return d.local !== undefined && Object.entries(d).every(([k, v]) => k === "local" || isEmpty(v));
}

/** A new, empty dataset the hub does not hold. */
export function emptyLocalDataset(index: FieldIndex): DeclDataset {
  const d: DeclDataset = { local: "", name: "", role: "", sources: [] };
  for (const f of Object.values(index.dataset_DatasetPackage)) {
    if (f.source.kind === "user" || f.declarable) d[f.id] = f.max === "*" ? [] : f.type === "Agent" ? null : "";
  }
  return d;
}

/** A slug for a dataset the hub does not hold, made from its name. Names with
 *  no Latin letters or digits fall back to a numbered one. */
export function slugFor(name: string, taken: string[], n: number, fallback = "dataset"): string {
  let base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "")
    .slice(0, 56);
  if (!base) base = `${fallback}-${n}`;
  let slug = base;
  for (let i = 2; taken.includes(slug); i++) slug = `${base}-${i}`;
  return slug;
}

// ---- a declaration with no scan behind it (MODE AIDECLARE) --------------------------

/** The HuggingFace id shape the converter and the server accept. */
export const HUB_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)?$/;

export function isHubId(id: string): boolean {
  return HUB_ID_RE.test(id) && !id.includes("..");
}

const blankOf = (f: MapField): Value => (f.max === "*" ? [] : f.type === "Agent" ? null : "");

/**
 * The empty declaration for a model described from the declaration alone.
 * Every field a publisher can declare is asked, except the version: the scan's
 * own version is the model's. Base models and datasets start empty and are
 * added by id.
 */
export function createTemplate(index: FieldIndex): Declaration {
  const model: ModelAnswers = { baseModels: [], license: "" };
  for (const f of Object.values(index.ai_AIPackage)) {
    if ((f.source.kind === "user" || f.declarable) && f.id !== "packageVersion") model[f.id] = blankOf(f);
  }
  const out: Declaration = { schema: DECLARATION_SCHEMA, document: { createdBy: [] }, model, datasets: [], relationships: [] };
  const service = blankService(index);
  if (service) out.service = service;
  return out;
}

/** The blank service the questions start from; undefined when the mapping
 *  knows no service (a server before v1.14). */
export function blankService(index: FieldIndex): DeclService | undefined {
  const fields = Object.values(index.service ?? {}).filter((f) => f.source.kind === "user");
  if (!fields.length) return undefined;
  const s: DeclService = {};
  for (const f of fields) s[f.id] = f.type === "ServiceData" ? [] : blankOf(f);
  s.dataFlows = [];
  s.externalModels = [];
  return s;
}

/**
 * For a scan made from a declaration (AIDECLARE), the saved file is the scan's
 * input, not only its supplement. Filling its open fields later must keep the
 * base models and hub datasets it named, or the next run would lose them.
 * `file` is what the fill wrote; `original` the declaration it started from.
 */
export function keepDeclaredIds(file: Declaration, original: unknown): Declaration {
  const prev = isObj(original) ? original : {};
  const model = isObj(prev.model) ? prev.model : {};
  const out: Declaration = clone(file);
  const bases = Array.isArray(model.baseModels) ? model.baseModels.filter(isObj) : [];
  if (out.model && bases.length) {
    const revs = new Map((out.model.baseModels ?? []).map((b) => [b.ref, b.revision]));
    out.model.baseModels = bases
      .filter((b) => typeof b.ref === "string")
      .map((b) => ({
        ref: b.ref as string,
        revision: revs.get(b.ref as string) ?? (typeof b.revision === "string" ? b.revision : ""),
      }));
    // A revision answered for an ancestor the hub showed (not one it named)
    // is kept too; the builder treats a walked ancestor as one, not a parent.
    for (const [ref, revision] of revs) {
      if (!out.model.baseModels.some((b) => b.ref === ref)) out.model.baseModels.push({ ref, revision });
    }
  }
  const have = new Set(out.datasets.map((d) => d.ref).filter(Boolean));
  for (const d of Array.isArray(prev.datasets) ? prev.datasets : []) {
    if (isObj(d) && typeof d.ref === "string" && !have.has(d.ref)) out.datasets.push({ ref: d.ref });
  }
  return out;
}

/** The questions for re-running a declared model: the empty declaration with
 *  the saved one's base models and hub datasets added back, and its answers
 *  laid over it. */
export function startCreate(index: FieldIndex, saved: unknown): Declaration {
  const t = createTemplate(index);
  const prev = isObj(saved) ? saved : {};
  const model = isObj(prev.model) ? prev.model : {};
  for (const b of Array.isArray(model.baseModels) ? model.baseModels : []) {
    const ref = isObj(b) && typeof b.ref === "string" ? b.ref : "";
    if (ref && !t.model!.baseModels!.some((x) => x.ref === ref)) t.model!.baseModels!.push({ ref, revision: "" });
  }
  for (const d of Array.isArray(prev.datasets) ? prev.datasets : []) {
    const ref = isObj(d) && typeof d.ref === "string" ? d.ref : "";
    if (ref.startsWith("huggingface:") && !t.datasets.some((x) => x.ref === ref))
      t.datasets.push(hubDatasetEntry(index, ref.slice("huggingface:".length)));
  }
  return startDeclaration(t, saved) ?? t;
}

/** A HuggingFace dataset added by id: the scan reads its address, publisher
 *  and licence from the hub, so only what the hub cannot say is asked. */
export function hubDatasetEntry(index: FieldIndex, id: string): DeclDataset {
  const d: DeclDataset = { ref: `huggingface:${id}`, role: "", sources: [] };
  for (const f of Object.values(index.dataset_DatasetPackage)) {
    if (f.source.kind === "user" || (f.declarable && f.source.kind === "rule")) d[f.id] = blankOf(f);
  }
  return d;
}

// ---- dates ------------------------------------------------------------------------

/** "2025-04-15" as the declaration writes it ("2025-04-15T00:00:00Z"). */
export function dateToDeclared(day: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? `${day}T00:00:00Z` : day;
}

/** The day part a date input shows. */
export function declaredToDate(v: unknown): string {
  return typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : "";
}

function realDateTime(v: string): boolean {
  const m = DATE_TIME_RE.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return (
    t.getUTCFullYear() === y &&
    t.getUTCMonth() === mo - 1 &&
    t.getUTCDate() === d &&
    h < 24 &&
    mi < 60 &&
    s < 60
  );
}

// ---- checking ----------------------------------------------------------------------

/** A problem with one value: a stable code for the screen's wording. */
export type Problem =
  | "date"
  | "uri"
  | "uriScheme"
  | "tooLong"
  | "agentName"
  | "duplicateKey"
  | "emptyKey"
  | "revision"
  | "noAssertionMixed"
  /** Not a HuggingFace id (owner/name). */
  | "hubId"
  /** A source with a licence but no name. */
  | "sourceName"
  /** A source licence that is neither a hub licence tag nor an SPDX id. */
  | "sourceLicense"
  /** The model's licence is neither a hub licence tag nor an SPDX id. */
  | "license"
  /** The same source twice. */
  | "sourceTwice"
  /** A dataset named as its own source. */
  | "sourceSelf"
  /** A hub source on data the hub does not hold (nothing would read it). */
  | "sourceHubOnLocal"
  /** A dataset the hub does not hold, partly filled but missing its name or
   *  address: the server would refuse the whole declaration. */
  | "localIncomplete"
  /** Not a positive decimal number (3.2e24, 1500000). */
  | "decimal"
  /** An agent of a kind the field does not take (a service's provider is an
   *  organization). */
  | "agentType"
  /** A data flow with no direction chosen. */
  | "flowMissing"
  /** A data flow that does not say what data it is. */
  | "classificationMissing"
  /** An external AI model with no name. */
  | "externalName"
  /** The same external AI model twice (or a key the converter cannot take). */
  | "externalTwice"
  /** A name or label over its 200-character limit. */
  | "labelTooLong";

/** A positive decimal number written as text, optionally in exponent notation
 *  (the converter's DECIMAL_RE). */
const DECIMAL_RE = /^(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$/;
const MAX_DECIMAL = 100;
/** A data flow's classification (the converter's MAX_LABEL). */
export const MAX_LABEL = 200;
/** An external model's key (the converter's LOCAL_RE). */
const KEY_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** "3.2e24" and "1500000" are; "0", "-1", "3,2e24" and "about 1e24" are not. */
export function isPositiveDecimal(v: string): boolean {
  const s = v.trim();
  if (!s || s.length > MAX_DECIMAL || !DECIMAL_RE.test(s)) return false;
  // Zero in any spelling (0, 0.0, 0e5): the digits before the exponent are all 0.
  return /[1-9]/.test(s.split(/[eE]/)[0]);
}

/** Check one value against its field, as the converter does. Null when fine
 *  (an empty value is fine here; whether it is required is counted apart). */
export function checkValue(field: MapField, v: unknown): Problem | null {
  if (isEmpty(v)) return null;
  switch (field.type) {
    case "decimal":
      return typeof v === "string" && isPositiveDecimal(v) ? null : "decimal";
    case "DateTime":
      return typeof v === "string" && realDateTime(v) ? null : "date";
    case "anyURI": {
      if (typeof v !== "string" || /\s/.test(v)) return "uri";
      const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/[^/?#]+/.exec(v);
      if (!m) return "uri";
      // An unclosed IPv6 bracket is not an address (the converter's parser rejects it).
      const host = m[0].slice(m[1].length + 3);
      if (host.includes("[") !== host.includes("]")) return "uri";
      if (!URI_SCHEMES.includes(m[1].toLowerCase())) return "uriScheme";
      return textLength(v) > MAX_TEXT ? "tooLong" : null;
    }
    case "Agent": {
      const list = (Array.isArray(v) ? v : [v]) as Agent[];
      for (const a of list) {
        if (!isObj(a) || typeof a.name !== "string" || !a.name.trim()) return "agentName";
        if (textLength(a.name) > MAX_TEXT) return "tooLong";
        if (field.agentTypes?.length && !field.agentTypes.includes(a.type || "Organization")) return "agentType";
      }
      return null;
    }
    case "DictionaryEntry": {
      const list = (v as DictEntry[]).filter((e) => !isEmpty(e));
      const keys = list.map((e) => (e.key ?? "").trim());
      if (keys.some((k) => !k)) return "emptyKey";
      if (new Set(keys).size !== keys.length) return "duplicateKey";
      return list.some((e) => textLength(e.key) > 200 || textLength(e.value ?? "") > MAX_TEXT) ? "tooLong" : null;
    }
    default:
      if (Array.isArray(v)) {
        if (field.enum && v.includes("noAssertion") && v.length > 1) return "noAssertionMixed";
        return v.some((x) => typeof x === "string" && textLength(x) > MAX_TEXT) ? "tooLong" : null;
      }
      return typeof v === "string" && textLength(v) > MAX_TEXT ? "tooLong" : null;
  }
}

/** One required field still empty, or one value with a problem. */
export interface Issue {
  /** "document", "model", "model.baseModels[0]", "datasets[2]", "service",
   *  "service.dataFlows[0]", "service.externalModels[1]" */
  where: string;
  field: string;
  problem: Problem | "required";
}

/** Required and left open when empty. A required field with a fallback (the
 *  dataset type's NOASSERTION) is written as that instead, so the check does
 *  not count it as open and neither does this. */
export function required(f: MapField): boolean {
  return f.min >= 1 && f.source.fallback === undefined;
}

/**
 * Every required field left empty and every value with a problem. Only fields
 * the declaration holds are counted: the server's empty declaration lists just
 * what the scan left open, so a filled-by-the-scan field never shows here.
 * `authorFromScan` is true when the scan named its author (--sbom-author), so
 * the document's author is not asked for.
 */
export function issues(index: FieldIndex, decl: Declaration, authorFromScan: boolean): Issue[] {
  const out: Issue[] = [];
  const visit = (where: string, fields: Record<string, MapField>, values: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(values)) {
      const f = fields[k];
      if (!f) continue;
      if (isEmpty(v)) {
        if (required(f)) out.push({ where, field: k, problem: "required" });
        continue;
      }
      const p = checkValue(f, v);
      if (p) out.push({ where, field: k, problem: p });
    }
  };
  if (!authorFromScan) {
    if (isEmpty(decl.document.createdBy)) out.push({ where: "document", field: "createdBy", problem: "required" });
    else {
      const p = checkValue(index.document.createdBy, decl.document.createdBy);
      if (p) out.push({ where: "document", field: "createdBy", problem: p });
    }
  }
  if (decl.model) {
    visit("model", index.ai_AIPackage, decl.model);
    const lic = typeof decl.model.license === "string" ? decl.model.license.trim() : "";
    if (lic && !SPDX_ID_RE.test(lic)) out.push({ where: "model", field: "license", problem: "license" });
    (decl.model.baseModels ?? []).forEach((b, i) => {
      if (!isHubId(b.ref)) out.push({ where: `model.baseModels[${i}]`, field: "ref", problem: "hubId" });
      if (!isEmpty(b.revision) && !REVISION_RE.test(b.revision.trim()))
        out.push({ where: `model.baseModels[${i}]`, field: "revision", problem: "revision" });
    });
  }
  if (decl.serviceAnswer === "yes" && decl.service) serviceIssues(index, decl.service, out, visit);
  decl.datasets.forEach((d, i) => {
    if (isBlankLocal(d)) return;
    const where = `datasets[${i}]`;
    visit(where, index.dataset_DatasetPackage, d);
    if (d.local !== undefined && (isEmpty(d.name) || isEmpty(d.downloadLocation)))
      out.push({ where, field: "local", problem: "localIncomplete" });
    const seen = new Set<string>();
    (d.sources ?? []).forEach((src) => {
      const name = (src.name ?? "").trim();
      const lic = (src.license ?? "").trim();
      if (!src.ref && !name) {
        if (lic) out.push({ where, field: "sources", problem: "sourceName" });
        return;
      }
      if (lic && !SPDX_ID_RE.test(lic)) out.push({ where, field: "sources", problem: "sourceLicense" });
      if (textLength(name) > MAX_TEXT) out.push({ where, field: "sources", problem: "tooLong" });
      if (src.ref && d.ref && src.ref.toLowerCase() === d.ref.toLowerCase())
        out.push({ where, field: "sources", problem: "sourceSelf" });
      if (src.ref && d.local !== undefined) out.push({ where, field: "sources", problem: "sourceHubOnLocal" });
      const key = src.ref ? `ref:${src.ref.toLowerCase()}` : `name:${name.toLowerCase()}`;
      if (seen.has(key)) out.push({ where, field: "sources", problem: "sourceTwice" });
      seen.add(key);
    });
  });
  return out;
}

const URI_FIELD: MapField = { id: "uri", type: "anyURI", min: 0, max: 1, noAssertion: false, source: { kind: "user" } };

/** The service's required fields and values, its data flows and its external
 *  models. Asked only once the person said the model runs in a service. */
function serviceIssues(
  index: FieldIndex,
  svc: DeclService,
  out: Issue[],
  visit: (where: string, fields: Record<string, MapField>, values: Record<string, unknown>) => void,
) {
  const plain: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(svc)) if (k !== "dataFlows" && k !== "externalModels") plain[k] = v;
  visit("service", index.service ?? {}, plain);
  (svc.dataFlows ?? []).forEach((d, i) => {
    if (blankDeep(d)) return;
    const where = `service.dataFlows[${i}]`;
    if (!(FLOWS as readonly string[]).includes(d.flow)) out.push({ where, field: "flow", problem: "flowMissing" });
    const cls = (d.classification ?? "").trim();
    if (!cls) out.push({ where, field: "classification", problem: "classificationMissing" });
    else if (textLength(cls) > MAX_LABEL) out.push({ where, field: "classification", problem: "labelTooLong" });
    if (textLength(d.name ?? "") > MAX_LABEL) out.push({ where, field: "name", problem: "labelTooLong" });
    if (textLength(d.description ?? "") > MAX_TEXT) out.push({ where, field: "description", problem: "tooLong" });
    for (const side of ["source", "destination"] as const) {
      const p = (d[side] ?? [])
        .filter((u) => u.trim())
        .map((u) => checkValue(URI_FIELD, u.trim()))
        .find(Boolean);
      if (p) out.push({ where, field: side, problem: p });
    }
  });
  const keys = new Set<string>();
  (svc.externalModels ?? []).forEach((e, i) => {
    if (blankDeep(e)) return;
    const where = `service.externalModels[${i}]`;
    const name = (e.name ?? "").trim();
    if (!name) out.push({ where, field: "name", problem: "externalName" });
    else if (!KEY_RE.test(e.key ?? "") || keys.has(e.key)) out.push({ where, field: "name", problem: "externalTwice" });
    keys.add(e.key);
    const fields = index.externalModel ?? {};
    for (const k of ["name", "suppliedBy", "packageVersion", "endpoint"]) {
      const f = fields[k];
      const v = (e as unknown as Record<string, unknown>)[k];
      if (!f || isEmpty(v)) continue;
      const p = checkValue(f, v);
      if (p) out.push({ where, field: k, problem: p });
    }
  });
}

export function remainingRequired(list: Issue[]): number {
  return list.filter((i) => i.problem === "required").length;
}

/** What the server would refuse: a value with a problem, or a dataset the hub
 *  does not hold without its name or address. A required field left empty is
 *  not one of them; the document then stays a draft. */
export function saveBlockers(list: Issue[]): Issue[] {
  return list.filter((i) => i.problem !== "required");
}

// ---- the file ------------------------------------------------------------------------

function pruned(v: Value | undefined): Value | undefined {
  if (v === undefined || isEmpty(v)) return undefined;
  if (Array.isArray(v)) {
    const kept = (v as unknown[]).filter((x) => !isEmpty(x));
    return kept.length ? (kept as Value) : undefined;
  }
  if (typeof v === "string") return v.trim();
  return v;
}

/**
 * The declaration as it is saved: empty answers left out, so the file holds
 * only what the publisher said. A dataset with nothing declared is left out,
 * and so is one the hub does not hold that was added and never filled.
 */
export function toFile(decl: Declaration, keepBases = false): Declaration {
  const out: Declaration = { schema: DECLARATION_SCHEMA, document: {}, datasets: [], relationships: [] };
  const agents = pruned(decl.document.createdBy as Value);
  if (agents) out.document.createdBy = agents as Agent[];
  if (decl.model) {
    const m: NonNullable<Declaration["model"]> = {};
    for (const [k, v] of Object.entries(decl.model)) {
      if (k === "baseModels") continue;
      const p = pruned(v as Value);
      if (p !== undefined) m[k] = p;
    }
    // A scan's base models are known to it, so only a revision is worth
    // writing; with no scan behind it (keepBases), the ids are the declaration.
    const bases = (decl.model.baseModels ?? []).filter((b) => keepBases || !isEmpty(b.revision));
    if (bases.length)
      m.baseModels = bases.map((b) => (isEmpty(b.revision) ? { ref: b.ref, revision: "" } : { ref: b.ref, revision: b.revision.trim() }));
    out.model = m;
  }
  for (const d of decl.datasets) {
    const e: DeclDataset = {};
    for (const [k, v] of Object.entries(d)) {
      if (k === "ref" || k === "local") continue;
      const p = pruned(v as Value);
      if (p !== undefined) e[k] = p;
    }
    if (d.local !== undefined) {
      if (!isBlankLocal(d)) out.datasets.push({ local: d.local, ...e });
    } else if (Object.keys(e).length || keepBases) out.datasets.push({ ref: d.ref, ...e });
  }
  const svc = decl.serviceAnswer === "yes" && decl.service ? serviceFile(decl.service) : undefined;
  if (svc) out.service = svc;
  return out;
}

/** The service as it is saved: blank answers, data flows and external models
 *  left out; undefined when nothing is left (an untouched service is not
 *  declared). */
function serviceFile(svc: DeclService): DeclService | undefined {
  const out: DeclService = {};
  for (const [k, v] of Object.entries(svc)) {
    if (k === "dataFlows" || k === "externalModels") continue;
    const p = pruned(v as Value);
    if (p !== undefined) out[k] = p;
  }
  const flows = (svc.dataFlows ?? [])
    .filter((d) => !blankDeep(d))
    .map((d) => {
      const f: DataFlow = { flow: d.flow, classification: (d.classification ?? "").trim() };
      if (d.name?.trim()) f.name = d.name.trim();
      if (d.description?.trim()) f.description = d.description.trim();
      for (const side of ["source", "destination"] as const) {
        const list = [...new Set((d[side] ?? []).map((u) => u.trim()).filter(Boolean))];
        if (list.length) f[side] = list;
      }
      return f;
    });
  if (flows.length) out.dataFlows = flows;
  const models = (svc.externalModels ?? [])
    .filter((e) => !blankDeep(e))
    .map((e) => {
      const m: ExternalModelEntry = { key: e.key, name: (e.name ?? "").trim() };
      const agent = pruned((e.suppliedBy ?? null) as Value);
      if (agent) m.suppliedBy = agent as Agent;
      if (e.packageVersion?.trim()) m.packageVersion = e.packageVersion.trim();
      if (e.endpoint?.trim()) m.endpoint = e.endpoint.trim();
      return m;
    });
  if (models.length) out.externalModels = models;
  return Object.keys(out).length ? out : undefined;
}

// ---- where each question goes --------------------------------------------------------

export type StepId = "base" | "model" | "data" | "service" | "legal" | "preview";

/** Model fields asked under "Use and scope (optional)", folded by default. */
export const MODEL_USE_FIELDS = ["domain", "informationAboutApplication", "standardCompliance", "modelExplainability"];
/** Model fields asked under "Regulatory submission (optional)", folded. */
export const REGULATORY_FIELDS = ["trainingComputeFlops", "trainingComputeBasis", "adversarialTesting"];
/** Service fields asked first, each required by SPDX for an AI package. */
export const SERVICE_REQUIRED_FIELDS = ["name", "packageVersion", "downloadLocation", "suppliedBy", "releaseTime"];
/** The service's optional questions, folded by subject. "dataFlows" and
 *  "externalModels" have their own editors. */
export const SERVICE_GROUPS: { id: string; fields: string[] }[] = [
  { id: "use", fields: ["informationAboutApplication", "domain", "autonomyType"] },
  { id: "io", fields: ["inputModality", "outputModality"] },
  { id: "flows", fields: ["dataFlows"] },
  { id: "external", fields: ["externalModels"] },
  { id: "standards", fields: ["standardCompliance", "disclosureUrl"] },
];
/** A data flow's questions, as fields the screens draw like any other. The
 *  direction and what the data is are needed once a flow is added. */
export function dataFlowFields(index: FieldIndex): MapField[] {
  const flowEnum = index.service?.dataFlows?.flowEnum ?? [...FLOWS];
  const f = (id: string, extra: Partial<MapField>): MapField => ({
    id,
    type: "string",
    min: 0,
    max: 1,
    noAssertion: false,
    source: { kind: "user" },
    ...extra,
  });
  return [
    f("flow", { enum: flowEnum, min: 1 }),
    f("classification", { min: 1 }),
    f("name", {}),
    f("description", {}),
    f("source", { type: "anyURI", max: "*" }),
    f("destination", { type: "anyURI", max: "*" }),
  ];
}

/** Model fields asked under "How it was trained (optional)", beside the data. */
export const TRAINING_FIELDS = ["informationAboutTraining", "hyperparameter", "modelDataPreprocessing"];
/** Dataset fields folded under "More about this data (optional)". */
export const DATASET_MORE_FIELDS = [
  "intendedUse",
  "confidentialityLevel",
  "dataCollectionProcess",
  "anonymizationMethodUsed",
  "dataPreprocessing",
  "datasetNoise",
  "datasetUpdateMechanism",
];
/** Text fields that take a sentence or more. */
export const LONG_TEXT = new Set([
  "informationAboutTraining",
  "informationAboutApplication",
  "dataCollectionProcess",
  "intendedUse",
  "datasetNoise",
  "datasetUpdateMechanism",
  "trainingComputeBasis",
]);

/** The model step's main questions: everything open on the model that is not a
 *  judgment, not folded into "use and scope", and not about training. */
export function modelMainFields(index: FieldIndex, decl: Declaration): string[] {
  if (!decl.model) return [];
  return Object.keys(decl.model).filter((k) => {
    const f = index.ai_AIPackage[k];
    return (
      f &&
      !f.judgment &&
      !MODEL_USE_FIELDS.includes(k) &&
      !TRAINING_FIELDS.includes(k) &&
      !REGULATORY_FIELDS.includes(k)
    );
  });
}

/**
 * The calls only the publisher can make about the model. Once the model runs
 * in a declared service, whether a person is involved in its decisions is
 * asked of the service (where it is decided), so the model's own question is
 * not asked again; one answered earlier stays on screen to be seen.
 */
export function judgmentFields(index: FieldIndex, decl: Declaration): string[] {
  if (!decl.model) return [];
  const viaService = decl.serviceAnswer === "yes" && decl.service !== undefined;
  return Object.keys(decl.model).filter(
    (k) => index.ai_AIPackage[k]?.judgment && !(viaService && k === "autonomyType" && isEmpty(decl.model?.[k])),
  );
}

/** The steps this declaration needs, in order. A dataset scan has no model, so
 *  it asks only about the data. A declaration with no scan behind it (create)
 *  always offers the base-model step, where base models are added. */
export function stepsFor(index: FieldIndex, decl: Declaration, create = false): StepId[] {
  const steps: StepId[] = [];
  if (decl.model && (create || decl.model.baseModels?.length)) steps.push("base");
  if (decl.model) steps.push("model");
  steps.push("data");
  // The service a model runs in, optional; a dataset's document has none.
  if (decl.model && decl.service) steps.push("service");
  if (judgmentFields(index, decl).length) steps.push("legal");
  steps.push("preview");
  return steps;
}

/** The step an issue belongs to, so the progress list can say which step still
 *  has something open. */
export function stepOf(issue: Issue): StepId {
  if (issue.where === "document") return "model";
  if (issue.where === "service" || issue.where.startsWith("service.")) return "service";
  if (issue.where.startsWith("model.baseModels")) return "base";
  if (issue.where.startsWith("datasets")) return "data";
  if (TRAINING_FIELDS.includes(issue.field)) return "data";
  return issue.field === "useSensitivePersonalInformation" ||
    issue.field === "autonomyType" ||
    issue.field === "safetyRiskAssessment"
    ? "legal"
    : "model";
}

/** How many open items (required fields left empty, values with a problem)
 *  each step still holds. */
export function openByStep(list: Issue[]): Partial<Record<StepId, number>> {
  const out: Partial<Record<StepId, number>> = {};
  for (const i of list) {
    const s = stepOf(i);
    out[s] = (out[s] ?? 0) + 1;
  }
  return out;
}

/** Where the questions open: the first step that still has something open,
 *  so a person is not walked through steps with nothing left to answer. */
export function firstOpenStep(steps: StepId[], list: Issue[]): StepId {
  const open = openByStep(list);
  return steps.find((s) => s !== "preview" && (open[s] ?? 0) > 0) ?? steps[0];
}

/** The first open item of a step, so jumping there can put the cursor on it. */
export function firstOpenIn(step: StepId, list: Issue[]): Issue | undefined {
  return list.find((i) => stepOf(i) === step);
}

/** The model's weights are declared an adapter while no base model is named.
 *  The converter then cannot record what the adapter runs on and lists it for
 *  review; quantized and merged weights are not treated so. */
export function adapterWithoutBase(decl: Declaration): boolean {
  return decl.model?.weightsScope === "adapter" && !(decl.model.baseModels ?? []).length;
}

// ---- what the review step shows -------------------------------------------------------

export interface SummaryRow {
  /** "document", "model", "datasets[i]" or "service": where the value sits. */
  where: string;
  ns: "document" | "model" | "dataset" | "service";
  field: MapField;
  value: Value;
}

export interface SummaryGroup {
  step: StepId;
  /** A dataset's name; null for the step's own rows. */
  title: string | null;
  /** The dataset's place in the declaration, for a dataset's group. */
  datasetIndex?: number;
  rows: SummaryRow[];
}

/**
 * What will be saved, grouped as the steps ask it: every answer given, field
 * by field, with each dataset as its own group. Empty answers are left out
 * (the file leaves them out too).
 */
export function summaryGroups(index: FieldIndex, decl: Declaration, steps: StepId[]): SummaryGroup[] {
  const out: SummaryGroup[] = [];
  const row = (where: string, ns: SummaryRow["ns"], field: MapField | undefined, value: unknown) =>
    field && !isEmpty(value) && !(Array.isArray(value) && value.every((x) => isEmpty(x)))
      ? [{ where, ns, field, value: value as Value }]
      : [];
  const modelRows = (ids: string[]) =>
    ids.flatMap((k) => row("model", "model", k === "license" ? MODEL_LICENSE_FIELD : index.ai_AIPackage[k], decl.model?.[k]));
  for (const s of steps) {
    if (s === "model") {
      const ids = decl.model ? Object.keys(decl.model).filter((k) => k !== "baseModels") : [];
      const main = ids.filter((k) => k === "license" || (index.ai_AIPackage[k] && !index.ai_AIPackage[k].judgment && !TRAINING_FIELDS.includes(k)));
      out.push({
        step: s,
        title: null,
        rows: [...row("document", "document", index.document.createdBy, decl.document.createdBy), ...modelRows(main)],
      });
    } else if (s === "data") {
      decl.datasets.forEach((d, i) => {
        if (isBlankLocal(d)) return;
        const where = `datasets[${i}]`;
        const rows = Object.keys(d)
          .filter((k) => k !== "name")
          .flatMap((k) => row(where, "dataset", index.dataset_DatasetPackage[k], d[k]));
        out.push({
          step: s,
          title: d.ref ? d.ref.replace(/^huggingface:/, "") : String(d.name ?? "") || null,
          datasetIndex: i,
          rows,
        });
      });
      const train = decl.model ? TRAINING_FIELDS.filter((k) => k in decl.model!) : [];
      if (train.length) out.push({ step: s, title: null, rows: modelRows(train) });
    } else if (s === "service") {
      // The service's own fields; its data flows and external models are
      // listed by the screen from the declaration.
      const svc = decl.service;
      if (decl.serviceAnswer === "yes" && svc) {
        const rows = Object.keys(svc)
          .filter((k) => k !== "dataFlows" && k !== "externalModels")
          .flatMap((k) => row("service", "service", index.service?.[k], svc[k]));
        out.push({ step: s, title: null, rows });
      }
    } else if (s === "legal") {
      out.push({ step: s, title: null, rows: modelRows(judgmentFields(index, decl)) });
    }
  }
  return out;
}

// ---- how a value in the check reads ---------------------------------------------------

/** Fields whose written value is a vocabulary word the screens have a label for. */
const ENUM_FIELDS = new Set([
  "primaryPurpose",
  "useSensitivePersonalInformation",
  "autonomyType",
  "safetyRiskAssessment",
  "weightsScope",
  "datasetType",
  "hasSensitivePersonalInformation",
  "datasetAvailability",
  "confidentialityLevel",
  "inputModality",
  "outputModality",
  "adversarialTesting",
]);

export type DisplayValue =
  | { kind: "date"; date: Date }
  | { kind: "enum"; values: string[] }
  | { kind: "text"; text: string };

/**
 * A value as the check writes it ("2026-10-01T00:00:00Z", "adapter",
 * "text, audio"), read so the screens can show a date in the reader's locale
 * and a vocabulary word with the label the questions use.
 */
export function readDisplay(fieldId: string, display: string): DisplayValue {
  if (DATE_TIME_RE.test(display) && realDateTime(display)) return { kind: "date", date: new Date(display) };
  if (ENUM_FIELDS.has(fieldId)) return { kind: "enum", values: display.split(",").map((s) => s.trim()).filter(Boolean) };
  return { kind: "text", text: display };
}

/**
 * A service's data flows as the check writes them ("inbound: personal data,
 * outbound: logs"), split into each flow's direction and the rest of its text,
 * so the screens can word the direction. A part that does not start with one
 * of the four directions is kept whole, with no direction.
 */
export function parseFlowDisplay(display: string): { flow: string | null; text: string }[] {
  const dirs = FLOWS.join("|");
  return display
    .split(new RegExp(`, (?=(?:${dirs}): )`))
    .map((part) => {
      const m = new RegExp(`^(${dirs}): ([\\s\\S]*)$`).exec(part);
      return m ? { flow: m[1], text: m[2] } : { flow: null, text: part };
    });
}

/** "2026-10-01T00:00:00Z" as a date in the reader's locale (the day as the
 *  declaration wrote it, in UTC, so no time zone moves it a day). */
export function formatDay(v: string, lang: string): string {
  const d = new Date(v);
  if (!DATE_TIME_RE.test(v) || Number.isNaN(d.getTime())) return v;
  try {
    return new Intl.DateTimeFormat(lang || undefined, { dateStyle: "medium", timeZone: "UTC" }).format(d);
  } catch {
    return v.slice(0, 10);
  }
}
