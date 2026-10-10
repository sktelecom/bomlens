// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Parse the AI surfaces out of a raw CycloneDX 1.7 ML-BOM (OWASP AIBOM
 * Generator output): the machine-learning-model components with their model
 * cards, and the datasets they reference. Pure and defensive — the BOM is
 * external input — so the Models & Datasets view never throws on a partial card.
 *
 * The pipeline stamps its AI-model risk verdict onto the components as
 * `bomlens:assessment:*` properties. This module only *reads* those values —
 * it never re-derives a grade from licenses or scan results, so the
 * classification logic lives in exactly one place (the pipeline).
 */

import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";

import { USAGE_CONTEXTS, type UsageContext } from "./api";

/** A pipeline-stamped risk grade, read verbatim from the SBOM. */
export type AssessmentGrade = "ok" | "conditional" | "caution" | "review";

const GRADES: readonly string[] = ["ok", "conditional", "caution", "review"];

/** HuggingFace file-security scan outcome (`bomlens:hf:scan:status`). */
export type HfScanStatus = "safe" | "queued" | "suspicious" | "unsafe" | "unavailable";

const HF_SCAN_STATUSES: readonly string[] = [
  "safe", "queued", "suspicious", "unsafe", "unavailable",
];

/** Outcome of the pickle scan run locally (`bomlens:localscan:status`). The
 *  only file-security source for a model file that was never published, where
 *  no Hub scan result exists to read. */
export type LocalScanStatus =
  | "clean"
  | "suspicious"
  | "unsafe"
  | "not-applicable"
  | "error";

const LOCAL_SCAN_STATUSES: readonly string[] = [
  "clean", "suspicious", "unsafe", "not-applicable", "error",
];

/** i18n label key per usage-context value (scan form + model card share it). */
export const USAGE_LABEL_KEY: Record<UsageContext, string> = {
  internal: "models.usageInternal",
  product: "models.usageProduct",
  redistribute: "models.usageRedistribute",
  "outputs-only": "models.usageOutputsOnly",
};

/** i18n label key + badge tone per stamped grade (color is never the only
 *  signal — the tone always pairs with the label word). */
export const GRADE_LABEL_KEY: Record<AssessmentGrade, string> = {
  ok: "models.gradeOk",
  conditional: "models.gradeConditional",
  caution: "models.gradeCaution",
  review: "models.gradeReview",
};

/** The pipeline's model risk verdict (`bomlens:assessment:*` properties). */
export interface ModelAssessment {
  overall: AssessmentGrade;
  /** Per-axis verdicts; an axis the pipeline did not evaluate is absent. */
  license?: AssessmentGrade;
  security?: AssessmentGrade;
  datasets?: AssessmentGrade;
  /** Stamped when the model states no training data at all, in a usage the
   *  terms of that data would reach. Absent when it declares its datasets —
   *  those are judged on the `datasets` axis instead. */
  trainingData?: AssessmentGrade;
  /** The usage the verdict was graded against, when one was specified. */
  usageContext?: UsageContext;
  /** Human-readable grounds, split from the "; "-joined property value. */
  reasons: string[];
}

export interface DatasetRef {
  name: string;
  url?: string;
  version?: string;
  /** Declared licenses of the dataset itself, not of the model that uses it. */
  licenses: string[];
  /** A content digest for the dataset is recorded. */
  hasIntegrity: boolean;
  /** Upstream datasets this one derives from, as the card declares them. */
  sources: string[];
  /** The component's bom-ref, which the source links below point at. */
  ref?: string;
  /** How far below the model card this dataset was reached: 0 is a dataset the
   *  card names, 1 and deeper are sources traced from it. Absent when the
   *  pipeline did not trace sources. */
  depth?: number;
  /** Sources the pipeline read and linked (`bomlens:dataset:derivedFrom`). */
  derivedFrom: { relation: string; ref: string }[];
  /** Sources the card names in words rather than as a dataset id: kept verbatim
   *  and never looked up, so a person has to check them. */
  unverifiedSources: string[];
  /** Why the walk stopped at this dataset, when it did ("depth-limit", "cycle"). */
  trace?: string;
  /** The repository the pipeline read this dataset from ("huggingface",
   *  "figshare"). Absent for a dataset a model card only named. */
  collectedBy?: string;
  /** The repository could not be read, so everything but the name is missing. */
  unresolved: boolean;
  /** Pipeline-stamped overall grade for this dataset (`bomlens:assessment:overall`). */
  assessment?: AssessmentGrade;
  /** Pipeline-stamped dataset-signal grade (`bomlens:assessment:signals`). */
  signals?: AssessmentGrade;
}

/** The four openness axes (G7): is each disclosed in the model card? */
export interface Disclosure {
  weights: boolean;
  architecture: boolean;
  trainingData: boolean;
  trainingProcess: boolean;
}

export interface ModelCard {
  name: string;
  version: string;
  group?: string;
  purl?: string;
  description?: string;
  licenses: string[];
  supplier?: string;
  authors: string[];
  architecture?: string;
  task?: string;
  /** A model integrity hash is present. */
  hasIntegrity: boolean;
  externalRefs: { type: string; url: string }[];
  datasets: DatasetRef[];
  limitations: string[];
  disclosure: Disclosure;
  /** Pipeline risk verdict; absent when the SBOM carries no assessment stamp. */
  assessment?: ModelAssessment;
  /** HuggingFace file-security scan outcome, when recorded. */
  scanStatus?: HfScanStatus;
  /** The concrete issue the file scan reported (`bomlens:hf:scan:issue`). */
  scanIssue?: string;
  /** Outcome of the pickle scan run here (`bomlens:localscan:*`), which is the
   *  only file-security source for a model file read from disk. */
  localScan?: LocalScanStatus;
  /** The tool and version behind that verdict, so the reader knows its scope. */
  localScanTool?: string;
  /** The globals it flagged, when it flagged any. */
  localScanFindings?: string;
  /** Weight file formats present (`bomlens:weights:formats`, comma-joined). */
  weightFormats?: string[];
  /** Excerpt of a custom (non-SPDX) license the pipeline scanned. */
  customLicenseQuote?: string;
  /** Upstream model whose license the declared one conflicts with. */
  lineageConflictWith?: string;
}

export interface AiModelData {
  models: ModelCard[];
  /** Union of datasets across all model cards (deduped by name). */
  datasets: DatasetRef[];
}

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** Read a component's `properties` list: first value / all values per key. */
function propReader(c: Obj) {
  const props = arr(c.properties).map((p) => obj(p));
  const all = (key: string) =>
    props
      .filter((p) => str(p.name) === key)
      .map((p) => str(p.value))
      .filter((v): v is string => Boolean(v));
  return { one: (key: string) => all(key)[0], all };
}

/** Accept a stamped grade verbatim; anything outside the vocabulary is treated
 *  as not stamped (defensive read, never a re-classification). */
const grade = (v: string | undefined): AssessmentGrade | undefined =>
  v && GRADES.includes(v) ? (v as AssessmentGrade) : undefined;

const usageContext = (v: string | undefined): UsageContext | undefined =>
  v && (USAGE_CONTEXTS as string[]).includes(v) ? (v as UsageContext) : undefined;

const scanStatus = (v: string | undefined): HfScanStatus | undefined =>
  v && HF_SCAN_STATUSES.includes(v) ? (v as HfScanStatus) : undefined;

const localScanStatus = (v: string | undefined): LocalScanStatus | undefined =>
  v && LOCAL_SCAN_STATUSES.includes(v) ? (v as LocalScanStatus) : undefined;

/** A comma-joined list property (e.g. `bomlens:weights:formats`). */
const splitList = (v: string | undefined): string[] =>
  (v ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

/** The "; "-joined reasons property back into a list. */
const splitReasons = (v: string | undefined): string[] =>
  (v ?? "")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);

/** The pipeline's verdict, present exactly when an overall grade is stamped. */
function readAssessment(one: (key: string) => string | undefined): ModelAssessment | undefined {
  const overall = grade(one("bomlens:assessment:overall"));
  if (!overall) return undefined;
  return {
    overall,
    license: grade(one("bomlens:assessment:license")),
    security: grade(one("bomlens:assessment:security")),
    datasets: grade(one("bomlens:assessment:datasets")),
    trainingData: grade(one("bomlens:assessment:trainingData")),
    usageContext: usageContext(one("bomlens:assessment:usageContext")),
    reasons: splitReasons(one("bomlens:assessment:reasons")),
  };
}

function readLicenses(raw: unknown): string[] {
  const out: string[] = [];
  for (const entry of arr(raw)) {
    const e = obj(entry);
    const expr = str(e.expression);
    if (expr) {
      out.push(expr);
      continue;
    }
    const lic = obj(e.license);
    const id = str(lic.id) ?? str(lic.name);
    if (id) out.push(id);
  }
  return out;
}

/** A dataset the model card names, before anything was resolved about it. */
function readDatasets(modelParameters: Obj): DatasetRef[] {
  const out: DatasetRef[] = [];
  for (const d of arr(modelParameters.datasets)) {
    const ds = obj(d);
    const name = str(ds.name) ?? str(ds.ref);
    if (!name) continue;
    out.push({
      name,
      url: str(obj(ds.contents).url),
      licenses: [],
      hasIntegrity: false,
      sources: [],
      derivedFrom: [],
      unverifiedSources: [],
      unresolved: false,
    });
  }
  return out;
}

/**
 * A standalone `data` component — what enrich-aibom.sh writes after resolving a
 * dataset id against HuggingFace. It carries the license, the digests and the
 * upstream the model card only hinted at, so it supersedes the card's bare name.
 */
function readDataComponent(c: Obj): DatasetRef | null {
  const name = str(c.name);
  if (!name) return null;
  const { one, all } = propReader(c);
  const cdata = arr(c.data).map((d) => obj(d))[0] ?? {};
  const refs = arr(c.externalReferences).map((r) => obj(r));
  const depth = Number.parseInt(one("bomlens:dataset:depth") ?? "", 10);
  const derivedFrom = all("bomlens:dataset:derivedFrom")
    .map((v) => {
      const cut = v.indexOf(" ");
      return cut > 0 ? { relation: v.slice(0, cut), ref: v.slice(cut + 1) } : null;
    })
    .filter((d): d is { relation: string; ref: string } => d !== null);
  return {
    name,
    ref: str(c["bom-ref"]),
    depth: Number.isNaN(depth) ? undefined : depth,
    derivedFrom,
    unverifiedSources: all("bomlens:dataset:sourceDataset:unverified"),
    trace: one("bomlens:dataset:sourceTrace"),
    url: str(obj(cdata.contents).url) ?? str(refs.map((r) => str(r.url)).find(Boolean)),
    version: str(c.version),
    licenses: readLicenses(c.licenses),
    hasIntegrity: arr(c.hashes).length > 0,
    sources: all("bomlens:dataset:sourceDataset"),
    collectedBy: one("bomlens:dataset:collectedBy"),
    unresolved: all("bomlens:dataset:unresolved").length > 0,
    assessment: grade(one("bomlens:assessment:overall")),
    signals: grade(one("bomlens:assessment:signals")),
  };
}

function parseModel(component: Obj): ModelCard {
  const card = obj(component.modelCard);
  const params = obj(card.modelParameters);
  const datasets = readDatasets(params);
  const externalRefs = arr(component.externalReferences)
    .map((r) => obj(r))
    .map((r) => ({ type: str(r.type) ?? "other", url: str(r.url) ?? "" }))
    .filter((r) => r.url);
  const authors = arr(component.authors)
    .map((a) => str(obj(a).name))
    .filter((n): n is string => Boolean(n));
  const limitations = arr(obj(card.considerations).technicalLimitations)
    .map((l) => str(l))
    .filter((l): l is string => Boolean(l));
  const hasIntegrity = arr(component.hashes).length > 0;
  const architecture = str(params.modelArchitecture);
  const licenses = readLicenses(component.licenses);
  const { one } = propReader(component);
  // enrich-aibom.sh resolves each declared dataset and records the verdict here.
  // A card that names datasets nobody can retrieve is "declared-unverified", not
  // open data, so prefer that judgement over counting names when it is present.
  const opennessData = one("openness:training-data");
  const weightFormats = splitList(one("bomlens:weights:formats"));

  return {
    name: str(component.name) ?? "(unnamed model)",
    version: str(component.version) ?? "",
    group: str(component.group),
    purl: str(component.purl),
    description: str(component.description),
    licenses,
    supplier: str(obj(component.supplier).name),
    authors,
    architecture,
    task: str(params.task),
    hasIntegrity,
    externalRefs,
    datasets,
    limitations,
    assessment: readAssessment(one),
    scanStatus: scanStatus(one("bomlens:hf:scan:status")),
    scanIssue: one("bomlens:hf:scan:issue"),
    localScan: localScanStatus(one("bomlens:localscan:status")),
    localScanTool: one("bomlens:localscan:tool"),
    localScanFindings: one("bomlens:localscan:findings"),
    weightFormats: weightFormats.length > 0 ? weightFormats : undefined,
    customLicenseQuote: one("bomlens:license:customScan:quote"),
    lineageConflictWith: one("bomlens:lineage:conflictWith"),
    disclosure: {
      // Documented-in-the-BOM, not a claim about the model itself.
      weights: hasIntegrity || externalRefs.some((r) => r.type === "distribution"),
      architecture: Boolean(architecture),
      trainingData: opennessData ? opennessData === "open-data" : datasets.length > 0,
      trainingProcess: limitations.length > 0,
    },
  };
}

/** One row of the datasets table: a dataset and how far it is indented under
 *  the dataset it was traced from. */
export interface DatasetRow {
  dataset: DatasetRef;
  level: number;
  /** How the row above it names this one ("extended", "listed"); root rows have none. */
  relation?: string;
  /** This dataset already has its full row further up (a source two datasets
   *  share, or one that leads back up a cycle): shown here by name only. */
  repeat?: boolean;
}

/**
 * Order datasets as a tree: each dataset the card names, then the sources
 * traced from it, indented beneath it. A dataset gets its full row once, under
 * the first dataset that reaches it; every later mention (a shared source, or a
 * link back up a cycle) is a short row marked as a repeat, which never expands
 * again. So every source a dataset names has a row under it, and the table
 * stays as long as the graph has links, however densely they connect.
 * Datasets nobody links to keep their original order.
 */
export function datasetTreeRows(datasets: DatasetRef[]): DatasetRow[] {
  const byRef = new Map<string, DatasetRef>();
  for (const d of datasets) if (d.ref) byRef.set(d.ref, d);
  const linked = new Set<string>();
  for (const d of datasets) for (const s of d.derivedFrom) linked.add(s.ref);
  const shown = new Set<DatasetRef>();
  const rows: DatasetRow[] = [];
  const visit = (d: DatasetRef, level: number, relation?: string) => {
    if (shown.has(d)) {
      if (level > 0) rows.push({ dataset: d, level, relation, repeat: true });
      return;
    }
    shown.add(d);
    rows.push({ dataset: d, level, relation });
    for (const s of d.derivedFrom) {
      const child = byRef.get(s.ref);
      if (child) visit(child, level + 1, s.relation);
    }
  };
  for (const d of datasets) {
    const isRoot = d.depth === undefined ? !(d.ref && linked.has(d.ref)) : d.depth === 0;
    if (isRoot) visit(d, 0);
  }
  for (const d of datasets) visit(d, 0);
  return rows;
}

/** Extract model cards and the datasets they reference from a raw SBOM. */
export function parseModelCards(sbom: unknown): AiModelData {
  const components = arr(obj(sbom).components).map((c) => obj(c));
  // A spec-shaped AI SBOM names the model as the document's own component and
  // lists only its datasets under components[], so reading that array alone
  // leaves this view empty on exactly the scans it exists for. Fold a
  // machine-learning-model root in, by the rule the server summary applies:
  // every other root is the scanned project itself, which is not one of its own
  // components and stays out.
  const root = obj(obj(sbom).metadata).component;
  const cards =
    obj(root).type === "machine-learning-model"
      ? [obj(root), ...components]
      : components;
  const models = cards
    .filter((c) => c.type === "machine-learning-model")
    .map(parseModel);

  // The card's bare name goes in first; a resolved `data` component with the same
  // name then overwrites it. Order matters — the data component is the richer
  // record (license, digests, upstream), so letting the card win would throw away
  // everything the resolve step collected.
  const byName = new Map<string, DatasetRef>();
  for (const m of models) {
    for (const d of m.datasets) if (!byName.has(d.name)) byName.set(d.name, d);
  }
  // A dataset scan describes one item and has no components[] at all, so the
  // root is folded in here for the same reason a model root is folded in above.
  const dataComponents = obj(root).type === "data" ? [obj(root), ...components] : components;
  for (const c of dataComponents) {
    if (c.type !== "data") continue;
    const ds = readDataComponent(c);
    if (!ds) continue;
    const prior = byName.get(ds.name);
    // Keep the card's URL when the resolve step could not supply one.
    byName.set(ds.name, { ...ds, url: ds.url ?? prior?.url });
  }

  return { models, datasets: [...byName.values()] };
}

// ── Declared services ────────────────────────────────────────────────────────

/** An AI model the declared service calls through an API, as the publisher
 *  named it. */
export interface DeclaredExternalModel {
  name: string;
  provider?: string;
  version?: string;
  endpoint?: string;
}

/**
 * The service (an app or API) the publisher declared the model runs in, as the
 * CycloneDX SBOM records it: a `services[]` entry marked
 * `bomlens:origin=declared-input` with `bomlens:service:kind=application`.
 * Nothing in it was read or checked by the tool.
 */
export interface DeclaredService {
  ref?: string;
  name: string;
  version?: string;
  provider?: string;
  endpoint?: string;
  description?: string;
  /** The names of the SBOM's models the service runs (its dependencies). */
  models: string[];
  externalModels: DeclaredExternalModel[];
  /** How many data flows (serviceData entries) it declares. */
  dataFlows: number;
}

const DECLARED_ORIGIN = "declared-input";

function readExternal(s: Obj): DeclaredExternalModel {
  return {
    name: str(s.name) ?? "",
    provider: str(obj(s.provider).name),
    version: str(s.version),
    endpoint: arr(s.endpoints).map(str).find(Boolean),
  };
}

/** The services the publisher declared, from a CycloneDX SBOM. Services the
 *  scan found itself (no declared origin) are not these and are left out. */
export function parseDeclaredServices(sbom: unknown): DeclaredService[] {
  const doc = obj(sbom);
  const declared = arr(doc.services)
    .map((s) => obj(s))
    .filter((s) => propReader(s).one("bomlens:origin") === DECLARED_ORIGIN);
  const kind = (s: Obj) => propReader(s).one("bomlens:service:kind");
  const externals = declared.filter((s) => kind(s) === "external-model");
  const apps = declared.filter((s) => kind(s) !== "external-model" && str(s.name));
  // Names of the SBOM's parts by bom-ref, the root included, so a dependency
  // reads as the model it points at.
  const names = new Map<string, string>();
  const root = obj(obj(doc.metadata).component);
  for (const c of [root, ...arr(doc.components).map((x) => obj(x))]) {
    const ref = str(c["bom-ref"]);
    const name = str(c.name);
    if (ref && name) names.set(ref, c.group ? `${String(c.group)}/${name}` : name);
  }
  const extByRef = new Map<string, Obj>();
  for (const e of externals) {
    const ref = str(e["bom-ref"]);
    if (ref) extByRef.set(ref, e);
  }
  const deps = new Map<string, string[]>();
  for (const d of arr(doc.dependencies).map((x) => obj(x))) {
    const ref = str(d.ref);
    if (ref) deps.set(ref, arr(d.dependsOn).map(str).filter((x): x is string => Boolean(x)));
  }
  return apps.map((s) => {
    const ref = str(s["bom-ref"]);
    const on = ref ? deps.get(ref) : undefined;
    // Without a dependency list (an SBOM with no model ref to point at), every
    // declared external model is the service's: there is one service at most.
    const ext = on ? on.filter((r) => extByRef.has(r)).map((r) => extByRef.get(r) as Obj) : externals;
    return {
      ref,
      name: str(s.name) ?? "",
      version: str(s.version),
      provider: str(obj(s.provider).name),
      endpoint: arr(s.endpoints).map(str).find(Boolean),
      description: str(s.description),
      models: (on ?? []).filter((r) => !extByRef.has(r) && names.has(r)).map((r) => names.get(r) as string),
      externalModels: ext.map(readExternal),
      dataFlows: arr(s.data).length,
    };
  });
}

// ── Grade badge ──────────────────────────────────────────────────────────────
//
// Shared between the Models & datasets view and the AI summary card, so a
// grade never reads as a different color depending on which screen shows it.

/** Badge tone per pipeline grade — the grade word itself is always shown, so
 *  the color is a reinforcement, never the only signal.
 *
 *  The tone ordering has to track the pipeline's own severity ranking
 *  (assess-ai-risk.sh: caution > review > conditional > ok — a known blocker
 *  outranks an unknown, which outranks a condition, which outranks a clear
 *  signal). Get that ordering wrong here and the two readings disagree: a
 *  reader sees "review" rendered milder than "conditional" and reasonably
 *  concludes it's the safer of the two, when the pipeline ranks it worse. */
export const GRADE_TONE: Record<AssessmentGrade, "positive" | "medium" | "high" | "critical"> = {
  ok: "positive",
  conditional: "medium",
  review: "high",
  caution: "critical",
};

/** Worst-first severity order (assess-ai-risk.sh), for picking one overall
 *  grade out of several (the AI summary card's header badge). */
export const GRADE_SEVERITY_ORDER: readonly AssessmentGrade[] = [
  "caution",
  "review",
  "conditional",
  "ok",
];

/** A stamped grade as word + tone (verbatim from the SBOM property). */
export function GradeBadge({ grade }: { grade: AssessmentGrade }) {
  const { t } = useTranslation();
  return <Badge tone={GRADE_TONE[grade]}>{t(GRADE_LABEL_KEY[grade])}</Badge>;
}
