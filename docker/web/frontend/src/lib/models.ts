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

import { USAGE_CONTEXTS, type UsageContext } from "./api";

/** A pipeline-stamped risk grade, read verbatim from the SBOM. */
export type AssessmentGrade = "ok" | "conditional" | "caution" | "review";

const GRADES: readonly string[] = ["ok", "conditional", "caution", "review"];

/** HuggingFace file-security scan outcome (`bomlens:hf:scan:status`). */
export type HfScanStatus = "safe" | "queued" | "suspicious" | "unsafe" | "unavailable";

const HF_SCAN_STATUSES: readonly string[] = [
  "safe", "queued", "suspicious", "unsafe", "unavailable",
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
  return {
    name,
    url: str(obj(cdata.contents).url) ?? str(refs.map((r) => str(r.url)).find(Boolean)),
    version: str(c.version),
    licenses: readLicenses(c.licenses),
    hasIntegrity: arr(c.hashes).length > 0,
    sources: all("bomlens:dataset:sourceDataset"),
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

/** Extract model cards and the datasets they reference from a raw SBOM. */
export function parseModelCards(sbom: unknown): AiModelData {
  const components = arr(obj(sbom).components).map((c) => obj(c));
  const models = components
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
  for (const c of components) {
    if (c.type !== "data") continue;
    const ds = readDataComponent(c);
    if (!ds) continue;
    const prior = byName.get(ds.name);
    // Keep the card's URL when the resolve step could not supply one.
    byName.set(ds.name, { ...ds, url: ds.url ?? prior?.url });
  }

  return { models, datasets: [...byName.values()] };
}
