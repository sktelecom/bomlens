/**
 * Parse the AI surfaces out of a raw CycloneDX 1.7 ML-BOM (OWASP AIBOM
 * Generator output): the machine-learning-model components with their model
 * cards, and the datasets they reference. Pure and defensive — the BOM is
 * external input — so the Models & Datasets view never throws on a partial card.
 */

export interface DatasetRef {
  name: string;
  url?: string;
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

function readDatasets(modelParameters: Obj): DatasetRef[] {
  const out: DatasetRef[] = [];
  for (const d of arr(modelParameters.datasets)) {
    const ds = obj(d);
    const name = str(ds.name) ?? str(ds.ref);
    if (!name) continue;
    out.push({ name, url: str(obj(ds.contents).url) });
  }
  return out;
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
    disclosure: {
      // Documented-in-the-BOM, not a claim about the model itself.
      weights: hasIntegrity || externalRefs.some((r) => r.type === "distribution"),
      architecture: Boolean(architecture),
      trainingData: datasets.length > 0,
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

  const byName = new Map<string, DatasetRef>();
  for (const m of models) {
    for (const d of m.datasets) if (!byName.has(d.name)) byName.set(d.name, d);
  }
  // Standalone data components, if any, also count as datasets.
  for (const c of components) {
    if (c.type === "data") {
      const name = str(c.name);
      if (name && !byName.has(name)) byName.set(name, { name });
    }
  }

  return { models, datasets: [...byName.values()] };
}
