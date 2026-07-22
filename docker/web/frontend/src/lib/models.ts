/**
 * Parse the AI surfaces out of a raw CycloneDX 1.7 ML-BOM (OWASP AIBOM
 * Generator output): the machine-learning-model components with their model
 * cards, and the datasets they reference. Pure and defensive — the BOM is
 * external input — so the Models & Datasets view never throws on a partial card.
 */

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
  const props = arr(c.properties).map((p) => obj(p));
  const propVals = (key: string) =>
    props
      .filter((p) => str(p.name) === key)
      .map((p) => str(p.value))
      .filter((v): v is string => Boolean(v));
  const cdata = arr(c.data).map((d) => obj(d))[0] ?? {};
  const refs = arr(c.externalReferences).map((r) => obj(r));
  return {
    name,
    url: str(obj(cdata.contents).url) ?? str(refs.map((r) => str(r.url)).find(Boolean)),
    version: str(c.version),
    licenses: readLicenses(c.licenses),
    hasIntegrity: arr(c.hashes).length > 0,
    sources: propVals("bomlens:dataset:sourceDataset"),
    unresolved: propVals("bomlens:dataset:unresolved").length > 0,
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
  // enrich-aibom.sh resolves each declared dataset and records the verdict here.
  // A card that names datasets nobody can retrieve is "declared-unverified", not
  // open data, so prefer that judgement over counting names when it is present.
  const opennessData = arr(component.properties)
    .map((p) => obj(p))
    .filter((p) => str(p.name) === "openness:training-data")
    .map((p) => str(p.value))[0];

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
