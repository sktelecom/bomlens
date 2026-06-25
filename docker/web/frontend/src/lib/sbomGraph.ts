/**
 * Parse a raw CycloneDX SBOM into the shapes the dependency views need:
 * a flat node/edge graph (for the Cytoscape canvas) and a collapsible
 * hierarchy tree (direct → transitive). Everything runs client-side on the
 * raw `_bom.json` fetched through `fileUrl()`; the backend is untouched.
 *
 * CycloneDX `dependencies[]` uses `ref` / `dependsOn` strings that match each
 * component's `bom-ref` (cdxgen sets `bom-ref` = purl, so we index by both).
 * When the SBOM carries no dependency graph (syft output, or a language whose
 * cdxgen image doesn't emit one) we fall back to a flat component list.
 */
import { fileUrl, type Severity } from "./api";

/** Resolve a node's worst vulnerability severity by name/version, if any. */
export type VulnLookup = (name: string, version: string) => Severity | undefined;

export interface RawComponent {
  "bom-ref"?: string;
  name?: string;
  version?: string;
  group?: string;
  purl?: string;
  type?: string;
  licenses?: unknown;
}

export interface RawSbom {
  bomFormat?: string;
  metadata?: { component?: RawComponent & { "bom-ref"?: string } };
  components?: RawComponent[];
  dependencies?: { ref?: string; dependsOn?: string[] }[];
}

export interface GraphNode {
  id: string;
  label: string;
  name: string;
  version: string;
  type: string;
  licenses: string[];
  /** true when this node is a direct dependency of the root component. */
  direct: boolean;
  /** worst severity of this package's known vulnerabilities, if any. */
  vuln?: Severity;
}

export interface GraphEdge {
  source: string;
  target: string;
}

export interface TreeNode {
  id: string;
  name: string;
  version: string;
  type: string;
  licenses: string[];
  depth: number;
  children: TreeNode[];
  /** worst severity of this package's known vulnerabilities, if any. */
  vuln?: Severity;
  /** set when expanding this node would revisit an ancestor (cycle guard). */
  cycle?: boolean;
}

export interface SbomGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  tree: TreeNode[];
  /** false when the SBOM had no usable `dependencies[]` (flat fallback). */
  hasDependencies: boolean;
  componentCount: number;
}

/** Normalize CycloneDX `licenses[]` (id | name | expression) to SPDX-ish strings. */
function readLicenses(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    if (typeof e.expression === "string") {
      out.push(e.expression);
      continue;
    }
    const lic = e.license as Record<string, unknown> | undefined;
    if (lic) {
      const id = (lic.id ?? lic.name) as string | undefined;
      if (typeof id === "string" && id) out.push(id);
    }
  }
  return out;
}

/** A component's stable key, matching how `dependencies[].ref` addresses it. */
function refOf(c: RawComponent): string {
  return c["bom-ref"] || c.purl || `${c.group ? c.group + "/" : ""}${c.name}@${c.version}`;
}

function labelOf(name: string, version: string): string {
  return version ? `${name}@${version}` : name || "(unknown)";
}

/** Fetch and parse the raw SBOM artifact. Throws on network/JSON failure. */
export async function loadSbom(name: string): Promise<RawSbom> {
  const res = await fetch(fileUrl(name));
  if (!res.ok) throw new Error(`SBOM fetch failed (${res.status})`);
  return (await res.json()) as RawSbom;
}

export function parseSbomGraph(sbom: RawSbom, vulnOf?: VulnLookup): SbomGraph {
  const components = Array.isArray(sbom.components) ? sbom.components : [];

  // Index every component by both bom-ref and purl so dependency refs resolve.
  const byRef = new Map<string, RawComponent>();
  for (const c of components) {
    if (c["bom-ref"]) byRef.set(c["bom-ref"], c);
    if (c.purl) byRef.set(c.purl, c);
  }

  const meta = (ref: string) => {
    const c = byRef.get(ref);
    const name = c?.name || ref;
    const version = c?.version || "";
    return {
      name,
      version,
      type: c?.type || "",
      licenses: readLicenses(c?.licenses),
      label: labelOf(name, version),
      vuln: vulnOf?.(name, version),
    };
  };

  const deps = Array.isArray(sbom.dependencies) ? sbom.dependencies : [];
  const adjacency = new Map<string, string[]>();
  const dependedOn = new Set<string>();
  for (const d of deps) {
    if (!d || typeof d.ref !== "string") continue;
    const targets = Array.isArray(d.dependsOn) ? d.dependsOn.filter((t) => typeof t === "string") : [];
    adjacency.set(d.ref, targets);
    for (const t of targets) dependedOn.add(t);
  }

  const hasDependencies = adjacency.size > 0 && Array.from(adjacency.values()).some((t) => t.length > 0);

  // Roots = the metadata component's direct dependencies, or (when the root has
  // no dependency entry) every ref that nothing else depends on. The same set
  // drives the tree's top level and the graph's "direct" highlight.
  const metaRef = sbom.metadata?.component
    ? sbom.metadata.component["bom-ref"] || sbom.metadata.component.purl
    : undefined;
  // Prefer the metadata component's direct dependencies. But some tools emit a
  // root entry with an EMPTY dependsOn while still recording component-to-
  // component edges (the graph renders, yet the tree would be empty), so fall
  // back to "refs nothing depends on" whenever the root yields no children.
  const rootChildren =
    metaRef && adjacency.has(metaRef) ? adjacency.get(metaRef)! : [];
  const rootRefs =
    rootChildren.length > 0
      ? rootChildren
      : Array.from(adjacency.keys()).filter((ref) => !dependedOn.has(ref));
  const directRefs = new Set<string>(rootRefs);

  // ---- flat graph (nodes = all components, edges = dependsOn) ----
  const nodeIds = new Set<string>();
  for (const c of components) nodeIds.add(refOf(c));
  for (const [ref, targets] of adjacency) {
    nodeIds.add(ref);
    for (const t of targets) nodeIds.add(t);
  }
  const nodes: GraphNode[] = Array.from(nodeIds).map((id) => {
    const m = meta(id);
    return {
      id,
      label: m.label,
      name: m.name,
      version: m.version,
      type: m.type,
      licenses: m.licenses,
      direct: directRefs.has(id),
      vuln: m.vuln,
    };
  });
  const edges: GraphEdge[] = [];
  for (const [ref, targets] of adjacency) {
    for (const t of targets) edges.push({ source: ref, target: t });
  }

  // ---- hierarchy tree ----
  let tree: TreeNode[];
  if (!hasDependencies) {
    // No dependency graph: flat list of components at depth 0.
    tree = components.map((c) => {
      const ref = refOf(c);
      const m = meta(ref);
      return {
        id: ref,
        name: m.name,
        version: m.version,
        type: m.type,
        licenses: m.licenses,
        depth: 0,
        children: [],
        vuln: m.vuln,
      };
    });
  } else {
    const build = (ref: string, depth: number, ancestors: Set<string>): TreeNode => {
      const m = meta(ref);
      const node: TreeNode = {
        id: ref,
        name: m.name,
        version: m.version,
        type: m.type,
        licenses: m.licenses,
        depth,
        children: [],
        vuln: m.vuln,
      };
      if (ancestors.has(ref)) {
        node.cycle = true;
        return node;
      }
      const next = new Set(ancestors);
      next.add(ref);
      for (const child of adjacency.get(ref) ?? []) {
        node.children.push(build(child, depth + 1, next));
      }
      return node;
    };

    const seenRoots = new Set<string>();
    tree = rootRefs
      .filter((r) => (seenRoots.has(r) ? false : (seenRoots.add(r), true)))
      .map((r) => build(r, 0, new Set()));
  }

  return {
    nodes,
    edges,
    tree,
    hasDependencies,
    componentCount: components.length,
  };
}
