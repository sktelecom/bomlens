import { describe, expect, it } from "vitest";

import type { Severity } from "./api";
import { parseSbomGraph, type RawSbom, type TreeNode } from "./sbomGraph";

// A small CycloneDX SBOM with a metadata root, a dependency graph and licenses.
// app → libA → libB; app → libC. cdxgen sets bom-ref = purl, so each component
// is addressable by either.
const BOM: RawSbom = {
  bomFormat: "CycloneDX",
  metadata: { component: { "bom-ref": "app@1.0", name: "app", version: "1.0", type: "application" } },
  components: [
    {
      "bom-ref": "pkg:npm/libA@1.0",
      name: "libA",
      version: "1.0",
      type: "library",
      purl: "pkg:npm/libA@1.0",
      licenses: [{ license: { id: "MIT" } }],
    },
    {
      "bom-ref": "pkg:npm/libB@2.0",
      name: "libB",
      version: "2.0",
      type: "library",
      purl: "pkg:npm/libB@2.0",
      licenses: [{ license: { name: "Apache-2.0" } }],
    },
    {
      "bom-ref": "pkg:npm/libC@3.0",
      name: "libC",
      version: "3.0",
      type: "library",
      purl: "pkg:npm/libC@3.0",
      licenses: [{ expression: "BSD-3-Clause OR MIT" }],
    },
  ],
  dependencies: [
    { ref: "app@1.0", dependsOn: ["pkg:npm/libA@1.0", "pkg:npm/libC@3.0"] },
    { ref: "pkg:npm/libA@1.0", dependsOn: ["pkg:npm/libB@2.0"] },
    { ref: "pkg:npm/libB@2.0", dependsOn: [] },
    { ref: "pkg:npm/libC@3.0", dependsOn: [] },
  ],
};

/** Find a tree node by name across the whole forest. */
function findNode(nodes: TreeNode[], name: string): TreeNode | undefined {
  for (const n of nodes) {
    if (n.name === name) return n;
    const hit = findNode(n.children, name);
    if (hit) return hit;
  }
  return undefined;
}

describe("parseSbomGraph", () => {
  it("builds one node per component and resolves names/versions/types", () => {
    const g = parseSbomGraph(BOM);
    expect(g.componentCount).toBe(3);
    expect(g.hasDependencies).toBe(true);
    // app appears via the dependency graph even though it's only in metadata.
    expect(g.nodes.map((n) => n.id).sort()).toEqual(
      ["app@1.0", "pkg:npm/libA@1.0", "pkg:npm/libB@2.0", "pkg:npm/libC@3.0"].sort(),
    );
    const a = g.nodes.find((n) => n.id === "pkg:npm/libA@1.0")!;
    expect(a).toMatchObject({ name: "libA", version: "1.0", type: "library", label: "libA@1.0" });
  });

  it("normalizes id / name / expression licenses", () => {
    const g = parseSbomGraph(BOM);
    const lics = (id: string) => g.nodes.find((n) => n.id === id)!.licenses;
    expect(lics("pkg:npm/libA@1.0")).toEqual(["MIT"]);
    expect(lics("pkg:npm/libB@2.0")).toEqual(["Apache-2.0"]);
    expect(lics("pkg:npm/libC@3.0")).toEqual(["BSD-3-Clause OR MIT"]);
  });

  it("emits an edge per dependsOn pair", () => {
    const g = parseSbomGraph(BOM);
    expect(g.edges).toContainEqual({ source: "app@1.0", target: "pkg:npm/libA@1.0" });
    expect(g.edges).toContainEqual({ source: "app@1.0", target: "pkg:npm/libC@3.0" });
    expect(g.edges).toContainEqual({ source: "pkg:npm/libA@1.0", target: "pkg:npm/libB@2.0" });
    // Empty dependsOn entries contribute no edges.
    expect(g.edges).toHaveLength(3);
  });

  it("marks the metadata root's direct dependencies as direct", () => {
    const g = parseSbomGraph(BOM);
    const direct = (id: string) => g.nodes.find((n) => n.id === id)!.direct;
    expect(direct("pkg:npm/libA@1.0")).toBe(true);
    expect(direct("pkg:npm/libC@3.0")).toBe(true);
    expect(direct("pkg:npm/libB@2.0")).toBe(false); // transitive
    expect(direct("app@1.0")).toBe(false); // the root itself
  });

  it("roots the tree at the metadata component's direct deps and nests transitives", () => {
    const g = parseSbomGraph(BOM);
    expect(g.tree.map((n) => n.name).sort()).toEqual(["libA", "libC"]);
    const libA = g.tree.find((n) => n.name === "libA")!;
    expect(libA.depth).toBe(0);
    expect(libA.children.map((c) => c.name)).toEqual(["libB"]);
    expect(libA.children[0].depth).toBe(1);
  });

  it("attaches severity from the vulnOf callback to nodes and tree", () => {
    const vulnOf = (name: string): Severity | undefined =>
      name === "libB" ? "HIGH" : undefined;
    const g = parseSbomGraph(BOM, vulnOf);
    expect(g.nodes.find((n) => n.id === "pkg:npm/libB@2.0")!.vuln).toBe("HIGH");
    expect(g.nodes.find((n) => n.id === "pkg:npm/libA@1.0")!.vuln).toBeUndefined();
    expect(findNode(g.tree, "libB")!.vuln).toBe("HIGH");
  });

  it("falls back to refs nothing depends on when the root is not in the graph", () => {
    // The metadata root has no dependency entry at all, while edges still
    // exist between components, so roots = refs nothing depends on.
    const bom: RawSbom = {
      metadata: { component: { "bom-ref": "root" } },
      components: [
        { "bom-ref": "x", name: "x", version: "1" },
        { "bom-ref": "y", name: "y", version: "2" },
      ],
      dependencies: [
        { ref: "x", dependsOn: ["y"] },
        { ref: "y", dependsOn: [] },
      ],
    };
    const g = parseSbomGraph(bom);
    // x is depended on by nothing → it becomes the tree root.
    expect(g.tree.map((n) => n.name)).toEqual(["x"]);
    expect(g.tree[0].children.map((c) => c.name)).toEqual(["y"]);
    expect(g.nodes.find((n) => n.id === "x")!.direct).toBe(true);
    expect(g.nodes.find((n) => n.id === "y")!.direct).toBe(false);
  });

  it("guards against cycles without infinite recursion", () => {
    const bom: RawSbom = {
      metadata: { component: { "bom-ref": "root" } },
      components: [
        { "bom-ref": "a", name: "a", version: "1" },
        { "bom-ref": "b", name: "b", version: "1" },
      ],
      dependencies: [
        { ref: "root", dependsOn: ["a"] },
        { ref: "a", dependsOn: ["b"] },
        { ref: "b", dependsOn: ["a"] }, // cycle back to a
      ],
    };
    const g = parseSbomGraph(bom);
    const a = g.tree.find((n) => n.name === "a")!;
    const b = a.children[0];
    expect(b.name).toBe("b");
    const aAgain = b.children[0];
    // The revisited ancestor is flagged and not expanded further.
    expect(aAgain.name).toBe("a");
    expect(aAgain.cycle).toBe(true);
    expect(aAgain.children).toEqual([]);
  });

  it("falls back to a flat tree when the SBOM has no dependency graph", () => {
    const bom: RawSbom = {
      components: [
        { "bom-ref": "p", name: "p", version: "1", type: "library" },
        { "bom-ref": "q", name: "q", version: "2", type: "library" },
      ],
    };
    const g = parseSbomGraph(bom);
    expect(g.hasDependencies).toBe(false);
    expect(g.edges).toEqual([]);
    expect(g.tree.map((n) => n.name).sort()).toEqual(["p", "q"]);
    expect(g.tree.every((n) => n.depth === 0 && n.children.length === 0)).toBe(true);
  });

  it("treats a dependencies array of only empty dependsOn as no graph", () => {
    const bom: RawSbom = {
      components: [{ "bom-ref": "p", name: "p", version: "1" }],
      dependencies: [{ ref: "p", dependsOn: [] }],
    };
    expect(parseSbomGraph(bom).hasDependencies).toBe(false);
  });

  it("is defensive about empty / missing input", () => {
    const empty = parseSbomGraph({});
    expect(empty).toMatchObject({
      nodes: [],
      edges: [],
      tree: [],
      hasDependencies: false,
      componentCount: 0,
    });
    // Non-array components/dependencies are ignored rather than throwing.
    const junk = parseSbomGraph({
      components: undefined,
      dependencies: undefined,
    } as RawSbom);
    expect(junk.componentCount).toBe(0);
  });

  it("synthesizes a label/ref for components missing bom-ref and purl", () => {
    const bom: RawSbom = {
      components: [{ name: "loose", version: "0.1", group: "acme" }],
    };
    const g = parseSbomGraph(bom);
    // refOf falls back to group/name@version for the node id.
    expect(g.nodes[0].id).toBe("acme/loose@0.1");
    // meta() can't re-resolve that synthesized ref (the component is indexed
    // only by bom-ref/purl, both absent), so name and label echo the ref.
    expect(g.nodes[0].name).toBe("acme/loose@0.1");
    expect(g.nodes[0].label).toBe("acme/loose@0.1");
  });
});
