// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import type { Severity } from "./api";
import { findFirstMatch, findPathToRef, parseSbomGraph, type RawSbom, type TreeNode } from "./sbomGraph";

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

describe("the document's own component", () => {
  // It keys the dependency graph but is not listed in components[], so it
  // resolved to nothing and its node fell back to the raw ref: an AI SBOM drew
  // its root as "pkg:huggingface/skt/A.X-K2@9af2e3d0", long enough to run under
  // the node beside it. It is also neither direct nor transitive, and the
  // legend has no colour that means "a dependency of itself".
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: {
      component: { "bom-ref": "pkg:huggingface/skt/model@abc", type: "machine-learning-model", name: "model", version: "abc" },
    },
    components: [
      { "bom-ref": "dataset:one", type: "data", name: "org/one", version: "1" },
    ],
    dependencies: [
      { ref: "pkg:huggingface/skt/model@abc", dependsOn: ["dataset:one"] },
      { ref: "dataset:one", dependsOn: [] },
    ],
  };

  it("is labelled by its name, not by its raw ref", () => {
    const g = parseSbomGraph(sbom);
    const root = g.nodes.find((n) => n.id === "pkg:huggingface/skt/model@abc")!;
    expect(root.label).toBe("model@abc");
  });

  it("is marked as the root and counted as neither direct nor transitive", () => {
    const g = parseSbomGraph(sbom);
    const root = g.nodes.find((n) => n.id === "pkg:huggingface/skt/model@abc")!;
    expect(root.root).toBe(true);
    expect(root.direct).toBe(false);
    const dataset = g.nodes.find((n) => n.id === "dataset:one")!;
    expect(dataset.root).toBe(false);
    expect(dataset.direct).toBe(true);
  });
});

describe("findPathToRef", () => {
  it("finds a direct dependency", () => {
    const g = parseSbomGraph(BOM);
    // app -> libA, libC: libA is tree[0], libC is tree[1].
    const found = findPathToRef(g.tree, { name: "libC", version: "3.0" });
    expect(found).toEqual({ target: "1", ancestors: [] });
  });

  it("finds a nested transitive dependency and lists every ancestor's path", () => {
    const g = parseSbomGraph(BOM);
    // app -> libA -> libB: libB sits under tree[0].children[0].
    const found = findPathToRef(g.tree, { name: "libB", version: "2.0" });
    expect(found).toEqual({ target: "0.0", ancestors: ["0"] });
  });

  it("returns null when nothing matches", () => {
    const g = parseSbomGraph(BOM);
    expect(findPathToRef(g.tree, { name: "does-not-exist" })).toBeNull();
  });

  it("prefers the exact version over a same-named sibling elsewhere in the tree", () => {
    // A dependency-conflict shape: two branches pull different versions of the
    // same package (measured for real on a qs@6.15.3 / qs@6.16.0 pair). Search
    // must land on the one that was actually asked for, not just the first
    // name match a naive walk would hit.
    const bom: RawSbom = {
      metadata: { component: { "bom-ref": "app" } },
      components: [
        { "bom-ref": "a", name: "a", version: "1" },
        { "bom-ref": "b", name: "b", version: "1" },
        { "bom-ref": "qs-old", name: "qs", version: "6.15.3" },
        { "bom-ref": "qs-new", name: "qs", version: "6.16.0" },
      ],
      dependencies: [
        { ref: "app", dependsOn: ["a", "b"] },
        { ref: "a", dependsOn: ["qs-old"] }, // a pulls the vulnerable version
        { ref: "b", dependsOn: ["qs-new"] }, // b already resolved to the fix
        { ref: "qs-old", dependsOn: [] },
        { ref: "qs-new", dependsOn: [] },
      ],
    };
    const g = parseSbomGraph(bom);
    const vulnerable = findPathToRef(g.tree, { name: "qs", version: "6.15.3" });
    expect(vulnerable).toEqual({ target: "0.0", ancestors: ["0"] }); // under a
    const fixed = findPathToRef(g.tree, { name: "qs", version: "6.16.0" });
    expect(fixed).toEqual({ target: "1.0", ancestors: ["1"] }); // under b
  });

  it("falls back to a name-only match when no version is given", () => {
    const g = parseSbomGraph(BOM);
    const found = findPathToRef(g.tree, { name: "libB" });
    expect(found).toEqual({ target: "0.0", ancestors: ["0"] });
  });

  it("falls back to a name-only match when the given version matches nothing", () => {
    const g = parseSbomGraph(BOM);
    const found = findPathToRef(g.tree, { name: "libB", version: "9.9.9-nope" });
    expect(found).toEqual({ target: "0.0", ancestors: ["0"] });
  });

  it("does not recurse into a cycle placeholder (stays terminating)", () => {
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
    // "a" is findable at its real position (tree[0]), not just the cycle echo.
    expect(findPathToRef(g.tree, { name: "a", version: "1" })).toEqual({
      target: "0",
      ancestors: [],
    });
  });
});

describe("findFirstMatch", () => {
  it("drives a substring search (the Dependencies tree's own search box)", () => {
    const g = parseSbomGraph(BOM);
    const found = findFirstMatch(g.tree, (n) => n.name.toLowerCase().includes("lib"));
    // Depth-first, so the first match is libA (tree[0]), not the deeper libB.
    expect(found).toEqual({ target: "0", ancestors: [] });
  });

  it("returns null when the predicate matches nothing", () => {
    const g = parseSbomGraph(BOM);
    expect(findFirstMatch(g.tree, (n) => n.name === "nope")).toBeNull();
  });
});
