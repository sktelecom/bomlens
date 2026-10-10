// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { createTemplate, parseMap, startDeclaration, type Declaration, type FieldIndex } from "./aiDeclaration";
import { declarationReducer, flushPendingIds, type DeclarationState } from "./useAiDeclaration";

const index = parseMap(
  JSON.parse(readFileSync(new URL("../../../../lib/spdx3-ai-map.json", import.meta.url), "utf-8")),
) as FieldIndex;

const start = (): DeclarationState => ({
  step: "model",
  decl: startDeclaration({
    schema: "bomlens-ai-declaration/1",
    document: { createdBy: [] },
    model: { releaseTime: "", baseModels: [{ ref: "org/base", revision: "" }] },
    datasets: [{ ref: "huggingface:org/ds", role: "", builtTime: "" }],
    relationships: [],
  }) as Declaration,
});

describe("declarationReducer", () => {
  it("sets an answer where it belongs without touching the rest", () => {
    const s0 = start();
    const s1 = declarationReducer(s0, { type: "set", target: { kind: "model" }, field: "releaseTime", value: "2025-01-01T00:00:00Z" });
    expect(s1.decl.model!.releaseTime).toBe("2025-01-01T00:00:00Z");
    expect(s0.decl.model!.releaseTime).toBe("");
    const s2 = declarationReducer(s1, { type: "set", target: { kind: "dataset", index: 0 }, field: "role", value: "trainedOn" });
    expect(s2.decl.datasets[0].role).toBe("trainedOn");
    const s3 = declarationReducer(s2, { type: "set", target: { kind: "base", index: 0 }, field: "revision", value: "abc" });
    expect(s3.decl.model!.baseModels).toEqual([{ ref: "org/base", revision: "abc" }]);
    const s4 = declarationReducer(s3, {
      type: "set",
      target: { kind: "document" },
      field: "createdBy",
      value: [{ type: "Organization", name: "Acme" }],
    });
    expect(s4.decl.document.createdBy).toEqual([{ type: "Organization", name: "Acme" }]);
  });

  it("ignores an answer for something that is not there", () => {
    const s0 = start();
    expect(declarationReducer(s0, { type: "set", target: { kind: "dataset", index: 9 }, field: "x", value: "" })).toBe(s0);
    expect(declarationReducer(s0, { type: "set", target: { kind: "base", index: 0 }, field: "ref", value: "other" })).toBe(s0);
  });

  it("adds a dataset the hub does not hold, slugs it from its name, and removes only those", () => {
    let s = declarationReducer(start(), { type: "addLocal", index });
    expect(s.decl.datasets).toHaveLength(2);
    s = declarationReducer(s, { type: "set", target: { kind: "dataset", index: 1 }, field: "name", value: "Support Logs" });
    expect(s.decl.datasets[1]).toMatchObject({ local: "support-logs", name: "Support Logs" });
    s = declarationReducer(s, { type: "addLocal", index });
    s = declarationReducer(s, { type: "set", target: { kind: "dataset", index: 2 }, field: "name", value: "Support logs" });
    expect(s.decl.datasets[2].local).toBe("support-logs-2");
    expect(declarationReducer(s, { type: "removeLocal", index: 0 })).toBe(s);
    s = declarationReducer(s, { type: "removeLocal", index: 1 });
    expect(s.decl.datasets.map((d) => d.local ?? d.ref)).toEqual(["huggingface:org/ds", "support-logs-2"]);
  });

  it("adds no dataset to a dataset scan, which has no model to relate it to", () => {
    const s0: DeclarationState = { step: "data", decl: { ...start().decl, model: undefined } };
    expect(declarationReducer(s0, { type: "addLocal", index })).toBe(s0);
  });

  it("moves between steps and resets", () => {
    const s = declarationReducer(start(), { type: "step", step: "preview" });
    expect(s.step).toBe("preview");
    const fresh = start().decl;
    expect(declarationReducer(s, { type: "reset", decl: fresh, step: "base" })).toEqual({ step: "base", decl: fresh });
  });

  it("adds and removes the base models and hub datasets of a declaration with no scan behind it", () => {
    let s: DeclarationState = { step: "base", decl: createTemplate(index) };
    s = declarationReducer(s, { type: "addBase", ref: " org/base " });
    s = declarationReducer(s, { type: "addBase", ref: "org/base" });
    expect(s.decl.model!.baseModels).toEqual([{ ref: "org/base", revision: "" }]);
    s = declarationReducer(s, { type: "addHub", index, id: "org/ds" });
    s = declarationReducer(s, { type: "addHub", index, id: "org/ds" });
    expect(s.decl.datasets.map((d) => d.ref)).toEqual(["huggingface:org/ds"]);
    // The hub gives the address and the publisher; they are not asked.
    expect(s.decl.datasets[0]).not.toHaveProperty("downloadLocation");
    expect(s.decl.datasets[0]).toHaveProperty("originatedBy");
    s = declarationReducer(s, { type: "removeHub", index: 0 });
    s = declarationReducer(s, { type: "removeBase", index: 0 });
    expect(s.decl.datasets).toEqual([]);
    expect(s.decl.model!.baseModels).toEqual([]);
  });
});

describe("clearBases", () => {
  it("drops every base model for a model trained from scratch", () => {
    const s1 = declarationReducer(start(), { type: "clearBases" });
    expect(s1.decl.model!.baseModels).toEqual([]);
    // Nothing to clear: the same state.
    expect(declarationReducer(s1, { type: "clearBases" })).toBe(s1);
  });
});

describe("flushPendingIds", () => {
  const create = (): DeclarationState => ({ step: "base", decl: createTemplate(index) });

  it("adds a valid id typed and not added, as its button would", () => {
    const r = flushPendingIds(create(), [
      { value: "  Qwen/Qwen2.5-0.5B ", toAction: (ref) => ({ type: "addBase", ref }) },
      { value: "", toAction: (id) => ({ type: "addHub", index, id }) },
    ]);
    expect(r.blocked).toBe(-1);
    expect(r.actions).toEqual([{ type: "addBase", ref: "Qwen/Qwen2.5-0.5B" }]);
    expect(r.state.decl.model!.baseModels).toEqual([{ ref: "Qwen/Qwen2.5-0.5B", revision: "" }]);
  });

  it("stops at an id that is not one, and adds nothing", () => {
    const s0 = create();
    const r = flushPendingIds(s0, [
      { value: "org/ok", toAction: (ref) => ({ type: "addBase", ref }) },
      { value: "not an id", toAction: (id) => ({ type: "addHub", index, id }) },
    ]);
    expect(r.blocked).toBe(1);
    expect(r.actions).toEqual([]);
    expect(r.state).toBe(s0);
  });

  it("skips an id already there", () => {
    const r = flushPendingIds(create(), [{ value: "org/ds", toAction: () => null }]);
    expect(r.actions).toEqual([]);
    expect(r.blocked).toBe(-1);
  });
});
