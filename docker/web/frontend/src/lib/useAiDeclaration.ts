// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The state of the declaration flow: which step is open and the answers so
 * far. The reducer is pure so the edits the screens make are tested without a
 * browser; the hook only wraps it.
 */
import { useReducer } from "react";

import {
  emptyLocalDataset,
  hubDatasetEntry,
  isHubId,
  slugFor,
  type DataFlow,
  type Declaration,
  type ExternalModelEntry,
  type FieldIndex,
  type ServiceAnswer,
  type StepId,
  type Value,
} from "./aiDeclaration";

export interface DeclarationState {
  step: StepId;
  decl: Declaration;
}

/** Where an answer goes: the document, the model, one base model, one
 *  dataset, the service, or one of the service's external models or data flows. */
export type Target =
  | { kind: "document" }
  | { kind: "model" }
  | { kind: "base"; index: number }
  | { kind: "dataset"; index: number }
  | { kind: "service" }
  | { kind: "externalModel"; index: number }
  | { kind: "dataFlow"; index: number };

export type DeclarationAction =
  | { type: "step"; step: StepId }
  | { type: "set"; target: Target; field: string; value: Value }
  | { type: "addLocal"; index: FieldIndex }
  | { type: "removeLocal"; index: number }
  /** A declaration with no scan behind it names its own base models and hub
   *  datasets; a scan's are what the scan found and cannot be added to. */
  | { type: "addBase"; ref: string }
  | { type: "removeBase"; index: number }
  /** "Trained from scratch": no base model at all. */
  | { type: "clearBases" }
  | { type: "addHub"; index: FieldIndex; id: string }
  | { type: "removeHub"; index: number }
  /** "Does this model run in a service?"; null takes the answer back. */
  | { type: "serviceAnswer"; answer: ServiceAnswer | null }
  | { type: "addExternalModel"; name: string }
  | { type: "removeExternalModel"; index: number }
  | { type: "addDataFlow"; classification: string }
  | { type: "removeDataFlow"; index: number }
  | { type: "reset"; decl: Declaration; step: StepId };

/** The key an external model gets from its name, unique in the service. */
function externalKey(name: string, models: ExternalModelEntry[], self: number): string {
  const taken = models.filter((_, i) => i !== self).map((m) => m.key);
  return slugFor(name, taken, self + 1, "model");
}

export function declarationReducer(state: DeclarationState, action: DeclarationAction): DeclarationState {
  switch (action.type) {
    case "step":
      return { ...state, step: action.step };
    case "reset":
      return { step: action.step, decl: action.decl };
    case "set": {
      const decl: Declaration = { ...state.decl };
      const t = action.target;
      if (t.kind === "document") {
        decl.document = { ...decl.document, [action.field]: action.value };
      } else if (t.kind === "model") {
        if (!decl.model) return state;
        decl.model = { ...decl.model, [action.field]: action.value };
      } else if (t.kind === "base") {
        const bases = decl.model?.baseModels;
        if (!decl.model || !bases?.[t.index] || action.field !== "revision") return state;
        decl.model = {
          ...decl.model,
          baseModels: bases.map((b, i) => (i === t.index ? { ...b, revision: String(action.value ?? "") } : b)),
        };
      } else if (t.kind === "service") {
        if (!decl.service) return state;
        decl.service = { ...decl.service, [action.field]: action.value };
      } else if (t.kind === "externalModel") {
        const models = decl.service?.externalModels ?? [];
        const m = models[t.index];
        if (!decl.service || !m) return state;
        const next = { ...m, [action.field]: action.value } as ExternalModelEntry;
        // The key follows the name until the declaration is saved.
        if (action.field === "name") next.key = externalKey(String(action.value ?? ""), models, t.index);
        decl.service = { ...decl.service, externalModels: models.map((x, i) => (i === t.index ? next : x)) };
      } else if (t.kind === "dataFlow") {
        const flows = decl.service?.dataFlows ?? [];
        if (!decl.service || !flows[t.index]) return state;
        decl.service = {
          ...decl.service,
          dataFlows: flows.map((x, i) => (i === t.index ? ({ ...x, [action.field]: action.value } as DataFlow) : x)),
        };
      } else {
        const d = decl.datasets[t.index];
        if (!d) return state;
        const next = { ...d, [action.field]: action.value };
        // A dataset the hub does not hold is named by its slug; keep the slug
        // following the name until the declaration is saved.
        if (d.local !== undefined && action.field === "name") {
          const taken = decl.datasets.filter((x, i) => i !== t.index && x.local).map((x) => x.local as string);
          next.local = slugFor(String(action.value ?? ""), taken, t.index + 1);
        }
        decl.datasets = decl.datasets.map((x, i) => (i === t.index ? next : x));
      }
      return { ...state, decl };
    }
    case "addLocal":
      if (!state.decl.model) return state;
      return { ...state, decl: { ...state.decl, datasets: [...state.decl.datasets, emptyLocalDataset(action.index)] } };
    case "removeLocal": {
      const d = state.decl.datasets[action.index];
      // Only a dataset the publisher added can be taken away; the scanned ones
      // are what the scan found.
      if (!d || d.local === undefined) return state;
      return {
        ...state,
        decl: { ...state.decl, datasets: state.decl.datasets.filter((_, i) => i !== action.index) },
      };
    }
    case "addBase": {
      const ref = action.ref.trim();
      const bases = state.decl.model?.baseModels ?? [];
      if (!state.decl.model || !ref || bases.some((b) => b.ref.toLowerCase() === ref.toLowerCase())) return state;
      return {
        ...state,
        decl: { ...state.decl, model: { ...state.decl.model, baseModels: [...bases, { ref, revision: "" }] } },
      };
    }
    case "removeBase": {
      const bases = state.decl.model?.baseModels;
      if (!state.decl.model || !bases?.[action.index]) return state;
      return {
        ...state,
        decl: {
          ...state.decl,
          model: { ...state.decl.model, baseModels: bases.filter((_, i) => i !== action.index) },
        },
      };
    }
    case "clearBases":
      if (!state.decl.model?.baseModels?.length) return state;
      return { ...state, decl: { ...state.decl, model: { ...state.decl.model, baseModels: [] } } };
    case "addHub": {
      const id = action.id.trim();
      const ref = `huggingface:${id}`;
      if (!state.decl.model || !id || state.decl.datasets.some((d) => d.ref?.toLowerCase() === ref.toLowerCase()))
        return state;
      return {
        ...state,
        decl: { ...state.decl, datasets: [...state.decl.datasets, hubDatasetEntry(action.index, id)] },
      };
    }
    case "removeHub": {
      const d = state.decl.datasets[action.index];
      if (!d || d.ref === undefined) return state;
      return {
        ...state,
        decl: { ...state.decl, datasets: state.decl.datasets.filter((_, i) => i !== action.index) },
      };
    }
    case "serviceAnswer": {
      if (!state.decl.service) return state;
      const decl = { ...state.decl };
      if (action.answer) decl.serviceAnswer = action.answer;
      else delete decl.serviceAnswer;
      return { ...state, decl };
    }
    case "addExternalModel": {
      const name = action.name.trim();
      const svc = state.decl.service;
      const models = svc?.externalModels ?? [];
      if (!svc || !name || models.some((m) => m.name.trim().toLowerCase() === name.toLowerCase())) return state;
      const entry: ExternalModelEntry = {
        key: externalKey(name, [...models, { key: "", name }], models.length),
        name,
        suppliedBy: null,
        packageVersion: "",
        endpoint: "",
      };
      return { ...state, decl: { ...state.decl, service: { ...svc, externalModels: [...models, entry] } } };
    }
    case "removeExternalModel": {
      const svc = state.decl.service;
      if (!svc?.externalModels?.[action.index]) return state;
      return {
        ...state,
        decl: {
          ...state.decl,
          service: { ...svc, externalModels: svc.externalModels.filter((_, i) => i !== action.index) },
        },
      };
    }
    case "addDataFlow": {
      const svc = state.decl.service;
      if (!svc) return state;
      const flow: DataFlow = {
        flow: "",
        classification: action.classification.trim(),
        name: "",
        description: "",
        source: [],
        destination: [],
      };
      return { ...state, decl: { ...state.decl, service: { ...svc, dataFlows: [...(svc.dataFlows ?? []), flow] } } };
    }
    case "removeDataFlow": {
      const svc = state.decl.service;
      if (!svc?.dataFlows?.[action.index]) return state;
      return {
        ...state,
        decl: { ...state.decl, service: { ...svc, dataFlows: svc.dataFlows.filter((_, i) => i !== action.index) } },
      };
    }
  }
}

/** An id typed into an add-by-id box (a base model, a hub dataset, a hub
 *  source) and not yet added with its button or Enter. */
export interface PendingId {
  value: string;
  /** What adding it does; null when it is already there. */
  toAction: (id: string) => DeclarationAction | null;
  /** Whether the typed value can be added. A HuggingFace id when not given
   *  (a base model, a dataset, a source); any name for an external model. */
  valid?: (value: string) => boolean;
}

/**
 * Leaving a step with ids still typed in their boxes: a valid one is added as
 * if its button had been pressed, so it is not lost; an invalid one stops the
 * step from being left (`blocked` is its position), and nothing is added.
 */
export function flushPendingIds(
  state: DeclarationState,
  pending: PendingId[],
): { state: DeclarationState; actions: DeclarationAction[]; blocked: number } {
  const typed = pending.map((p) => ({ ...p, value: p.value.trim() }));
  const blocked = typed.findIndex((p) => p.value !== "" && !(p.valid ?? isHubId)(p.value));
  if (blocked >= 0) return { state, actions: [], blocked };
  const actions: DeclarationAction[] = [];
  let next = state;
  for (const p of typed) {
    if (!p.value) continue;
    const a = p.toAction(p.value);
    if (!a) continue;
    actions.push(a);
    next = declarationReducer(next, a);
  }
  return { state: next, actions, blocked: -1 };
}

export function useAiDeclaration(decl: Declaration, step: StepId) {
  return useReducer(declarationReducer, { decl, step });
}
