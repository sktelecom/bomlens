// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A sentence the scanner wrote in English, recognised and turned into an i18n
 * key with its parameters, so it can be rendered in the UI language. A
 * parameter is either a value copied from the sentence (a license id, a model
 * name: facts, not translated) or another recognised phrase; a list is
 * rendered comma-separated.
 */
export interface LocalizedText {
  key: string;
  params?: Record<string, LocalizedParam>;
}

export type LocalizedParam = string | LocalizedText | LocalizedParam[];

type T = (key: string, opts?: Record<string, unknown>) => string;

function renderParam(t: T, p: LocalizedParam): string {
  if (typeof p === "string") return p;
  if (Array.isArray(p)) return p.map((x) => renderParam(t, x)).join(", ");
  return renderLocalized(t, p);
}

/** Resolve a LocalizedText with `t`, nested parameters first. */
export function renderLocalized(t: T, text: LocalizedText): string {
  const params: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(text.params ?? {})) params[k] = renderParam(t, v);
  return t(text.key, params);
}
