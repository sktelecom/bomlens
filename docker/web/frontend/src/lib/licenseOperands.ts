// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The licences of one package as separate display operands. An SPDX expression
 * ("MIT AND (Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0)") splits
 * at AND and OR into one operand per licence; `X WITH Y` stays one operand, and
 * a value that is not an expression (prose, a hash) stays whole, so nothing is
 * lost. Repeats are dropped, order is kept.
 */
export function licenseOperands(licenses: string[]): string[] {
  const out: string[] = [];
  for (const raw of licenses) {
    const value = (raw ?? "").trim();
    if (!value) continue;
    // Only a string whose every operand is an id (or `id WITH exception`) is
    // split; prose that merely contains "or" is left whole.
    const split = value
      .replace(/[()]/g, " ")
      .split(/\s+(?:AND|OR)\s+/i)
      .map((p) => p.trim().replace(/\s+/g, " "))
      .filter(Boolean);
    const isExpression = split.length > 1 && split.every((p) => /^[A-Za-z0-9.+_:-]+(?: WITH [A-Za-z0-9.+_:-]+)?$/i.test(p));
    const parts = isExpression ? split : [value];
    for (const p of parts) if (!out.includes(p)) out.push(p);
  }
  return out;
}
