// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";

import { licenseOperands } from "@/lib/licenseOperands";

/**
 * A package's licences as Labels: one per SPDX operand (an expression splits at
 * AND and OR; `X WITH Y` stays one), the first two and "+N" for the rest, or all
 * of them with `all`. Each Label stays on one line; the whole value is in the
 * tooltip.
 */
export function LicenseLabels({
  licenses,
  all,
}: {
  licenses: string[];
  /** Show every operand (the node detail), not two and a count. */
  all?: boolean;
}) {
  const operands = licenseOperands(licenses);
  if (operands.length === 0) return null;
  const shown = all ? operands : operands.slice(0, 2);
  return (
    <span className="bl-dep-labels" title={licenses.join(", ")}>
      {shown.map((l) => (
        <Label key={l} variant="secondary" className="bl-dep-label">
          {l}
        </Label>
      ))}
      {!all && operands.length > 2 && (
        <Label variant="secondary" className="bl-dep-label" title={operands.slice(2).join(", ")}>
          +{operands.length - 2}
        </Label>
      )}
    </span>
  );
}
