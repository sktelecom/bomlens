// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Label } from "@primer/react";
import { Fragment } from "react";

import { licenseOperands, shownLicenseLabels } from "@/lib/licenseOperands";

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
  const shown = shownLicenseLabels(licenses, all);
  // The spaces keep the labels apart as words in the text; the box is flex, so
  // they take no room.
  return (
    <span className="bl-dep-labels" title={licenses.join(", ")}>
      {shown.map((l, i) => (
        <Fragment key={l}>
          {i > 0 && " "}
          <Label variant="secondary" className="bl-dep-label" title={!all && i === 2 ? operands.slice(2).join(", ") : undefined}>
            {l}
          </Label>
        </Fragment>
      ))}
    </span>
  );
}
