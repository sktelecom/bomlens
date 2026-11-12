// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { packageCoordinateText, PACKAGE_SEPARATOR, type PackageCoordinateParts } from "./display";

/**
 * A package as "group / name": the group and separator muted, the name in the
 * default colour (bold with `strongName`). The tooltip carries the full text,
 * or `title` when given (a purl, for instance).
 */
export function PackageCoordinate({
  group,
  name,
  title,
  strongName,
  className,
}: PackageCoordinateParts & { title?: string; strongName?: boolean; className?: string }) {
  return (
    <span className={className} title={title ?? packageCoordinateText({ group, name })}>
      {group && (
        <span style={{ color: "var(--fgColor-muted)" }}>
          {group}
          {PACKAGE_SEPARATOR}
        </span>
      )}
      <span style={{ color: "var(--fgColor-default)", fontWeight: strongName ? 600 : undefined }}>{name}</span>
    </span>
  );
}
