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
  shrink,
}: PackageCoordinateParts & {
  title?: string;
  strongName?: boolean;
  className?: string;
  /** One line: the group gives way to an ellipsis, the name stays whole. */
  shrink?: boolean;
}) {
  const full = title ?? packageCoordinateText({ group, name });
  if (shrink) {
    return (
      <span className={`bl-coord${className ? ` ${className}` : ""}`} title={full}>
        {group && <span className="bl-coord-group">{group}</span>}
        {group && <span className="bl-coord-sep">{PACKAGE_SEPARATOR}</span>}
        <span className="bl-coord-name" style={{ fontWeight: strongName ? 600 : undefined }}>
          {name}
        </span>
      </span>
    );
  }
  return (
    <span className={className} title={full}>
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
