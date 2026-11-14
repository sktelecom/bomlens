// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { SortAscIcon, SortDescIcon } from "@primer/octicons-react";
import { Table } from "@primer/react/experimental";

export type SortDirection = "asc" | "desc";

/**
 * A sortable column header for Primer's Table: a button inside the header cell,
 * `aria-sort` on the cell and an arrow for the direction. An inactive column
 * shows a faint arrow so it reads as sortable.
 */
export function SortHeader({
  label,
  active,
  dir,
  onSort,
  align,
}: {
  label: string;
  active: boolean;
  dir: SortDirection;
  onSort: () => void;
  align?: "start" | "end";
}) {
  return (
    <Table.Header align={align} aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="bl-sortbtn" onClick={onSort}>
        {label}
        {active ? (
          dir === "asc" ? (
            <SortAscIcon size={14} />
          ) : (
            <SortDescIcon size={14} />
          )
        ) : (
          <span className="bl-sortbtn-hint" aria-hidden>
            <SortDescIcon size={14} />
          </span>
        )}
      </button>
    </Table.Header>
  );
}
