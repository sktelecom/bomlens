// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { SortDir, VulnSortKey } from "@/lib/vulns";
import { cn } from "@/lib/utils";

export type Sort = { key: VulnSortKey; dir: SortDir };

/** Sortable column header for the Severity / CVSS columns. */
export function SortableTh({
  label,
  sortKey,
  sort,
  onSort,
  className,
}: {
  label: string;
  sortKey: VulnSortKey;
  sort: Sort;
  onSort: (key: VulnSortKey) => void;
  className?: string;
}) {
  const active = sort.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    // Same reason as the components table: a Korean header splits between any
    // two characters, so a narrow column stacked it vertically.
    <th
      className={cn("whitespace-nowrap px-3 py-2 font-medium", className)}
      aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        <Icon
          className={cn("h-3 w-3", active ? "text-foreground" : "text-muted-foreground/60")}
          aria-hidden
        />
      </button>
    </th>
  );
}
