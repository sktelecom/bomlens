// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { ComponentSortKey, SortDir } from "@/lib/components";
import { cn } from "@/lib/utils";

export type Sort = { key: ComponentSortKey; dir: SortDir };

export function SortHeader({
  label,
  sortKey,
  sort,
  onSort,
  className,
}: {
  label: string;
  sortKey: ComponentSortKey;
  sort: Sort | null;
  onSort: (key: ComponentSortKey) => void;
  className?: string;
}) {
  const active = sort?.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    // whitespace-nowrap: CJK text breaks between any two characters, so a
    // two-character Korean header in a narrow column split down the middle.
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
