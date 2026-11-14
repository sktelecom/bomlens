// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { XIcon } from "@primer/octicons-react";
import { ActionList, ActionMenu, Button } from "@primer/react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { useFormatNumber } from "@/lib/format";

export interface FilterOption {
  value: string;
  /** Text shown on the menu button when this option is chosen. */
  text: string;
  count?: number;
}

/**
 * A single-choice filter menu. The button names the filter and shows the
 * current choice ("Type: All types"); choosing the chosen option again clears it.
 */
export function FilterMenu({
  name,
  allLabel,
  options,
  value,
  onChange,
}: {
  name: string;
  allLabel: string;
  options: FilterOption[];
  value: string;
  onChange: (value: string) => void;
}) {
  const fmt = useFormatNumber();
  const current = options.find((o) => o.value === value);
  return (
    <ActionMenu>
      <ActionMenu.Button>
        <span className="bl-muted">{name}:</span> {current ? current.text : allLabel}
      </ActionMenu.Button>
      <ActionMenu.Overlay width="auto">
        <ActionList selectionVariant="single" aria-label={name}>
          <ActionList.Item selected={!value} onSelect={() => onChange("")}>
            {allLabel}
          </ActionList.Item>
          {options.map((o) => (
            <ActionList.Item key={o.value} selected={o.value === value} onSelect={() => onChange(o.value === value ? "" : o.value)}>
              {o.text}
              {o.count !== undefined && <ActionList.TrailingVisual>{fmt(o.count)}</ActionList.TrailingVisual>}
            </ActionList.Item>
          ))}
        </ActionList>
      </ActionMenu.Overlay>
    </ActionMenu>
  );
}

/**
 * The row under a filter bar: each active filter as a button that removes it,
 * "Clear filters", and a polite live count ("3 of 10") for screen readers.
 */
export function ActiveFilters({
  chips,
  onClear,
  summary,
}: {
  chips: { key: string; label: string; onRemove: () => void }[];
  onClear?: () => void;
  summary?: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className="bl-chips" role="group" aria-label={t("filters.active")} data-empty={chips.length === 0 && !summary ? "" : undefined}>
      {chips.map((c) => (
        <Button key={c.key} size="small" trailingVisual={XIcon} onClick={c.onRemove} aria-label={t("filters.remove", { label: c.label })}>
          {c.label}
        </Button>
      ))}
      {chips.length > 0 && onClear && (
        <Button size="small" variant="invisible" onClick={onClear}>
          {t("result.clearFilters")}
        </Button>
      )}
      <span className="bl-chips-count bl-muted bl-num" aria-live="polite">
        {summary}
      </span>
    </div>
  );
}
