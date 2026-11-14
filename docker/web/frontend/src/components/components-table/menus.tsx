// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { GearIcon } from "@primer/octicons-react";
import { ActionList, ActionMenu } from "@primer/react";
import { useTranslation } from "react-i18next";

import type { Density } from "@/lib/tableDensity";

export interface CheckItem {
  id: string;
  label: string;
  checked: boolean;
  onToggle: () => void;
}

/** Primer closes a menu after a choice unless the handler cancels the event. A set of independent on and off
 *  choices stays open, so several can be changed in one visit (Escape or a click outside closes it). */
const keepOpen = (toggle: () => void) => (event: { preventDefault: () => void }) => {
  event.preventDefault();
  toggle();
};

/**
 * A multi-choice menu (the Filters menu). The number of checked items rides on
 * the button, so a closed menu still says that something is narrowed.
 */
export function CheckMenu({ name, items }: { name: string; items: CheckItem[] }) {
  const on = items.filter((i) => i.checked).length;
  return (
    <ActionMenu>
      <ActionMenu.Button count={on > 0 ? on : undefined}>{name}</ActionMenu.Button>
      <ActionMenu.Overlay width="auto">
        <ActionList selectionVariant="multiple" aria-label={name}>
          {items.map((i) => (
            <ActionList.Item key={i.id} selected={i.checked} onSelect={keepOpen(i.onToggle)}>
              {i.label}
            </ActionList.Item>
          ))}
        </ActionList>
      </ActionMenu.Overlay>
    </ActionMenu>
  );
}

/** The View menu: row height (one preference for every table) and the columns. */
export function ViewMenu({
  density,
  onDensity,
  columns,
}: {
  density: Density;
  onDensity: (next: Density) => void;
  columns: CheckItem[];
}) {
  const { t } = useTranslation();
  return (
    <ActionMenu>
      <ActionMenu.Button leadingVisual={GearIcon}>{t("result.componentsView")}</ActionMenu.Button>
      <ActionMenu.Overlay width="auto" align="end">
        <ActionList>
          <ActionList.Group selectionVariant="single">
            <ActionList.GroupHeading>{t("result.density")}</ActionList.GroupHeading>
            <ActionList.Item selected={density === "compact"} onSelect={() => onDensity("compact")}>
              {t("result.densityCompact")}
            </ActionList.Item>
            <ActionList.Item selected={density === "comfortable"} onSelect={() => onDensity("comfortable")}>
              {t("result.densityComfortable")}
            </ActionList.Item>
          </ActionList.Group>
          {columns.length > 0 && (
            <>
              <ActionList.Divider />
              <ActionList.Group selectionVariant="multiple">
                <ActionList.GroupHeading>{t("result.columns")}</ActionList.GroupHeading>
                {columns.map((c) => (
                  <ActionList.Item key={c.id} selected={c.checked} onSelect={keepOpen(c.onToggle)}>
                    {c.label}
                  </ActionList.Item>
                ))}
              </ActionList.Group>
            </>
          )}
        </ActionList>
      </ActionMenu.Overlay>
    </ActionMenu>
  );
}
