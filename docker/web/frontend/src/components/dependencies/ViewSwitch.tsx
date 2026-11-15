// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ListUnorderedIcon, WorkflowIcon } from "@primer/octicons-react";
import { SegmentedControl } from "@primer/react";
import { useTranslation } from "react-i18next";

import type { DependencyView } from "@/lib/graphView";

/** Graph or Tree. The chosen segment is `aria-pressed`. */
export function ViewSwitch({ view, onPick }: { view: DependencyView; onPick: (v: DependencyView) => void }) {
  const { t } = useTranslation();
  return (
    <SegmentedControl aria-label={t("deps.viewLabel")} onChange={(i) => onPick(i === 0 ? "graph" : "tree")}>
      <SegmentedControl.Button data-testid="deps-view-graph" leadingIcon={WorkflowIcon} selected={view === "graph"}>
        {t("deps.viewGraph")}
      </SegmentedControl.Button>
      <SegmentedControl.Button data-testid="deps-view-tree" leadingIcon={ListUnorderedIcon} selected={view === "tree"}>
        {t("deps.viewTree")}
      </SegmentedControl.Button>
    </SegmentedControl>
  );
}
