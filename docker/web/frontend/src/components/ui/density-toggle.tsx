// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { Rows2, Rows4 } from "lucide-react";

import { FOCUS_RING, SELECTED_SOLID } from "@/components/ui/selectable";
import { SEGMENT, SEGMENT_GROUP } from "@/components/ui/toolbar";
import { type Density, readDensity, writeDensity } from "@/lib/tableDensity";
import { cn } from "@/lib/utils";

/** The reader's row density, read once from browser-local storage and written
 *  back on change. One preference shared by every table. */
export function useDensity(): [Density, (next: Density) => void] {
  const [density, setDensity] = useState<Density>(() => readDensity());
  const choose = useCallback((next: Density) => {
    setDensity(next);
    writeDensity(next);
  }, []);
  return [density, choose];
}

const OPTIONS: { value: Density; labelKey: string; Icon: typeof Rows2 }[] = [
  { value: "compact", labelKey: "result.densityCompact", Icon: Rows4 },
  { value: "comfortable", labelKey: "result.densityComfortable", Icon: Rows2 },
];

/** Two-step row density switch, icons with a text name for assistive tech. Selection is the solid fill; the focus ring is
 *  separate, as on every other pickable control. */
export function DensityToggle({
  density,
  onChange,
}: {
  density: Density;
  onChange: (next: Density) => void;
}) {
  const { t } = useTranslation();
  return (
    <div
      role="group"
      aria-label={t("result.density")}
      data-testid="density-toggle"
      className={SEGMENT_GROUP}
    >
      {OPTIONS.map(({ value, labelKey, Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={density === value}
          title={t(labelKey)}
          onClick={() => onChange(value)}
          className={cn(
            SEGMENT,
            "transition-colors duration-fast ease-out-soft",
            FOCUS_RING,
            density === value
              ? SELECTED_SOLID
              : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
          )}
        >
          <Icon className="h-3.5 w-3.5" aria-hidden />
          {/* Icon-only: the toolbar it joins is already full at 1440px. The name
              is still read out, and the tooltip carries it for the pointer. */}
          <span className="sr-only">{t(labelKey)}</span>
        </button>
      ))}
    </div>
  );
}
