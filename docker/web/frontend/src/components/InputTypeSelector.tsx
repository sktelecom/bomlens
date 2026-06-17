import { useTranslation } from "react-i18next";

import { SOURCE_TYPES, type SourceType } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  value: SourceType;
  onChange: (v: SourceType) => void;
  disabled?: boolean;
  /** Firmware analysis needs the firmware image; disable the tab otherwise. */
  firmwareDisabled?: boolean;
}

const LABEL_KEY: Record<SourceType, string> = {
  "current-dir": "source.currentDir",
  "rootfs-dir": "source.rootfsDir",
  "git-url": "source.gitUrl",
  "zip-upload": "source.zipUpload",
  "sbom-upload": "source.sbomUpload",
  "firmware-upload": "source.firmwareUpload",
  "docker-image": "source.dockerImage",
};

// A segmented selector. Previously this used the Tabs primitive, but Tabs without
// TabsContent panels emits an aria-controls pointing at a tabpanel that is never
// rendered, which fails axe aria-valid-attr-value (V13-3/F3). These are mutually
// exclusive options with no associated panel, so a labelled group of aria-pressed
// toggle buttons is the accessible primitive.
export function InputTypeSelector({
  value,
  onChange,
  disabled,
  firmwareDisabled,
}: Props) {
  const { t } = useTranslation();
  return (
    <div
      role="group"
      aria-label={t("source.label")}
      className="grid w-full grid-cols-2 gap-1 rounded-lg bg-muted p-1 sm:grid-cols-3"
    >
      {SOURCE_TYPES.map((s) => {
        const fwLocked = s === "firmware-upload" && firmwareDisabled;
        const active = value === s;
        return (
          <button
            key={s}
            type="button"
            aria-pressed={active}
            disabled={disabled || fwLocked}
            title={fwLocked ? t("source.firmwareUnavailable") : undefined}
            onClick={() => onChange(s)}
            className={cn(
              "inline-flex items-center justify-center whitespace-nowrap rounded-md px-2 py-1.5 text-xs font-medium",
              "ring-offset-background transition-all duration-fast ease-out-soft",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
              "disabled:pointer-events-none disabled:opacity-50",
              active
                ? "bg-card text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {t(LABEL_KEY[s])}
          </button>
        );
      })}
    </div>
  );
}
