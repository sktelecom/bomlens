import { useTranslation } from "react-i18next";

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SOURCE_TYPES, type SourceType } from "@/lib/api";

interface Props {
  value: SourceType;
  onChange: (v: SourceType) => void;
  disabled?: boolean;
  /** Firmware analysis needs the firmware image; disable the tab otherwise. */
  firmwareDisabled?: boolean;
}

const LABEL_KEY: Record<SourceType, string> = {
  "current-dir": "source.currentDir",
  "git-url": "source.gitUrl",
  "zip-upload": "source.zipUpload",
  "sbom-upload": "source.sbomUpload",
  "firmware-upload": "source.firmwareUpload",
  "docker-image": "source.dockerImage",
};

export function InputTypeSelector({
  value,
  onChange,
  disabled,
  firmwareDisabled,
}: Props) {
  const { t } = useTranslation();
  return (
    <Tabs value={value} onValueChange={(v) => onChange(v as SourceType)}>
      <TabsList className="grid h-auto w-full grid-cols-2 gap-1 sm:grid-cols-3">
        {SOURCE_TYPES.map((s) => {
          const fwLocked = s === "firmware-upload" && firmwareDisabled;
          return (
            <TabsTrigger
              key={s}
              value={s}
              disabled={disabled || fwLocked}
              title={fwLocked ? t("source.firmwareUnavailable") : undefined}
              className="px-2 py-1.5 text-xs"
            >
              {t(LABEL_KEY[s])}
            </TabsTrigger>
          );
        })}
      </TabsList>
    </Tabs>
  );
}
