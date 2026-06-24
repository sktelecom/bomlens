import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Capabilities, ScanParams } from "@/lib/api";
import { useScanForm } from "@/lib/useScanForm";

import { InputTypeSelector } from "./InputTypeSelector";
import {
  FormMessages,
  GenerationOptions,
  RunButton,
  SourceControls,
} from "./ScanFormFields";

interface Props {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
}

/** Classic single-column scan form (default UI). Logic lives in useScanForm. */
export function ScanForm({ running, capabilities, onRun }: Props) {
  const { t } = useTranslation();
  const state = useScanForm({ running, capabilities, onRun });

  return (
    <Card className="h-fit animate-fade-in">
      <CardHeader>
        <CardTitle>{t("form.title")}</CardTitle>
        <CardDescription>{t("form.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="space-y-2">
          <Label htmlFor="project">{t("form.project")}</Label>
          <Input
            id="project"
            value={state.project}
            onChange={(e) => state.setProject(e.target.value)}
            placeholder={t("form.projectPlaceholder")}
            disabled={state.busy}
            autoFocus
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="version">{t("form.version")}</Label>
          <Input
            id="version"
            value={state.version}
            onChange={(e) => state.setVersion(e.target.value)}
            placeholder={t("form.versionPlaceholder")}
            disabled={state.busy}
          />
        </div>

        <div className="space-y-2">
          <Label>{t("source.label")}</Label>
          <InputTypeSelector
            value={state.source}
            onChange={state.changeSource}
            disabled={state.busy}
            firmwareDisabled={!capabilities.firmware}
          />
        </div>

        <SourceControls state={state} />

        <div className="space-y-3 pt-1">
          <Label>{t("form.options")}</Label>
          <GenerationOptions state={state} />
        </div>

        <FormMessages state={state} />
        <RunButton state={state} running={running} />
      </CardContent>
    </Card>
  );
}
