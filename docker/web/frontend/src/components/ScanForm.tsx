import { Loader2, Play } from "lucide-react";
import { useState, type Dispatch, type SetStateAction } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { ScanParams } from "@/lib/api";

interface Props {
  running: boolean;
  onRun: (params: ScanParams) => void;
}

export function ScanForm({ running, onRun }: Props) {
  const { t } = useTranslation();
  const [project, setProject] = useState("");
  const [version, setVersion] = useState("");
  const [target, setTarget] = useState("");
  const [notice, setNotice] = useState(true);
  const [security, setSecurity] = useState(true);
  const [deepLicense, setDeepLicense] = useState(false);
  const [byteStable, setByteStable] = useState(false);
  const [invalid, setInvalid] = useState(false);

  const submit = () => {
    if (!project.trim() || !version.trim()) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    onRun({
      project: project.trim(),
      version: version.trim(),
      target: target.trim() || undefined,
      notice,
      security,
      deepLicense,
      byteStable,
    });
  };

  const options: Array<{
    key: string;
    value: boolean;
    set: Dispatch<SetStateAction<boolean>>;
  }> = [
    { key: "notice", value: notice, set: setNotice },
    { key: "security", value: security, set: setSecurity },
    { key: "deepLicense", value: deepLicense, set: setDeepLicense },
    { key: "byteStable", value: byteStable, set: setByteStable },
  ];

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
            value={project}
            onChange={(e) => setProject(e.target.value)}
            placeholder={t("form.projectPlaceholder")}
            disabled={running}
            autoFocus
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="version">{t("form.version")}</Label>
          <Input
            id="version"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder={t("form.versionPlaceholder")}
            disabled={running}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="target">{t("form.target")}</Label>
          <Input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={t("form.targetPlaceholder")}
            disabled={running}
          />
          <p className="text-xs text-muted-foreground">{t("form.targetHint")}</p>
        </div>

        <div className="space-y-3 pt-1">
          <Label>{t("form.options")}</Label>
          <div className="space-y-3">
            {options.map((o) => (
              <label
                key={o.key}
                className="flex cursor-pointer items-start justify-between gap-4"
              >
                <span className="space-y-0.5">
                  <span className="block text-sm font-medium">
                    {t(`options.${o.key}`)}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {t(`options.${o.key}Hint`)}
                  </span>
                </span>
                <Switch
                  checked={o.value}
                  onCheckedChange={o.set}
                  disabled={running}
                  aria-label={t(`options.${o.key}`)}
                />
              </label>
            ))}
          </div>
        </div>

        {invalid && (
          <p className="text-sm text-destructive" role="alert">
            {t("validation.required")}
          </p>
        )}

        <Button className="w-full" onClick={submit} disabled={running}>
          {running ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {t("form.running")}
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              {t("form.run")}
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}
