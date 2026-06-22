import { Loader2, Play, Upload } from "lucide-react";
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
import {
  stashGitCred,
  uploadFile,
  type Capabilities,
  type ScanParams,
  type SourceType,
  type UploadKind,
} from "@/lib/api";

import { InputTypeSelector } from "./InputTypeSelector";

interface Props {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
}

const UPLOAD_KIND: Partial<Record<SourceType, UploadKind>> = {
  "zip-upload": "zip",
  "sbom-upload": "sbom",
  "firmware-upload": "firmware",
};

const ACCEPT: Record<UploadKind, string> = {
  zip: ".zip,.tar.gz,.tgz,.tar.bz2,.tar.xz,.tar",
  sbom: ".json,.xml,.spdx,.cdx.json,.spdx.json",
  firmware: ".bin,.img,.squashfs,.sqsh,.ubi,.ubifs,.trx,.chk,.fw,.rom,.dlf",
};

// Free-text inputs: the single `target` field, with per-source i18n keys.
const TEXT_INPUT: Partial<
  Record<SourceType, { label: string; placeholder: string; hint: string }>
> = {
  "git-url": {
    label: "source.gitUrl",
    placeholder: "source.gitPlaceholder",
    hint: "source.gitHint",
  },
  "docker-image": {
    label: "source.dockerImage",
    placeholder: "source.dockerPlaceholder",
    hint: "source.dockerHint",
  },
  "rootfs-dir": {
    label: "source.rootfsDir",
    placeholder: "source.rootfsPlaceholder",
    hint: "source.rootfsHint",
  },
};

export function ScanForm({ running, capabilities, onRun }: Props) {
  const { t } = useTranslation();
  const [project, setProject] = useState("");
  const [version, setVersion] = useState("");
  const [source, setSource] = useState<SourceType>("current-dir");
  const [target, setTarget] = useState(""); // git URL or docker image
  const [gitToken, setGitToken] = useState(""); // optional private-repo token
  const [file, setFile] = useState<File | null>(null);
  const [notice, setNotice] = useState(true);
  const [security, setSecurity] = useState(true);
  const [deepLicense, setDeepLicense] = useState(false);
  const [identifyVendored, setIdentifyVendored] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  const uploadKind = UPLOAD_KIND[source];
  const textInput = TEXT_INPUT[source];
  const isText = textInput !== undefined;
  const isAnalyze = source === "sbom-upload";
  // Vendored-OSS identification only applies to a scanned source tree.
  const isSourceScan =
    source === "current-dir" || source === "git-url" || source === "zip-upload";
  const showVendored = Boolean(capabilities.scanoss) && isSourceScan;
  const busy = running || uploading;

  const submit = async () => {
    setUploadError(null);
    if (!project.trim() || !version.trim()) {
      setInvalid(true);
      return;
    }
    if (isText && !target.trim()) {
      setInvalid(true);
      return;
    }
    if (uploadKind && !file) {
      setInvalid(true);
      return;
    }
    setInvalid(false);

    let token: string | undefined;
    let cred: string | undefined;
    if (uploadKind && file) {
      try {
        setUploading(true);
        const r = await uploadFile(file, uploadKind);
        token = r.token;
      } catch (e) {
        setUploadError((e as Error).message);
        setUploading(false);
        return;
      }
      setUploading(false);
    }
    // Private git URL: stash the token (single-use) so it never hits the query string.
    if (source === "git-url" && gitToken.trim()) {
      try {
        setUploading(true);
        const r = await stashGitCred(gitToken.trim());
        cred = r.credId;
      } catch (e) {
        setUploadError((e as Error).message);
        setUploading(false);
        return;
      }
      setUploading(false);
    }

    onRun({
      project: project.trim(),
      version: version.trim(),
      source,
      target: isText ? target.trim() : undefined,
      token,
      cred,
      // ANALYZE forces notice+security on (needed for the risk report).
      notice: isAnalyze ? true : notice,
      security: isAnalyze ? true : security,
      deepLicense,
      identifyVendored: showVendored ? identifyVendored : false,
      // Byte-stable (reproducible) output is a CI concern; not exposed in the UI
      // so the default deliverable keeps a real timestamp + serialNumber.
      byteStable: false,
    });
  };

  const options: Array<{
    key: string;
    value: boolean;
    set: Dispatch<SetStateAction<boolean>>;
    forced?: boolean;
  }> = [
    { key: "notice", value: isAnalyze ? true : notice, set: setNotice, forced: isAnalyze },
    { key: "security", value: isAnalyze ? true : security, set: setSecurity, forced: isAnalyze },
    { key: "deepLicense", value: deepLicense, set: setDeepLicense },
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
            disabled={busy}
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
            disabled={busy}
          />
        </div>

        <div className="space-y-2">
          <Label>{t("source.label")}</Label>
          <InputTypeSelector
            value={source}
            onChange={(s) => {
              setSource(s);
              setFile(null);
              setTarget("");
              setGitToken("");
              setUploadError(null);
              setInvalid(false);
            }}
            disabled={busy}
            firmwareDisabled={!capabilities.firmware}
          />
        </div>

        {/* Source-specific control */}
        {source === "current-dir" && (
          <div className="rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
            {capabilities.hostDir && (
              <div className="mb-1">
                <span className="text-foreground">{t("source.currentDirPath")}: </span>
                <span className="break-all font-mono">{capabilities.hostDir}</span>
              </div>
            )}
            {t("source.currentDirHint")}
          </div>
        )}

        {textInput && (
          <div className="space-y-2">
            <Label htmlFor="target">{t(textInput.label)}</Label>
            <Input
              id="target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t(textInput.placeholder)}
              disabled={busy}
            />
            <p className="text-xs text-muted-foreground">{t(textInput.hint)}</p>
          </div>
        )}

        {source === "git-url" && (
          <div className="space-y-2">
            <Label htmlFor="gitToken">{t("source.gitToken")}</Label>
            <Input
              id="gitToken"
              type="password"
              autoComplete="off"
              value={gitToken}
              onChange={(e) => setGitToken(e.target.value)}
              placeholder={t("source.gitTokenPlaceholder")}
              disabled={busy}
            />
            <p className="text-xs text-muted-foreground">{t("source.gitTokenHint")}</p>
          </div>
        )}

        {uploadKind && (
          <div className="space-y-2">
            <Label htmlFor="file">
              {uploadKind === "zip"
                ? t("source.zipUpload")
                : uploadKind === "sbom"
                  ? t("source.sbomUpload")
                  : t("source.firmwareUpload")}
            </Label>
            <input
              id="file"
              type="file"
              accept={ACCEPT[uploadKind]}
              disabled={busy}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block w-full rounded-md border bg-background text-sm text-muted-foreground file:mr-3 file:cursor-pointer file:border-0 file:border-r file:bg-muted file:px-3 file:py-2 file:text-sm file:font-medium file:text-foreground hover:file:bg-accent"
            />
            {isAnalyze && (
              <p className="text-xs text-muted-foreground">{t("source.sbomAnalyzeHint")}</p>
            )}
            {source === "firmware-upload" && (
              <p className="text-xs text-muted-foreground">{t("source.firmwareHint")}</p>
            )}
          </div>
        )}

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
                  disabled={busy || o.forced}
                  aria-label={t(`options.${o.key}`)}
                />
              </label>
            ))}
          </div>
        </div>

        {/* Advanced: vendored-OSS identification. Hidden by default — only shown
            when the running image supports it (SBOM_SCANOSS) and the input is a
            source tree, since it sends file fingerprints to an external service. */}
        {showVendored && (
          <details className="pt-1">
            <summary className="cursor-pointer text-sm font-medium text-muted-foreground">
              {t("form.advanced")}
            </summary>
            <label className="mt-3 flex cursor-pointer items-start justify-between gap-4">
              <span className="space-y-0.5">
                <span className="block text-sm font-medium">
                  {t("options.identifyVendored")}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {t("options.identifyVendoredHint")}
                </span>
              </span>
              <Switch
                checked={identifyVendored}
                onCheckedChange={setIdentifyVendored}
                disabled={busy}
                aria-label={t("options.identifyVendored")}
              />
            </label>
          </details>
        )}

        {invalid && (
          <p className="text-sm text-destructive" role="alert">
            {uploadKind && !file ? t("validation.file") : t("validation.required")}
          </p>
        )}
        {uploadError && (
          <p className="text-sm text-destructive" role="alert">
            {t("source.uploadFailed", { msg: uploadError })}
          </p>
        )}

        <Button className="w-full" onClick={submit} disabled={busy}>
          {uploading ? (
            <>
              <Upload className="h-4 w-4 animate-pulse" />
              {t("source.uploading")}
            </>
          ) : running ? (
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
