import { Loader2, Play, Upload } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { canManageScanFolders, desktopBridge } from "@/lib/desktop";
import { ACCEPT, type ScanFormState } from "@/lib/useScanForm";

/**
 * Shared scan-form pieces rendered identically by the classic ScanForm and the
 * new two-pane NewScan, so there is one markup source for the source controls,
 * generation options, validation messages and the run button.
 */

/** Red asterisk marking a required field; hidden from AT — the input itself
 *  carries `aria-required`, so the mark is purely visual. */
export function RequiredMark() {
  return (
    <span className="text-destructive" aria-hidden>
      {" "}
      *
    </span>
  );
}

/** Per-field inline validation message, announced as an alert. Renders nothing
 *  while the field is valid. */
export function FieldError({ id, msgKey }: { id: string; msgKey?: string }) {
  const { t } = useTranslation();
  if (!msgKey) return null;
  return (
    <p id={id} className="text-xs text-destructive" role="alert">
      {t(msgKey)}
    </p>
  );
}

/** Source-specific control: current-folder hint / free-text target / git token / upload. */
export function SourceControls({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const { source, target, setTarget, scanRoot, setScanRoot, scanRoots, gitToken, setGitToken, setFile, uploadKind, textInput, isAnalyze, busy, capabilities, errors } = state;

  // Extra --mount scan targets make the rootfs-dir path a subpath inside the
  // chosen base — and optional when a mounted base is selected (empty = scan
  // the whole mount). In the desktop app the list is editable in place: the
  // shell picks a folder, remounts and restarts the UI container (the page
  // reloads on its own, so no state cleanup is needed after an ok response).
  const bridge = desktopBridge();
  const desktopFolders = canManageScanFolders(bridge);
  const showScanRoots =
    source === "rootfs-dir" && (scanRoots.length > 0 || desktopFolders);
  const targetOptional =
    source === "rootfs-dir" && scanRoots.length > 0 && scanRoot !== "";
  const [mountBusy, setMountBusy] = useState(false);

  const addScanFolder = async () => {
    if (!bridge?.chooseScanFolder) return;
    setMountBusy(true);
    const res = await bridge.chooseScanFolder().catch(() => ({ ok: false }));
    // ok면 앱이 컨테이너를 재시작하며 이 페이지를 다시 로드한다.
    if (!res.ok) setMountBusy(false);
  };
  const removeScanFolder = async () => {
    const host = scanRoots.find((r) => r.path === scanRoot)?.hostPath;
    if (!bridge?.removeScanFolder || !host) return;
    setMountBusy(true);
    const res = await bridge.removeScanFolder(host).catch(() => ({ ok: false }));
    if (!res.ok) setMountBusy(false);
  };

  return (
    <>
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

      {showScanRoots && (
        <div className="space-y-2">
          {scanRoots.length > 0 && <Label htmlFor="scanRoot">{t("source.scanRoot")}</Label>}
          <div className="flex items-center gap-2">
            {scanRoots.length > 0 && (
              <Select
                id="scanRoot"
                className="flex-1"
                value={scanRoot}
                onChange={(e) => setScanRoot(e.target.value)}
                disabled={busy || mountBusy}
              >
                <option value="">
                  {capabilities.hostDir
                    ? t("source.scanRootCurrent", { path: capabilities.hostDir })
                    : t("source.scanRootCurrentNoPath")}
                </option>
                {scanRoots.map((r) => (
                  <option key={r.path} value={r.path}>
                    {r.hostPath || r.path}
                  </option>
                ))}
              </Select>
            )}
            {desktopFolders && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={busy || mountBusy}
                onClick={addScanFolder}
              >
                {mountBusy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
                {t("source.addScanFolder")}
              </Button>
            )}
          </div>
          {desktopFolders && scanRoot !== "" && (
            <button
              type="button"
              className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground disabled:opacity-50"
              disabled={busy || mountBusy}
              onClick={removeScanFolder}
            >
              {t("source.removeScanFolder")}
            </button>
          )}
          {desktopFolders && (
            <p className="text-xs text-muted-foreground">{t("source.scanFolderDesktopHint")}</p>
          )}
        </div>
      )}

      {textInput && (
        <div className="space-y-2">
          <Label htmlFor="target">
            {targetOptional ? t("source.rootfsSubpath") : t(textInput.label)}
            {!targetOptional && <RequiredMark />}
          </Label>
          <Input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={t(textInput.placeholder)}
            disabled={busy}
            aria-required={!targetOptional || undefined}
            aria-invalid={errors.target ? true : undefined}
            aria-describedby={errors.target ? "target-error" : undefined}
          />
          <FieldError id="target-error" msgKey={errors.target} />
          <p className="text-xs text-muted-foreground">
            {targetOptional ? t("source.rootfsSubpathHint") : t(textInput.hint)}
          </p>
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
            <RequiredMark />
          </Label>
          <input
            id="file"
            type="file"
            accept={ACCEPT[uploadKind]}
            disabled={busy}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            aria-required
            aria-invalid={errors.file ? true : undefined}
            aria-describedby={errors.file ? "file-error" : undefined}
            className="block w-full rounded-md border bg-background text-sm text-muted-foreground file:mr-3 file:cursor-pointer file:border-0 file:border-r file:bg-muted file:px-3 file:py-2 file:text-sm file:font-medium file:text-foreground hover:file:bg-accent"
          />
          <FieldError id="file-error" msgKey={errors.file} />
          {isAnalyze && (
            <p className="text-xs text-muted-foreground">{t("source.sbomAnalyzeHint")}</p>
          )}
          {source === "firmware-upload" && (
            <p className="text-xs text-muted-foreground">{t("source.firmwareHint")}</p>
          )}
        </div>
      )}

      <SiblingPullNotice state={state} />
      <HfAuthNotice state={state} />
    </>
  );
}

/** First-run notice: when firmware/AI runs via a sibling container (the desktop
 *  base UI image), the dedicated image is pulled on the first scan — a large,
 *  one-time download. Shown only when the selected source needs it. */
function SiblingPullNotice({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const { source, capabilities } = state;
  const needsPull =
    (source === "firmware-upload" && capabilities.firmwareSibling) ||
    (source === "ai-model" && capabilities.aibomSibling);
  if (!needsPull) return null;
  return (
    <div className="rounded-md border border-brand/30 bg-brand/5 px-3 py-2 text-xs text-muted-foreground">
      {t("source.siblingPullNotice")}
    </div>
  );
}

/** Whether a HuggingFace credential reached this container, which decides
 *  whether private and gated model repos resolve. There is no token field here
 *  on purpose: the server keeps no credentials, so the token comes from the
 *  environment that launched the UI. Shown only for the AI-model source. */
function HfAuthNotice({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const { source, capabilities } = state;
  if (source !== "ai-model") return null;
  return (
    <div className="rounded-md border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
      {t(capabilities.hfAuth ? "source.hfAuthOn" : "source.hfAuthOff")}
    </div>
  );
}

/** One label + hint + switch row, shared by the output and scan-option groups. */
function ToggleRow({
  labelKey,
  checked,
  onChange,
  disabled,
}: {
  labelKey: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4">
      <span className="space-y-0.5">
        <span className="block text-sm font-medium">{t(`options.${labelKey}`)}</span>
        <span className="block text-xs text-muted-foreground">{t(`options.${labelKey}Hint`)}</span>
      </span>
      <Switch
        checked={checked}
        onCheckedChange={onChange}
        disabled={disabled}
        aria-label={t(`options.${labelKey}`)}
      />
    </label>
  );
}

/** Outputs: what the scan generates (notice / security report). */
export function GenerationOptions({ state }: { state: ScanFormState }) {
  const { options, busy, isAiModel } = state;
  const { t } = useTranslation();
  return (
    <div className="space-y-3">
      {options.map((o) => (
        <ToggleRow
          key={o.key}
          labelKey={o.key}
          checked={o.value}
          onChange={o.set}
          disabled={busy || o.forced}
        />
      ))}
      {isAiModel && (
        <p className="text-xs text-muted-foreground">{t("options.aiNoticeHint")}</p>
      )}
    </div>
  );
}

/** Scan method: how the source is analyzed (deep license / vendored identification). */
export function ScanOptions({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const {
    deepLicense,
    setDeepLicense,
    identifyVendored,
    setIdentifyVendored,
    includeOsv,
    setIncludeOsv,
    byteStable,
    setByteStable,
    scanossToken,
    setScanossToken,
    showVendored,
    showDeepLicense,
    showIncludeOsv,
    showByteStable,
    busy,
  } = state;
  return (
    <div className="space-y-3">
      {/* Set the group's altitude once: these are advanced analyses for source
          without a package manager, so PM-built projects can leave them off. */}
      {(showVendored || showDeepLicense) && (
        <p className="text-xs text-muted-foreground">{t("options.scanMethodHint")}</p>
      )}
      {showVendored && (
        <div className="space-y-2">
          <ToggleRow
            labelKey="identifyVendored"
            checked={identifyVendored}
            onChange={setIdentifyVendored}
            disabled={busy}
          />
          {identifyVendored && (
            <div className="space-y-1">
              <Input
                id="scanossToken"
                type="password"
                autoComplete="off"
                value={scanossToken}
                onChange={(e) => setScanossToken(e.target.value)}
                placeholder={t("options.scanossTokenPlaceholder")}
                disabled={busy}
              />
              <p className="text-xs text-muted-foreground">
                {t("options.scanossTokenHint")}
              </p>
            </div>
          )}
        </div>
      )}
      {showDeepLicense && (
        <ToggleRow
          labelKey="deepLicense"
          checked={deepLicense}
          onChange={setDeepLicense}
          disabled={busy}
        />
      )}
      {showIncludeOsv && (
        <ToggleRow
          labelKey="includeOsv"
          checked={includeOsv}
          onChange={setIncludeOsv}
          disabled={busy}
        />
      )}
      {showByteStable && (
        <ToggleRow
          labelKey="byteStable"
          checked={byteStable}
          onChange={setByteStable}
          disabled={busy}
        />
      )}
    </div>
  );
}

/** Optional upload of the generated SBOM to a Dependency-Track or TRUSCA server.
 *  The server URL and token are used for this run only and never persisted. */
export function UploadOptions({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const {
    uploadEnabled,
    setUploadEnabled,
    uploadTarget,
    setUploadTarget,
    uploadUrl,
    setUploadUrl,
    uploadToken,
    setUploadToken,
    truscaProjectId,
    setTruscaProjectId,
    showUpload,
    errors,
    busy,
  } = state;
  if (!showUpload) return null;
  return (
    <div className="space-y-3">
      <ToggleRow
        labelKey="upload"
        checked={uploadEnabled}
        onChange={setUploadEnabled}
        disabled={busy}
      />
      {uploadEnabled && (
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="uploadTarget">{t("upload.target")}</Label>
            <Select
              id="uploadTarget"
              value={uploadTarget}
              onChange={(e) =>
                setUploadTarget(e.target.value as "dependency-track" | "trusca")
              }
              disabled={busy}
            >
              <option value="dependency-track">{t("upload.targetDT")}</option>
              <option value="trusca">{t("upload.targetTrusca")}</option>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="uploadUrl">{t("upload.url")}</Label>
            <Input
              id="uploadUrl"
              value={uploadUrl}
              onChange={(e) => setUploadUrl(e.target.value)}
              placeholder={t("upload.urlPlaceholder")}
              disabled={busy}
              aria-invalid={errors.uploadUrl ? true : undefined}
              aria-describedby={errors.uploadUrl ? "uploadUrl-error" : undefined}
            />
            <FieldError id="uploadUrl-error" msgKey={errors.uploadUrl} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="uploadToken">{t("upload.token")}</Label>
            <Input
              id="uploadToken"
              type="password"
              autoComplete="off"
              value={uploadToken}
              onChange={(e) => setUploadToken(e.target.value)}
              placeholder={t("upload.tokenPlaceholder")}
              disabled={busy}
              aria-invalid={errors.uploadToken ? true : undefined}
              aria-describedby={errors.uploadToken ? "uploadToken-error" : undefined}
            />
            <FieldError id="uploadToken-error" msgKey={errors.uploadToken} />
            <p className="text-xs text-muted-foreground">{t("upload.tokenHint")}</p>
          </div>
          {uploadTarget === "trusca" && (
            <div className="space-y-1">
              <Label htmlFor="truscaProjectId">{t("upload.projectId")}</Label>
              <Input
                id="truscaProjectId"
                value={truscaProjectId}
                onChange={(e) => setTruscaProjectId(e.target.value)}
                placeholder={t("upload.projectIdPlaceholder")}
                disabled={busy}
                aria-invalid={errors.truscaProjectId ? true : undefined}
                aria-describedby={
                  errors.truscaProjectId ? "truscaProjectId-error" : undefined
                }
              />
              <FieldError
                id="truscaProjectId-error"
                msgKey={errors.truscaProjectId}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Validation / upload error messages (the summary near the Run button; the
 *  per-field messages render inline next to their inputs). */
export function FormMessages({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const { errors, uploadError } = state;
  const hasErrors = Object.keys(errors).length > 0;
  return (
    <>
      {hasErrors && (
        <p className="text-sm text-destructive" role="alert">
          {errors.file && !errors.project && !errors.version && !errors.target
            ? t("validation.file")
            : t("validation.required")}
        </p>
      )}
      {uploadError && (
        <div role="alert">
          <p className="text-sm text-destructive">{t(uploadError.key)}</p>
          {uploadError.detail && (
            <p className="text-xs text-muted-foreground">{uploadError.detail}</p>
          )}
        </div>
      )}
    </>
  );
}

/** The run / uploading / scanning button. */
export function RunButton({ state, running }: { state: ScanFormState; running: boolean }) {
  const { t } = useTranslation();
  const { submit, busy, uploading } = state;
  return (
    <Button className="w-full" data-testid="run-scan" onClick={submit} disabled={busy}>
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
  );
}
