import { Loader2, Play, Upload } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
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
  const { source, target, setTarget, gitToken, setGitToken, setFile, uploadKind, textInput, isAnalyze, busy, capabilities, errors } = state;

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

      {textInput && (
        <div className="space-y-2">
          <Label htmlFor="target">
            {t(textInput.label)}
            <RequiredMark />
          </Label>
          <Input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={t(textInput.placeholder)}
            disabled={busy}
            aria-required
            aria-invalid={errors.target ? true : undefined}
            aria-describedby={errors.target ? "target-error" : undefined}
          />
          <FieldError id="target-error" msgKey={errors.target} />
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
    scanossToken,
    setScanossToken,
    showVendored,
    showDeepLicense,
    showIncludeOsv,
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
        <p className="text-sm text-destructive" role="alert">
          {t("source.uploadFailed", { msg: uploadError })}
        </p>
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
