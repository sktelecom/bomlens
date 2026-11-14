// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { InfoIcon, PaperAirplaneIcon, PlayIcon, UploadIcon } from "@primer/octicons-react";
import {
  Button,
  FormControl,
  Label,
  Link,
  Select,
  TextInput,
  Textarea,
  VisuallyHidden,
} from "@primer/react";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Switch } from "@/components/primer";
import { FileDropzone } from "@/components/FileDropzone";
import { SiblingImagePanel } from "@/components/SiblingImagePanel";
import {
  CDX_SPEC_VERSIONS,
  CONFORMANCE_PROFILES,
  USAGE_CONTEXTS,
  type CdxSpecVersion,
  type ConformanceProfile,
  type UploadKind,
  type UsageContext,
} from "@/lib/api";
import { demoInstallUrl, demoRunAction, IS_STATIC_DEMO } from "@/lib/demo";
import { canManageScanFolders, desktopBridge } from "@/lib/desktop";
import { USAGE_LABEL_KEY } from "@/lib/models";
import { ACCEPT, type ScanFormState } from "@/lib/useScanForm";

/**
 * Scan-form pieces for the New scan screen (NewScan.tsx): the source controls,
 * the option groups, the output switches of the action bar, the validation line
 * and the run button. State and validation live in useScanForm.
 */

/** File-picker label per upload kind. A record rather than a chain of ternaries
 *  so a new kind is a type error here until it is named. */
const UPLOAD_LABEL: Record<UploadKind, string> = {
  zip: "source.zipUpload",
  sbom: "source.sbomUpload",
  package: "source.packageUpload",
  firmware: "source.firmwareUpload",
  model: "source.modelUpload",
  declaration: "source.aiDeclare",
};

/** i18n label key per conformance-profile value. */
const CONFORMANCE_PROFILE_LABEL_KEY: Record<ConformanceProfile, string> = {
  default: "options.conformanceProfileDefault",
  "skt-submission": "options.conformanceProfileSktSubmission",
  "bsi-tr-03183-2": "options.conformanceProfileBsi",
};

/** The `aria-describedby` of a field: its error message first, then its hint.
 *  Primer's FormControl names the validation message `<id>-validationMessage`. */
function describedBy(id: string, hasError: boolean, hasHint = true): string | undefined {
  const ids = [hasError ? `${id}-validationMessage` : null, hasHint ? `${id}-hint` : null];
  return ids.filter(Boolean).join(" ") || undefined;
}

/**
 * A hint. The whole text is always in the page and is what the field is
 * described by. When it does not fit in two lines it is cut there and a text
 * button opens it, set at the end of the second line; the button is not part of
 * the description.
 */
export function Hint({ text, id, about }: { text: string; id?: string; about?: string }) {
  const { t } = useTranslation();
  const own = useId();
  const textId = id ?? `${own}-t`;
  const ref = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [overflows, setOverflows] = useState(false);

  // Measured while the text is cut: only a hint that really loses lines gets a
  // button. Re-measured when the width changes and when the fonts arrive.
  useLayoutEffect(() => {
    const el = ref.current;
    if (open || !el) return;
    const measure = () => setOverflows(el.scrollHeight > el.clientHeight + 1);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    void document.fonts?.ready.then(measure);
    return () => observer.disconnect();
  }, [open, text]);

  const showButton = overflows || open;
  const label = open ? t("newscan.less") : t("newscan.more");
  return (
    <span className="bl-hint" data-open={open ? "" : undefined}>
      <span
        ref={ref}
        id={textId}
        className="bl-hint-text"
        data-clamped={!open ? "" : undefined}
      >
        {text}
      </span>
      {showButton && (
        <Link
          as="button"
          type="button"
          className="bl-hint-button"
          aria-expanded={open}
          aria-controls={textId}
          onClick={() => setOpen(!open)}
        >
          {label}
          {/* Which hint it opens, for a reader who meets the button out of
              context. The visible word comes first (label in name). */}
          {about && <VisuallyHidden>{`: ${about}`}</VisuallyHidden>}
        </Link>
      )}
    </span>
  );
}

/** Marks an option that sends data off this machine. The same mark sits on
 *  every such option so a reader can scan the panel for it. */
export function ExternalMark() {
  const { t } = useTranslation();
  return (
    <Label variant="secondary" data-testid="external-mark" className="bl-external">
      <PaperAirplaneIcon size={12} />
      {t("newscan.externalMark")}
    </Label>
  );
}

/** One option: the name and what it does on the left, the switch on the right.
 *  The name and the description are a label for the switch, so pressing them
 *  flips it; the "More" button inside is not a toggle. */
function Toggle({
  labelKey,
  checked,
  onChange,
  disabled,
  external,
  wide,
}: {
  labelKey: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  external?: boolean;
  wide?: boolean;
}) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <div className={`bl-toggle${wide ? " bl-span2" : ""}`} data-testid={`option-${labelKey}`}>
      <label htmlFor={`${id}-s`} className="bl-toggle-text">
        <span id={`${id}-l`} className="bl-strong bl-toggle-label">
          {t(`options.${labelKey}`)}
          {external && <ExternalMark />}
        </span>
        <Hint id={`${id}-h`} text={t(`options.${labelKey}Hint`)} about={t(`options.${labelKey}`)} />
      </label>
      <Switch
        id={`${id}-s`}
        checked={checked}
        onChange={onChange}
        disabled={disabled}
        labelledBy={`${id}-l`}
        describedBy={`${id}-h`}
      />
    </div>
  );
}

/** Why a switch in the action bar cannot be changed, or null. */
export function outputLockReason(state: ScanFormState, t: (k: string) => string): string | null {
  if (state.isAnalyze) return t("newscan.lockAnalyze");
  const reasons = [
    state.showDeepCve && state.deepCve ? t("newscan.lockDeepCve") : null,
    state.showReachability && state.reachability ? t("newscan.lockReachability") : null,
  ].filter(Boolean);
  return reasons.length ? reasons.join(" ") : null;
}

/** A compact output switch for the action bar. Its description opens from the
 *  info button into the line above the bar (see ActionNotes), so the bar keeps
 *  its one line. */
function OutputSwitch({
  labelKey,
  checked,
  onChange,
  disabled,
  locked,
  open,
  onToggleHint,
  lockId,
}: {
  labelKey: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  locked?: boolean;
  open: boolean;
  onToggleHint: () => void;
  lockId?: string;
}) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <div className="bl-outswitch" data-testid={`output-${labelKey}`}>
      <label htmlFor={`${id}-s`} id={`${id}-l`} className="bl-strong bl-small bl-outlabel">
        {t(`options.${labelKey}`)}
      </label>
      <Button
        size="small"
        variant="invisible"
        className="bl-infobtn"
        aria-label={t("newscan.aboutOption", { name: t(`options.${labelKey}`) })}
        aria-expanded={open}
        aria-controls={`output-hint-${labelKey}`}
        onClick={onToggleHint}
      >
        <InfoIcon size={16} />
      </Button>
      <Switch
        id={`${id}-s`}
        checked={checked}
        onChange={onChange}
        disabled={disabled}
        locked={locked}
        labelledBy={`${id}-l`}
        describedBy={[`output-hint-${labelKey}`, locked ? lockId : null].filter(Boolean).join(" ")}
      />
    </div>
  );
}

/** The two output switches (notice, security report) in the action bar. */
export function OutputSwitches({
  state,
  openHint,
  onOpenHint,
}: {
  state: ScanFormState;
  openHint: string | null;
  onOpenHint: (key: string | null) => void;
}) {
  const { t } = useTranslation();
  const { options, busy } = state;
  return (
    <div className="bl-af-outputs" role="group" aria-label={t("newscan.outputs")}>
      {options.map((o) => (
        <OutputSwitch
          key={o.key}
          labelKey={o.key}
          checked={o.value}
          onChange={(v) => o.set(v)}
          disabled={busy}
          locked={o.forced}
          open={openHint === o.key}
          onToggleHint={() => onOpenHint(openHint === o.key ? null : o.key)}
          lockId="output-lock"
        />
      ))}
    </div>
  );
}

/** Source-specific control: current-folder hint / free-text target / git token / upload. */
export function SourceControls({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const {
    source,
    target,
    setTarget,
    scanRoot,
    setScanRoot,
    scanRoots,
    deepSource,
    setDeepSource,
    showDeepSource,
    gitToken,
    setGitToken,
    gitRef,
    setGitRef,
    exclude,
    setExclude,
    showExclude,
    file,
    setFile,
    uploadPercent,
    uploadKind,
    textInput,
    isAnalyze,
    busy,
    capabilities,
    errors,
  } = state;

  // Extra --mount scan targets make the rootfs-dir path a subpath inside the
  // chosen base, and optional when a mounted base is selected (empty = scan
  // the whole mount). In the desktop app the list is editable in place: the
  // shell picks a folder, remounts and restarts the UI container (the page
  // reloads on its own, so no state cleanup is needed after an ok response).
  const bridge = desktopBridge();
  const desktopFolders = canManageScanFolders(bridge);
  const showScanRoots = source === "rootfs-dir" && (scanRoots.length > 0 || desktopFolders);
  const targetOptional = source === "rootfs-dir" && scanRoots.length > 0 && scanRoot !== "";
  const [mountBusy, setMountBusy] = useState(false);

  const addScanFolder = async () => {
    if (!bridge?.chooseScanFolder) return;
    setMountBusy(true);
    const res = await bridge.chooseScanFolder().catch(() => ({ ok: false }));
    // When ok, the app restarts the container and reloads this page.
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
    <div className="bl-stack">
      {source === "current-dir" && (
        <div className="bl-inset bl-small">
          {capabilities.hostDir && (
            <div className="bl-currentdir-path">
              <span className="bl-strong">{t("source.currentDirPath")}: </span>
              <span className="bl-mono bl-breakall">{capabilities.hostDir}</span>
            </div>
          )}
          <span className="bl-muted">{t("source.currentDirHint")}</span>
        </div>
      )}

      {showScanRoots && (
        <div className="bl-stack-8">
          {scanRoots.length > 0 && (
            <FormControl id="scanRoot" disabled={busy || mountBusy}>
              <FormControl.Label>{t("source.scanRoot")}</FormControl.Label>
              <Select block value={scanRoot} onChange={(e) => setScanRoot(e.target.value)}>
                <Select.Option value="">
                  {capabilities.hostDir
                    ? t("source.scanRootCurrent", { path: capabilities.hostDir })
                    : t("source.scanRootCurrentNoPath")}
                </Select.Option>
                {scanRoots.map((r) => (
                  <Select.Option key={r.path} value={r.path}>
                    {r.hostPath || r.path}
                  </Select.Option>
                ))}
              </Select>
            </FormControl>
          )}
          {desktopFolders && (
            <div>
              <Button
                size="small"
                disabled={busy || mountBusy}
                loading={mountBusy}
                onClick={addScanFolder}
              >
                {t("source.addScanFolder")}
              </Button>
            </div>
          )}
          {desktopFolders && scanRoot !== "" && (
            <Link
              as="button"
              type="button"
              className="bl-small"
              disabled={busy || mountBusy}
              onClick={removeScanFolder}
            >
              {t("source.removeScanFolder")}
            </Link>
          )}
          {desktopFolders && (
            <p className="bl-muted bl-small bl-flat">{t("source.scanFolderDesktopHint")}</p>
          )}
          {showDeepSource && (
            <Toggle
              labelKey="deepSource"
              checked={deepSource}
              onChange={setDeepSource}
              disabled={busy}
            />
          )}
        </div>
      )}

      {textInput && (
        <FormControl id="target" required={!targetOptional} disabled={busy}>
          <FormControl.Label>
            {targetOptional ? t("source.rootfsSubpath") : t(textInput.label)}
          </FormControl.Label>
          <TextInput
            block
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={t(textInput.placeholder)}
            validationStatus={errors.target ? "error" : undefined}
            aria-describedby={describedBy("target", Boolean(errors.target))}
          />
          <Hint
            id="target-hint"
            text={targetOptional ? t("source.rootfsSubpathHint") : t(textInput.hint)}
            about={targetOptional ? t("source.rootfsSubpath") : t(textInput.label)}
          />
          {errors.target && (
            <FormControl.Validation variant="error">{t(errors.target)}</FormControl.Validation>
          )}
        </FormControl>
      )}

      {source === "git-url" && (
        <FormControl id="gitRef" disabled={busy}>
          <FormControl.Label>{t("source.gitRef")}</FormControl.Label>
          <TextInput
            block
            value={gitRef}
            onChange={(e) => setGitRef(e.target.value)}
            placeholder={t("source.gitRefPlaceholder")}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="off"
            validationStatus={errors.gitRef ? "error" : undefined}
            aria-describedby={describedBy("gitRef", Boolean(errors.gitRef))}
          />
          <Hint id="gitRef-hint" text={t("source.gitRefHint")} about={t("source.gitRef")} />
          {errors.gitRef && (
            <FormControl.Validation variant="error">{t(errors.gitRef)}</FormControl.Validation>
          )}
        </FormControl>
      )}

      {showExclude && (
        <FormControl id="exclude" disabled={busy}>
          <FormControl.Label>{t("source.exclude")}</FormControl.Label>
          <Textarea
            block
            rows={3}
            value={exclude}
            onChange={(e) => setExclude(e.target.value)}
            placeholder={t("source.excludePlaceholder")}
            spellCheck={false}
            autoCapitalize="off"
            validationStatus={errors.exclude ? "error" : undefined}
            aria-describedby={describedBy("exclude", Boolean(errors.exclude))}
          />
          <Hint id="exclude-hint" text={t("source.excludeHint")} about={t("source.exclude")} />
          {errors.exclude && (
            <FormControl.Validation variant="error">{t(errors.exclude)}</FormControl.Validation>
          )}
        </FormControl>
      )}

      {source === "git-url" && (
        <FormControl id="gitToken" disabled={busy}>
          <FormControl.Label>{t("source.gitToken")}</FormControl.Label>
          <TextInput
            block
            type="password"
            autoComplete="off"
            value={gitToken}
            onChange={(e) => setGitToken(e.target.value)}
            placeholder={t("source.gitTokenPlaceholder")}
            aria-describedby="gitToken-hint"
          />
          <Hint id="gitToken-hint" text={t("source.gitTokenHint")} about={t("source.gitToken")} />
        </FormControl>
      )}

      {uploadKind && (
        <div>
          <label htmlFor="file" className="bl-fieldlabel">
            {t(UPLOAD_LABEL[uploadKind])}
            <span aria-hidden className="bl-required">
              {" "}
              *
            </span>
          </label>
          <FileDropzone
            id="file"
            accept={ACCEPT[uploadKind]}
            file={file}
            onFile={setFile}
            disabled={busy}
            percent={uploadPercent}
            invalid={Boolean(errors.file)}
            describedBy={errors.file ? "file-error" : undefined}
          />
          {errors.file && (
            <p id="file-error" className="bl-small bl-danger bl-fielderror">
              {t(errors.file)}
            </p>
          )}
          {isAnalyze && <p className="bl-muted bl-small bl-filehint">{t("source.sbomAnalyzeHint")}</p>}
          {source === "firmware-upload" && (
            <p className="bl-muted bl-small bl-filehint">{t("source.firmwareHint")}</p>
          )}
          {source === "package-upload" && (
            <p className="bl-muted bl-small bl-filehint">{t("source.packageUploadHint")}</p>
          )}
          {source === "model-upload" && (
            <p className="bl-muted bl-small bl-filehint">{t("source.modelUploadHint")}</p>
          )}
        </div>
      )}

      {source === "ai-declare" && (
        <p className="bl-muted bl-flat" data-testid="ai-declare-hint">
          {t("source.aiDeclareHint")}
        </p>
      )}

      {(source === "ai-model" || source === "model-upload" || source === "ai-declare") && (
        <UsageContextSelect state={state} />
      )}

      <SiblingPullNotice state={state} />
      <HfAuthNotice state={state} />
    </div>
  );
}

/** AI-model only: how the model will be used. Optional: the default sends
 *  nothing, and the pipeline then assesses without a usage-specific tightening. */
function UsageContextSelect({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const { usage, setUsage, busy } = state;
  return (
    <FormControl id="usage" disabled={busy}>
      <FormControl.Label>{t("source.usageContext")}</FormControl.Label>
      <Select
        block
        value={usage}
        onChange={(e) => setUsage(e.target.value as UsageContext | "")}
        aria-describedby="usage-hint"
      >
        <Select.Option value="">{t("source.usageUnspecified")}</Select.Option>
        {USAGE_CONTEXTS.map((u) => (
          <Select.Option key={u} value={u}>
            {t(USAGE_LABEL_KEY[u])}
          </Select.Option>
        ))}
      </Select>
      <Hint id="usage-hint" text={t("source.usageContextHint")} about={t("source.usageContext")} />
    </FormControl>
  );
}

/** First-run notice: when firmware/AI runs via a sibling container (the desktop
 *  base UI image), the dedicated image is pulled on the first scan, a large,
 *  one-time download. Shown only when the selected source needs it. */
function SiblingPullNotice({ state }: { state: ScanFormState }) {
  const { source, capabilities } = state;
  const imageKey =
    source === "firmware-upload" && capabilities.firmwareSibling
      ? ("firmware" as const)
      : source === "ai-model" && capabilities.aibomSibling
        ? ("aibom" as const)
        : null;
  if (!imageKey) return null;
  // The panel adds the download button and layer progress to the same notice, so
  // the wait happens before the scan rather than inside it.
  return <SiblingImagePanel imageKey={imageKey} />;
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
    <div className="bl-inset bl-small bl-sibling-ready">
      <InfoIcon size={16} />
      <span className="bl-muted">
        {t(capabilities.hfAuth ? "source.hfAuthOn" : "source.hfAuthOff")}
      </span>
    </div>
  );
}

/** Result quality: how the source is analyzed (deep license / vendored identification / CVE matching). */
export function ScanOptions({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const tokenId = useId();
  const {
    deepLicense,
    setDeepLicense,
    identifyVendored,
    setIdentifyVendored,
    resolveModels,
    setResolveModels,
    showResolveModels,
    deepCve,
    setDeepCve,
    reachability,
    setReachability,
    byteStable,
    setByteStable,
    analyzeCpeIndex,
    setAnalyzeCpeIndex,
    readLockFile,
    setReadLockFile,
    showDetection,
    readDeclared,
    setReadDeclared,
    showReadDeclared,
    scanossToken,
    setScanossToken,
    showVendored,
    showDeepLicense,
    showDeepCve,
    showReachability,
    showByteStable,
    showAnalyzeCpeIndex,
    capabilities,
    busy,
  } = state;
  return (
    <div className="bl-optgrid">
      {/* Set the group's altitude once: these are advanced analyses for source
          without a package manager, so PM-built projects can leave them off. */}
      {(showVendored || showDeepLicense) && (
        <p className="bl-muted bl-small bl-flat bl-span2">{t("options.scanMethodHint")}</p>
      )}
      {showVendored && (
        <>
          <Toggle
            labelKey="identifyVendored"
            checked={identifyVendored}
            onChange={setIdentifyVendored}
            disabled={busy}
            external
          />
          {identifyVendored && (
            <FormControl id="scanossToken" disabled={busy} className="bl-span2">
              <FormControl.Label>{t("options.scanossTokenLabel")}</FormControl.Label>
              <TextInput
                block
                type="password"
                autoComplete="off"
                value={scanossToken}
                onChange={(e) => setScanossToken(e.target.value)}
                placeholder={t("options.scanossTokenPlaceholder")}
                aria-describedby={`${tokenId}-h`}
              />
              <Hint
                id={`${tokenId}-h`}
                text={t("options.scanossTokenHint")}
                about={t("options.scanossTokenLabel")}
              />
            </FormControl>
          )}
        </>
      )}
      {showResolveModels && (
        <ToggleRow
          labelKey="resolveModels"
          checked={resolveModels}
          onChange={setResolveModels}
          disabled={busy}
          external
        />
      )}
      {showDeepLicense && (
        <Toggle labelKey="deepLicense" checked={deepLicense} onChange={setDeepLicense} disabled={busy} />
      )}
      {showDeepCve && (
        <>
          <Toggle labelKey="deepCve" checked={deepCve} onChange={setDeepCve} disabled={busy} />
          {/* Deep CVE runs via a sibling container here, so the first run pulls
              the (large) deep-cve image: say so only once the toggle is on. */}
          {deepCve && capabilities.deepCveSibling && (
            <div className="bl-span2">
              <SiblingImagePanel imageKey="deep-cve" />
            </div>
          )}
        </>
      )}
      {showReachability && (
        <Toggle
          labelKey="reachability"
          checked={reachability}
          onChange={setReachability}
          disabled={busy}
        />
      )}
      {showDetection && (
        <Toggle
          labelKey="readLockFile"
          checked={readLockFile}
          onChange={setReadLockFile}
          disabled={busy}
        />
      )}
      {showReadDeclared && (
        <Toggle
          labelKey="readDeclared"
          checked={readDeclared}
          onChange={setReadDeclared}
          disabled={busy}
        />
      )}
      {showAnalyzeCpeIndex && (
        <Toggle
          labelKey="analyzeCpeIndex"
          checked={analyzeCpeIndex}
          onChange={setAnalyzeCpeIndex}
          disabled={busy}
        />
      )}
      {showByteStable && (
        <Toggle labelKey="byteStable" checked={byteStable} onChange={setByteStable} disabled={busy} />
      )}
    </div>
  );
}

/** Output format: which thresholds, license and author the SBOM and its checks carry. */
export function FormatOptions({ state }: { state: ScanFormState }) {
  const { t } = useTranslation();
  const {
    conformanceProfile,
    setConformanceProfile,
    isAnalyze,
    outboundLicense,
    setOutboundLicense,
    sbomAuthor,
    setSbomAuthor,
    supplier,
    setSupplier,
    specVersion,
    setSpecVersion,
    showOutboundLicense,
    showSbomAuthor,
    showSupplier,
    showSpecVersion,
    showConformanceProfile,
    busy,
  } = state;
  return (
    <div className="bl-optgrid">
      {showConformanceProfile && (
        <FormControl id="conformance-profile" disabled={busy}>
          <FormControl.Label>{t("options.conformanceProfile")}</FormControl.Label>
          <Select
            block
            value={conformanceProfile}
            onChange={(e) => setConformanceProfile(e.target.value as ConformanceProfile)}
            aria-describedby="conformance-profile-hint"
          >
            {CONFORMANCE_PROFILES.map((p) => (
              <Select.Option key={p} value={p}>
                {t(CONFORMANCE_PROFILE_LABEL_KEY[p])}
              </Select.Option>
            ))}
          </Select>
          <Hint
            id="conformance-profile-hint"
            text={`${t("options.conformanceProfileHint")}${
              isAnalyze ? ` ${t("options.conformanceProfileAnalyzeHint")}` : ""
            }`}
            about={t("options.conformanceProfile")}
          />
        </FormControl>
      )}
      {showOutboundLicense && (
        <FormControl id="outbound-license" disabled={busy}>
          <FormControl.Label>{t("options.outboundLicense")}</FormControl.Label>
          <TextInput
            block
            value={outboundLicense}
            onChange={(e) => setOutboundLicense(e.target.value)}
            placeholder="Apache-2.0"
            spellCheck={false}
            aria-describedby="outbound-license-hint"
          />
          <Hint
            id="outbound-license-hint"
            text={t("options.outboundLicenseHint")}
            about={t("options.outboundLicense")}
          />
        </FormControl>
      )}
      {showSbomAuthor && (
        <FormControl id="sbom-author" disabled={busy}>
          <FormControl.Label>{t("options.sbomAuthor")}</FormControl.Label>
          <TextInput
            block
            value={sbomAuthor}
            onChange={(e) => setSbomAuthor(e.target.value)}
            placeholder="SK Telecom Co., Ltd."
            spellCheck={false}
            aria-describedby="sbom-author-hint"
          />
          <Hint
            id="sbom-author-hint"
            text={t("options.sbomAuthorHint")}
            about={t("options.sbomAuthor")}
          />
        </FormControl>
      )}
      {showSupplier && (
        <FormControl id="product-supplier" disabled={busy}>
          <FormControl.Label>{t("options.supplier")}</FormControl.Label>
          <TextInput
            block
            value={supplier}
            onChange={(e) => setSupplier(e.target.value)}
            placeholder="SK Telecom Co., Ltd. <https://www.sktelecom.com>"
            spellCheck={false}
            aria-describedby="product-supplier-hint"
          />
          <Hint
            id="product-supplier-hint"
            text={t("options.supplierHint")}
            about={t("options.supplier")}
          />
        </FormControl>
      )}
      {showSpecVersion && (
        <FormControl id="spec-version" disabled={busy}>
          <FormControl.Label>{t("options.specVersion")}</FormControl.Label>
          <Select
            block
            value={specVersion}
            onChange={(e) => setSpecVersion(e.target.value as CdxSpecVersion)}
            aria-describedby="spec-version-hint"
          >
            {CDX_SPEC_VERSIONS.map((v) => (
              <Select.Option key={v} value={v}>
                {t(v === "1.6" ? "options.specVersionDefault" : "options.specVersion17")}
              </Select.Option>
            ))}
          </Select>
          <Hint
            id="spec-version-hint"
            text={t("options.specVersionHint")}
            about={t("options.specVersion")}
          />
        </FormControl>
      )}
    </div>
  );
}

/** Optional upload of the generated SBOM to a Dependency-Track or TRUSCA server.
 *  The server URL and token are used for this run only and never persisted.
 *  One row (the switch); the form opens under it while the switch is on. */
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
    <div className="bl-optgrid">
      <Toggle
        labelKey="upload"
        checked={uploadEnabled}
        onChange={setUploadEnabled}
        disabled={busy}
        external
        wide
      />
      {uploadEnabled && (
        <>
          <FormControl id="uploadTarget" disabled={busy}>
            <FormControl.Label>{t("upload.target")}</FormControl.Label>
            <Select
              block
              value={uploadTarget}
              onChange={(e) => setUploadTarget(e.target.value as "dependency-track" | "trusca")}
            >
              <Select.Option value="dependency-track">{t("upload.targetDT")}</Select.Option>
              <Select.Option value="trusca">{t("upload.targetTrusca")}</Select.Option>
            </Select>
          </FormControl>
          <FormControl id="uploadUrl" required disabled={busy}>
            <FormControl.Label>{t("upload.url")}</FormControl.Label>
            <TextInput
              block
              value={uploadUrl}
              onChange={(e) => setUploadUrl(e.target.value)}
              placeholder={t("upload.urlPlaceholder")}
              validationStatus={errors.uploadUrl ? "error" : undefined}
              aria-describedby={describedBy("uploadUrl", Boolean(errors.uploadUrl), false)}
            />
            {errors.uploadUrl && (
              <FormControl.Validation variant="error">{t(errors.uploadUrl)}</FormControl.Validation>
            )}
          </FormControl>
          <FormControl id="uploadToken" required disabled={busy}>
            <FormControl.Label>{t("upload.token")}</FormControl.Label>
            <TextInput
              block
              type="password"
              autoComplete="off"
              value={uploadToken}
              onChange={(e) => setUploadToken(e.target.value)}
              placeholder={t("upload.tokenPlaceholder")}
              validationStatus={errors.uploadToken ? "error" : undefined}
              aria-describedby={describedBy("uploadToken", Boolean(errors.uploadToken))}
            />
            <Hint id="uploadToken-hint" text={t("upload.tokenHint")} about={t("upload.token")} />
            {errors.uploadToken && (
              <FormControl.Validation variant="error">
                {t(errors.uploadToken)}
              </FormControl.Validation>
            )}
          </FormControl>
          {uploadTarget === "trusca" && (
            <FormControl id="truscaProjectId" required disabled={busy}>
              <FormControl.Label>{t("upload.projectId")}</FormControl.Label>
              <TextInput
                block
                value={truscaProjectId}
                onChange={(e) => setTruscaProjectId(e.target.value)}
                placeholder={t("upload.projectIdPlaceholder")}
                validationStatus={errors.truscaProjectId ? "error" : undefined}
                aria-describedby={describedBy(
                  "truscaProjectId",
                  Boolean(errors.truscaProjectId),
                  false,
                )}
              />
              {errors.truscaProjectId && (
                <FormControl.Validation variant="error">
                  {t(errors.truscaProjectId)}
                </FormControl.Validation>
              )}
            </FormControl>
          )}
        </>
      )}
    </div>
  );
}

/** The fields whose error is a malformed value rather than an empty one. */
const FORMAT_KEYS = new Set(["gitRef", "exclude"]);

/**
 * The line above the action bar. It holds, in order: one alert that names the
 * fields to fix (the field messages stay at their fields), the reason a switch
 * is locked, the description of the output switch whose info button is open (the
 * switches describe themselves from here, open or not), the note for a declared
 * model's project name, and in the static demo why the run button is disabled.
 * Empty, it takes no room.
 */
export function ActionNotes({
  state,
  openHint,
}: {
  state: ScanFormState;
  openHint: string | null;
}) {
  const { t, i18n } = useTranslation();
  const { errors, uploadError, source, options, isAiModel } = state;

  const fieldLabel: Record<string, string> = {
    project: t("form.project"),
    version: t("form.version"),
    target: state.textInput ? t(state.textInput.label) : "",
    gitRef: t("source.gitRef"),
    exclude: t("source.exclude"),
    file: state.uploadKind ? t(UPLOAD_LABEL[state.uploadKind]) : "",
    uploadUrl: t("upload.url"),
    uploadToken: t("upload.token"),
    truscaProjectId: t("upload.projectId"),
  };
  const keys = Object.keys(errors);
  const missing = keys.filter((k) => !FORMAT_KEYS.has(k)).map((k) => fieldLabel[k]);
  const malformed = keys.filter((k) => FORMAT_KEYS.has(k)).map((k) => fieldLabel[k]);
  const sentence = [
    missing.length ? t("validation.requiredList", { fields: missing.join(", ") }) : null,
    malformed.length ? t("validation.formatList", { fields: malformed.join(", ") }) : null,
    uploadError ? t(uploadError.key) : null,
  ]
    .filter(Boolean)
    .join(" ");

  const lock = outputLockReason(state, t);
  const describe = source === "ai-declare";
  const hintText = (key: string) =>
    [t(`options.${key}Hint`), key === "notice" && isAiModel ? t("options.aiNoticeHint") : null]
      .filter(Boolean)
      .join(" ");
  const any = Boolean(sentence) || Boolean(lock) || describe || openHint !== null || IS_STATIC_DEMO;
  return (
    <div className="bl-actionnotes" hidden={!any}>
      {sentence && (
        <p id="scan-alert" role="alert" className="bl-small bl-danger bl-flat">
          {sentence}
          {uploadError?.detail && <span className="bl-muted"> {uploadError.detail}</span>}
        </p>
      )}
      {lock && (
        <p id="output-lock" className="bl-small bl-flat">
          {lock}
        </p>
      )}
      {/* Always in the page: the switches are described by these. Shown while
          their info button is open. */}
      {options.map((o) => (
        <p
          key={o.key}
          id={`output-hint-${o.key}`}
          className="bl-muted bl-small bl-flat"
          hidden={openHint !== o.key}
        >
          {hintText(o.key)}
        </p>
      ))}
      {describe && (
        <p id="project-hint" className="bl-muted bl-small bl-flat">
          {t("form.projectHintDeclare")}
        </p>
      )}
      {IS_STATIC_DEMO && (
        <p className="bl-muted bl-small bl-flat">
          {t("form.demoRunDisabled")}{" "}
          <Link href={demoInstallUrl(i18n.language)} target="_blank" rel="noreferrer">
            {t("form.demoRunDisabledCta")}
          </Link>
        </p>
      )}
    </div>
  );
}

/** The run / uploading / scanning button. */
export function RunButton({ state, running }: { state: ScanFormState; running: boolean }) {
  const { t } = useTranslation();
  const { submit, busy, uploading } = state;

  // The demo shows this form so the range of inputs is visible, but running a
  // scan needs a machine that can build the target. Disable rather than hide:
  // a missing button reads as a broken page, a disabled one with a reason reads
  // as a boundary, and the reason (with the install link) is in the line above
  // the action bar. The model questionnaire runs in the browser, so it stays
  // reachable; only its last step (starting a scan) is refused there.
  if (IS_STATIC_DEMO) {
    const questions = demoRunAction(state.source) === "questions";
    return (
      <Button
        variant="primary"
        block
        leadingVisual={PlayIcon}
        data-testid="run-scan"
        disabled={!questions}
        onClick={questions ? submit : undefined}
      >
        {questions ? t("newscan.startQuestions") : t("form.run")}
      </Button>
    );
  }

  return (
    <Button
      variant="primary"
      block
      onClick={submit}
      disabled={busy}
      data-testid="run-scan"
      leadingVisual={uploading ? UploadIcon : running ? undefined : PlayIcon}
      loading={running && !uploading}
    >
      {uploading
        ? t("source.uploading")
        : running
          ? t("form.running")
          : // A declaration has no input to scan yet: the button opens the
            // questions, and the scan starts when they are answered.
            state.source === "ai-declare"
            ? t("newscan.startQuestions")
            : t("form.run")}
    </Button>
  );
}
