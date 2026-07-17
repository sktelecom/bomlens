/**
 * Scan-form state and submit logic, extracted so the classic single-column
 * ScanForm and the new two-pane NewScan share one source of truth (validation,
 * upload, git-cred stash, ANALYZE forcing, vendored gating). UI-only; the
 * components render it.
 */
import { type Dispatch, type SetStateAction, useEffect, useState } from "react";

import {
  describeUploadError,
  stashGitCred,
  uploadFile,
  type Capabilities,
  type ScanConfig,
  type ScanParams,
  type SourceType,
  type UploadErrorInfo,
  type UploadKind,
} from "@/lib/api";
import { DEFAULT_VERSION, parseSbomIdentity, suggestIdentity } from "@/lib/scanDefaults";

export const UPLOAD_KIND: Partial<Record<SourceType, UploadKind>> = {
  "zip-upload": "zip",
  "sbom-upload": "sbom",
  "firmware-upload": "firmware",
};

export const ACCEPT: Record<UploadKind, string> = {
  zip: ".zip,.tar.gz,.tgz,.tar.bz2,.tar.xz,.tar",
  sbom: ".json,.xml,.spdx,.cdx.json,.spdx.json",
  firmware:
    ".bin,.img,.squashfs,.sqsh,.ubi,.ubifs,.trx,.chk,.fw,.rom,.dlf," +
    ".gz,.tgz,.tar,.xz,.bz2,.lzma,.zst,.img.gz,.tar.gz",
};

/** Free-text inputs: the single `target` field, with per-source i18n keys. */
export const TEXT_INPUT: Partial<
  Record<SourceType, { label: string; placeholder: string; hint: string }>
> = {
  "git-url": { label: "source.gitUrl", placeholder: "source.gitPlaceholder", hint: "source.gitHint" },
  "docker-image": { label: "source.dockerImage", placeholder: "source.dockerPlaceholder", hint: "source.dockerHint" },
  "rootfs-dir": { label: "source.rootfsDir", placeholder: "source.rootfsPlaceholder", hint: "source.rootfsHint" },
  "ai-model": { label: "source.aiModel", placeholder: "source.aiModelPlaceholder", hint: "source.aiModelHint" },
};

/** Rootfs-dir target to submit: with a mounted scan root selected, `target`
 *  is an optional subpath inside it and the result is the absolute container
 *  path (the server allow-lists the root); without one, `target` passes
 *  through (a path relative to /src). */
export function composeRootfsTarget(scanRoot: string, target: string): string {
  if (!scanRoot) return target.trim();
  const sub = target.trim().replace(/^\/+/, "");
  return sub ? `${scanRoot}/${sub}` : scanRoot;
}

/** Per-field validation errors; values are i18n keys for the inline message.
 *  Keys double as the input element ids, so the first invalid field can be
 *  focused directly on a failed submit. */
export interface FieldErrors {
  project?: string;
  version?: string;
  target?: string;
  file?: string;
  uploadUrl?: string;
  uploadToken?: string;
  truscaProjectId?: string;
}

const FIELD_ORDER: Array<keyof FieldErrors> = [
  "project", "version", "target", "file", "uploadUrl", "uploadToken", "truscaProjectId",
];

export interface OptionToggle {
  key: string;
  value: boolean;
  set: Dispatch<SetStateAction<boolean>>;
  forced?: boolean;
}

export function useScanForm({
  running,
  capabilities,
  onRun,
  initialConfig,
}: {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
  /**
   * Seed the form from a finished scan's config (the "Re-scan" flow). Read once,
   * at mount, via the lazy state initializers, so later changes to the prop
   * never reset the user's edits. Credentials (git/SCANOSS token) and the file
   * are deliberately not seeded — they aren't in the config and must be
   * re-supplied. Absent for an ordinary (blank) new scan.
   */
  initialConfig?: ScanConfig | null;
}) {
  const [project, setProjectRaw] = useState(() => initialConfig?.project ?? "");
  const [version, setVersionRaw] = useState(() => initialConfig?.version ?? "");
  // Dirty = the user (or a re-scan seed) owns the field, so the source-based
  // autofill below must never overwrite it. A re-scan (`initialConfig`) starts
  // dirty: the seeded identity is deliberate, not a suggestion to replace.
  const [projectDirty, setProjectDirty] = useState(() => Boolean(initialConfig));
  const [versionDirty, setVersionDirty] = useState(() => Boolean(initialConfig));
  const [source, setSource] = useState<SourceType>(
    () => initialConfig?.source ?? "current-dir",
  );
  const [target, setTargetRaw] = useState(() => initialConfig?.target ?? "");
  // Extra --mount scan targets (capabilities.scanRoots): the rootfs-dir input
  // offers them as base locations. "" = the /src launch folder (classic
  // behavior). A re-scan seeds the *full* container path into `target`
  // instead — safe_scan_dir accepts it as-is, so no root matching is needed.
  const [scanRoot, setScanRootRaw] = useState("");
  const [gitToken, setGitToken] = useState("");
  const [file, setFileRaw] = useState<File | null>(null);
  const [notice, setNotice] = useState(() => initialConfig?.notice ?? true);
  const [security, setSecurity] = useState(() => initialConfig?.security ?? true);
  // SPDX 2.3 export (opt-in): an extra artifact converted from the CycloneDX BOM.
  const [spdx, setSpdx] = useState(() => initialConfig?.spdx ?? false);
  const [deepLicense, setDeepLicense] = useState(
    () => initialConfig?.deepLicense ?? false,
  );
  const [identifyVendored, setIdentifyVendored] = useState(
    () => initialConfig?.identifyVendored ?? false,
  );
  // Byte-stable (reproducible) output: identical SBOM when the same input is
  // re-scanned, so it can be diffed/checksummed.
  const [byteStable, setByteStable] = useState(
    () => initialConfig?.byteStable ?? false,
  );
  // Optional upload of the generated SBOM to Dependency-Track or TRUSCA. The
  // server URL and token are never persisted (not in the re-scan sidecar), so a
  // re-scan always starts with upload off and the fields blank.
  const [uploadEnabled, setUploadEnabled] = useState(false);
  const [uploadTarget, setUploadTarget] = useState<"dependency-track" | "trusca">(
    "dependency-track",
  );
  const [uploadUrl, setUploadUrlRaw] = useState("");
  const [uploadToken, setUploadTokenRaw] = useState("");
  const [truscaProjectId, setTruscaProjectIdRaw] = useState("");
  // Firmware only: opt in to OSV.dev advisories (downloaded on this run).
  const [includeOsv, setIncludeOsv] = useState(
    () => initialConfig?.includeOsv ?? false,
  );
  const [scanossToken, setScanossToken] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});
  const [uploadError, setUploadError] = useState<UploadErrorInfo | null>(null);
  const [uploading, setUploading] = useState(false);

  /** Typing into a field resolves its inline error immediately. */
  const clearError = (k: keyof FieldErrors) =>
    setErrors((prev) => {
      if (!(k in prev)) return prev;
      const next = { ...prev };
      delete next[k];
      return next;
    });

  const uploadKind = UPLOAD_KIND[source];
  const textInput = TEXT_INPUT[source];
  const isText = textInput !== undefined;
  const scanRoots = capabilities.scanRoots ?? [];
  // With a mounted scan root selected, `target` becomes an optional subpath
  // inside it (empty = scan the whole mount); the submitted target is the
  // absolute container path the server allow-lists.
  const activeScanRoot = source === "rootfs-dir" ? scanRoot : "";
  const activeScanRootHost =
    scanRoots.find((r) => r.path === activeScanRoot)?.hostPath ?? "";
  const isAnalyze = source === "sbom-upload";
  // AI-model scans have no source tree and no package CVEs, so the security
  // report (Trivy → 0 results) and deep-license (needs /src) don't apply.
  const isAiModel = source === "ai-model";
  // OSV.dev advisories are only fetched for firmware scans (cve-bin-tool), and
  // the osv.dev DB is not in the image, so it downloads on this run when on.
  const isFirmware = source === "firmware-upload";
  const showIncludeOsv = isFirmware;
  // Vendored-OSS identification only applies to a scanned source tree.
  const isSourceScan =
    source === "current-dir" || source === "git-url" || source === "zip-upload";
  const showVendored = Boolean(capabilities.scanoss) && isSourceScan;
  // Deep license (ScanCode) needs a source tree too, so like SCANOSS it only
  // applies to source scans — not Docker images, SBOM uploads, firmware or AI
  // models, where there is nothing to scan and the toggle would be a no-op.
  const showDeepLicense = isSourceScan;
  // Reproducible output applies to any generated SBOM. It is a near no-op for a
  // supplier SBOM we only analyze, and for an AI model, so hide it there.
  const showByteStable = !isAnalyze && !isAiModel;
  const showScanOptions =
    showDeepLicense || showVendored || showIncludeOsv || showByteStable;
  // Any scan produces an SBOM, so upload is offered for every source.
  const showUpload = true;
  const busy = running || uploading;

  /** A user edit owns the field from then on — even when cleared to empty,
   *  so the autofill never fights someone who deliberately blanked it. */
  const setProject = (v: string) => {
    setProjectDirty(true);
    clearError("project");
    setProjectRaw(v);
  };
  const setVersion = (v: string) => {
    setVersionDirty(true);
    clearError("version");
    setVersionRaw(v);
  };
  const setTarget = (v: string) => {
    clearError("target");
    setTargetRaw(v);
  };
  const setScanRoot = (v: string) => {
    clearError("target");
    setScanRootRaw(v);
  };
  const setFile = (f: File | null) => {
    clearError("file");
    setFileRaw(f);
  };
  const setUploadUrl = (v: string) => {
    clearError("uploadUrl");
    setUploadUrlRaw(v);
  };
  const setUploadToken = (v: string) => {
    clearError("uploadToken");
    setUploadTokenRaw(v);
  };
  const setTruscaProjectId = (v: string) => {
    clearError("truscaProjectId");
    setTruscaProjectIdRaw(v);
  };

  // Prefill project/version from the scan source while the user hasn't touched
  // them. Clean fields *mirror* the suggestion (including clearing when it goes
  // away), so switching source or retyping the target never leaves a stale
  // guess behind. Version is only ever a real value from the source (docker
  // tag, versioned file name, SBOM metadata) — never a made-up "1.0".
  const hostDir = capabilities.hostDir;
  useEffect(() => {
    if (projectDirty && versionDirty) return;
    let cancelled = false;
    const apply = (s: { project?: string; version?: string }) => {
      if (cancelled) return;
      if (!projectDirty) setProjectRaw(s.project ?? "");
      // Prefer a version the source states; otherwise seed the placeholder
      // default so the required field is satisfied on a first run — but only
      // once a target is actually identified (a suggested project). With no
      // target yet, both fields stay empty rather than showing a lone version.
      if (!versionDirty) setVersionRaw(s.version || (s.project ? DEFAULT_VERSION : ""));
    };
    if (source === "sbom-upload" && file) {
      // The SBOM's own metadata beats filename guessing; fall back to the
      // filename when the file isn't parseable JSON (xml / tag-value SPDX)
      // or its metadata names nothing.
      void file
        .text()
        .then((text) => parseSbomIdentity(text))
        .catch(() => null)
        .then((id) => apply(id ?? suggestIdentity(source, { fileName: file.name })));
    } else {
      // A selected scan root with no subpath: suggest from its host path (the
      // folder the user actually mounted), not the synthetic container path.
      const suggestFrom =
        activeScanRoot && !target.trim() ? activeScanRootHost : target;
      apply(suggestIdentity(source, { target: suggestFrom, fileName: file?.name, hostDir }));
    }
    return () => {
      cancelled = true;
    };
  }, [source, target, file, hostDir, projectDirty, versionDirty,
      activeScanRoot, activeScanRootHost]);

  /** Switching source resets the dependent inputs. */
  const changeSource = (s: SourceType) => {
    setSource(s);
    setFileRaw(null);
    setTargetRaw("");
    setScanRootRaw("");
    setGitToken("");
    setUploadError(null);
    setErrors({});
  };

  const submit = async () => {
    setUploadError(null);
    const errs: FieldErrors = {};
    if (!project.trim()) errs.project = "validation.project";
    if (!version.trim()) errs.version = "validation.version";
    if (isText && !target.trim() && !activeScanRoot)
      errs.target = "validation.target";
    if (uploadKind && !file) errs.file = "validation.file";
    if (showUpload && uploadEnabled) {
      if (!uploadUrl.trim()) errs.uploadUrl = "validation.uploadUrl";
      if (!uploadToken.trim()) errs.uploadToken = "validation.uploadToken";
      if (uploadTarget === "trusca" && !truscaProjectId.trim())
        errs.truscaProjectId = "validation.truscaProjectId";
    }
    setErrors(errs);
    const firstInvalid = FIELD_ORDER.find((k) => errs[k]);
    if (firstInvalid) {
      // Land keyboard/screen-reader users on the first field that needs fixing
      // (field keys double as the input ids). The Run button itself stays
      // enabled — disabling it would hide *why* the scan can't start.
      document.getElementById(firstInvalid)?.focus();
      return;
    }

    let token: string | undefined;
    let cred: string | undefined;
    let scanossCred: string | undefined;
    let uploadCred: string | undefined;
    if (uploadKind && file) {
      try {
        setUploading(true);
        token = (await uploadFile(file, uploadKind)).token;
      } catch (e) {
        setUploadError(describeUploadError(e));
        setUploading(false);
        return;
      }
      setUploading(false);
    }
    // Private git URL: stash the token (single-use) so it never hits the query string.
    if (source === "git-url" && gitToken.trim()) {
      try {
        setUploading(true);
        cred = (await stashGitCred(gitToken.trim())).credId;
      } catch (e) {
        setUploadError(describeUploadError(e));
        setUploading(false);
        return;
      }
      setUploading(false);
    }

    // SCANOSS token: stashed the same single-use way so the OSSKB key never hits
    // the scan-stream query string. Only relevant when vendored ID is active.
    if (showVendored && identifyVendored && scanossToken.trim()) {
      try {
        setUploading(true);
        scanossCred = (await stashGitCred(scanossToken.trim())).credId;
      } catch (e) {
        setUploadError(describeUploadError(e));
        setUploading(false);
        return;
      }
      setUploading(false);
    }

    // Upload token: stashed the same single-use way so the API key never hits the
    // scan-stream query string.
    if (showUpload && uploadEnabled && uploadToken.trim()) {
      try {
        setUploading(true);
        uploadCred = (await stashGitCred(uploadToken.trim())).credId;
      } catch (e) {
        setUploadError(describeUploadError(e));
        setUploading(false);
        return;
      }
      setUploading(false);
    }

    const effectiveTarget = composeRootfsTarget(activeScanRoot, target);

    onRun({
      project: project.trim(),
      version: version.trim(),
      source,
      target: isText ? effectiveTarget : undefined,
      token,
      cred,
      scanossCred,
      // ANALYZE forces notice+security on (needed for the risk report). AI-model
      // scans have no package CVEs, so security is off there.
      notice: isAnalyze ? true : notice,
      security: isAiModel ? false : isAnalyze ? true : security,
      spdx,
      deepLicense: showDeepLicense ? deepLicense : false,
      identifyVendored: showVendored ? identifyVendored : false,
      // OSV.dev advisories: firmware-only opt-in; ignored for any other source.
      includeOsv: showIncludeOsv ? includeOsv : false,
      byteStable: showByteStable ? byteStable : false,
      uploadTarget: showUpload && uploadEnabled ? uploadTarget : "",
      uploadUrl: showUpload && uploadEnabled ? uploadUrl.trim() : "",
      uploadCred,
      truscaProjectId:
        showUpload && uploadEnabled && uploadTarget === "trusca"
          ? truscaProjectId.trim()
          : "",
    });
  };

  // "Outputs" = what gets generated. Scan-method options (deep license / vendored
  // identification) are surfaced separately, not as outputs.
  const options: OptionToggle[] = [
    { key: "notice", value: isAnalyze ? true : notice, set: setNotice, forced: isAnalyze },
    // AI-model scans skip the (empty) security report.
    ...(isAiModel
      ? []
      : [{ key: "security", value: isAnalyze ? true : security, set: setSecurity, forced: isAnalyze }]),
    { key: "spdx", value: spdx, set: setSpdx },
  ];

  return {
    project, setProject,
    version, setVersion,
    source, changeSource,
    target, setTarget,
    scanRoot, setScanRoot, scanRoots,
    gitToken, setGitToken,
    file, setFile,
    deepLicense, setDeepLicense,
    identifyVendored, setIdentifyVendored,
    includeOsv, setIncludeOsv,
    byteStable, setByteStable,
    scanossToken, setScanossToken,
    uploadEnabled, setUploadEnabled,
    uploadTarget, setUploadTarget,
    uploadUrl, setUploadUrl,
    uploadToken, setUploadToken,
    truscaProjectId, setTruscaProjectId,
    errors, uploadError, uploading,
    busy, uploadKind, textInput, isText, isAnalyze, isAiModel, showVendored,
    showDeepLicense, showIncludeOsv, showByteStable, showScanOptions, showUpload,
    options, submit,
    capabilities,
  };
}

export type ScanFormState = ReturnType<typeof useScanForm>;
