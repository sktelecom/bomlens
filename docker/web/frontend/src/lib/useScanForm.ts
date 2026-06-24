/**
 * Scan-form state and submit logic, extracted so the classic single-column
 * ScanForm and the new two-pane NewScan share one source of truth (validation,
 * upload, git-cred stash, ANALYZE forcing, vendored gating). UI-only; the
 * components render it.
 */
import { type Dispatch, type SetStateAction, useState } from "react";

import {
  stashGitCred,
  uploadFile,
  type Capabilities,
  type ScanParams,
  type SourceType,
  type UploadKind,
} from "@/lib/api";

export const UPLOAD_KIND: Partial<Record<SourceType, UploadKind>> = {
  "zip-upload": "zip",
  "sbom-upload": "sbom",
  "firmware-upload": "firmware",
};

export const ACCEPT: Record<UploadKind, string> = {
  zip: ".zip,.tar.gz,.tgz,.tar.bz2,.tar.xz,.tar",
  sbom: ".json,.xml,.spdx,.cdx.json,.spdx.json",
  firmware: ".bin,.img,.squashfs,.sqsh,.ubi,.ubifs,.trx,.chk,.fw,.rom,.dlf",
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
}: {
  running: boolean;
  capabilities: Capabilities;
  onRun: (params: ScanParams) => void;
}) {
  const [project, setProject] = useState("");
  const [version, setVersion] = useState("");
  const [source, setSource] = useState<SourceType>("current-dir");
  const [target, setTarget] = useState("");
  const [gitToken, setGitToken] = useState("");
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

  /** Switching source resets the dependent inputs. */
  const changeSource = (s: SourceType) => {
    setSource(s);
    setFile(null);
    setTarget("");
    setGitToken("");
    setUploadError(null);
    setInvalid(false);
  };

  const submit = async () => {
    setUploadError(null);
    if (!project.trim() || !version.trim()) return setInvalid(true);
    if (isText && !target.trim()) return setInvalid(true);
    if (uploadKind && !file) return setInvalid(true);
    setInvalid(false);

    let token: string | undefined;
    let cred: string | undefined;
    if (uploadKind && file) {
      try {
        setUploading(true);
        token = (await uploadFile(file, uploadKind)).token;
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
        cred = (await stashGitCred(gitToken.trim())).credId;
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
      // Byte-stable (reproducible) output is a CI concern; not exposed in the UI.
      byteStable: false,
    });
  };

  // "Outputs" = what gets generated. Scan-method options (deep license / vendored
  // identification) are surfaced separately, not as outputs.
  const options: OptionToggle[] = [
    { key: "notice", value: isAnalyze ? true : notice, set: setNotice, forced: isAnalyze },
    { key: "security", value: isAnalyze ? true : security, set: setSecurity, forced: isAnalyze },
  ];

  return {
    project, setProject,
    version, setVersion,
    source, changeSource,
    target, setTarget,
    gitToken, setGitToken,
    file, setFile,
    deepLicense, setDeepLicense,
    identifyVendored, setIdentifyVendored,
    invalid, uploadError, uploading,
    busy, uploadKind, textInput, isText, isAnalyze, showVendored,
    options, submit,
    capabilities,
  };
}

export type ScanFormState = ReturnType<typeof useScanForm>;
