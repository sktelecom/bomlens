// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { demoInstallUrl, IS_STATIC_DEMO } from "@/lib/demo";

import { ErrorState, LoadingState } from "@/components/ui/state";
import {
  checkAiDeclaration,
  describeUploadError,
  fetchSpdx3Map,
  uploadFile,
  type ScanParams,
  type Spdx3Failure,
} from "@/lib/api";
import {
  createTemplate,
  parseMap,
  startCreate,
  type Declaration,
  type FieldIndex,
} from "@/lib/aiDeclaration";

import { AiDeclarationWizard } from "./AiDeclarationWizard";

/**
 * A model described from its publisher's declaration alone: the questions in
 * create mode, then the answers uploaded as the declaration and the scan
 * started with it. `saved` is the declaration of the scan being re-run, which
 * reopens the questions at the review step.
 */
export function DeclareFlow({
  params,
  saved,
  onCancel,
  onStart,
}: {
  /** The scan the form prepared (project, version, author, usage...). */
  params: ScanParams;
  /** The declaration of the scan being re-run, still being read when the
   *  questions open (they wait for it). */
  saved?: Promise<unknown>;
  onCancel: () => void;
  onStart: (params: ScanParams) => void;
}) {
  const { t, i18n } = useTranslation();
  const [index, setIndex] = useState<FieldIndex | null>(null);
  const [loaded, setLoaded] = useState<{ saved: unknown } | null>(null);
  const [failed, setFailed] = useState(false);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let alive = true;
    setFailed(false);
    void Promise.all([fetchSpdx3Map(), saved ?? Promise.resolve(undefined)]).then(([raw, s]) => {
      if (!alive) return;
      const idx = parseMap(raw);
      if (idx) {
        setIndex(idx);
        setLoaded({ saved: s });
      } else setFailed(true);
    });
    return () => {
      alive = false;
    };
  }, [reload, saved]);

  // Leaving the page loses the answers, which are kept nowhere else.
  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, []);

  const initial: Declaration | null = useMemo(
    () => (index && loaded ? (loaded.saved ? startCreate(index, loaded.saved) : createTemplate(index)) : null),
    [index, loaded],
  );

  if (failed) {
    return (
      <ErrorState onRetry={() => setReload((n) => n + 1)} retryLabel={t("retry")}>
        {t("spdx3.openFailed")}
      </ErrorState>
    );
  }
  if (!index || !initial) return <LoadingState>{t("models.loading")}</LoadingState>;
  // A sbom author given on the form is the document's author; the question is
  // then not asked (the converter prefers it the same way).
  const authorFromScan = Boolean(params.sbomAuthor?.trim());

  const start = async (file: Declaration): Promise<Spdx3Failure | null> => {
    // Refusals come back here, with the answers still on screen, rather than
    // after the scan has started.
    const refused = await checkAiDeclaration(params.project, params.version, file);
    if (refused) return refused;
    const blob = new File([JSON.stringify(file, null, 2)], "ai-declaration.json", { type: "application/json" });
    try {
      const { token } = await uploadFile(blob, "declaration");
      onStart({ ...params, token });
      return null;
    } catch (e) {
      const info = describeUploadError(e);
      return { ok: false, status: 0, error: t(info.key), reasons: [t(info.key)] };
    }
  };

  return (
    <AiDeclarationWizard
      mode="create"
      title={`${params.project} ${params.version}`}
      index={index}
      initial={initial}
      initialStep={loaded?.saved ? "preview" : undefined}
      check={null}
      authorFromScan={authorFromScan}
      onCancel={onCancel}
      onSave={start}
      // The questions run in the browser; only starting the scan needs a
      // server, so the demo stops there with a pointer to installing it.
      startNote={
        IS_STATIC_DEMO ? (
          <>
            {t("form.demoRunDisabled")}{" "}
            <a
              href={demoInstallUrl(i18n.language)}
              target="_blank"
              rel="noreferrer"
              className="font-medium text-foreground underline underline-offset-2 hover:no-underline"
            >
              {t("form.demoRunDisabledCta")}
            </a>
          </>
        ) : undefined
      }
    />
  );
}
