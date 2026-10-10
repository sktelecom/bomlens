// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  exportSpdx3,
  fetchSpdx3Map,
  fileUrl,
  getCapabilities,
  makeDeclarationTemplate,
  saveAiDeclaration,
  type DoneEvent,
  type ResultFile,
  type Spdx3Summary,
} from "@/lib/api";
import {
  firstOpenStep,
  issues as findIssues,
  keepDeclaredIds,
  parseCheck,
  parseMap,
  startDeclaration,
  stepsFor,
  type Declaration,
  type FieldIndex,
  type Spdx3Check,
  type StepId,
} from "@/lib/aiDeclaration";
import { IS_STATIC_DEMO } from "@/lib/demo";
import { useToast } from "@/lib/toast";

import { AiDeclarationWizard } from "./AiDeclarationWizard";
import { Spdx3Fields, Spdx3StatusBand } from "./Spdx3StatusBand";

/** Answers in progress, by scan. Leaving the section (or the scan) and coming
 *  back reopens the questions where they were; saving or cancelling drops
 *  them. Kept for the page's life only, never written anywhere. */
type Draft = {
  index: FieldIndex;
  initial: Declaration;
  current: Declaration;
  step: StepId;
  /** The declaration saved before, as read. */
  original: unknown;
};
const drafts = new Map<string, Draft>();

async function readJson(scanId: string | null, name: string): Promise<unknown | null> {
  try {
    const res = await fetch(fileUrl(scanId, name));
    return res.ok ? ((await res.json()) as unknown) : null;
  } catch {
    return null;
  }
}

/**
 * The SPDX 3.0.1 part of the Models & datasets screen: the status band and
 * the fields table, or, while the publisher fills the open fields, the
 * question flow in their place. Saving goes through the server, which checks
 * the declaration and rewrites the document; the refreshed summary and
 * listing go back to the owner of the result.
 */
export function Spdx3Panel({
  scanId,
  title,
  summary,
  results,
  onPatch,
  onFillingChange,
  declaredScan = false,
  autoFill = false,
  onAutoFill,
}: {
  scanId: string | null;
  /** Shown above the steps: the project and version. */
  title: string;
  summary: Spdx3Summary | null | undefined;
  results: ResultFile[];
  onPatch?: (patch: Partial<DoneEvent>) => void;
  /** The question flow took over the screen (true) or gave it back. */
  onFillingChange?: (filling: boolean) => void;
  /** The scan was made from a declaration (AIDECLARE): its saved file is the
   *  scan's input, so the ids it names are kept when it is saved again. */
  declaredScan?: boolean;
  /** Open the questions straight away (the Overview's "fill" link). */
  autoFill?: boolean;
  /** The questions were opened for autoFill; the request can be dropped. */
  onAutoFill?: () => void;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [available, setAvailable] = useState(false);
  const [check, setCheck] = useState<Spdx3Check | null>(null);
  const [busy, setBusy] = useState(false);
  const [fill, setFill] = useState<Draft | null>(() => (scanId ? drafts.get(scanId) ?? null : null));
  const [closed, setClosed] = useState(false);

  // Another scan: its own draft, or none.
  useEffect(() => {
    setFill(scanId ? drafts.get(scanId) ?? null : null);
  }, [scanId]);

  useEffect(() => {
    let alive = true;
    void getCapabilities().then((c) => alive && setAvailable(c.spdx3 === true && !IS_STATIC_DEMO));
    return () => {
      alive = false;
    };
  }, []);

  // The check holds the per-field detail; the summary in the result only the
  // counts. Re-read whenever a save changed the summary.
  useEffect(() => {
    let alive = true;
    if (summary?.check) {
      // The table stays on screen until the new check replaces it.
      void readJson(scanId, summary.check).then((raw) => alive && setCheck(parseCheck(raw)));
    } else {
      setCheck(null);
    }
    return () => {
      alive = false;
    };
  }, [scanId, summary]);

  useEffect(() => {
    setCheck(null);
  }, [scanId]);

  useEffect(() => {
    onFillingChange?.(fill !== null);
  }, [fill, onFillingChange]);

  const write = async () => {
    if (!scanId) return;
    setBusy(true);
    const res = await exportSpdx3(scanId);
    setBusy(false);
    if (!res.ok) {
      toast(res.status === 409 ? t("spdx3.notAi") : t("spdx3.writeFailed"));
      return;
    }
    onPatch?.({ results: res.results, spdx3: res.spdx3 });
  };

  const open = async () => {
    if (!scanId) return;
    setBusy(true);
    const savedName = results.find((r) => r.name.endsWith("_ai-declaration.json"))?.name;
    const [rawMap, tpl, saved] = await Promise.all([
      fetchSpdx3Map(),
      makeDeclarationTemplate(scanId),
      savedName ? readJson(scanId, savedName) : Promise.resolve(null),
    ]);
    const index = parseMap(rawMap);
    const template = tpl ? await readJson(scanId, tpl.name) : null;
    // Whether the scan named the author decides a question, so the check has
    // to be there before the questions open.
    let current = check;
    if (!current && summary?.check) {
      current = parseCheck(await readJson(scanId, summary.check));
      setCheck(current);
    }
    setBusy(false);
    const initial = template ? startDeclaration(template, saved) : null;
    if (!index || !initial) {
      toast(t("spdx3.openFailed"));
      return;
    }
    if (tpl) onPatch?.({ results: tpl.results });
    setClosed(false);
    // Open where something is still open, not at a step with nothing to ask.
    const authorFromScan =
      current?.elements.find((e) => e.type === "CreationInfo")?.fields.find((f) => f.id === "createdBy")?.status === "auto";
    const step = firstOpenStep(stepsFor(index, initial), findIssues(index, initial, authorFromScan));
    setFill({ index, initial, current: initial, step, original: saved });
  };

  // The Overview's "fill" link: open the questions once the server can take them.
  const autoOpened = useRef(false);
  useEffect(() => {
    if (!autoFill || autoOpened.current || !available || !summary || fill) return;
    autoOpened.current = true;
    onAutoFill?.();
    void open();
    // open() reads the current props; it is not a dependency to react to.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFill, available, summary, fill]);

  const close = () => {
    if (scanId) drafts.delete(scanId);
    setFill(null);
    setClosed(true);
  };

  const keepDraft = useCallback(
    (current: Declaration, step: StepId) => {
      if (!scanId || !fill) return;
      drafts.set(scanId, { ...fill, current, step });
    },
    [scanId, fill],
  );

  const save = async (file: Declaration) => {
    if (!scanId) return null;
    const res = await saveAiDeclaration(scanId, declaredScan && fill ? keepDeclaredIds(file, fill.original) : file);
    if (!res.ok) return res;
    onPatch?.({ results: res.results, spdx3: res.spdx3 });
    close();
    toast(res.spdx3 && !res.spdx3.draft ? t("spdx3.savedComplete") : t("spdx3.savedDraft"));
    return null;
  };

  if (fill) {
    return (
      <AiDeclarationWizard
        key={scanId ?? ""}
        title={title}
        index={fill.index}
        initial={fill.current}
        initialStep={fill.step}
        check={check}
        onCancel={close}
        onSave={save}
        onDraft={keepDraft}
        declaredScan={declaredScan}
      />
    );
  }
  return (
    <div className="space-y-3">
      <Spdx3StatusBand
        summary={summary}
        available={available}
        busy={busy}
        onFill={open}
        onWrite={write}
        focusFill={closed}
        check={check}
        publisher={declaredScan}
      />
      {check && <Spdx3Fields check={check} defaultOpen={declaredScan} />}
    </div>
  );
}
