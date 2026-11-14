// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";

import { getDiagnostics } from "@/lib/api";
import { IS_STATIC_DEMO } from "@/lib/demo";

/**
 * A finished scan's summary is fixed, so it is fetched once per scan and kept:
 * moving between result sections remounts the panel, and a second `docker info`
 * behind each remount is not worth it. Only summaries built from a run id are
 * kept (one built from an on-screen error has no id to key on).
 */
const summaryCache = new Map<string, string>();

/**
 * The diagnostics summary for a finished scan, fetched once `enabled` turns on
 * (the panel or dialog was opened) and kept per scan. `copyBlocked` is the
 * "copying was blocked here" state the buttons set.
 */
export function useDiagnosticsSummary(
  scanId: string | null | undefined,
  errorMessage: string | null | undefined,
  enabled: boolean,
) {
  const [text, setText] = useState<string | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "failed">("idle");
  const [copyBlocked, setCopyBlocked] = useState(false);

  useEffect(() => {
    if (!enabled || IS_STATIC_DEMO) return;
    const cached = scanId ? summaryCache.get(scanId) : undefined;
    if (cached !== undefined) {
      setText(cached);
      setState("ready");
      return;
    }
    let cancelled = false;
    setState("loading");
    setCopyBlocked(false);
    void getDiagnostics(scanId, errorMessage).then((value) => {
      if (cancelled) return;
      if (value !== null && scanId) summaryCache.set(scanId, value);
      setText(value);
      setState(value === null ? "failed" : "ready");
    });
    return () => {
      cancelled = true;
    };
  }, [enabled, scanId, errorMessage]);

  return { text, state, copyBlocked, setCopyBlocked };
}
