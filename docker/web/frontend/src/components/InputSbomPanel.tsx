import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { ErrorState, LoadingState } from "@/components/ui/state";
import {
  inputFacts,
  loadInputSbom,
  type InputSbom,
} from "@/lib/inputSbom";
import { formatBytes } from "@/lib/utils";

/**
 * What the supplier actually sent, for a scan whose input was an SBOM.
 *
 * Everything else on screen describes the CycloneDX document this scan produced
 * by converting that input. This section describes the input itself — its
 * format and version, the tool behind it, when it was made and by whom — which
 * is what a reviewer of a supplier SBOM is being asked to judge.
 *
 * The components are not repeated here; the Components section already lists
 * them with sorting, filters and risk.
 */
export function InputSbomPanel({
  scanId,
  inputFile,
  componentsHref,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  inputFile: string;
  /** Link to the Components section, where the entries themselves are listed. */
  componentsHref?: string;
}) {
  const { t } = useTranslation();
  const [input, setInput] = useState<InputSbom | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadInputSbom(scanId, inputFile)
      .then((got) => {
        if (!active) return;
        setInput(got);
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });
    return () => {
      active = false;
    };
  }, [scanId, inputFile, reloadKey]);

  if (state === "loading") {
    return <LoadingState>{t("inputSbom.loading")}</LoadingState>;
  }
  if (state === "error" || !input) {
    return (
      <ErrorState
        onRetry={() => setReloadKey((k) => k + 1)}
        retryLabel={t("retry")}
      >
        {t("inputSbom.loadError")}
      </ErrorState>
    );
  }

  const facts = inputFacts(input);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{t("inputSbom.intro")}</p>

      <div className="rounded-md border">
        <div className="flex flex-wrap items-center gap-3 border-b px-4 py-3">
          <span className="truncate font-mono text-sm" title={input.originalName}>
            {input.originalName || t("inputSbom.unnamed")}
          </span>
          {input.originalBytes > 0 && (
            <span className="text-xs text-muted-foreground">
              {formatBytes(input.originalBytes)}
            </span>
          )}
          <Badge variant="muted" className="ml-auto">
            {t("inputSbom.entries", { count: input.componentCount })}
          </Badge>
        </div>

        <dl className="divide-y">
          {facts.map((fact) => (
            <div
              key={fact.labelKey}
              className="grid grid-cols-[minmax(0,12rem)_minmax(0,1fr)] gap-3 px-4 py-2"
            >
              <dt className="text-xs text-muted-foreground">
                {t(`inputSbom.field.${fact.labelKey}`)}
              </dt>
              <dd
                className={
                  fact.mono
                    ? "break-all font-mono text-xs"
                    : "break-words text-sm"
                }
              >
                {fact.value}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      <p className="text-xs text-muted-foreground">
        {t("inputSbom.componentsHint")}
        {componentsHref && (
          <>
            {" "}
            <a className="underline hover:text-foreground" href={componentsHref}>
              {t("nav.components")}
            </a>
          </>
        )}
      </p>
    </div>
  );
}
