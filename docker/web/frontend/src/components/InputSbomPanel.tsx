// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { AlertIcon, CopyIcon, FileIcon, SyncIcon } from "@primer/octicons-react";
import { IconButton, Label, Link, Spinner } from "@primer/react";
import { Blankslate } from "@primer/react/experimental";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { inputFacts, loadInputSbom, type InputSbom } from "@/lib/inputSbom";
import { useToast } from "@/lib/toast";
import { formatBytes } from "@/lib/utils";

import { formatCreated } from "./input-sbom/created";
import "./input-sbom/input-sbom.css";

/**
 * What the supplier actually sent, for a scan whose input was an SBOM.
 *
 * Everything else on screen describes the CycloneDX document this scan produced
 * by converting that input. This section describes the input itself: its
 * format and version, the tool behind it, when it was made and by whom, which
 * is what a reviewer of a supplier SBOM is being asked to judge.
 *
 * The components are not repeated here; the Components section already lists
 * them with sorting, filters and risk.
 */
export function InputSbomPanel({
  scanId,
  inputFile,
  componentsHref,
  componentsTotal,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  inputFile: string;
  /** Link to the Components section, where the entries themselves are listed. */
  componentsHref?: string;
  /** How many components the converted document lists, shown beside the link. */
  componentsTotal?: number;
}) {
  const { t, i18n } = useTranslation();
  const { toast } = useToast();
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
    return (
      <div className="bl-is">
        <div className="bl-box bl-is-state" role="status" data-testid="loading-state">
          <Spinner size="small" srText={null} />
          <span>{t("inputSbom.loading")}</span>
        </div>
      </div>
    );
  }
  if (state === "error" || !input) {
    return (
      <div className="bl-is">
        <div className="bl-box" role="alert" data-testid="error-state">
          <Blankslate>
            <Blankslate.Visual>
              <span className="bl-muted" style={{ display: "flex" }}>
                <AlertIcon size={24} />
              </span>
            </Blankslate.Visual>
            <Blankslate.Heading as="h2">{t("inputSbom.loadError")}</Blankslate.Heading>
            <Blankslate.PrimaryAction onClick={() => setReloadKey((k) => k + 1)}>
              <SyncIcon size={16} /> {t("retry")}
            </Blankslate.PrimaryAction>
          </Blankslate>
        </div>
      </div>
    );
  }

  const facts = inputFacts(input);
  const name = input.originalName || t("inputSbom.unnamed");
  const converted =
    componentsHref && componentsTotal !== undefined && componentsTotal !== input.componentCount
      ? componentsTotal
      : null;

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast(t("inputSbom.copied"));
    } catch {
      /* clipboard blocked (insecure context): the value is still on screen to select */
    }
    
  };

  return (
    <div className="bl-is">
      <p>{t("inputSbom.intro")}</p>

      <section className="bl-box bl-is-box" aria-labelledby="bl-is-title">
        <div className="bl-box-head bl-is-head">
          <FileIcon size={16} />
          <h2 id="bl-is-title">{name}</h2>
          {input.originalBytes > 0 && (
            <span className="bl-is-size">{formatBytes(input.originalBytes)}</span>
          )}
          <span className="bl-is-count">
            <Label>{t("inputSbom.entries", { count: input.componentCount })}</Label>
          </span>
        </div>

        <dl className="bl-is-facts">
          {facts.map((fact) => {
            const label = t(`inputSbom.field.${fact.labelKey}`);
            return (
              <div key={fact.labelKey} className="bl-is-fact">
                <dt>{label}</dt>
                <dd className={fact.mono ? "bl-is-mono" : undefined}>
                  {fact.labelKey === "created" ? (
                    <span title={fact.value}>{formatCreated(fact.value, i18n.language)}</span>
                  ) : (
                    fact.value
                  )}
                  {fact.mono && (
                    <IconButton
                      className="bl-is-copy"
                      size="small"
                      variant="invisible"
                      icon={CopyIcon}
                      aria-label={t("inputSbom.copyValue", { name: label })}
                      onClick={() => void copy(fact.value)}
                    />
                  )}
                </dd>
              </div>
            );
          })}
        </dl>
      </section>

      {componentsHref && (
        <p>
          {t("inputSbom.componentsBefore")}
          <Link href={componentsHref}>{t("nav.components")}</Link>
          {t("inputSbom.componentsAfter")}
          {converted !== null && (
            <span className="bl-is-converted">
              {" "}
              {t("inputSbom.converted", { count: converted })}
            </span>
          )}
        </p>
      )}
    </div>
  );
}
