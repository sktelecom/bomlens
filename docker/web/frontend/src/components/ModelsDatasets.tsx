import {
  Boxes,
  CircleCheck,
  CircleDashed,
  Database,
  ExternalLink,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/state";
import {
  type AiModelData,
  type AssessmentGrade,
  GRADE_LABEL_KEY,
  type ModelAssessment,
  type ModelCard,
  parseModelCards,
  USAGE_LABEL_KEY,
} from "@/lib/models";
import { loadSbom } from "@/lib/sbomGraph";
import { cn } from "@/lib/utils";

/** Badge tone per pipeline grade — the grade word itself is always shown, so
 *  the color is a reinforcement, never the only signal. */
const GRADE_TONE: Record<AssessmentGrade, "success" | "high" | "critical" | "info"> = {
  ok: "success",
  conditional: "high",
  caution: "critical",
  review: "info",
};

/** A stamped grade as word + tone (verbatim from the SBOM property). */
function GradeBadge({ grade }: { grade: AssessmentGrade }) {
  const { t } = useTranslation();
  return <Badge tone={GRADE_TONE[grade]}>{t(GRADE_LABEL_KEY[grade])}</Badge>;
}

/**
 * Models & Datasets — the AI surface. Fetches the raw ML-BOM, parses each
 * machine-learning-model's card (identifier, architecture, task, license,
 * integrity, references, limitations), shows the four openness-disclosure axes
 * and the datasets the models reference. Only reachable for AI/ANALYZE scans.
 */
export function ModelsDatasets({
  scanId,
  sbomFile,
}: {
  /** The scan's run_id, scoping the artifact fetch to its run folder. */
  scanId: string | null;
  sbomFile: string;
}) {
  const { t } = useTranslation();
  const [data, setData] = useState<AiModelData | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setState("loading");
    void loadSbom(scanId, sbomFile)
      .then((sbom) => {
        if (!active) return;
        setData(parseModelCards(sbom));
        setState("ready");
      })
      .catch(() => active && setState("error"));
    return () => {
      active = false;
    };
  }, [scanId, sbomFile, reloadKey]);

  if (state === "loading") return <LoadingState>{t("models.loading")}</LoadingState>;
  if (state === "error" || !data) {
    return (
      <ErrorState onRetry={() => setReloadKey((k) => k + 1)} retryLabel={t("retry")}>
        {t("models.loadError")}
      </ErrorState>
    );
  }
  if (data.models.length === 0) {
    return <EmptyState icon={Boxes}>{t("models.empty")}</EmptyState>;
  }

  // The assessment surface only exists when the pipeline stamped one (older
  // BOMs and non-assessed runs render exactly as before).
  const hasDsAssessment = data.datasets.some((d) => d.assessment);
  const hasAssessment = data.models.some((m) => m.assessment) || hasDsAssessment;

  return (
    <div className="space-y-6">
      {data.models.map((m, i) => (
        <ModelCardView key={m.purl || `${m.name}-${i}`} model={m} />
      ))}
      {data.datasets.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Database className="h-4 w-4 text-muted-foreground" aria-hidden />
            {t("models.datasets")}
            <span className="tabular-nums text-muted-foreground">{data.datasets.length}</span>
          </div>
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full text-left text-xs">
              <thead className="border-b bg-muted/40 text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("models.dsName")}
                  </th>
                  {hasDsAssessment && (
                    <th scope="col" className="px-3 py-2 font-medium">
                      {t("models.dsAssessment")}
                    </th>
                  )}
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("models.dsLicense")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("models.dsIntegrity")}
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("models.dsSource")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.datasets.map((d) => (
                  <tr key={d.name} className="border-b last:border-0">
                    <td className="px-3 py-2 align-top">
                      <span className="font-mono">{d.name}</span>
                      {d.version && (
                        <span className="text-muted-foreground">@{d.version}</span>
                      )}
                      {d.url && (
                        <a
                          href={d.url}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-0.5 flex items-center gap-1 break-all text-primary underline-offset-2 hover:underline"
                        >
                          <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                          {d.url}
                        </a>
                      )}
                    </td>
                    {hasDsAssessment && (
                      <td className="px-3 py-2 align-top">
                        {d.assessment ? (
                          <GradeBadge grade={d.assessment} />
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                    )}
                    <td className="px-3 py-2 align-top">
                      {/* An unreadable repository is said so, rather than shown as
                          a dataset with no license — the two mean different things. */}
                      {d.unresolved ? (
                        <Badge variant="outline">{t("models.dsUnresolved")}</Badge>
                      ) : d.licenses.length > 0 ? (
                        <span className="font-mono">{d.licenses.join(", ")}</span>
                      ) : (
                        <span className="text-muted-foreground">{t("models.dsNoLicense")}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 align-top">
                      {d.hasIntegrity ? (
                        <CircleCheck className="h-4 w-4 text-emerald-600" aria-hidden />
                      ) : (
                        <CircleDashed className="h-4 w-4 text-muted-foreground" aria-hidden />
                      )}
                      <span className="sr-only">
                        {d.hasIntegrity ? t("models.dsHashed") : t("models.dsNotHashed")}
                      </span>
                    </td>
                    <td className="px-3 py-2 align-top">
                      {d.sources.length > 0 ? (
                        <span className="break-all">{d.sources.join(", ")}</span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {hasAssessment && (
        <p className="text-xs text-muted-foreground">{t("models.disclaimer")}</p>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-0.5">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm">{children}</div>
    </div>
  );
}

/**
 * The pipeline's stamped verdict: per-axis grades (an unevaluated axis shows
 * "—"), the grounds, the custom-license excerpt and the lineage warning. Pure
 * display — every value comes verbatim from the SBOM properties.
 */
function AssessmentBlock({
  assessment: a,
  customLicenseQuote,
  lineageConflictWith,
}: {
  assessment: ModelAssessment;
  customLicenseQuote?: string;
  lineageConflictWith?: string;
}) {
  const { t } = useTranslation();
  const axes: Array<{ key: string; label: string; grade?: AssessmentGrade }> = [
    { key: "license", label: t("models.assessLicense"), grade: a.license },
    { key: "security", label: t("models.assessSecurity"), grade: a.security },
    { key: "datasets", label: t("models.assessDatasets"), grade: a.datasets },
  ];

  return (
    <div className="space-y-3 rounded-md border bg-muted/30 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">{t("models.assessment")}</span>
        {axes.map(({ key, label, grade }) => (
          <span
            key={key}
            className="inline-flex items-center gap-1.5 rounded-md border bg-background px-2 py-1 text-xs text-foreground"
          >
            {label}
            {grade ? (
              <GradeBadge grade={grade} />
            ) : (
              <>
                <span className="text-muted-foreground" aria-hidden>
                  —
                </span>
                <span className="sr-only">{t("models.assessNotEvaluated")}</span>
              </>
            )}
          </span>
        ))}
      </div>

      {a.usageContext && (
        <Field label={t("models.usageContext")}>
          {t(USAGE_LABEL_KEY[a.usageContext])}
        </Field>
      )}

      {a.reasons.length > 0 && (
        <Field label={t("models.reasons")}>
          <ul className="list-inside list-disc text-sm text-muted-foreground">
            {a.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </Field>
      )}

      {customLicenseQuote && (
        <Field label={t("models.customLicenseQuote")}>
          <p className="border-l-2 border-border pl-3 text-sm italic text-muted-foreground">
            {customLicenseQuote}
          </p>
        </Field>
      )}

      {lineageConflictWith && (
        <p className="flex items-start gap-1.5 text-xs text-foreground">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-risk-high" aria-hidden />
          {t("models.lineageConflict", { name: lineageConflictWith })}
        </p>
      )}
    </div>
  );
}

function ModelCardView({ model: m }: { model: ModelCard }) {
  const { t } = useTranslation();
  const axes: Array<{ key: keyof ModelCard["disclosure"]; label: string }> = [
    { key: "weights", label: t("models.axisWeights") },
    { key: "architecture", label: t("models.axisArchitecture") },
    { key: "trainingData", label: t("models.axisTrainingData") },
    { key: "trainingProcess", label: t("models.axisTrainingProcess") },
  ];

  return (
    <Card>
      <CardContent className="space-y-4 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Boxes className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="font-mono text-sm font-medium text-foreground">
            {m.group ? `${m.group} / ` : ""}
            {m.name}
            {m.version ? <span className="text-muted-foreground"> {m.version}</span> : null}
          </span>
          {m.assessment && <GradeBadge grade={m.assessment.overall} />}
          {m.licenses.map((l) => (
            <Badge key={l} variant="muted">
              {l}
            </Badge>
          ))}
        </div>

        {m.assessment && (
          <AssessmentBlock
            assessment={m.assessment}
            customLicenseQuote={m.customLicenseQuote}
            lineageConflictWith={m.lineageConflictWith}
          />
        )}

        {m.description && (
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
            {m.description}
          </p>
        )}

        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {m.architecture && <Field label={t("models.architecture")}>{m.architecture}</Field>}
          {m.task && <Field label={t("models.task")}>{m.task}</Field>}
          {m.supplier && <Field label={t("models.supplier")}>{m.supplier}</Field>}
          <Field label={t("models.integrity")}>
            <span className={m.hasIntegrity ? "text-foreground" : "text-muted-foreground"}>
              {m.hasIntegrity ? t("models.integrityYes") : t("models.integrityNo")}
            </span>
          </Field>
        </div>

        {m.purl && (
          <Field label={t("models.identifier")}>
            <span className="break-all font-mono text-xs">{m.purl}</span>
          </Field>
        )}

        <div className="space-y-1.5">
          <div className="text-xs text-muted-foreground" title={t("models.disclosureHint")}>
            {t("models.disclosure")}
          </div>
          <div className="flex flex-wrap gap-2">
            {axes.map(({ key, label }) => {
              const on = m.disclosure[key];
              const Icon = on ? CircleCheck : CircleDashed;
              return (
                <span
                  key={key}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs",
                    on ? "text-foreground" : "text-muted-foreground",
                  )}
                  title={on ? t("models.documented") : t("models.notDocumented")}
                >
                  <Icon
                    className={cn("h-3.5 w-3.5", on ? "text-risk-low" : "text-muted-foreground/60")}
                    aria-hidden
                  />
                  {label}
                  <span className="sr-only">
                    : {on ? t("models.documented") : t("models.notDocumented")}
                  </span>
                </span>
              );
            })}
          </div>
        </div>

        {m.limitations.length > 0 && (
          <Field label={t("models.limitations")}>
            <ul className="list-inside list-disc text-sm text-muted-foreground">
              {m.limitations.map((l, i) => (
                <li key={i}>{l}</li>
              ))}
            </ul>
          </Field>
        )}

        {m.externalRefs.length > 0 && (
          <Field label={t("models.references")}>
            <ul className="space-y-0.5">
              {m.externalRefs.map((r) => (
                <li key={r.url}>
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 break-all text-primary underline-offset-2 hover:underline"
                  >
                    <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                    <span className="text-muted-foreground">{r.type}:</span> {r.url}
                  </a>
                </li>
              ))}
            </ul>
          </Field>
        )}
      </CardContent>
    </Card>
  );
}
