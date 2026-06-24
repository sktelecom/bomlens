import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/ui/state";
import type { DoneEvent } from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { sbomFileName, scancodeFileName } from "@/lib/results";

import { ComponentsTable } from "./ComponentsTable";
import { DependenciesPanel } from "./DependenciesPanel";
import { KpiCards } from "./KpiCards";
import { LicenseSummary } from "./LicenseSummary";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";
import { SourceTreePanel } from "./SourceTreePanel";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

/**
 * Renders one result section's content inside the shell canvas. The components
 * are the same ones the classic dashboard used — Phase 1 only moves them out of
 * the tab layout and under the left-rail nav (no content change).
 */
export function ResultSection({
  section,
  result,
}: {
  section: SectionId;
  result: DoneEvent;
}) {
  const { t } = useTranslation();

  switch (section) {
    case "overview":
      return <OverviewSection result={result} />;

    case "components":
      return (
        <ComponentsTable
          items={result.sbom?.componentList ?? []}
          total={result.sbom?.components ?? 0}
          truncated={result.sbom?.truncated}
        />
      );

    case "vulnerabilities":
      return result.security ? (
        <VulnerabilitiesTable security={result.security} />
      ) : (
        <EmptyState>{t("result.noSecurity")}</EmptyState>
      );

    case "dependencies": {
      const sbomFile = sbomFileName(result);
      return sbomFile ? <DependenciesPanel sbomFile={sbomFile} /> : null;
    }

    case "sourceTree": {
      const scancodeFile = scancodeFileName(result);
      return scancodeFile ? (
        <SourceTreePanel scancodeFile={scancodeFile} />
      ) : null;
    }

    // g7 / models are AI surfaces wired in Phase 3.
    default:
      return null;
  }
}

/**
 * Overview = the classic "Summary" tab: the vendored-source nudge, the KPI
 * cards, the severity distribution, the license summary and the generated
 * artifacts. Same information, same order.
 */
function OverviewSection({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-6">
      {result.sbom?.suggestIdentifyVendored && (
        <div className="rounded-md border border-amber-300/60 bg-amber-50 px-4 py-3 text-amber-900 dark:border-amber-400/20 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="text-sm font-medium">{t("result.vendoredHintTitle")}</div>
          <p className="mt-1 text-xs">{t("result.vendoredHintBody")}</p>
        </div>
      )}

      <KpiCards
        sbom={result.sbom}
        security={result.security}
        conformance={result.conformance}
      />

      {result.security ? (
        <SeverityBar security={result.security} />
      ) : (
        <EmptyState>{t("result.noSecurity")}</EmptyState>
      )}

      <LicenseSummary components={result.sbom?.componentList ?? []} />

      <div className="space-y-3">
        <div className="text-sm font-medium">{t("result.artifacts")}</div>
        <ResultsList results={result.results} />
      </div>
    </div>
  );
}
