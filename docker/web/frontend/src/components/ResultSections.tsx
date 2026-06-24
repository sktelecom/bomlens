import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/ui/state";
import type { DoneEvent } from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { sbomFileName, scancodeFileName } from "@/lib/results";

import { ArtifactsSection, Overview } from "./Overview";
import { ComponentsTable } from "./ComponentsTable";
import { DependenciesPanel } from "./DependenciesPanel";
import { ModelsDatasets } from "./ModelsDatasets";
import { SourceTreePanel } from "./SourceTreePanel";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

/**
 * Renders one result section's content inside the shell canvas. The detail
 * components are the same ones the classic dashboard used; the Overview is the
 * decision-first landing (needs-attention + summaries + jump cards).
 */
export function ResultSection({
  section,
  result,
  onNavigate,
}: {
  section: SectionId;
  result: DoneEvent;
  onNavigate: (section: SectionId) => void;
}) {
  const { t } = useTranslation();

  switch (section) {
    case "overview":
      return <Overview result={result} onNavigate={onNavigate} />;

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
      return sbomFile ? (
        <DependenciesPanel
          sbomFile={sbomFile}
          components={result.sbom?.componentList ?? []}
        />
      ) : null;
    }

    case "sourceTree": {
      const scancodeFile = scancodeFileName(result);
      return scancodeFile ? <SourceTreePanel scancodeFile={scancodeFile} /> : null;
    }

    case "artifacts":
      return <ArtifactsSection result={result} />;

    case "models": {
      const sbomFile = sbomFileName(result);
      return sbomFile ? <ModelsDatasets sbomFile={sbomFile} /> : null;
    }

    // g7 is an AI surface wired in a later phase (needs the backend G7 checks).
    default:
      return null;
  }
}
