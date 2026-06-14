import { CheckCircle2, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EmptyState } from "@/components/ui/state";
import type { DoneEvent } from "@/lib/api";

import { ComponentsTable } from "./ComponentsTable";
import { DependenciesPanel } from "./DependenciesPanel";
import { KpiCards } from "./KpiCards";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";
import { SourceTreePanel } from "./SourceTreePanel";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

export function ResultDashboard({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  const ok = result.ok;
  const componentCount = result.sbom?.components ?? 0;
  const vulnCount = result.security?.TOTAL ?? 0;

  // Raw artifacts the dependency/source views fetch and parse client-side.
  const sbomFile = result.results.find((r) => r.name.endsWith("_bom.json"))?.name;
  const scancodeFile = result.results.find((r) => r.name.includes("_scancode"))?.name;

  return (
    <Card className="animate-fade-in">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-base">
          {ok ? (
            <CheckCircle2 className="h-5 w-5 text-emerald-500" />
          ) : (
            <XCircle className="h-5 w-5 text-destructive" />
          )}
          {ok ? t("result.succeeded") : t("result.failed")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <KpiCards
          sbom={result.sbom}
          security={result.security}
          conformance={result.conformance}
        />

        <Tabs defaultValue="summary">
          <TabsList>
            <TabsTrigger value="summary">{t("result.tabSummary")}</TabsTrigger>
            <TabsTrigger value="components">
              {t("result.tabComponents")}
              <span className="ml-1.5 tabular-nums text-muted-foreground">
                {componentCount}
              </span>
            </TabsTrigger>
            <TabsTrigger value="vulns">
              {t("result.tabVulns")}
              <span className="ml-1.5 tabular-nums text-muted-foreground">
                {vulnCount}
              </span>
            </TabsTrigger>
            {sbomFile && (
              <TabsTrigger value="deps">{t("result.tabDependencies")}</TabsTrigger>
            )}
            {scancodeFile && (
              <TabsTrigger value="sourceTree">
                {t("result.tabSourceTree")}
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="summary" className="space-y-6 pt-4">
            {result.security ? (
              <SeverityBar security={result.security} />
            ) : (
              <EmptyState>{t("result.noSecurity")}</EmptyState>
            )}
            <div className="space-y-3">
              <div className="text-sm font-medium">{t("result.artifacts")}</div>
              <ResultsList results={result.results} />
            </div>
          </TabsContent>

          <TabsContent value="components" className="pt-4">
            <ComponentsTable
              items={result.sbom?.componentList ?? []}
              total={componentCount}
              truncated={result.sbom?.truncated}
            />
          </TabsContent>

          <TabsContent value="vulns" className="pt-4">
            {result.security ? (
              <VulnerabilitiesTable security={result.security} />
            ) : (
              <EmptyState>{t("result.noSecurity")}</EmptyState>
            )}
          </TabsContent>

          {sbomFile && (
            <TabsContent value="deps" className="pt-4">
              <DependenciesPanel sbomFile={sbomFile} />
            </TabsContent>
          )}

          {scancodeFile && (
            <TabsContent value="sourceTree" className="pt-4">
              <SourceTreePanel scancodeFile={scancodeFile} />
            </TabsContent>
          )}
        </Tabs>
      </CardContent>
    </Card>
  );
}
