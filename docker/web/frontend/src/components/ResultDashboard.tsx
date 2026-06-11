import { CheckCircle2, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { DoneEvent } from "@/lib/api";

import { ComponentsTable } from "./ComponentsTable";
import { KpiCards } from "./KpiCards";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

export function ResultDashboard({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  const ok = result.ok;
  const componentCount = result.sbom?.components ?? 0;
  const vulnCount = result.security?.TOTAL ?? 0;

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
          </TabsList>

          <TabsContent value="summary" className="space-y-6 pt-4">
            {result.security ? (
              <SeverityBar security={result.security} />
            ) : (
              <p className="text-sm text-muted-foreground">
                {t("result.noSecurity")}
              </p>
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
              <p className="text-sm text-muted-foreground">
                {t("result.noSecurity")}
              </p>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
