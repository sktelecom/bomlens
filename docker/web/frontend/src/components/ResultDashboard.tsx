import { CheckCircle2, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { DoneEvent } from "@/lib/api";

import { KpiCards } from "./KpiCards";
import { ResultsList } from "./ResultsList";
import { SeverityBar } from "./SeverityBar";

export function ResultDashboard({ result }: { result: DoneEvent }) {
  const { t } = useTranslation();
  const ok = result.ok;

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
        {result.security ? (
          <SeverityBar security={result.security} />
        ) : (
          <p className="text-sm text-muted-foreground">{t("result.noSecurity")}</p>
        )}
        <div className="space-y-3">
          <div className="text-sm font-medium">{t("result.artifacts")}</div>
          <ResultsList results={result.results} />
        </div>
      </CardContent>
    </Card>
  );
}
