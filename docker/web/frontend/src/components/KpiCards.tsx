import { BadgeCheck, Package, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type {
  ConformanceSummary,
  SbomSummary,
  SecuritySummary,
} from "@/lib/api";

interface Props {
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
  conformance?: ConformanceSummary | null;
}

export function KpiCards({ sbom, security, conformance }: Props) {
  const { t } = useTranslation();
  const items: Array<{
    Icon: typeof Package;
    label: string;
    value: string | number | null;
    valueClass?: string;
  }> = [
    { Icon: Package, label: t("result.components"), value: sbom?.components ?? 0 },
    {
      Icon: ShieldAlert,
      label: t("result.vulnerabilities"),
      value: security ? security.TOTAL : null,
    },
  ];

  if (conformance) {
    const pass = conformance.result === "pass";
    items.push({
      Icon: BadgeCheck,
      label: t("result.conformance"),
      value: pass ? t("result.verdictPass") : t("result.verdictFail"),
      valueClass: pass ? "text-emerald-500" : "text-destructive",
    });
  }

  return (
    <div className={conformance ? "grid grid-cols-3 gap-4" : "grid grid-cols-2 gap-4"}>
      {items.map(({ Icon, label, value, valueClass }) => (
        <Card key={label}>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className={"text-2xl font-semibold tabular-nums " + (valueClass ?? "")}>
                {value ?? "—"}
              </div>
              <div className="truncate text-xs text-muted-foreground">{label}</div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
