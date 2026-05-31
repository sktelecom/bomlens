import { Package, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type { SbomSummary, SecuritySummary } from "@/lib/api";

interface Props {
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
}

export function KpiCards({ sbom, security }: Props) {
  const { t } = useTranslation();
  const items = [
    { Icon: Package, label: t("result.components"), value: sbom?.components ?? 0 },
    {
      Icon: ShieldAlert,
      label: t("result.vulnerabilities"),
      value: security ? security.TOTAL : null,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4">
      {items.map(({ Icon, label, value }) => (
        <Card key={label}>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="text-2xl font-semibold tabular-nums">
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
