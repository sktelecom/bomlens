import { BadgeCheck, Package, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import type {
  ConformanceSummary,
  SbomSummary,
  SecuritySummary,
} from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { scanHash } from "@/lib/route";
import { cn } from "@/lib/utils";

interface Props {
  sbom: SbomSummary | null;
  security: SecuritySummary | null;
  conformance?: ConformanceSummary | null;
  /** When set, cards with a target become links into that section. */
  scanId?: string | null;
}

export function KpiCards({ sbom, security, conformance, scanId }: Props) {
  const { t } = useTranslation();
  const items: Array<{
    Icon: typeof Package;
    label: string;
    value: string | number | null;
    valueClass?: string;
    target?: SectionId;
  }> = [
    { Icon: Package, label: t("result.components"), value: sbom?.components ?? 0, target: "components" },
    {
      Icon: ShieldAlert,
      label: t("result.vulnerabilities"),
      value: security ? security.TOTAL : null,
      target: security ? "vulnerabilities" : undefined,
    },
  ];

  if (conformance) {
    const pass = conformance.result === "pass";
    const hasG7 = Boolean(conformance.checks?.some((c) => c.id?.startsWith("g7-")));
    items.push({
      Icon: BadgeCheck,
      label: t("result.conformance"),
      value: pass ? t("result.verdictPass") : t("result.verdictFail"),
      valueClass: pass ? "text-emerald-500" : "text-destructive",
      target: hasG7 ? "g7" : undefined,
    });
  }

  return (
    <div className={conformance ? "grid grid-cols-3 gap-4" : "grid grid-cols-2 gap-4"}>
      {items.map(({ Icon, label, value, valueClass, target }) => {
        const linkable = Boolean(target && scanId);
        const card = (
          <Card
            className={cn(
              "h-full",
              linkable &&
                "transition-colors duration-fast ease-out-soft hover:border-brand/40 hover:bg-muted/50",
            )}
          >
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
        );
        return linkable ? (
          <a
            key={label}
            href={scanHash(scanId as string, target as SectionId)}
            aria-label={t("overview.jumpHint", { section: label })}
            className="rounded-lg text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          >
            {card}
          </a>
        ) : (
          <div key={label}>{card}</div>
        );
      })}
    </div>
  );
}
