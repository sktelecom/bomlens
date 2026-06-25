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
    label: string;
    value: string | number | null;
    valueClass?: string;
    target?: SectionId;
  }> = [
    { label: t("result.components"), value: sbom?.components ?? 0, target: "components" },
    {
      label: t("result.vulnerabilities"),
      value: security ? security.TOTAL : null,
      target: security ? "vulnerabilities" : undefined,
    },
  ];

  if (conformance) {
    const pass = conformance.result === "pass";
    const hasG7 = Boolean(conformance.checks?.some((c) => c.id?.startsWith("g7-")));
    items.push({
      label: t("result.conformance"),
      value: pass ? t("result.verdictPass") : t("result.verdictFail"),
      valueClass: pass ? "text-emerald-500" : "text-destructive",
      target: hasG7 ? "g7" : undefined,
    });
  }

  return (
    <div className={conformance ? "grid grid-cols-3 gap-4" : "grid grid-cols-2 gap-4"}>
      {items.map(({ label, value, valueClass, target }) => {
        const linkable = Boolean(target && scanId);
        const card = (
          <Card
            className={cn(
              "h-full",
              linkable &&
                "transition-colors duration-fast ease-out-soft hover:border-brand/40 hover:bg-muted/50",
            )}
          >
            {/* Label above a large number, no icon — matches the design's
                stat tiles (Image #3). */}
            <CardContent className="flex flex-col gap-1.5 p-5">
              <div className="truncate text-xs text-muted-foreground">{label}</div>
              <div
                className={"text-3xl font-semibold tabular-nums " + (valueClass ?? "")}
              >
                {value ?? "—"}
              </div>
            </CardContent>
          </Card>
        );
        return linkable ? (
          <a
            key={label}
            href={scanHash(scanId as string, target as SectionId)}
            aria-label={t("overview.jumpHint", { section: label })}
            className="rounded-xl text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
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
