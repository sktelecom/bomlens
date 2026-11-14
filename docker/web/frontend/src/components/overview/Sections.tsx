// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { GitBranchIcon, ShieldCheckIcon, ShieldIcon } from "@primer/octicons-react";
import type { ElementType } from "react";
import { useTranslation } from "react-i18next";

import type { DoneEvent, YoctoVex } from "@/lib/api";
import type { SectionId } from "@/lib/nav";
import { scanHash } from "@/lib/route";

import { OvBox, OvRow } from "./parts";

/**
 * What the figures in the navigation and the page header do not say, each with
 * the way to its section: how many vulnerability checks did not run or were
 * judged not reachable (the Vulnerabilities count leaves them out), and that
 * the dependency view holds no relationships. The component, vulnerability,
 * dependency, model, conformance and artifact counts are the navigation's
 * counts and are not repeated here. Renders nothing when neither applies.
 */
export function SectionsBox({
  result,
  scanId,
  hasDeps,
}: {
  result: DoneEvent;
  scanId: string | null;
  hasDeps: boolean;
}) {
  const { t } = useTranslation();
  const sec = result.security;
  const depTotal = (result.sbom?.directCount ?? 0) + (result.sbom?.transitiveCount ?? 0);
  // A 0 vulnerabilities covers only the components a check reached. Findings
  // judged not reachable are out of the total, as in the security report.
  const vulnNote = sec?.uncheckedCount
    ? t("result.uncheckedTile", { count: sec.uncheckedCount })
    : sec?.notReachableCount
      ? t("result.notReachableTile", { count: sec.notReachableCount })
      : undefined;
  const rows: { id: SectionId; icon: ElementType; note: string }[] = [
    ...(vulnNote ? [{ id: "vulnerabilities" as SectionId, icon: ShieldIcon, note: vulnNote }] : []),
    ...(hasDeps && depTotal === 0 ? [{ id: "dependencies" as SectionId, icon: GitBranchIcon, note: t("overview.depNone") }] : []),
  ];
  if (rows.length === 0) return null;
  return (
    <OvBox testId="sections" title={t("overview.summaryLabel")}>
      <ul className="bl-ovlist">
        {rows.map(({ id, icon, note }) => (
          <li key={id}>
            <OvRow href={scanId ? scanHash(scanId, id) : undefined} icon={icon}>
              <span style={{ display: "flex", alignItems: "baseline", gap: "var(--base-size-8)", flexWrap: "wrap" }}>
                <span>{t(`nav.${id}`)}</span>
                <span className="bl-muted bl-small">{note}</span>
              </span>
            </OvRow>
          </li>
        ))}
      </ul>
    </OvBox>
  );
}

/**
 * Vulnerability work the Yocto build already did.
 *
 * A Yocto SBOM carries bitbake's own CVE verdicts, and on a real image the
 * patched count dwarfs the open one (measured on core-image-minimal: 12255
 * patched, 63 not applicable, 0 open). The security panel lists only what is
 * still open, so without this note "0 vulnerabilities" would read as "nothing
 * was checked" instead of "the build closed all of them". Rendered only for
 * Yocto input; `yoctoVex` is null everywhere else.
 */
export function YoctoVexNote({ vex }: { vex: YoctoVex }) {
  const { t } = useTranslation();
  if (vex.fixed + vex.notAffected === 0) return null;
  return (
    <section className="bl-box" data-testid="yocto-vex">
      <div className="bl-box-body" style={{ display: "flex", gap: "var(--base-size-12)" }}>
        <span className="bl-success">
          <ShieldCheckIcon size={20} />
        </span>
        <div>
          <div className="bl-strong">{t("overview.yoctoVex.title")}</div>
          <p className="bl-muted bl-flat" style={{ marginTop: "var(--base-size-4)" }}>
            {vex.unresolved > 0
              ? t("overview.yoctoVex.withOpen", { fixed: vex.fixed, notAffected: vex.notAffected, open: vex.unresolved })
              : t("overview.yoctoVex.allHandled", { fixed: vex.fixed, notAffected: vex.notAffected })}
          </p>
        </div>
      </div>
    </section>
  );
}
