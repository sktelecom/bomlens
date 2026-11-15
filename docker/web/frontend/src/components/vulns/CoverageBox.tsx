// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon } from "@primer/octicons-react";
import { Table } from "@primer/react/experimental";
import type { ElementType, ReactNode } from "react";

import { OvBox } from "@/components/overview/parts";

/**
 * A box for what the findings list leaves out (unchecked components, findings
 * judged not reachable, advisories with no CVE): a title, one explanatory line
 * and, when there are rows, a folded table of them.
 */
export function CoverageBox({
  testId,
  icon,
  title,
  hint,
  listLabel,
  columns,
  grid,
  rows,
  note,
}: {
  testId: string;
  icon: ElementType;
  title: string;
  hint: ReactNode;
  listLabel: string;
  columns: { label: string; align?: "start" | "end" }[];
  /** CSS grid-template-columns of the table. */
  grid: string;
  rows: { key: string; cells: ReactNode[] }[];
  /** Under the table, e.g. that the list is cut off. */
  note?: ReactNode;
}) {
  return (
    <OvBox title={title} icon={icon} testId={testId}>
      <div className="bl-box-body bl-v-cov">
        <p className="bl-muted bl-flat">{hint}</p>
        {rows.length > 0 && (
          <details className="bl-v-fold">
            <summary>
              <span className="bl-chev">
                <ChevronRightIcon size={16} />
              </span>
              <span className="bl-strong">{listLabel}</span>
            </summary>
            {/* Capped like the old list: 500 rows must not push the table off the screen. */}
            <div className="bl-v-covscroll" role="region" aria-label={listLabel} tabIndex={0}>
            <Table.Container className="bl-v-covtbl">
              <Table aria-label={listLabel} gridTemplateColumns={grid} cellPadding="condensed">
                <Table.Head>
                  <Table.Row>
                    {columns.map((c) => (
                      <Table.Header key={c.label} align={c.align}>
                        {c.label}
                      </Table.Header>
                    ))}
                  </Table.Row>
                </Table.Head>
                <Table.Body>
                  {rows.map((r) => (
                    <Table.Row key={r.key}>
                      {r.cells.map((c, i) => (
                        <Table.Cell key={columns[i].label}>{c}</Table.Cell>
                      ))}
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            </Table.Container>
            </div>
            {note && <p className="bl-muted bl-small bl-v-covnote">{note}</p>}
          </details>
        )}
      </div>
    </OvBox>
  );
}
