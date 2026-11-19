// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * CSV serialisation for the result tables, so a filtered list can be taken into
 * a spreadsheet and turned into a report.
 *
 * Pure and offline: the rows the user is looking at are already in the browser,
 * so nothing is asked of the server and nothing about the scan leaves the
 * machine, which is the same bargain the rest of this tool makes.
 *
 * Quoting follows RFC 4180. It matters more here than in most tables: package
 * names carry commas in their license lists, CVE titles carry quotes, and a
 * description can carry a newline. Any of the three, unescaped, silently shifts
 * every later column of that row into the wrong place — a corrupted report that
 * still opens.
 */

import type { ComponentItem, VulnItem } from "./api";

/** Values a cell can hold before it is rendered. */
export type CsvValue = string | number | boolean | null | undefined;

function quote(value: CsvValue): string {
  if (value === null || value === undefined) return "";
  const s = String(value);
  // A leading =, +, - or @ makes a spreadsheet treat the cell as a formula.
  // Prefixing with a quote keeps it text, which is what a package name is.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/**
 * Rows to a CSV document. The first row is the header.
 *
 * CRLF line endings, as RFC 4180 specifies and as Excel expects; a bare LF is
 * read as a line break inside a cell by some readers.
 */
export function toCsv(rows: readonly (readonly CsvValue[])[]): string {
  return rows.map((row) => row.map(quote).join(",")).join("\r\n");
}

/**
 * A filename that says which scan and which list it came from, and sorts by
 * date in a folder. Anything a filesystem would refuse becomes a hyphen.
 */
export function csvFilename(scanId: string, section: string, stamp: string): string {
  const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return `${safe(scanId) || "scan"}-${safe(section)}-${safe(stamp)}.csv`;
}

/**
 * Hand the CSV to the browser as a download.
 *
 * A UTF-8 byte-order mark leads the file: without it Excel reads the bytes as
 * the system codepage, and a Korean license name or a package with an accent
 * arrives as mojibake. Other readers ignore the mark.
 */
export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob(["﻿", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoked on the next tick: revoking synchronously can cancel the download
  // in some browsers before it has read the blob.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * The Components table as CSV rows, in the order the table is showing them.
 *
 * Exporting what is on screen — the current filter, the current sort — is the
 * point: the reader has already narrowed the list to the thing they mean to
 * report on, and an export of everything would make them do it twice.
 *
 * Columns beyond the visible ones are included where they answer the next
 * question a spreadsheet gets asked (the purl for identity, the counts for
 * sorting), but nothing here is derived: every cell is a field of the row.
 */
export function componentCsvRows(
  items: readonly ComponentItem[],
  headers: readonly string[],
): CsvValue[][] {
  return [
    [...headers],
    ...items.map((c) => [
      c.name,
      c.version,
      c.type,
      c.licenses.join(", "),
      c.scope ?? "",
      c.vulnCount ?? 0,
      c.maxSeverity ?? "",
      c.purl,
    ]),
  ];
}

/** The Vulnerabilities table as CSV rows, in the order the table is showing them. */
export function vulnCsvRows(
  items: readonly VulnItem[],
  headers: readonly string[],
): CsvValue[][] {
  return [
    [...headers],
    ...items.map((v) => [
      v.id,
      v.severity,
      v.pkg,
      v.installed,
      v.fixed,
      v.cvss ?? "",
      v.epss ?? "",
      v.kev ? "yes" : "",
      v.title,
      (v.introducedBy ?? []).map((d) => (d.version ? `${d.name} ${d.version}` : d.name)).join("; "),
    ]),
  ];
}
