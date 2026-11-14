// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The name a scan is shown under: "project version" (SpringBootDemo 1.1.0),
 * never the run folder id (SpringBootDemo_1.1.0, or a timestamped variant),
 * which is an address rather than a name.
 *
 * Used by the top bar's path, the result heading and the run and failure
 * screens, so a scan reads the same everywhere.
 */

export interface ProjectName {
  name: string;
  version?: string;
}

/** The fields of a stored scan the name is read from. */
interface ScanMeta {
  id: string;
  project: string;
  version: string;
}

/** The settings a scan ran with (the part that names it). */
interface ConfigName {
  project?: string;
  version?: string;
}

/**
 * Name the scan `id`. The scan list wins, since it is what the server stored
 * for the run; then the settings the scan ran with. The id itself is the last
 * resort, for a run neither of them describes.
 */
export function scanProjectName(
  id: string,
  recent: readonly ScanMeta[],
  config?: ConfigName | null,
): ProjectName {
  const meta = recent.find((s) => s.id === id);
  if (meta?.project) return withVersion(meta.project, meta.version);
  if (config?.project) return withVersion(config.project, config.version);
  return { name: id };
}

function withVersion(name: string, version?: string): ProjectName {
  return version ? { name, version } : { name };
}

/** "SpringBootDemo 1.1.0", or the name alone when there is no version. */
export function projectText(p: ProjectName | undefined): string {
  if (!p) return "";
  return p.version ? `${p.name} ${p.version}` : p.name;
}
