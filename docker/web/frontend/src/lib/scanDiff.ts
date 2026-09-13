// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Diff two scans' component and vulnerability lists. Pure and unit tested so
 * "what changed since the last submission" is verifiable independently of
 * the Overview card that shows it.
 */
import type { ComponentItem, VulnItem } from "./api";

export interface ChangedComponent {
  name: string;
  group: string;
  from: string;
  to: string;
}

export interface ComponentDiff {
  added: ComponentItem[];
  removed: ComponentItem[];
  changed: ChangedComponent[];
}

export interface VulnDiff {
  new: VulnItem[];
  resolved: VulnItem[];
}

/** Group + name identifies the same component across versions; the version
 *  itself is what a "changed" entry compares. */
function componentKey(c: ComponentItem): string {
  return `${c.group}/${c.name}`;
}

/**
 * Which components were added, removed, or moved to a different version,
 * between a previous scan and the current one.
 */
export function diffComponents(prev: ComponentItem[], curr: ComponentItem[]): ComponentDiff {
  const prevByKey = new Map<string, ComponentItem>();
  for (const c of prev) prevByKey.set(componentKey(c), c);

  const added: ComponentItem[] = [];
  const changed: ChangedComponent[] = [];
  const seen = new Set<string>();
  for (const c of curr) {
    const key = componentKey(c);
    seen.add(key);
    const p = prevByKey.get(key);
    if (!p) {
      added.push(c);
    } else if (p.version !== c.version) {
      changed.push({ name: c.name, group: c.group, from: p.version, to: c.version });
    }
  }

  const removed = prev.filter((c) => !seen.has(componentKey(c)));
  return { added, removed, changed };
}

/** Which CVEs are new since the previous scan, and which no longer appear. */
export function diffVulnerabilities(prev: VulnItem[], curr: VulnItem[]): VulnDiff {
  const prevIds = new Set(prev.map((v) => v.id));
  const currIds = new Set(curr.map((v) => v.id));
  return {
    new: curr.filter((v) => !prevIds.has(v.id)),
    resolved: prev.filter((v) => !currIds.has(v.id)),
  };
}
