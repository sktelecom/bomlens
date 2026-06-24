/**
 * Joins component vulnerability data (from the Components join, Phase 2a) into
 * the dependency views so the graph and tree can mark which packages carry
 * known vulnerabilities. Keyed by name@version since the graph nodes expose
 * name/version, not the raw purl.
 */
import type { ComponentItem, Severity } from "./api";

function keyOf(name: string, version: string): string {
  return `${(name || "").toLowerCase()}@${version || ""}`;
}

/** name@version → worst severity, for components that have any vulnerability. */
export function vulnSeverityIndex(components: ComponentItem[]): Map<string, Severity> {
  const index = new Map<string, Severity>();
  for (const c of components) {
    if (c.maxSeverity) index.set(keyOf(c.name, c.version), c.maxSeverity);
  }
  return index;
}

/** Look up the worst severity for a graph/tree node, if it is vulnerable. */
export function severityFor(
  index: Map<string, Severity>,
  name: string,
  version: string,
): Severity | undefined {
  return index.get(keyOf(name, version));
}
