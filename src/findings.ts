// Builds findings from the catalog, so group, severity and impact live in one place
// (catalog/index.ts). A check may lower a severity for one case (one bad MX host among good ones).
import { catalogEntry } from "./catalog/index.ts";
import type { FindingVars } from "./finding-vars.ts";
import { type Finding, type FindingId, type Group, type GroupStatus, SEVERITIES, type Severity } from "./types.ts";

/** Most serious first: the order in which a result lists its findings. */
export const SEVERITY_ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i])) as Readonly<
  Record<Severity, number>
>;

export interface FindingExtra {
  group?: Group;
  severity?: Severity;
  found?: string;
  vars?: FindingVars;
}

export function finding(id: FindingId, extra: FindingExtra = {}): Finding {
  const entry = catalogEntry(id);
  if (!entry) throw new Error(`no catalog entry for ${id}`);
  const group = extra.group ?? (entry.group === "any" ? undefined : entry.group);
  if (!group) throw new Error(`${id} needs the group it affects`);
  const f: Finding = { id, group, severity: extra.severity ?? entry.severity, impact: entry.impact, fixes: [] };
  if (extra.found !== undefined) f.found = extra.found;
  if (extra.vars) f.vars = extra.vars;
  return f;
}

/**
 * A group's status: a critical finding fails it; with `unknown`, a group without one is unknown;
 * otherwise a warning weakens it. Hardening findings never count.
 */
export function statusOf(findings: readonly Finding[], { unknown = false }: { unknown?: boolean } = {}): GroupStatus {
  if (findings.some((f) => f.severity === "critical" && f.impact !== "hardening")) return "fail";
  if (unknown) return "unknown";
  if (findings.some((f) => f.severity === "warning" && f.impact !== "hardening")) return "weak";
  return "pass";
}
