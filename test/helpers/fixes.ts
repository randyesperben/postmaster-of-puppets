// For the fix scenarios: a resolver that leaves some queries unanswered, and every fix of a report.
import { LookupError } from "../../src/dns/doh.ts";
import type { Resolver } from "../../src/dns/types.ts";
import type { Fix, Report } from "../../src/types.ts";
import { type Zone, zoneResolver } from "./zone.ts";

/** A zone where the queries listed ("<name> <TYPE>") get no answer from any operator. */
export function failing(
  zone: Zone,
  unanswered: readonly string[],
  options: Parameters<typeof zoneResolver>[1] = {},
): Resolver {
  const inner = zoneResolver(zone, options);
  return {
    query(name, type, opts) {
      if (unanswered.includes(`${name.toLowerCase()} ${type.toUpperCase()}`))
        return Promise.reject(new LookupError("unreachable", `no resolver answered ${name}`));
      return inner.query(name, type, opts);
    },
  };
}

export const allFixes = (r: Report): Fix[] => r.findings.flatMap((f) => f.fixes);
