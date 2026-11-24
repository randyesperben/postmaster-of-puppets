// The SPF check over a zone (checkSpf), and zones with an SPF record, a provider's record or
// n includes.
import { checkSpf } from "../../src/checks/spf.ts";
import { type Zone, zoneResolver } from "./zone.ts";

export const run = (zone: Zone, domain = "example.com") => checkSpf({ resolver: zoneResolver(zone) }, domain);
/** A cloud table with nothing in it, for cases about other kinds of opening. */
const NO_CLOUD = { v4: [], v6: [] };
export const runNoCloud = (zone: Zone) => checkSpf({ resolver: zoneResolver(zone) }, "example.com", NO_CLOUD);
export const spf = (record: string, extra: Zone = {}): Zone => ({ "example.com": { TXT: [record] }, ...extra });
export const provider = (record = "v=spf1 ip4:192.0.2.0/24 -all"): Zone => ({ "_spf.example.net": { TXT: [record] } });

/**
 * n include: terms s1..sN, each to a record with no further lookups, and the zone of their records.
 */
export function includeTerms(n: number): { zone: Zone; terms: string[] } {
  const zone: Zone = {};
  const terms: string[] = [];
  for (let i = 1; i <= n; i++) {
    zone[`s${i}.example.net`] = { TXT: [`v=spf1 ip4:192.0.2.${i} -all`] };
    terms.push(`include:s${i}.example.net`);
  }
  return { zone, terms };
}

/** example.com's SPF record with n include: terms, and their records. */
export function includes(n: number): Zone {
  const { zone, terms } = includeTerms(n);
  return { ...zone, "example.com": { TXT: [`v=spf1 ${terms.join(" ")} -all`] } };
}
