// The full check of the scenario tests: checkDomain over a case zone, the case zones themselves,
// and fixes applied back to a zone, step by step.
import { expect } from "vitest";
import { checkDomain, parseInput } from "../../src/index.ts";
import type { Ask, Finding, Fix, Report } from "../../src/types.ts";
import { chunks } from "./dns.ts";
import { rsaKey } from "./keys.ts";
import { type Node, SOA_RECORD, type Zone, zoneResolver } from "./zone.ts";

// Public, non-special addresses (ICANN's own block): documentation ranges count as unreachable.
export const P4 = "192.0.32.10";
/** A second public address next to P4, for an answer that differs. */
export const P4B = "192.0.32.11";
export const P6 = "2620:0:2d0:200::10";
export const RSA2048 = rsaKey(2048);
export const DKIM = chunks(`v=DKIM1; k=rsa; p=${RSA2048}`);
export const SOA = [SOA_RECORD];
export const RUA = "dmarc@example.com";

export function input(domain = "example.com") {
  const p = parseInput(domain);
  if (!p.ok) throw new Error(domain);
  return p;
}
export const check = (zone: Zone, domain = "example.com", extra: Partial<Parameters<typeof checkDomain>[1]> = {}) =>
  checkDomain(input(domain), { resolver: zoneResolver(zone), ...extra });
export const bad = (r: Report) =>
  r.findings.filter((f) => f.severity === "critical" || f.severity === "warning").map((f) => f.id);
/**
 * The findings that carry weaker: the reading that decides is the weaker of RFC 7489 and RFC 9989.
 */
export const weakerOf = (r: Report) => r.findings.filter((f) => f.vars?.weaker === 1).map((f) => f.id);

/**
 * What DMARC asks of receivers, as a number: higher asks more. Written out here rather than taken
 * from simulate.ts, so the tests do not check the engine against its own table.
 */
export const RANK: Record<Ask, number> = { nothing: 0, quarantine: 1, reject: 2 };
/**
 * The two readings a DMARC fix must never lower: the one that reads pct (simulation.asks) and the
 * one that reads none (sampled.full, where pct splits them).
 */
export const readings = (r: Report) => [
  RANK[r.simulation?.asks ?? "nothing"],
  RANK[r.simulation?.sampled?.full ?? r.simulation?.asks ?? "nothing"],
];

/** Expects that no report of `steps`, taken in order from `start`, lowers either reading. */
export function expectNoStepLowers(start: Report, steps: readonly Report[]): void {
  let before = readings(start);
  for (const s of steps) {
    const now = readings(s);
    expect(
      now.every((level, i) => level >= (before[i] ?? 0)),
      `${s.dmarc.record}: lowers a reading`,
    ).toBe(true);
    before = now;
  }
}

/** A domain on Google Workspace with everything right (case A of check.test.ts). */
export function googleZone(dmarc = `v=DMARC1; p=reject; rua=mailto:${RUA}`): Zone {
  return {
    "example.com": { SOA, MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
    "smtp.google.com": { A: [P4] },
    "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    "google._domainkey.example.com": { TXT: [DKIM] },
    "_dmarc.example.com": { TXT: [dmarc] },
  };
}

/** Google Workspace's zone plus a key at a selector, through a CNAME into target when given. */
export function withKey(sel: string, target?: string): Zone {
  const z = googleZone();
  const name = `${sel}._domainkey.example.com`;
  if (target) Object.assign(z, { [name]: { CNAME: [target] }, [target]: { TXT: [DKIM] } });
  else z[name] = { TXT: [DKIM] };
  return z;
}

/** A domain whose MX is `mx` and that has no SPF record. */
export const byMx = (mx: string): Zone => ({
  "example.com": { SOA, MX: [`10 ${mx}`] },
  [mx]: { A: [P4] },
  "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
});

/**
 * The SPF record of an include that authorizes a public range: a fresh node, as tests change zones.
 */
export const spfRange = (): Node => ({ TXT: ["v=spf1 ip4:192.0.32.0/24 -all"] });

export function applyFix(zone: Zone, fix: Fix, rua = RUA): Zone {
  const z: Zone = structuredClone(zone);
  const fill = (v: string) => v.split("{rua}").join(rua);
  const node: Node = (z[fix.name] ??= {});
  const list = ((node[fix.type] as (string | string[])[] | undefined) ?? []).slice();
  const text = (d: string | string[]) => (Array.isArray(d) ? d.join("") : d);
  if (fix.action === "add") list.push(fill(fix.value));
  else {
    const at = list.findIndex((d) => text(d) === fill(fix.replaces ?? ""));
    if (at < 0) throw new Error(`${fix.action}: ${fix.replaces} not found at ${fix.name}`);
    if (fix.action === "replace") list[at] = fill(fix.value);
    else list.splice(at, 1);
  }
  node[fix.type] = list;
  return z;
}

/** Applies the fixes of one finding step by step; returns the report after each step. */
export async function stepThrough(zone: Zone, f: Finding, domain = "example.com"): Promise<Report[]> {
  const steps = [...new Set(f.fixes.map((x) => x.step?.n ?? 1))].sort((a, b) => a - b);
  const out: Report[] = [];
  let z = zone;
  for (const n of steps) {
    for (const fix of f.fixes.filter((x) => (x.step?.n ?? 1) === n)) z = applyFix(z, fix);
    out.push(await check(z, domain));
  }
  return out;
}

// A domain whose signed DNS denies _domainkey: by default case A without its DKIM key, checked
// through a resolver that validates the signed zone.
export function signedNoKeys(
  zone: Zone = (() => {
    const z = googleZone();
    delete z["google._domainkey.example.com"];
    return z;
  })(),
) {
  return check(zone, "example.com", { resolver: zoneResolver(zone, { signed: true }) });
}

// shop.example.com sends (MX, SPF, DKIM) and has no DMARC record: it inherits example.com's.
export const inheritingShop = (parent: string): Zone => ({
  "example.com": { SOA },
  "_dmarc.example.com": { TXT: [parent] },
  "shop.example.com": { MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
  "smtp.google.com": { A: [P4] },
  "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
  "google._domainkey.shop.example.com": { TXT: [DKIM] },
});

/** shop.example.com with no record of its own, under these records at _dmarc.example.com. */
export const brokenParent = (records: string[]): Promise<Report> => {
  const z = inheritingShop(`v=DMARC1; p=reject; rua=mailto:${RUA}`);
  (z["_dmarc.example.com"] as Node).TXT = records;
  return check(z, "shop.example.com");
};
