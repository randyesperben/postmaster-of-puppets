// Fix.after against the engine itself: each DMARC fix is applied to the zone, with the fixes before
// it in its finding, and the check runs again; what the fix said the record would ask must be what
// the new report asks. `sub` is compared with simulation.subdomain, which is set exactly when
// the subdomains get less than the name. Below the Organizational Domain the subdomains may follow
// another name's record, so a record of the name's own does not move them; where the check cannot
// know, `sub` is left out.
import { describe, expect, it } from "vitest";
import type { Report } from "../src/types.ts";
import { applyFix, check, googleZone, inheritingShop, P4, RANK, RUA, SOA } from "./helpers/check.ts";
import type { Zone } from "./helpers/zone.ts";

const dmarc = (tags: string) => `v=DMARC1; ${tags}; rua=mailto:${RUA}`;

/** shop.example.com, or a.shop.example.com, sending, under these records. */
function below(parent: string | undefined, own?: string, name = "shop.example.com"): Zone {
  const z = inheritingShop(parent ?? "");
  if (parent === undefined) delete z["_dmarc.example.com"];
  if (name !== "shop.example.com") {
    z[name] = z["shop.example.com"]!;
    z["shop.example.com"] = {};
    z[`google._domainkey.${name}`] = z["google._domainkey.shop.example.com"]!;
    delete z["google._domainkey.shop.example.com"];
  }
  if (own !== undefined) z[`_dmarc.${name}`] = { TXT: [own] };
  return z;
}

/**
 * Every fix with an after, applied with the ones before it in its finding, and the report that
 * follows.
 */
async function walkFixes(zone: Zone, domain: string) {
  const r = await check(zone, domain);
  const out: {
    label: string;
    after: NonNullable<Report["findings"][number]["fixes"][number]["after"]>;
    next: Report;
  }[] = [];
  for (const f of r.findings) {
    let z = zone;
    for (const [i, fix] of f.fixes.entries()) {
      z = applyFix(z, fix);
      if (fix.after) out.push({ label: `${domain} ${f.id}:${i}`, after: fix.after, next: await check(z, domain) });
    }
  }
  return out;
}

const PARENTS = [
  "p=reject; sp=quarantine; np=none",
  "p=none",
  "p=reject; sp=none",
  "p=reject; sp=quarantine",
  "p=quarantine; sp=none",
  "p=reject; t=y",
  "p=quarantine; pct=0",
  "p=reject; pct=50",
];

const ZONES: [string, Zone, string][] = [
  ...PARENTS.map((p): [string, Zone, string] => [`shop under ${p}`, below(dmarc(p)), "shop.example.com"]),
  ...PARENTS.map((p): [string, Zone, string] => [
    `a.shop under ${p}`,
    below(dmarc(p), undefined, "a.shop.example.com"),
    "a.shop.example.com",
  ]),
  ["shop's own quarantine under sp=none", below(dmarc("p=reject; sp=none"), dmarc("p=quarantine")), "shop.example.com"],
  [
    "shop's own quarantine; sp=none under p=reject",
    below(dmarc("p=reject"), dmarc("p=quarantine; sp=none")),
    "shop.example.com",
  ],
  [
    "none-declared shop under p=none",
    { ...below(dmarc("p=none")), "shop.example.com": { MX: ["0 ."], TXT: ["v=spf1 -all"] } },
    "shop.example.com",
  ],
  [
    "no record at the Organizational Domain",
    (() => {
      const z = googleZone();
      delete z["_dmarc.example.com"];
      return z;
    })(),
    "example.com",
  ],
  ...[
    "p=none",
    "p=quarantine; sp=none",
    "p=reject; sp=none",
    "p=reject; np=none",
    "p=quarantine; sp=reject",
    "p=reject; pct=50; sp=none",
    "p=reject; t=y",
  ].map((p): [string, Zone, string] => [`example.com at ${p}`, googleZone(dmarc(p)), "example.com"]),
];

describe("Fix.after is what the check reads once the fix is in", () => {
  for (const [name, zone, domain] of ZONES) {
    it(name, async () => {
      const steps = await walkFixes(zone, domain);
      expect(steps.length, "a fix with after").toBeGreaterThan(0);
      for (const { label, after, next } of steps) {
        const s = next.simulation!;
        expect(s.reason === "open-spf" ? s.dmarcAsks : s.asks, label).toBe(after.asks);
        if (after.sub === undefined) continue;
        expect(s.subdomain?.asks, label).toBe(RANK[after.sub] < RANK[after.asks] ? after.sub : undefined);
      }
    });
  }
});

describe("Fix.after.sub is left out where the check cannot know it", () => {
  const subs = async (zone: Zone, domain: string) =>
    (await check(zone, domain)).findings.flatMap((f) => f.fixes.filter((x) => x.after).map((x) => x.after!.sub));

  it("a record of the name's own at p=none, under a parent with a record: the parent's sp is not read", async () => {
    const got = await subs(below(dmarc("p=reject; sp=none"), dmarc("p=none")), "shop.example.com");
    expect(got.length).toBeGreaterThan(0);
    expect(got).toEqual(got.map(() => undefined));
  });

  it("no record anywhere, three labels: RFC 7489 receivers read the subdomains where the PSL says", async () => {
    const got = await subs(below(undefined), "shop.example.com");
    expect(got.length).toBeGreaterThan(0);
    expect(got).toEqual(got.map(() => undefined));
  });

  it("a lookup of the walk failed: the record over the subdomains is unknown", async () => {
    const z = { ...below(dmarc("p=none"), dmarc("p=none")), "_dmarc.example.com": { $unreachable: true } } as Zone;
    const got = await subs(z, "shop.example.com");
    expect(got.length).toBeGreaterThan(0);
    expect(got).toEqual(got.map(() => undefined));
  });

  it("two labels and no record: the new record speaks for its subdomains, so sub is the record's", async () => {
    const z: Zone = {
      "example.com": { SOA, A: [P4], MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
      "smtp.google.com": { A: [P4] },
      "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    };
    expect(await subs(z, "example.com")).toEqual(["nothing", "quarantine", "reject"]);
  });
});
