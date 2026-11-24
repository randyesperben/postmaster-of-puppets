// What the name is, through full checks: whether it exists, whether it takes mail (a null MX),
// whether it is an alias, and the lookups that leave the verdict at Can't tell. A zone goes through
// checkDomain, and each fix is applied back to it.
import { describe, expect, it } from "vitest";
import { catalog, checkDomain, fixesAsText, variantText } from "../src/index.ts";
import { SELECTORS } from "../src/providers.ts";
import type { CatalogEntry, Report } from "../src/types.ts";
import { applyFix, check, DKIM, googleZone, input, P4, RSA2048, RUA, SOA, weakerOf } from "./helpers/check.ts";
import { chunks } from "./helpers/dns.ts";
import { ids } from "./helpers/findings.ts";
import { allFixes, failing } from "./helpers/fixes.ts";
import { type Node, type Zone, zoneResolver } from "./helpers/zone.ts";

/** Every name that would hold a CNAME and another record after applying all fixes of a report. */
function cnameClashes(zone: Zone, r: Report): string[] {
  let z = zone;
  for (const fix of allFixes(r)) z = applyFix(z, fix);
  return Object.entries(z)
    .filter(
      ([, node]) =>
        Array.isArray(node.CNAME) &&
        node.CNAME.length > 0 &&
        Object.keys(node).some(
          (k) => k !== "CNAME" && !k.startsWith("$") && Array.isArray(node[k]) && (node[k] as unknown[]).length > 0,
        ),
    )
    .map(([name]) => name);
}

/** A domain with no MX, no SPF and no DKIM, DMARC at the given record. */
function quietZone(dmarc?: string): Zone {
  return { "example.com": { SOA, A: [P4] }, ...(dmarc ? { "_dmarc.example.com": { TXT: [dmarc] } } : {}) };
}

describe("a name that does not exist", () => {
  it("np=reject with sp absent or at reject on the Organizational Domain: Protected, policy from np", async () => {
    for (const record of [
      `v=DMARC1; p=reject; np=reject; rua=mailto:${RUA}`,
      `v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:${RUA}`,
    ]) {
      for (const compactDenial of [false, true]) {
        const zone: Zone = { "example.com": { SOA }, "_dmarc.example.com": { TXT: [record] } };
        const r = await checkDomain(input("billing.example.com"), { resolver: zoneResolver(zone, { compactDenial }) });
        expect(r.exists).toBe(compactDenial ? "nxname" : "nxdomain");
        expect(r.outcome).toBe("done");
        expect(r.verdict).toBe("protected");
        expect(r.dmarc.policyFrom).toBe("np");
        // Both readings agree, so no finding says that part of the receivers differ.
        expect(weakerOf(r)).toEqual([]);
      }
    }
  });

  it("np=reject with sp=none: RFC 7489 receivers apply sp, the weaker reading decides and says so", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=none; np=reject; rua=mailto:${RUA}`] },
    };
    const r = await check(zone, "billing.example.com");
    expect(r.verdict).toBe("spoofable");
    expect(r.findings.find((f) => f.id === "dmarc-subdomains-open")?.vars).toMatchObject({
      sp: "none",
      np: "reject",
      weaker: 1,
    });
  });

  it("no DMARC record covers it: outcome nxdomain, spoofable underneath", async () => {
    for (const compactDenial of [false, true]) {
      const r = await checkDomain(input("nope.example.com"), {
        resolver: zoneResolver({ "example.com": { SOA } }, { compactDenial }),
      });
      expect(r.outcome).toBe("nxdomain");
      expect(r.verdict).toBe("spoofable");
    }
  });

  it("existence unknown while np asks for less than sp: Can't tell, with the lookup's real reason", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=reject; np=none; rua=mailto:${RUA}`] },
    };
    const r = await checkDomain(input("x.example.com"), {
      resolver: failing(zone, ["x.example.com MX", "x.example.com A"]),
    });
    expect(r.verdict).toBe("cant-tell");
    const missing = r.findings.find((f) => f.id === "lookup-failed" && f.group === "dmarc");
    expect(missing).toMatchObject({ found: "x.example.com A", vars: { reason: "no-answer", name: "x.example.com" } });
  });

  it("a name that does not exist while the Tree Walk got no answer does not give the nxdomain outcome", async () => {
    const zone: Zone = {
      "example.com": { SOA, MX: ["10 mx.example.com"] },
      "mx.example.com": { A: [P4] },
      "_dmarc.example.com": { $unreachable: true },
    };
    const r = await check(zone, "gone.example.com");
    expect(r.exists).toBe("nxdomain");
    expect(r.outcome).not.toBe("nxdomain");
    expect(r.verdict).toBe("cant-tell");
  });
});

describe("what leaves the verdict at Can't tell", () => {
  it("an MX with no answer: no Can't tell, delivery unknown and both paths", async () => {
    const r = await checkDomain(input(), {
      resolver: failing(quietZone(`v=DMARC1; p=reject; rua=mailto:${RUA}`), ["example.com MX"]),
    });
    expect(r.verdict).toBe("protected");
    expect(r.delivery).toBe("unknown");
    expect(r.mailUse).toBe("probably-none");
    const path = r.findings.find((f) => f.id === "lookup-failed" && f.group === "mx");
    expect(path?.fixes.map((f) => `${f.action} ${f.type} ${f.value}`)).toEqual([
      "add MX 0 .",
      "add TXT v=spf1 -all",
      "add TXT v=DKIM1; p=",
    ]);
    expect(fixesAsText(r)).toContain("If example.com sends no email:");
  });

  it("an MX with no answer on a domain with no DMARC: both paths, never the set alone", async () => {
    const r = await checkDomain(input(), { resolver: failing(quietZone(), ["example.com MX"]) });
    expect(r.verdict).toBe("spoofable");
    const text = fixesAsText(r);
    expect(text).toContain("If example.com sends no email:");
    expect(text).toContain("If it sends email through a service:");
    expect(text).toContain("p=none; rua=mailto:{rua}");
  });

  it("SPF with no answer: Spoofable with DMARC missing or at none, Can't tell with reject", async () => {
    const z = (dmarc?: string) => {
      const zone = googleZone(dmarc);
      if (!dmarc) delete zone["_dmarc.example.com"];
      return zone;
    };
    const run = (zone: Zone) => checkDomain(input(), { resolver: failing(zone, ["example.com TXT"]) });
    expect((await run(z())).verdict).toBe("spoofable");
    expect((await run(z(`v=DMARC1; p=none; rua=mailto:${RUA}`))).verdict).toBe("spoofable");
    expect((await run(z(`v=DMARC1; p=reject; rua=mailto:${RUA}`))).verdict).toBe("cant-tell");
  });
});

describe("a null MX", () => {
  it("with an SPF that authorizes a sender: mail, mx-null with sending, at-risk, no no-mail set", async () => {
    const zone = googleZone(`v=DMARC1; p=none; rua=mailto:${RUA}`);
    // Preference 10 would get “set it to 0” on a domain without mail; here the null MX itself is
    // wrong.
    (zone["example.com"] as Node).MX = ["10 ."];
    delete zone["google._domainkey.example.com"];
    const r = await check(zone);
    expect(r.mailUse).toBe("mail");
    expect(r.delivery).toBe("at-risk");
    expect(r.findings.find((f) => f.id === "mx-null")).toMatchObject({
      severity: "warning",
      vars: { sending: 1 },
      fixes: [],
    });
    const values = allFixes(r).map((f) => f.value);
    for (const v of ["v=spf1 -all", "v=DMARC1; p=reject", "v=DKIM1; p="]) expect(values).not.toContain(v);
    expect(values).toContain("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com");
  });

  it("with a usable DKIM key and no SPF: mail as well", async () => {
    const zone: Zone = { "example.com": { SOA, MX: ["0 ."] }, "google._domainkey.example.com": { TXT: [DKIM] } };
    const r = await check(zone);
    expect(r.mailUse).toBe("mail");
    expect(r.findings.find((f) => f.id === "mx-null")?.vars?.sending).toBe(1);
    expect(allFixes(r).map((f) => f.value)).not.toContain("v=spf1 -all");
  });

  // mx-null carries sendingUnknown, not sending.
  it("with SPF or DKIM unanswered: the DMARC steps, never the no-mail set, and at-risk", async () => {
    // The SPF that would authorize Google gets no answer; or there is no SPF and no DKIM selector
    // gets one.
    const zone = (spf: string[]): Zone => ({
      "example.com": { SOA, MX: ["0 ."], TXT: spf },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=none; rua=mailto:${RUA}`] },
    });
    const dkimUnanswered = SELECTORS.map((s) => `${s}._domainkey.example.com TXT`);
    const cases: [Zone, string[]][] = [
      [zone(["v=spf1 include:_spf.google.com ~all"]), ["example.com TXT"]],
      [zone([]), dkimUnanswered],
    ];
    for (const [z, unanswered] of cases) {
      const r = await checkDomain(input("example.com"), { resolver: failing(z, unanswered) });
      expect(r.mailUse, unanswered[0]).toBe("mail");
      expect(r.delivery, unanswered[0]).toBe("at-risk");
      expect(r.deliveryCause, unanswered[0]).toEqual({ rule: 3, finding: "mx-null" });
      const values = allFixes(r).map((f) => f.value);
      for (const v of ["v=spf1 -all", "v=DMARC1; p=reject", "v=DKIM1; p="])
        expect(values, unanswered[0]).not.toContain(v);
      expect(values, unanswered[0]).toContain("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com");
      // A lookup with no answer counts as a sign of sending, never the no-mail set; mx-null carries
      // sendingUnknown, not sending.
      const mxNull = r.findings.find((f) => f.id === "mx-null");
      expect(mxNull, unanswered[0]).toMatchObject({ severity: "warning", vars: { sendingUnknown: 1 } });
      expect(mxNull?.vars?.sending, unanswered[0]).toBeUndefined();
    }
  });

  it("a null MX, v=spf1 -all, p=reject and one DKIM selector without an answer: no claim that it sends", async () => {
    const zone: Zone = {
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    };
    const r = await checkDomain(input("example.com"), {
      resolver: failing(zone, ["selector1._domainkey.example.com TXT"]),
    });
    expect(r.delivery).toBe("at-risk");
    const f = r.findings.find((x) => x.id === "mx-null");
    expect(f?.vars).toEqual({ sendingUnknown: 1 });
    const entry = catalog.find((e) => e.id === "mx-null") as CatalogEntry;
    expect(variantText(entry, "why", f?.vars)).not.toContain("{domain} also sends email, and");
    expect(variantText(entry, "fix", f?.vars)).toMatch(/^Run the check again/);
  });

  it("with a DKIM key in testing mode only: mail, since a key not revoked is someone's signing key", async () => {
    const zone: Zone = {
      "example.com": { SOA, MX: ["0 ."] },
      "google._domainkey.example.com": { TXT: [chunks(`v=DKIM1; k=rsa; t=y; p=${RSA2048}`)] },
    };
    const r = await check(zone);
    expect(r.mailUse).toBe("mail");
    for (const v of ["v=spf1 -all", "v=DMARC1; p=reject", "v=DKIM1; p="])
      expect(allFixes(r).map((f) => f.value)).not.toContain(v);
  });

  it("without signs of sending: none-declared, mx-null stays info", async () => {
    const r = await check({ "example.com": { SOA, MX: ["0 ."] } });
    expect(r.mailUse).toBe("none-declared");
    expect(r.delivery).toBe("no-mail");
    const f = r.findings.find((x) => x.id === "mx-null");
    expect(f?.severity).toBe("info");
    expect(f?.vars?.sending).toBeUndefined();
  });
});

// The MX group's status follows the MX findings the report ends with. A null MX on a domain that
// sends becomes a warning once every group is in (RFC 7505 §4.2), so the group is weak by the rule
// of statusOf: a warning that is not hardening weakens its group.
describe("the MX group's status after the report adjusts its findings", () => {
  it("a null MX on a domain that sends: the warning makes the group weak", async () => {
    const z = googleZone();
    (z["example.com"] as Node).MX = ["0 ."];
    const r = await check(z);
    expect(r.findings.find((f) => f.id === "mx-null")).toMatchObject({ severity: "warning", vars: { sending: 1 } });
    expect(r.groups.mx).toBe("weak");
  });

  it("a null MX with only an unanswered DKIM lookup keeping sending open: a warning, the group weak", async () => {
    const z = googleZone();
    (z["example.com"] as Node).MX = ["0 ."];
    (z["example.com"] as Node).TXT = ["v=spf1 -all"];
    (z["google._domainkey.example.com"] as Node).$unreachable = true;
    const r = await check(z);
    expect(r.findings.find((f) => f.id === "mx-null")).toMatchObject({
      severity: "warning",
      vars: { sendingUnknown: 1 },
    });
    expect(r.groups.mx).toBe("weak");
  });

  it("a null MX on a domain that sends no email stays info, and the group passes", async () => {
    const z = googleZone();
    (z["example.com"] as Node).MX = ["0 ."];
    (z["example.com"] as Node).TXT = ["v=spf1 -all"];
    delete z["google._domainkey.example.com"];
    const r = await check(z);
    expect(r.findings.find((f) => f.id === "mx-null")?.severity).toBe("info");
    expect(r.groups.mx).toBe("pass");
  });
});

describe("names with a CNAME (RFC 1034 §3.6.2)", () => {
  it("a checked name that is an alias: name-is-alias with its target, and no MX or SPF fix at the name", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "shop.example.com": { CNAME: ["shops.example.net"] },
      "shops.example.net": { SOA, A: [P4], MX: ["0 ."] },
    };
    const r = await check(zone, "shop.example.com");
    const alias = r.findings.find((f) => f.id === "name-is-alias");
    expect(alias).toMatchObject({ group: "mx", severity: "info", vars: { target: "shops.example.net" } });
    expect(r.exists).toBe("yes");
    expect(allFixes(r).filter((f) => f.name === "shop.example.com")).toEqual([]);
    expect(allFixes(r).length).toBeGreaterThan(0);
    expect(cnameClashes(zone, r)).toEqual([]);
  });

  it("an alias of a domain with mail or of one that probably sends none: still nothing at the name", async () => {
    const targets: Node[] = [
      { SOA, A: [P4], MX: ["10 mx.example.net"], TXT: ["v=spf1 +all"] },
      { SOA, A: [P4] },
    ];
    for (const target of targets) {
      const zone: Zone = {
        "example.com": { SOA },
        "shop.example.com": { CNAME: ["shops.example.net"] },
        "shops.example.net": target,
        "mx.example.net": { A: [P4] },
      };
      const r = await check(zone, "shop.example.com");
      expect(r.mailUse).not.toBe("none-declared");
      expect(allFixes(r).filter((f) => f.name === "shop.example.com")).toEqual([]);
      expect(cnameClashes(zone, r)).toEqual([]);
    }
  });

  it("an alias whose target does not exist still exists itself (RFC 6604 §3)", async () => {
    const zone: Zone = { "example.com": { SOA }, "old.example.com": { CNAME: ["gone.example.net"] } };
    const r = await check(zone, "old.example.com");
    expect(r.exists).toBe("yes");
    expect(r.outcome).toBe("done");
    expect(ids(r)).toContain("name-is-alias");
  });

  it("_dmarc delegated to a hosted service: remove the CNAME and add the TXT, in the first step", async () => {
    const zone = googleZone();
    delete zone["_dmarc.example.com"];
    zone["_dmarc.example.com"] = { CNAME: ["example-com.dmarc.example.net"] };
    zone["example-com.dmarc.example.net"] = { TXT: [`v=DMARC1; p=none; rua=mailto:${RUA}`] };
    const r = await check(zone);
    const on = r.findings.find((f) => f.id === "dmarc-policy-none");
    expect(on?.fixes.slice(0, 2)).toEqual([
      {
        action: "remove",
        type: "CNAME",
        host: "_dmarc",
        name: "_dmarc.example.com",
        value: "example-com.dmarc.example.net",
        replaces: "example-com.dmarc.example.net",
        step: { n: 2, of: 3, protects: true },
      },
      {
        action: "add",
        type: "TXT",
        host: "_dmarc",
        name: "_dmarc.example.com",
        value: `v=DMARC1; p=quarantine; rua=mailto:${RUA}`,
        step: { n: 2, of: 3, protects: true },
        after: { asks: "quarantine", sub: "quarantine" },
      },
    ]);
    expect(cnameClashes(zone, r)).toEqual([]);
    // After every step the record is the domain's own and the alias is gone.
    let z = zone;
    for (const fix of on?.fixes ?? []) z = applyFix(z, fix);
    const after = await check(z);
    expect(after.verdict).toBe("protected");
  });

  it("_dmarc as a CNAME to nothing under an inherited policy: the alias goes before the record", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=none; rua=mailto:${RUA}`] },
      "shop.example.com": { A: [P4], TXT: ["v=spf1 -all"] },
      "_dmarc.shop.example.com": { CNAME: ["gone.example.net"] },
    };
    const r = await check(zone, "shop.example.com");
    // Two paths (probably-none): the no-mail set and the DMARC steps both write a record of the
    // name's own, each one through the alias; the owner applies one path, so each is applied alone.
    const paths = r.findings.filter((f) => f.fixes.some((x) => x.name === "_dmarc.shop.example.com"));
    expect(paths.length).toBeGreaterThan(0);
    for (const f of paths) {
      expect(
        f.fixes.find((x) => x.name === "_dmarc.shop.example.com"),
        f.id,
      ).toMatchObject({ action: "remove", type: "CNAME", value: "gone.example.net" });
      expect(cnameClashes(zone, { ...r, findings: [f] }), f.id).toEqual([]);
    }
  });

  it("no fix of a domain with mail leaves a CNAME next to other data", async () => {
    const zones: [Zone, string][] = [
      [
        {
          ...googleZone(),
          "_dmarc.example.com": { CNAME: ["x.dmarc.example.net"] },
          "x.dmarc.example.net": { TXT: ["v=DMARC1; p=quarantine; pct=25"] },
        },
        "example.com",
      ],
      [{ "example.com": { SOA }, "www.example.com": { CNAME: ["example.com"] } }, "www.example.com"],
      // Two records at the alias's target: removing one of them is not this domain's to do.
      [
        {
          ...googleZone(),
          "_dmarc.example.com": { CNAME: ["x.dmarc.example.net"] },
          "x.dmarc.example.net": { TXT: ["v=DMARC1; p=none", "v=DMARC1; p=reject"] },
        },
        "example.com",
      ],
    ];
    for (const [zone, domain] of zones) expect(cnameClashes(zone, await check(zone, domain))).toEqual([]);
  });
});
