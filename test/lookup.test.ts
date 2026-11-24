import { describe, expect, it } from "vitest";
import { ask, existence, failedVars, lookup, txt } from "../src/dns/lookup.ts";
import type { DnsResult, QueryOptions, Resolver } from "../src/dns/types.ts";
import { buildMessage, fixtureResolver, type Rec, toResult } from "./helpers/dns.ts";
import { zoneResolver } from "./helpers/zone.ts";

function scripted(answers: Record<string, DnsResult | Error>): Resolver & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    async query(name, type, opts = {}) {
      const key = `${name} ${type}${opts.cd ? " cd" : ""}`;
      asked.push(key);
      const a = answers[key];
      if (!a) throw new Error(`unexpected ${key}`);
      if (a instanceof Error) throw a;
      return a;
    },
  };
}

const msg = (
  rcode: number,
  records: { name: string; type: string; data: string | string[] }[] = [],
  ede?: number[],
): DnsResult =>
  toResult(buildMessage({ qname: "example.com", qtype: "TXT", rcode, answers: records, ...(ede ? { ede } : {}) }));

describe("lookup", () => {
  it("ok, nodata and nxdomain from recorded answers", async () => {
    const r = fixtureResolver();
    expect((await lookup(r, "google.com", "MX")).status).toBe("ok");
    expect((await lookup(r, "google.com", "TLSA")).status).toBe("nodata");
    const nx = await lookup(r, "nonexistent-xyz-12345.google.com", "TXT");
    expect(nx.status).toBe("nxdomain");
    expect(nx.authority[0]?.type).toBe("SOA");
  });

  it("keeps the CNAME chain apart from the records of the asked type", async () => {
    const r = fixtureResolver();
    const sts = await lookup(r, "_mta-sts.proton.me", "TXT");
    expect(sts.answers.map((a) => a.type)).toEqual(["CNAME", "TXT"]);
    expect(txt(sts)).toEqual(["v=STSv1; id=190906205100Z;"]);
    const dangling = await lookup(r, "selector1._domainkey.microsoft.com", "txt");
    expect(dangling.status).toBe("nxdomain");
    expect(dangling.records).toEqual([]);
    expect(dangling.answers[0]?.data).toBe("selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com");
  });

  it("SERVFAIL that answers with CD is broken DNSSEC (dnssec-failed.org, recorded)", async () => {
    const r = fixtureResolver();
    const l = await lookup(r, "dnssec-failed.org", "A");
    expect(l.status).toBe("dnssec-broken");
    expect(l.records.map((x) => x.data)).toHaveLength(1);
    expect(r.asked).toEqual(["dnssec-failed.org A", "dnssec-failed.org A cd"]);
  });

  it("SERVFAIL that also fails with CD is a failed lookup", async () => {
    const r = scripted({ "example.com TXT": msg(2), "example.com TXT cd": msg(2) });
    const l = await lookup(r, "example.com", "TXT");
    expect(l.status).toBe("failed");
    expect(l.result?.rcode).toBe(2);
  });

  it("SERVFAIL then NXDOMAIN with CD is broken DNSSEC too", async () => {
    const r = scripted({ "example.com TXT": msg(2, [], [9]), "example.com TXT cd": msg(3) });
    expect((await lookup(r, "example.com", "TXT")).status).toBe("dnssec-broken");
  });

  it("the CD retry keeps DO, so an NSEC with NXNAME could come back with it (RFC 9824 §5)", async () => {
    const asked: string[] = [];
    const r: Resolver = {
      async query(name, type, opts = {}) {
        asked.push(`${name} ${type}${opts.cd ? " cd" : ""}${opts.dnssecOk ? " do" : ""}`);
        return opts.cd ? msg(3) : msg(2, [], [9]);
      },
    };
    expect((await lookup(r, "example.com", "TXT", undefined, { dnssecOk: true })).status).toBe("dnssec-broken");
    expect(asked).toEqual(["example.com TXT do", "example.com TXT cd do"]);
  });

  it("an unreachable resolver, before or after the CD retry, is a failed lookup with its error", async () => {
    const down = new Error("unreachable");
    const before = await lookup(scripted({ "example.com TXT": down }), "example.com", "TXT");
    expect(before.status).toBe("failed");
    expect(before.error).toBe(down);
    const after = await lookup(
      scripted({ "example.com TXT": msg(2), "example.com TXT cd": down }),
      "example.com",
      "TXT",
    );
    expect(after.status).toBe("failed");
    expect(after.result?.rcode).toBe(2);
  });

  it("REFUSED and other codes are failed lookups", async () => {
    expect((await lookup(scripted({ "example.com TXT": msg(5) }), "example.com", "TXT")).status).toBe("failed");
  });

  it("passes the signal on", async () => {
    let seen: AbortSignal | undefined;
    const r: Resolver = {
      async query(_n, _t, opts = {}) {
        seen = opts.signal;
        return msg(0, [{ name: "example.com", type: "TXT", data: "v=spf1 -all" }]);
      },
    };
    const ctrl = new AbortController();
    const l = await lookup(r, "example.com", "TXT", ctrl.signal);
    expect(seen).toBe(ctrl.signal);
    expect(txt(l)).toEqual(["v=spf1 -all"]);
  });
});

// A disagreement or a lone operator is a lookup with no answer, with the reason the finding shows.
describe("confirm", () => {
  const spf = { name: "example.com", type: "TXT", ttl: 3600, data: ["v=spf1 -all"] };
  const soa = {
    name: "example.com",
    type: "SOA",
    ttl: 900,
    data: "ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 120",
  };

  function confirming(r: Partial<DnsResult>, seen: QueryOptions[] = []): Resolver {
    return {
      async query(_n, _t, opts = {}) {
        seen.push(opts);
        return { rcode: 0, ad: false, answers: [], authority: [], resolver: "cloudflare", ...r };
      },
    };
  }

  it("ask passes confirm only when asked", async () => {
    const seen: QueryOptions[] = [];
    await ask({ resolver: confirming({ answers: [spf] }, seen) }, "example.com", "TXT", { confirm: true });
    await ask({ resolver: confirming({ answers: [spf] }, seen) }, "example.com", "TXT");
    expect(seen.map((o) => o.confirm === true)).toEqual([true, false]);
  });

  it("agreed is an answer like any other", async () => {
    const l = await ask({ resolver: confirming({ answers: [spf], confirm: "agreed" }) }, "example.com", "TXT", {
      confirm: true,
    });
    expect(l.status).toBe("ok");
    expect(l.reason).toBeUndefined();
  });

  it("disagree fails with both answers as a person reads them and the longer wait", async () => {
    const l = await ask(
      {
        resolver: confirming({
          answers: [spf],
          confirm: "disagree",
          second: { resolver: "google", rcode: 0, answers: [], authority: [soa] },
        }),
      },
      "example.com",
      "TXT",
      { confirm: true },
    );
    expect(l.status).toBe("failed");
    expect(l.records).toEqual([]);
    expect(failedVars(l)).toEqual({
      reason: "disagree",
      name: "example.com",
      first: "cloudflare: v=spf1 -all",
      second: "google: NODATA",
      waitSeconds: 3600,
    });
  });

  it("disagree with no TTL to read leaves the wait out", async () => {
    const l = await ask(
      {
        resolver: confirming({
          rcode: 3,
          confirm: "disagree",
          second: { resolver: "google", rcode: 0, answers: [], authority: [] },
        }),
      },
      "example.com",
      "TXT",
      { confirm: true },
    );
    expect(failedVars(l)).toEqual({
      reason: "disagree",
      name: "example.com",
      first: "cloudflare: NXDOMAIN",
      second: "google: NODATA",
    });
  });

  it("unconfirmed fails; other failures say no-answer", async () => {
    const l = await ask({ resolver: confirming({ answers: [spf], confirm: "unconfirmed" }) }, "example.com", "TXT", {
      confirm: true,
    });
    expect(failedVars(l)).toEqual({ reason: "unconfirmed", name: "example.com" });
    const down = await lookup(scripted({ "example.com TXT": new Error("down") }), "example.com", "TXT");
    expect(failedVars(down)).toEqual({ reason: "no-answer", name: "example.com" });
  });
});

// A SERVFAIL has many causes (RFC 8914 §4.23 “No Reachable Authority”, a lame server); an answer
// with CD after it is broken DNSSEC only when a resolver says DNSSEC (EDE 1, 2, 5 to 12).
describe("dnssec-broken needs a DNSSEC Extended DNS Error", () => {
  const ok = [{ name: "example.com", type: "TXT", data: "v=spf1 -all" }];

  it("SERVFAIL with EDE 22 and an answer with CD is a failed lookup", async () => {
    const l = await lookup(
      scripted({ "example.com TXT": msg(2, [], [22]), "example.com TXT cd": msg(0, ok) }),
      "example.com",
      "TXT",
    );
    expect(l.status).toBe("failed");
    expect(l.records).toEqual([]);
    expect(l.result?.rcode).toBe(2);
  });

  it("SERVFAIL without EDE and an answer with CD without EDE is a failed lookup", async () => {
    expect(
      (await lookup(scripted({ "example.com TXT": msg(2), "example.com TXT cd": msg(0, ok) }), "example.com", "TXT"))
        .status,
    ).toBe("failed");
  });

  it("every DNSSEC code, on the SERVFAIL or on the CD answer, says dnssec-broken; the others do not", async () => {
    for (const code of [1, 2, 5, 6, 7, 8, 9, 10, 11, 12]) {
      expect(
        (
          await lookup(
            scripted({ "example.com TXT": msg(2, [], [code]), "example.com TXT cd": msg(0, ok) }),
            "example.com",
            "TXT",
          )
        ).status,
      ).toBe("dnssec-broken");
      expect(
        (
          await lookup(
            scripted({ "example.com TXT": msg(2), "example.com TXT cd": msg(0, ok, [code]) }),
            "example.com",
            "TXT",
          )
        ).status,
      ).toBe("dnssec-broken");
    }
    for (const code of [0, 3, 4, 13, 14, 22, 23]) {
      expect(
        (
          await lookup(
            scripted({ "example.com TXT": msg(2, [], [code]), "example.com TXT cd": msg(0, ok) }),
            "example.com",
            "TXT",
          )
        ).status,
      ).toBe("failed");
    }
  });

  it("the zone helper: $servfail is broken DNSSEC (EDE 9), $ede: false and $ede: 22 are not", async () => {
    const zone = (ede?: number | false) =>
      zoneResolver({
        "example.com": { TXT: ["v=spf1 -all"], $servfail: true, ...(ede === undefined ? {} : { $ede: ede }) },
      });
    expect((await lookup(zone(), "example.com", "TXT")).status).toBe("dnssec-broken");
    expect((await lookup(zone(false), "example.com", "TXT")).status).toBe("failed");
    expect((await lookup(zone(22), "example.com", "TXT")).status).toBe("failed");
  });
});

// RFC 9989 §3.2.13 decides np by NXDOMAIN, but zones with Compact Denial of Existence (Cloudflare)
// answer NOERROR to names that do not exist; with DO the NSEC says NXNAME (RFC 9824 §6).
/** What existence() says of the name, without the vars of a failure. */
const existsOf = async (ctx: Parameters<typeof existence>[0], name: string) => (await existence(ctx, name)).exists;

describe("existence", () => {
  it("asks one question with DO, confirmed by two operators, and passes the signal", async () => {
    const seen: QueryOptions[] = [];
    const r: Resolver = {
      async query(_n, _t, opts = {}) {
        seen.push(opts);
        return msg(3);
      },
    };
    const ctrl = new AbortController();
    expect(await existsOf({ resolver: r, signal: ctrl.signal }, "example.com")).toBe("nxdomain");
    expect(seen).toEqual([{ dnssecOk: true, confirm: true, signal: ctrl.signal }]);
  });

  it("is undefined when the two operators disagree or only one answered", async () => {
    const answer = (confirm: NonNullable<DnsResult["confirm"]>): Resolver => ({
      query: async () => ({
        ...msg(3),
        resolver: "cloudflare",
        confirm,
        ...(confirm === "disagree"
          ? { second: { resolver: "google" as const, rcode: 0, answers: [], authority: [] } }
          : {}),
      }),
    });
    expect(await existsOf({ resolver: answer("agreed") }, "example.com")).toBe("nxdomain");
    expect(await existsOf({ resolver: answer("disagree") }, "example.com")).toBeUndefined();
    expect(await existsOf({ resolver: answer("unconfirmed") }, "example.com")).toBeUndefined();
    // existence() says why, for the lookup-failed finding the DMARC group shows.
    expect(await existence({ resolver: answer("disagree") }, "example.com")).toEqual({
      failure: { reason: "disagree", name: "example.com", first: "cloudflare: NXDOMAIN", second: "google: NODATA" },
    });
    expect(await existence({ resolver: answer("unconfirmed") }, "example.com")).toEqual({
      failure: { reason: "unconfirmed", name: "example.com" },
    });
    expect(await existence({ resolver: answer("agreed") }, "example.com")).toEqual({ exists: "nxdomain" });
  });

  it("reads NXNAME in the recorded Cloudflare-signed answers of the three resolvers", async () => {
    for (const variant of [undefined, "google", "quad9"] as const) {
      const resolver = fixtureResolver(variant);
      expect(await existsOf({ resolver }, "nonexistent-xyz-12345.cloudflare.com")).toBe("nxname");
      expect(await existsOf({ resolver }, "_dmarc.cloudflare.com")).toBe("yes");
      expect(resolver.asked).toEqual(["nonexistent-xyz-12345.cloudflare.com A do", "_dmarc.cloudflare.com A do"]);
    }
  });

  it("a compact-denial zone: a missing name is nxname; an empty non-terminal and a name without A exist", async () => {
    const resolver = zoneResolver(
      { "example.com": { MX: ["10 mx.example.com"] }, "a.b.example.com": { TXT: ["x"] } },
      { compactDenial: true },
    );
    expect(await existsOf({ resolver }, "nope.example.com")).toBe("nxname");
    expect(await existsOf({ resolver }, "b.example.com")).toBe("yes");
    expect(await existsOf({ resolver }, "example.com")).toBe("yes");
    expect((await lookup(resolver, "nope.example.com", "TXT")).status).toBe("nodata");
  });

  it("NXDOMAIN is false, an answer is true, and a CNAME to nowhere is true (RFC 6604 §3)", async () => {
    const resolver = zoneResolver({
      "example.com": { A: ["192.0.2.1"] },
      "alias.example.com": { CNAME: ["gone.example.net"] },
    });
    expect(await existsOf({ resolver }, "nope.example.com")).toBe("nxdomain");
    expect(await existsOf({ resolver }, "example.com")).toBe("yes");
    expect(await existsOf({ resolver }, "alias.example.com")).toBe("yes");
  });

  it("NXNAME in an NSEC3 bitmap is nxname; NXNAME on another owner's NSEC does not count", async () => {
    const nodata = (authority: Rec[]): Resolver => ({
      query: async () => toResult(buildMessage({ qname: "nope.example.com", qtype: "A", authority })),
    });
    const nsec3 = {
      name: "h64kfa4p1acer2ebps9qsdk6dnp8b3jq.example.com",
      type: "NSEC3",
      data: "1 0 0 - H64KFA4P1ACER2EBPS9QSDK6DNP8B3JR NXNAME",
    };
    expect(await existsOf({ resolver: nodata([nsec3]) }, "nope.example.com")).toBe("nxname");
    const other = { name: "other.example.com", type: "NSEC", data: "\\000.other.example.com RRSIG NSEC NXNAME" };
    expect(await existsOf({ resolver: nodata([other]) }, "nope.example.com")).toBe("yes");
    const ent = { name: "nope.example.com", type: "NSEC", data: "\\000.nope.example.com RRSIG NSEC" };
    expect(await existsOf({ resolver: nodata([ent]) }, "nope.example.com")).toBe("yes");
  });

  it("is undefined when it cannot tell: no resolver, SERVFAIL, REFUSED or a name DNS cannot carry", async () => {
    const resolver = zoneResolver({ "down.example.com": { $unreachable: true }, "dead.example.com": { $dead: true } });
    expect(await existsOf({ resolver }, "down.example.com")).toBeUndefined();
    expect(await existsOf({ resolver }, "dead.example.com")).toBeUndefined();
    expect(await existsOf({ resolver: scripted({ "example.com A": msg(5) }) }, "example.com")).toBeUndefined();
    expect(await existsOf({ resolver }, "a..example.com")).toBeUndefined();
  });
});
