// The queries that decide the verdict go to two operators and are compared normalized. The checks
// run over the real DoH client with a fake fetch that serves a zone per operator.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDohResolver } from "../src/dns/doh.ts";
import { DEFAULT_ORDER } from "../src/dns/endpoints.ts";
import { ask } from "../src/dns/lookup.ts";
import { checkDomain } from "../src/index.ts";
import type { ResolverId } from "../src/dns/types.ts";
import type { Report } from "../src/types.ts";
import { DKIM, input, P4, P4B, SOA } from "./helpers/check.ts";
import { buildMessage } from "./helpers/dns.ts";
import { type Call, fakeFetch, isProbe, recordedOrEmpty, type Rules, zones } from "./helpers/fetch.ts";
import type { Zone } from "./helpers/zone.ts";

const DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@example.net";
const D = "example.net";

/** Case A of check.test.ts on example.net: Google Workspace, everything right. */
function zone(): Zone {
  return {
    [D]: { SOA, MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com ~all"] },
    "smtp.google.com": { A: [P4] },
    "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    [`google._domainkey.${D}`]: { TXT: [DKIM] },
    [`_dmarc.${D}`]: { TXT: [DMARC] },
  };
}

/** A full check over DoH, each operator answering from `base` with its own changes on top. */
async function run(base: Zone, perOperator: Partial<Record<ResolverId, Zone>> = {}, rules: Rules = {}) {
  const f = fakeFetch(rules, zones(base, perOperator));
  vi.stubGlobal("fetch", f.fn);
  const r = await checkDomain(input(D));
  return { r, f };
}

const failure = (r: Report, group: string) => r.findings.find((x) => x.id === "lookup-failed" && x.group === group);

afterEach(() => vi.unstubAllGlobals());

describe("two operators per query that decides", () => {
  it("a record that differs by a space disagrees; the same MX in another order and case agrees", async () => {
    const f = fakeFetch(
      {},
      zones(zone(), {
        google: { [D]: { SOA, MX: ["1 smtp.google.com"], TXT: ["v=spf1  include:_spf.google.com ~all"] } },
      }),
    );
    // The extra space changes the record: a record that differs is not the same answer.
    const doh = createDohResolver({ fetch: f.fn });
    const spf = await ask({ resolver: doh }, D, "TXT", { confirm: true });
    expect(spf.status).toBe("failed");
    expect(spf.reason).toBe("disagree");
    const g = fakeFetch({}, (op, name, type, flags) =>
      zones({
        [D]: {
          SOA,
          MX: op === "google" ? ["20 b.example.net", "10 a.example.net"] : ["10 A.example.net", "20 b.example.net"],
        },
      })(op, name, type, flags),
    );
    const mx = await ask({ resolver: createDohResolver({ fetch: g.fn }) }, D, "MX", { confirm: true });
    expect(mx.status).toBe("ok");
    expect(mx.result?.confirm).toBe("agreed");
    expect(g.calls.map((c) => c.resolver)).toEqual(["cloudflare", "google"]);
  });

  it("with agreed, AD is the AND of the two operators: AD from one alone gives ad false", async () => {
    const withAd = (signed: ResolverId[]) =>
      fakeFetch({}, (op, name, type) =>
        isProbe(name, type)
          ? undefined
          : buildMessage({
              qname: name,
              qtype: type,
              ad: signed.includes(op),
              answers: [{ name, type: "TXT", data: ["v=spf1 -all"] }],
            }),
      );
    const cases: [ResolverId[], boolean][] = [
      [["cloudflare"], false],
      [["google"], false],
      [["cloudflare", "google"], true],
      [[], false],
    ];
    for (const [signed, ad] of cases) {
      const f = withAd(signed);
      const r = await createDohResolver({ fetch: f.fn }).query(D, "TXT", { confirm: true });
      expect([signed, r.confirm, r.ad]).toEqual([signed, "agreed", ad]);
      const asked = f.queries().map((c) => c.resolver);
      expect(asked.sort()).toEqual(["cloudflare", "google"]);
    }
  });

  it("the full check asks both operators at once and lands on Protected", async () => {
    const { r, f } = await run(zone());
    expect(r.verdict).toBe("protected");
    expect(r.resolvers).toEqual(["cloudflare", "google"]);
    const both = f.calls.filter((c) => c.name === `_dmarc.${D}`).map((c) => c.resolver);
    expect(both.sort()).toEqual(["cloudflare", "google"]);
  });

  for (const [what, google] of [
    ["a record against NODATA", { [`_dmarc.${D}`]: {} }],
    ["a record against NXDOMAIN", { [`_dmarc.${D}`]: undefined }],
    ["two different records", { [`_dmarc.${D}`]: { TXT: ["v=DMARC1; p=none"] } }],
  ] as const) {
    it(`${what} is a disagreement: lookup-failed with both answers, and Can't tell`, async () => {
      const { r } = await run(zone(), { google: google as unknown as Zone });
      expect(r.verdict).toBe("cant-tell");
      const f = failure(r, "dmarc");
      expect(f?.vars?.reason).toBe("disagree");
      expect(f?.vars?.name).toBe(`_dmarc.${D}`);
      expect(f?.vars?.first).toBe(`cloudflare: ${DMARC}`);
      expect(String(f?.vars?.second)).toMatch(/^google: (NODATA|NXDOMAIN|v=DMARC1; p=none)$/);
      expect(f?.vars?.waitSeconds).toBe(300);
    });
  }

  it("an SPF include that differs between the two is a disagreement in the SPF group", async () => {
    const { r } = await run(zone(), { google: { "_spf.google.com": { TXT: ["v=spf1 +all"] } } });
    expect(failure(r, "spf")?.vars?.reason).toBe("disagree");
    expect(r.verdict).toBe("cant-tell");
  });

  it("MX hosts whose addresses rotate agree; 0.0.0.0 against a public address does not", async () => {
    const rotating = await run(zone(), { google: { "smtp.google.com": { A: [P4B] } } });
    expect(rotating.r.verdict).toBe("protected");
    const sunk = await run(zone(), { google: { "smtp.google.com": { A: ["0.0.0.0"] } } });
    expect(failure(sunk.r, "mx")?.vars?.reason).toBe("disagree");
    expect(failure(sunk.r, "mx")?.vars?.second).toBe("google: private");
  });

  it("the second operator down: the third confirms", async () => {
    const { r, f } = await run(zone(), {}, { google: "network" });
    expect(r.verdict).toBe("protected");
    expect(r.findings.some((x) => x.id === "lookup-failed")).toBe(false);
    expect(r.resolvers).toEqual(["cloudflare", "quad9"]);
    expect(f.calls.filter((c) => c.probe)).toHaveLength(9);
  });

  it("one operator alone in the whole time: unconfirmed, and Can't tell", async () => {
    const rules: Rules = Object.fromEntries(
      DEFAULT_ORDER.filter((op) => op !== "cloudflare").map((op) => [op, "network"]),
    );
    const { r } = await run(zone(), {}, rules);
    expect(r.outcome).toBe("done");
    expect(r.verdict).toBe("cant-tell");
    expect(failure(r, "mx")?.vars).toEqual({ reason: "unconfirmed", name: D });
    // What goes to one operator still answers: DKIM is read.
    expect(r.dkim.keys.map((k) => k.selector)).toEqual(["google"]);
  });

  // The five other operators agree with one of the two.
  it("never a majority: Cloudflare against Google stays a disagreement", async () => {
    const { r, f } = await run(zone(), { google: { [`_dmarc.${D}`]: { TXT: ["v=DMARC1; p=none"] } } });
    expect(failure(r, "dmarc")?.vars?.reason).toBe("disagree");
    expect(f.calls.filter((c) => c.name === `_dmarc.${D}`)).toHaveLength(2);
  });

  it("DKIM, transport, rua authorization and the doubled-name probes go to one operator", async () => {
    const z = zone();
    z[`_dmarc.${D}`] = { TXT: ["v=DMARC1; p=reject; rua=mailto:d@reports.example.org"] };
    z["_dmarc.reports.example.org"] = {};
    z[`${D}._report._dmarc.reports.example.org`] = { TXT: ["v=DMARC1"] };
    const { r, f } = await run(z);
    expect(r.findings.some((x) => x.id === "dmarc-rua-unauthorized")).toBe(false);
    const by = new Map<string, Call[]>();
    for (const c of f.queries()) by.set(`${c.name} ${c.type}`, [...(by.get(`${c.name} ${c.type}`) ?? []), c]);
    const single = [...by.entries()].filter(([k]) =>
      /\._domainkey\.|^_mta-sts\.|^_smtp\._tls\.|_report\._dmarc\.|^_dmarc\.reports\.example\.org|^_dmarc\.example\.org |example\.net\.example\.net|_pmp-probe\./.test(
        k,
      ),
    );
    expect(single.length).toBeGreaterThan(30);
    for (const [k, calls] of single) expect([k, calls.length]).toEqual([k, 1]);
    const decided = [
      `${D} MX`,
      `${D} TXT`,
      "smtp.google.com A",
      "smtp.google.com AAAA",
      "_spf.google.com TXT",
      `_dmarc.${D} TXT`,
      "_dmarc.net TXT",
    ];
    const operatorsOf = (k: string) => by.get(k)?.map((c) => c.resolver);
    for (const k of decided) expect([k, operatorsOf(k)?.sort()]).toEqual([k, ["cloudflare", "google"]]);
  });

  it("the requests of one check are fixed: the cross-check adds one per query that decides", async () => {
    const { f } = await run(zone());
    const extra = f.calls.filter((c) => c.resolver === "google").length;
    // This zone: 92 requests on one operator (MX, the MX host's A and AAAA, the zone's SOA, the two
    // SPF records, the two Tree Walk names, the two doubled-name probes, two transport records, 76
    // DKIM selectors, _adsp and _report, the DKIM wildcard probe and _domainkey) and 8 more for the
    // cross-check, _domainkey's among them.
    expect({ total: f.calls.length, extra }).toEqual({ total: 100, extra: 8 });
  });

  // Recorded on 2026-11-18 by the fixture recorder (in the source of postmasterofpuppets.com), with
  // the A and AAAA of each MTA-STS policy host added on 2026-11-19. It asked 31 DKIM selectors, 29
  // of them still among the 76 the check tries. Replayed, 48 requests of google.com and 56 of
  // microsoft.com find a recording, 6 and 10 of them on the cross-check's operator. What was not
  // recorded answers empty: the other 47 selectors, _adsp, _report and the DKIM wildcard probe,
  // and on both operators _domainkey and _dmarc.com, with _spf-ssg-a.msft.net for microsoft.com.
  // 48 + 54 = 102 and 56 + 56 = 112 requests; 6 + 2 = 8 and 10 + 3 = 13 for the cross-check.
  for (const [domain, total, extra] of [
    ["google.com", 102, 8],
    ["microsoft.com", 112, 13],
  ] as const) {
    it(`${domain} replayed from its recordings: ${total} requests, ${extra} for the cross-check`, async () => {
      // Names the recorder did not save answer empty, the same for all.
      const f = fakeFetch({}, recordedOrEmpty);
      vi.stubGlobal("fetch", f.fn);
      const r = await checkDomain(input(domain));
      expect(r.verdict).toBe("protected");
      expect({ total: f.calls.length, extra: f.calls.filter((c) => c.resolver === "google").length }).toEqual({
        total,
        extra,
      });
    });
  }

  it("crossCheck: false (as the fixture recorder sets it) asks one operator even when confirm is asked", async () => {
    const f = fakeFetch({}, zones(zone()));
    const doh = createDohResolver({ fetch: f.fn, crossCheck: false });
    const l = await ask({ resolver: doh }, D, "MX", { confirm: true });
    expect(l.status).toBe("ok");
    expect(l.result?.confirm).toBeUndefined();
    expect(f.calls).toHaveLength(1);
  });
});
