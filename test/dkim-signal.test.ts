import { describe, expect, it } from "vitest";
import { checkDkim, randomProbeSelector } from "../src/checks/dkim.ts";
import { createDohResolver } from "../src/dns/doh.ts";
import { SELECTORS } from "../src/providers.ts";
import { key, run } from "./helpers/dkim.ts";
import { chunks } from "./helpers/dns.ts";
import { fakeFetch, zones } from "./helpers/fetch.ts";
import { ids } from "./helpers/findings.ts";
import { rsaKey } from "./helpers/keys.ts";
import { type Zone, zoneAnswer, type ZoneOptions, zoneResolver } from "./helpers/zone.ts";

describe("wildcards, pasted quotes, FWS in p= and testing mode", () => {
  const PROBE = "pmp-0123abcd";
  const probed = (zone: Zone, extra: string[] = []) => {
    const resolver = zoneResolver(zone);
    return { resolver, done: checkDkim({ resolver }, "example.com", extra, PROBE) };
  };
  const WILD = "*._domainkey.example.com";

  it("asks one random pmp-<8 hex> selector besides the common ones, never counted as tried", async () => {
    const a = randomProbeSelector();
    expect(a).toMatch(/^pmp-[0-9a-f]{8}$/);
    expect(randomProbeSelector()).not.toBe(a);
    const { resolver, done } = probed({});
    const r = await done;
    expect(resolver.asked).toContain(`${PROBE}._domainkey.example.com TXT do`);
    expect(r.selectorsTried).toBe(SELECTORS.length);
    expect(ids(r)).toEqual(["dkim-not-found"]);
    expect(r.findings[0]?.vars?.wildcard).toBeUndefined();
  });

  // RFC 4592 §2.2: the wildcard answers every selector.
  it("a *._domainkey wildcard with an empty p=: not found, never a revoked key per selector", async () => {
    const r = await probed({ [WILD]: { TXT: ["v=DKIM1; p="] } }).done;
    expect(ids(r)).toEqual(["dkim-not-found"]);
    expect(r.findings[0]?.vars).toEqual({ tried: SELECTORS.length, wildcard: 1 });
    // Read once as "*", so the no-mail fixes know the set's wildcard is there (fixes.ts).
    expect(r.keys).toEqual([{ selector: "*", algorithm: "rsa", revoked: true }]);
    expect(r).toMatchObject({ found: false, usable: false, status: "unknown" });
    // With the random probe of the default call too.
    expect(ids(await run({ [WILD]: { TXT: ["v=DKIM1; p="] } }))).toEqual(["dkim-not-found"]);
  });

  it("a wildcard with a broken key, a CNAME or a typed selector under it: no false alarm", async () => {
    const bad = await probed({ [WILD]: { TXT: ["v=DKIM1; p=AAAA"] } }, ["mine"]).done;
    expect(ids(bad)).toEqual(["dkim-not-found"]);
    expect(bad).toMatchObject({ found: false, keys: [], selectorsTried: SELECTORS.length + 1 });
    // A live key in the wildcard signs under any selector: kept, so the domain counts as sending.
    const live = await probed({ [WILD]: { TXT: [`v=DKIM1; p=${rsaKey(2048)}`] } }).done;
    expect(ids(live)).toEqual(["dkim-not-found"]);
    expect(live.keys).toEqual([{ selector: "*", algorithm: "rsa", bits: 2048, revoked: false }]);
    expect(live).toMatchObject({ found: false, usable: false });
    const cname = await probed({ [WILD]: { CNAME: ["gone.provider.example.net"] } }).done;
    expect(ids(cname)).toEqual(["dkim-not-found"]);
    expect(cname.findings[0]?.vars?.wildcard).toBe(1);
  });

  it("a real selector next to the wildcard is still read", async () => {
    const r = await probed({ [WILD]: { TXT: ["v=DKIM1; p="] }, ...key("google", `v=DKIM1; p=${rsaKey(2048)}`) }).done;
    expect(ids(r)).toEqual(["dkim-ok"]);
    expect(r.keys.map((k) => [k.selector, k.revoked])).toEqual([
      ["*", true],
      ["google", false],
    ]);
  });

  it("the probe lookup failing leaves the wildcard unknown: failed, never a found key", async () => {
    const r = await probed({ [`${PROBE}._domainkey.example.com`]: { $unreachable: true } }).done;
    // No key found and a lookup without an answer, the probe's: absence cannot be claimed.
    expect(r).toMatchObject({ failed: true, found: false });
    expect(ids(r)).toEqual(["lookup-failed"]);
  });

  it("quotes pasted inside the record (zone file syntax): dkim-invalid-record with reason quotes", async () => {
    const b = rsaKey(2048);
    for (const rec of [
      `v=DKIM1; k=rsa; p=${b.slice(0, 200)}" "${b.slice(200)}`,
      `"v=DKIM1; k=rsa; p=${b}"`,
      `"p=${b}"`,
      `v=DKIM1; p=${b}"`,
      `v=DKIM1"; p=${b}`,
    ]) {
      const r = await run(key("s1", rec));
      expect(ids(r), rec).toEqual(["dkim-invalid-record"]);
      expect(r.findings[0]?.vars, rec).toEqual({ reason: "quotes" });
      expect(r.found, rec).toBe(true);
    }
    // n= is quoted-printable, where " is a safe character (RFC 6376 §2.11, §3.6.1).
    expect(ids(await run(key("s1", `v=DKIM1; n="rotated"; p=${b}`)))).toEqual(["dkim-ok"]);
  });

  it("FWS inside p= is part of the base64 string (RFC 6376 §3.6.1): no warning", async () => {
    const b = rsaKey(2048);
    const spaced = `${b.slice(0, 64)} ${b.slice(64, 128)}\t${b.slice(128, 192)}\r\n ${b.slice(192)}`;
    expect(ids(await run(key("s1", `v=DKIM1; k=rsa; p= ${spaced}`)))).toEqual(["dkim-ok"]);
    expect(ids(await run(key("s1", chunks(`v=DKIM1; p=${spaced}`))))).toEqual(["dkim-ok"]);
  });
});

// Q0 is _domainkey.<d> TXT, Q1 the random probe; both with DO. The zones are generated on
// example.com.
describe("the _domainkey signal", () => {
  const PROBE = "pmp-0123abcd";
  const D = "example.com";
  const LIVE = `v=DKIM1; p=${rsaKey(2048)}`;
  const signal = (zone: Zone, options: ZoneOptions = {}, extra: string[] = []) => {
    const resolver = zoneResolver(zone, options);
    return { resolver, done: checkDkim({ resolver }, D, extra, PROBE) };
  };
  const vars = async (zone: Zone, options: ZoneOptions = {}, extra: string[] = []) => {
    const r = await signal(zone, options, extra).done;
    return r.findings.find((f) => f.id === "dkim-not-found")?.vars;
  };
  const SIGNED: ZoneOptions = { signed: true };
  const CLOUDFLARE_SIGNED: ZoneOptions = { signed: true, compactDenial: true };
  // A key under a selector off the list: _domainkey is an empty non-terminal.
  const OFF_LIST: Zone = { [`x9._domainkey.${D}`]: { TXT: [LIVE] } };

  it("asks _domainkey.<d> TXT with DO, confirmed, and the probe with DO", async () => {
    const { resolver, done } = signal({});
    await done;
    expect(resolver.asked).toContain(`_domainkey.${D} TXT do`);
    expect(resolver.asked).toContain(`${PROBE}._domainkey.${D} TXT do`);
  });

  it("validated NXDOMAIN with precomputed signatures: `none`, a warning, the group weak", async () => {
    const r = await signal({}, SIGNED).done;
    expect(ids(r)).toEqual(["dkim-not-found"]);
    expect(r.findings[0]).toMatchObject({ severity: "warning", vars: { tried: SELECTORS.length, none: 1 } });
    expect(r.status).toBe("weak");
  });

  it("NXNAME validated (Compact Denial, RFC 9824 §3.1) gives `none`", async () => {
    expect(await vars({}, CLOUDFLARE_SIGNED)).toEqual({ tried: SELECTORS.length, none: 1 });
  });

  it("NXDOMAIN without AD and no keys: dkim-not-found with no variant, info, status unknown", async () => {
    const r = await signal({}).done;
    expect(r.findings[0]?.vars).toEqual({ tried: SELECTORS.length });
    expect(r.findings[0]?.severity).toBe("info");
    expect(r.status).toBe("unknown");
  });

  it("unsigned Route 53 with a key at google (Q0 NXDOMAIN without AD) changes nothing", async () => {
    const r = await signal({ [`_domainkey.${D}`]: { $nxdomain: true }, ...key("google", LIVE) }).done;
    expect(ids(r)).toEqual(["dkim-ok"]);
    // Without a key either, an unsigned denial proves nothing: unsigned Route 53 denies _domainkey
    // with keys below it (checks/dkim.ts).
    expect(await vars({ [`_domainkey.${D}`]: { $nxdomain: true }, ...OFF_LIST })).toEqual({ tried: SELECTORS.length });
  });

  // Q0 answers empty and Q1 NXNAME.
  it("Cloudflare signed with keys off the list: `hidden`, info, status unknown", async () => {
    const r = await signal(OFF_LIST, CLOUDFLARE_SIGNED).done;
    expect(r.findings[0]).toMatchObject({ severity: "info", vars: { tried: SELECTORS.length, hidden: 1 } });
    expect(r.status).toBe("unknown");
    // Unsigned zones answer the empty non-terminal with NODATA and the probe with NXDOMAIN: the
    // same.
    expect(await vars(OFF_LIST)).toEqual({ tried: SELECTORS.length, hidden: 1 });
  });

  // Q0 answers empty and Q1 NXDOMAIN.
  it("Microsoft 365 with both CNAMEs dangling: dkim-dangling-cname, not found without `hidden`", async () => {
    const z: Zone = {
      [`selector1._domainkey.${D}`]: { CNAME: ["selector1-example-com._domainkey.example.onmicrosoft.example"] },
      [`selector2._domainkey.${D}`]: { CNAME: ["selector2-example-com._domainkey.example.onmicrosoft.example"] },
    };
    const r = await signal(z, SIGNED).done;
    expect(ids(r)).toEqual(["dkim-dangling-cname", "dkim-dangling-cname", "dkim-not-found"]);
    expect(r.findings.at(-1)?.vars).toEqual({ tried: SELECTORS.length });
  });

  it("an empty p= at a selector of the list is an answer: no `hidden`", async () => {
    const r = await signal(key("google", "v=DKIM1; p="), SIGNED).done;
    expect(ids(r)).toEqual(["dkim-revoked", "dkim-not-found"]);
    expect(r.findings.at(-1)?.vars).toEqual({ tried: SELECTORS.length });
  });

  it("another TXT at a selector of the list is an answer: no `hidden`", async () => {
    expect(await vars(key("default", "google-site-verification=abc"), SIGNED)).toEqual({ tried: SELECTORS.length });
  });

  it("a dangling CNAME at _domainkey (NXDOMAIN with the CNAME, RFC 6604 §3) never gives `none`", async () => {
    expect(await vars({ [`_domainkey.${D}`]: { CNAME: ["gone.example.net"] } }, SIGNED)).toEqual({
      tried: SELECTORS.length,
    });
  });

  it("a wildcard at the apex and signed Route 53 (Q1 empty without NXNAME) change nothing", async () => {
    // The apex wildcard answers the probe too (RFC 4592 §2.2.1): the same wildcard reading, no
    // more.
    expect(await vars({ [`*.${D}`]: { TXT: ["v=spf1 -all"] } }, CLOUDFLARE_SIGNED)).toEqual({
      tried: SELECTORS.length,
      wildcard: 1,
    });
    expect(await vars({}, { signed: true, compactDenial: "without-nxname" })).toEqual({ tried: SELECTORS.length });
    expect(await vars(OFF_LIST, { signed: true, compactDenial: "without-nxname" })).toEqual({
      tried: SELECTORS.length,
    });
  });

  it("Q0 without an answer changes nothing and adds no lookup-failed", async () => {
    const r = await signal({ [`_domainkey.${D}`]: { $unreachable: true } }, SIGNED).done;
    expect(ids(r)).toEqual(["dkim-not-found"]);
    expect(r.findings[0]?.vars).toEqual({ tried: SELECTORS.length });
    expect(r.status).toBe("unknown");
  });

  // ADSP (RFC 5617 §4.1) and DKIM reporting (RFC 6651 §3.3) records make _domainkey an empty
  // non-terminal with no key under it.
  it("asks _adsp._domainkey and _report._domainkey, and either one answering rules out `hidden`", async () => {
    const { resolver, done } = signal({});
    await done;
    expect(resolver.asked).toContain(`_adsp._domainkey.${D} TXT`);
    expect(resolver.asked).toContain(`_report._domainkey.${D} TXT`);
    for (const [name, record] of [
      ["_adsp", "dkim=unknown"],
      ["_report", "ra=postmaster"],
    ] as const) {
      const zone: Zone = { [`${name}._domainkey.${D}`]: { TXT: [record] } };
      expect(await vars(zone), name).toEqual({ tried: SELECTORS.length });
      expect(await vars(zone, CLOUDFLARE_SIGNED), name).toEqual({ tried: SELECTORS.length });
    }
    // Their answering nothing leaves hidden as it was; their failing leaves no signal.
    expect(await vars(OFF_LIST)).toEqual({ tried: SELECTORS.length, hidden: 1 });
    expect(await vars({ ...OFF_LIST, [`_adsp._domainkey.${D}`]: { $unreachable: true } })).toEqual({
      tried: SELECTORS.length,
    });
  });

  it("an NXNAME without AD (DNSSEC on, no DS at the registrar) does not give none", async () => {
    expect(await vars({}, { compactDenial: true })).toEqual({ tried: SELECTORS.length });
  });

  it("a signed denial of _domainkey next to an empty p= at a selector does not give none", async () => {
    const z: Zone = { [`_domainkey.${D}`]: { $nxdomain: true }, ...key("google", "v=DKIM1; p=") };
    expect(await vars(z, SIGNED)).toEqual({ tried: SELECTORS.length });
    const dangling: Zone = {
      [`_domainkey.${D}`]: { $nxdomain: true },
      [`k1._domainkey.${D}`]: { CNAME: ["gone.example.net"] },
    };
    expect(await vars(dangling, SIGNED)).toEqual({ tried: SELECTORS.length });
  });

  it("a selector lookup that fails changes nothing but its lookup-failed", async () => {
    expect(ids(await signal({ [`google._domainkey.${D}`]: { $unreachable: true } }, SIGNED).done)).toEqual([
      "lookup-failed",
    ]);
  });

  describe("over DoH, through confirmed()", () => {
    // Each operator answers from the zone, signed or not on its own.
    const per = (zone: Zone, signedBy: readonly string[], options: ZoneOptions = {}) =>
      fakeFetch({}, (op, name, type, flags) =>
        zoneAnswer(zone, name, type, flags, { ...options, signed: signedBy.includes(op) }),
      );
    const over = async (f: ReturnType<typeof fakeFetch>) => {
      const r = await checkDkim({ resolver: createDohResolver({ fetch: f.fn }) }, D, [], PROBE);
      return { r, f };
    };

    it("AD from both operators gives `none`; Q0 goes to two operators, each selector to one", async () => {
      const { r, f } = await over(per({}, ["cloudflare", "google"]));
      expect(r.findings[0]?.vars).toEqual({ tried: SELECTORS.length, none: 1 });
      expect(
        f
          .queries()
          .filter((c) => c.name === `_domainkey.${D}`)
          .map((c) => [c.resolver, c.dnssecOk])
          .sort(),
      ).toEqual([
        ["cloudflare", true],
        ["google", true],
      ]);
      expect(f.queries().filter((c) => c.name === `google._domainkey.${D}`)).toHaveLength(1);
    });

    it("AD in one operator only does not give none, with NXDOMAIN or NXNAME", async () => {
      for (const one of ["cloudflare", "google"]) {
        for (const options of [{}, { compactDenial: true }] as ZoneOptions[]) {
          const { r } = await over(per({}, [one], options));
          expect(r.findings[0]?.vars, `${one} ${JSON.stringify(options)}`).toEqual({ tried: SELECTORS.length });
        }
      }
    });

    it("Q0 in disagreement changes nothing and adds no lookup-failed", async () => {
      // Google sees a key under _domainkey (an empty non-terminal), Cloudflare does not.
      const f = fakeFetch({}, zones({}, { google: OFF_LIST }, { signed: true }));
      const { r } = await over(f);
      expect(ids(r)).toEqual(["dkim-not-found"]);
      expect(r.findings[0]?.vars).toEqual({ tried: SELECTORS.length });
    });
  });

  describe("typed: the user's selector has no key", () => {
    it("a *._domainkey wildcard with a live key answers the given selector: no `typed`", async () => {
      const r = await signal({ [`*._domainkey.${D}`]: { TXT: [LIVE] } }, {}, ["s1"]).done;
      expect(r.findings.find((f) => f.id === "dkim-not-found")?.vars).toEqual({ tried: SELECTORS.length, wildcard: 1 });
      // An empty p= or a TXT that is no key at the wildcard: the given selector has no key, as
      // typed says.
      expect(await vars({ [`*._domainkey.${D}`]: { TXT: ["v=DKIM1; p="] } }, {}, ["s1"])).toEqual({
        tried: SELECTORS.length,
        wildcard: 1,
        typed: "s1",
      });
      expect(await vars({ [`*._domainkey.${D}`]: { TXT: ["v=spf1 -all"] } }, {}, ["s1"])).toEqual({
        tried: SELECTORS.length,
        wildcard: 1,
        typed: "s1",
      });
    });

    it("a selector given with no key and no other key gives `typed`, with the first one given", async () => {
      expect(await vars({}, {}, [" Custom2026 ", "other"])).toEqual({
        tried: SELECTORS.length + 2,
        typed: "custom2026",
      });
    });

    // Both vars are set; the catalog's order decides which text applies.
    it("next to `none` or `hidden`: the catalog's order picks `none`, `typed`, `hidden`", async () => {
      expect(await vars({}, SIGNED, ["custom2026"])).toEqual({
        tried: SELECTORS.length + 1,
        none: 1,
        typed: "custom2026",
      });
      expect(await vars(OFF_LIST, {}, ["custom2026"])).toEqual({
        tried: SELECTORS.length + 1,
        hidden: 1,
        typed: "custom2026",
      });
    });

    it("with a key at another selector, no dkim-not-found and no `typed`", async () => {
      expect(ids(await signal(key("google", LIVE), {}, ["custom2026"]).done)).toEqual(["dkim-ok"]);
    });

    it("a given selector with an empty p= is revoked, not missing: dkim-revoked says it, no `typed`", async () => {
      const r = await signal(key("s9", "v=DKIM1; p="), {}, ["s9"]).done;
      expect(ids(r)).toEqual(["dkim-revoked", "dkim-not-found"]);
      expect(r.findings.find((f) => f.id === "dkim-not-found")?.vars).toEqual({ tried: SELECTORS.length + 1 });
    });

    it("a typed selector that DNS cannot carry is not `typed`", async () => {
      expect(await vars({}, {}, ["bad selector"])).toEqual({ tried: SELECTORS.length });
    });
  });
});
