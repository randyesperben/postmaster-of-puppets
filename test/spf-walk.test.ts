import { describe, expect, it } from "vitest";
import { checkSpf } from "../src/checks/spf.ts";
import type { Resolver } from "../src/dns/types.ts";
import { ids } from "./helpers/findings.ts";
import { includes, includeTerms, provider, run, spf } from "./helpers/spf.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

describe("failures and limits", () => {
  it("lookup-failed when the domain's TXT gets no answer", async () => {
    const r = await run({ "example.com": { $unreachable: true } });
    expect(ids(r)).toEqual(["lookup-failed"]);
    expect(r.findings[0]?.group).toBe("spf");
    expect(r.status).toBe("unknown");
  });

  it("lookup-failed inside the tree", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net a:down.example.org mx:down2.example.org -all", {
        "_spf.example.net": { $unreachable: true },
        "down.example.org": { $unreachable: true },
        "down2.example.org": { $unreachable: true },
      }),
    );
    expect(r.findings.filter((f) => f.id === "lookup-failed").map((f) => f.found)).toEqual([
      "_spf.example.net TXT",
      "down.example.org A",
      "down2.example.org MX",
    ]);
  });

  it("dnssec-broken in the SPF group, with the record still read", async () => {
    const r = await run({ "example.com": { TXT: ["v=spf1 -all"], $servfail: true } });
    expect(ids(r)).toEqual(["dnssec-broken"]);
    expect(r.findings[0]?.group).toBe("spf");
    expect(r.record).toBe("v=spf1 -all");
  });

  it("a name that does not exist", async () => {
    const r = await run({}, "nope.example.com");
    expect(r.lookup).toBe("nxdomain");
    expect(r.findings).toEqual([]);
  });

  it("stops an include loop and reports it as too many lookups", async () => {
    const r = await run({
      "example.com": { TXT: ["v=spf1 include:a.example.net -all"] },
      "a.example.net": { TXT: ["v=spf1 include:example.com -all"] },
    });
    expect(r.findings.find((f) => f.id === "spf-too-many-lookups")?.vars?.loop).toBe("example.com");
  });

  it("bounds the walk of a huge tree", async () => {
    const zone: Zone = {};
    for (let i = 0; i < 60; i++) zone[`n${i}.example.net`] = { TXT: [`v=spf1 include:n${i + 1}.example.net -all`] };
    zone["example.com"] = { TXT: ["v=spf1 include:n0.example.net -all"] };
    const resolver = zoneResolver(zone);
    const r = await checkSpf({ resolver }, "example.com");
    expect(ids(r)).toContain("spf-too-many-lookups");
    expect(resolver.asked.length).toBeLessThanOrEqual(32);
    expect(r.lookupsAtLeast).toBe(true);
  });
});

/**
 * The zone resolver behind a delay drawn from a seeded generator, so answers arrive in a different
 * order on every seed.
 */
function jittered(zone: Zone, seed: number): Resolver {
  const inner = zoneResolver(zone);
  let s = seed;
  const next = (): number => {
    s = (s * 1103515245 + 12345) % 2147483648;
    return s / 2147483648;
  };
  return {
    async query(name, type, opts) {
      await new Promise((r) => setTimeout(r, Math.floor(next() * 6)));
      return inner.query(name, type, opts);
    },
  };
}

describe("evaluation as a receiver walks it", () => {
  it("terms after all are never evaluated, in the domain's own record", async () => {
    const plus = await run(spf("v=spf1 -all include:_spf.example.net", provider("v=spf1 +all")));
    expect(ids(plus)).toEqual(["spf-terms-after-all", "spf-ok"]);
    expect(plus.lookups).toBe(0);
    expect(plus.includes).toEqual([]);
    expect(ids(await run(spf("v=spf1 -all ip4:0.0.0.0/0")))).toEqual(["spf-terms-after-all", "spf-ok"]);
    const auth = await run(spf("v=spf1 -all ip4:192.0.2.1 redirect=_spf.example.net", provider()));
    expect(auth.authorizes).toBe(false);
  });

  it("a provider added after ~all costs no lookup", async () => {
    const { zone, terms } = includeTerms(11);
    const r = await run({
      ...zone,
      "example.com": { TXT: [`v=spf1 ${terms.slice(0, 10).join(" ")} ~all ${terms[10]}`] },
    });
    expect(r.lookups).toBe(10);
    expect(ids(r)).toEqual(["spf-terms-after-all", "spf-ok"]);
  });

  it("terms after all inside an included record are ignored too", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net -all", {
        ...provider("v=spf1 ip4:192.0.2.0/24 ~all include:open.example.net"),
        "open.example.net": { TXT: ["v=spf1 +all"] },
      }),
    );
    expect(ids(r)).toEqual(["spf-ok"]);
    expect(r.lookups).toBe(1);
  });

  for (const q of ["-", "~", "?"]) {
    it(`${q}include of an open record opens nothing`, async () => {
      expect(ids(await run(spf(`v=spf1 ${q}include:_spf.example.net -all`, provider("v=spf1 +all"))))).toEqual([
        "spf-ok",
      ]);
      expect(
        ids(await run(spf(`v=spf1 ${q}include:_spf.example.net -all`, provider("v=spf1 ip4:0.0.0.0/0 -all")))),
      ).toEqual(["spf-ok"]);
    });
  }

  it("a qualifier anywhere on the path closes the branch, while redirect keeps it", async () => {
    const zone = {
      "a.example.net": { TXT: ["v=spf1 -include:b.example.net -all"] },
      "b.example.net": { TXT: ["v=spf1 +all"] },
    };
    expect(ids(await run(spf("v=spf1 include:a.example.net -all", zone)))).toEqual(["spf-ok"]);
    const redirected = await run(
      spf("v=spf1 redirect=_spf.example.net", { ...provider("v=spf1 include:b.example.net -all"), ...zone }),
    );
    expect(ids(redirected)).toEqual(["spf-plus-all"]);
    expect(redirected.findings[0]?.vars?.via).toBe("example.com > redirect=_spf.example.net > include:b.example.net");
  });

  it("a fail match ends the evaluation, so a later open include is never reached", async () => {
    const zone = { "a.example.net": { TXT: ["v=spf1 +all"] }, "b.example.net": { TXT: ["v=spf1 +all"] } };
    expect(ids(await run(spf("v=spf1 -include:a.example.net include:b.example.net -all", zone)))).toEqual(["spf-ok"]);
  });

  it("+all in the 10th include opens the domain, in the 11th it is past the limit", async () => {
    const { zone, terms } = includeTerms(11);
    const open = { "open.example.net": { TXT: ["v=spf1 +all"] } };
    const tenth = await run({
      ...zone,
      ...open,
      "example.com": { TXT: [`v=spf1 ${terms.slice(0, 9).join(" ")} include:open.example.net -all`] },
    });
    expect(ids(tenth)).toEqual(["spf-plus-all"]);
    expect(tenth.lookups).toBe(10);
    const eleventh = await run({
      ...zone,
      ...open,
      "example.com": { TXT: [`v=spf1 ${terms.slice(0, 10).join(" ")} include:open.example.net -all`] },
    });
    expect(ids(eleventh)).toEqual(["spf-too-many-lookups"]);
    const own = await run({ ...zone, "example.com": { TXT: [`v=spf1 ${terms.join(" ")} +all`] } });
    expect(ids(own)).toEqual(["spf-too-many-lookups"]);
  });

  it("an include without SPF stops the evaluation before a later open branch", async () => {
    const r = await run(
      spf("v=spf1 include:gone.example.net include:open.example.net -all", {
        "open.example.net": { TXT: ["v=spf1 +all"] },
      }),
    );
    expect(ids(r)).toEqual(["spf-include-no-spf"]);
  });

  it("the result does not depend on which answer arrives first", async () => {
    // Depth first, include:d.example.net is the 4th lookup; the wide branch after it holds 37 more.
    const zone: Zone = {
      "example.com": { TXT: ["v=spf1 include:a.example.net include:wide.example.net -all"] },
      "a.example.net": { TXT: ["v=spf1 include:b.example.net -all"] },
      "b.example.net": { TXT: ["v=spf1 include:c.example.net -all"] },
      "c.example.net": { TXT: ["v=spf1 include:d.example.net -all"] },
      "d.example.net": { TXT: ["v=spf1 +all"] },
      "wide.example.net": {
        TXT: [`v=spf1 ${Array.from({ length: 9 }, (_, i) => `include:w${i}.example.net`).join(" ")} -all`],
      },
    };
    for (let i = 0; i < 9; i++) {
      zone[`w${i}.example.net`] = {
        TXT: [`v=spf1 ${[0, 1, 2].map((j) => `include:w${i}-${j}.example.net`).join(" ")} -all`],
      };
      for (let j = 0; j < 3; j++) zone[`w${i}-${j}.example.net`] = { TXT: ["v=spf1 ip4:192.0.2.1 -all"] };
    }
    const results = [];
    for (let seed = 1; seed <= 12; seed++)
      results.push(await checkSpf({ resolver: jittered(zone, seed) }, "example.com"));
    const first = results[0];
    expect(first?.findings.find((f) => f.id === "spf-plus-all")?.vars?.via).toBe(
      "example.com > include:a.example.net > include:b.example.net > include:c.example.net > include:d.example.net",
    );
    expect(first?.lookupsAtLeast).toBe(true);
    expect(first?.findings.find((f) => f.id === "spf-too-many-lookups")?.vars).toMatchObject({
      count: first?.lookups,
      atLeast: 1,
    });
    for (const r of results) expect(r).toEqual(first);
  });

  it("a tree inside the budget gives an exact count", async () => {
    const r = await run(includes(11));
    expect(r.lookupsAtLeast).toBe(false);
    expect(r.findings.find((f) => f.id === "spf-too-many-lookups")?.vars).toEqual({ count: 11 });
  });

  it("void lookups of a are counted per address family, and the worse family counts", async () => {
    const v4only = {
      "h1.example.com": { A: ["192.0.2.1"] },
      "h2.example.com": { A: ["192.0.2.2"] },
      "h3.example.com": { A: ["192.0.2.3"] },
    };
    const r = await run(
      spf("v=spf1 a:h1.example.com a:h2.example.com a:h3.example.com include:_spf.example.net -all", {
        ...v4only,
        ...provider(),
      }),
    );
    expect(ids(r)).toContain("spf-too-many-void-lookups");
    expect(r.voidLookups).toBe(3);
    const mixed = await run(
      spf("v=spf1 a:h1.example.com a:h2.example.com a:h3.example.com -all", {
        ...v4only,
        "h2.example.com": { AAAA: ["2001:db8::2"] },
      }),
    );
    expect(mixed.voidLookups).toBe(2);
    expect(ids(mixed)).toEqual(["spf-ok"]);
  });
});

describe("case, the MX limit, unknown modifiers and an include at a CNAME", () => {
  it("reads mechanisms and qualifiers in any case", async () => {
    const r = await run(spf("v=spf1 INCLUDE:_spf.example.net -ALL", provider("v=spf1 +ALL")));
    expect(ids(r)).toEqual(["spf-plus-all"]);
    expect(r.findings[0]?.vars?.via).toBe("example.com > INCLUDE:_spf.example.net");
    expect(r.includes).toEqual(["_spf.example.net"]);
  });

  it("10 MX hosts are within the limit", async () => {
    const mx = Array.from({ length: 10 }, (_, i) => `${i} mx${i}.example.com`);
    expect(ids(await run(spf("v=spf1 mx -all", { "example.com": { TXT: ["v=spf1 mx -all"], MX: mx } })))).toEqual([
      "spf-ok",
    ]);
  });

  it("ignores unknown modifiers (§6)", async () => {
    expect(ids(await run(spf("v=spf1 foo=bar ip4:192.0.2.1 x-custom=%{d}.%% v2=-all -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(spf("v=spf1 ip4:192.0.2.1 empty= -all")))).toEqual(["spf-ok"]);
  });

  it("follows an include that points at a CNAME", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net -all", {
        "_spf.example.net": { CNAME: ["spf.example.org"] },
        "spf.example.org": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      }),
    );
    expect(ids(r)).toEqual(["spf-ok"]);
    expect(r.lookups).toBe(1);
    expect(r.tree?.children[0]?.children.map((c) => c.term)).toEqual(["ip4:192.0.2.0/24", "-all"]);
    const open = await run(
      spf("v=spf1 include:_spf.example.net -all", {
        "_spf.example.net": { CNAME: ["spf.example.org"] },
        "spf.example.org": { TXT: ["v=spf1 +all"] },
      }),
    );
    expect(ids(open)).toEqual(["spf-plus-all"]);
  });
});
