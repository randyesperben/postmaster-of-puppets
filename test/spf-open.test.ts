import { describe, expect, it } from "vitest";
import { checkSpf } from "../src/checks/spf.ts";
import { ids } from "./helpers/findings.ts";
import { provider, run, runNoCloud, spf } from "./helpers/spf.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

describe("open to the whole internet", () => {
  const host = (record: string): Zone => ({
    "example.com": { TXT: [record], A: ["192.0.2.1"], AAAA: ["2001:db8::1"], MX: ["10 mx.example.com"] },
    "mx.example.com": { A: ["192.0.2.2"] },
    "v6.example.com": { AAAA: ["2001:db8::3"] },
  });

  it("a/0 and mx/0 when the target has an address of that family", async () => {
    expect(ids(await run(host("v=spf1 a/0 -all")))).toEqual(["spf-open-range"]);
    expect(ids(await run(host("v=spf1 a//0 -all")))).toEqual(["spf-open-range"]);
    expect(ids(await run(host("v=spf1 mx/0 -all")))).toEqual(["spf-open-range"]);
    expect(ids(await run(host("v=spf1 mx//0 -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(host("v=spf1 ~a/0 -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(host("v=spf1 a:v6.example.com/0 -all")))).toEqual(["spf-ok"]);
    const r = await run(host("v=spf1 a/0 -all"));
    expect(r.findings[0]).toMatchObject({ found: "a/0", vars: { via: "example.com" } });
  });

  it("an exists with no sender macro that resolves matches every address (§5.7)", async () => {
    const zone = (record: string) => spf(record, { "x.example.com": { A: ["127.0.0.2"] }, ...provider("v=spf1 +all") });
    expect(ids(await run(zone("v=spf1 exists:x.example.com -all")))).toEqual(["spf-open-range"]);
    expect(ids(await run(zone("v=spf1 ~exists:x.example.com include:_spf.example.net -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(zone("v=spf1 exists:void.example.com ~all")))).toEqual(["spf-ok"]);
  });

  it("ip4 or ip6 ranges whose union covers the whole space", async () => {
    // With the generated table a /1 already reaches cloud blocks on its own; the union needs none.
    const run = runNoCloud;
    const two = await run(spf("v=spf1 ip4:0.0.0.0/1 ip4:128.0.0.0/1 -all"));
    expect(ids(two)).toContain("spf-open-range");
    expect(two.findings.find((f) => f.id === "spf-open-range")?.found).toBe("ip4:0.0.0.0/1 ip4:128.0.0.0/1");
    const split = await run(
      spf("v=spf1 ip6:::/1 include:_spf.example.net -all", provider("v=spf1 ip4:192.0.2.0/24 ip6:8000::/1 -all")),
    );
    expect(split.findings.find((f) => f.id === "spf-open-range")?.vars?.via).toBe(
      "example.com > include:_spf.example.net",
    );
    expect(ids(await run(spf("v=spf1 ip4:0.0.0.0/1 ip4:128.0.0.0/2 -all")))).not.toContain("spf-open-range");
    expect(ids(await run(spf("v=spf1 ip4:0.0.0.0/1 ~ip4:128.0.0.0/1 -all")))).not.toContain("spf-open-range");
    expect(
      ids(
        await run(spf("v=spf1 ip4:0.0.0.0/1 -include:_spf.example.net -all", provider("v=spf1 ip4:128.0.0.0/1 -all"))),
      ),
    ).not.toContain("spf-open-range");
  });
});

describe("lookups and DNSSEC", () => {
  // A broken DNSSEC answer with no address in it is no match, so exists and a/0 open nothing on an
  // empty CD answer.
  for (const record of ["v=spf1 exists:broken.example.org -all", "v=spf1 a:broken.example.org/0 -all"]) {
    it(`${record} over broken DNSSEC with no address does not open SPF`, async () => {
      const r = await run(spf(record, { "broken.example.org": { $servfail: true } }));
      expect(ids(r)).not.toContain("spf-open-range");
      expect(ids(r)).not.toContain("spf-plus-all");
      expect(ids(r)).toContain("dnssec-broken");
    });
  }

  // Each address lookup of mx/N goes through answered() like any other lookup, so a host with no
  // answer cannot hide an opening.
  it("mx/8 with its host unanswered says lookup-failed, and with broken DNSSEC says so", async () => {
    const mx = { "example.net": { MX: ["10 mx.example.net"] } };
    const down = await run(spf("v=spf1 mx:example.net/8 -all", { ...mx, "mx.example.net": { $unreachable: true } }));
    expect(down.findings.filter((f) => f.id === "lookup-failed").map((f) => f.found)).toContain("mx.example.net A");
    const broken = await run(
      spf("v=spf1 mx:example.net/8 -all", { ...mx, "mx.example.net": { A: ["3.5.6.7"], $servfail: true } }),
    );
    expect(broken.findings.filter((f) => f.id === "dnssec-broken").map((f) => f.found)).toContain("mx.example.net A");
  });

  it("dnssec-broken on the target of include, a, mx and exists, with its path", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net a:h.example.org mx:m.example.org exists:e.example.org -all", {
        "_spf.example.net": { TXT: ["v=spf1 -all"], $servfail: true },
        "h.example.org": { A: ["192.0.2.1"], $servfail: true },
        "m.example.org": { MX: ["10 mx.example.org"], $servfail: true },
        "e.example.org": { A: ["127.0.0.2"], $servfail: true },
      }),
    );
    const broken = r.findings.filter((f) => f.id === "dnssec-broken");
    expect(broken.map((f) => [f.group, f.found, f.vars?.via])).toEqual([
      ["spf", "_spf.example.net TXT", "example.com > include:_spf.example.net"],
      ["spf", "h.example.org A", "example.com"],
      ["spf", "h.example.org AAAA", "example.com"],
      ["spf", "m.example.org MX", "example.com"],
      ["spf", "e.example.org A", "example.com"],
    ]);
    expect(r.status).toBe("fail");
  });
});

describe("errors that cut the evaluation", () => {
  const plusAll = (r: { findings: { id: string }[] }) =>
    ids(r).some((id) => id === "spf-plus-all" || id === "spf-open-range");

  it("+all in a record with a syntax error behind the all opens nothing (§4.6)", async () => {
    const r = await run(spf("v=spf1 +all ip4:192.0.2.300"));
    expect(ids(r)).toContain("spf-syntax-error");
    expect(plusAll(r)).toBe(false);
  });

  it("+all with two v=spf1 records at a name of the path opens nothing (§4.5)", async () => {
    const root = await run({ "example.com": { TXT: ["v=spf1 +all", "v=spf1 -all"] } });
    expect(ids(root)).toEqual(["spf-multiple-records"]);
    const inner = await run(
      spf("v=spf1 include:_spf.example.net +all", { "_spf.example.net": { TXT: ["v=spf1 -all", "v=spf1 +all"] } }),
    );
    expect(ids(inner)).toContain("spf-multiple-records");
    expect(plusAll(inner)).toBe(false);
  });

  it("+all behind an include of a name with no SPF opens nothing (§5.2)", async () => {
    const r = await run(
      spf("v=spf1 include:_spf.example.net +all", { "_spf.example.net": { TXT: ["google-site-verification=x"] } }),
    );
    expect(ids(r)).toContain("spf-include-no-spf");
    expect(plusAll(r)).toBe(false);
  });

  it("+all behind the third void lookup opens nothing, behind the second it does (§4.6.4)", async () => {
    const three = await run(spf("v=spf1 a:v1.example.net a:v2.example.net a:v3.example.net +all"));
    expect(ids(three)).toContain("spf-too-many-void-lookups");
    expect(plusAll(three)).toBe(false);
    expect(plusAll(await run(spf("v=spf1 a:v1.example.net a:v2.example.net +all")))).toBe(true);
  });

  it("+all behind an mx term with 11 hosts opens nothing (§4.6.4)", async () => {
    const mx = Array.from({ length: 11 }, (_, i) => `10 mx${i}.example.net`);
    const r = await run({ "example.com": { TXT: ["v=spf1 mx +all"], MX: mx } });
    expect(ids(r)).toContain("spf-mx-too-many-hosts");
    expect(plusAll(r)).toBe(false);
  });
});

describe("ranges anyone can rent", () => {
  // Injected table: the single /16 block 203.0.0.0/16 and the single /32 block 2001:db8::/32.
  const TABLE = { v4: [203 * 256, 0], v6: [0x20010db8, 0] };
  const runT = (zone: Zone) => checkSpf({ resolver: zoneResolver(zone) }, "example.com", TABLE);
  const cloud = (r: { findings: { id: string; vars?: Record<string, string | number> }[] }) =>
    r.findings.find((f) => f.id === "spf-open-range" && f.vars?.reason === "cloud");

  it("injected table: a + range wider than the cut that reaches a block opens, with reason cloud", async () => {
    const r = await runT(spf("v=spf1 ip4:203.0.0.0/8 -all"));
    expect(ids(r)).toEqual(["spf-open-range"]);
    expect(r.findings[0]).toMatchObject({ found: "ip4:203.0.0.0/8", vars: { via: "example.com", reason: "cloud" } });
    expect(cloud(await runT(spf("v=spf1 ip6:2001:db8::/28 -all")))).toBeDefined();
    expect(
      cloud(await runT(spf("v=spf1 include:_spf.example.net -all", provider("v=spf1 ip4:203.0.0.0/15 -all"))))?.vars
        ?.via,
    ).toBe("example.com > include:_spf.example.net");
  });

  it("injected table: outside the blocks, at the cut, with another qualifier or after all: closed", async () => {
    expect(ids(await runT(spf("v=spf1 ip4:198.0.0.0/8 -all")))).toEqual(["spf-wide-range"]);
    expect(ids(await runT(spf("v=spf1 ip4:203.0.0.0/16 -all")))).toEqual(["spf-ok"]);
    expect(ids(await runT(spf("v=spf1 ip6:2001:db8::/32 -all")))).toEqual(["spf-ok"]);
    expect(ids(await runT(spf("v=spf1 ~ip4:203.0.0.0/8 -all")))).toEqual(["spf-ok"]);
    expect(ids(await runT(spf("v=spf1 -all ip4:203.0.0.0/8")))).toEqual(["spf-terms-after-all", "spf-ok"]);
    expect(
      cloud(await runT(spf("v=spf1 -include:_spf.example.net -all", provider("v=spf1 ip4:203.0.0.0/8 -all")))),
    ).toBeUndefined();
  });

  it("injected table: a block an earlier non-pass term already matches is not the forger's, even in part", async () => {
    expect(cloud(await runT(spf("v=spf1 -ip4:203.0.0.0/16 ip4:203.0.0.0/8 -all")))).toBeUndefined();
    expect(cloud(await runT(spf("v=spf1 ?ip4:203.0.0.128/25 ip4:203.0.0.0/8 -all")))).toBeUndefined();
    expect(
      cloud(
        await runT(
          spf("v=spf1 -ip4:203.0.0.0/16 include:_spf.example.net -all", provider("v=spf1 ip4:203.0.0.0/8 -all")),
        ),
      ),
    ).toBeUndefined();
    // A block taken inside an include does not stop the parent: that include just does not match.
    expect(
      cloud(
        await runT(
          spf("v=spf1 include:_spf.example.net ip4:203.0.0.0/8 -all", provider("v=spf1 -ip4:203.0.0.0/16 -all")),
        ),
      ),
    ).toBeDefined();
    expect(cloud(await runT(spf("v=spf1 ip4:203.0.0.0/8 -ip4:203.0.0.0/16 -all")))).toBeDefined();
  });

  it("injected table: a and mx with a wide prefix, through their addresses", async () => {
    const zone = (record: string): Zone => ({
      "example.com": { TXT: [record], A: ["203.0.113.1"], MX: ["10 mx.example.com"] },
      "mx.example.com": { A: ["198.51.100.1"], AAAA: ["2001:db8::1"] },
    });
    expect(cloud(await runT(zone("v=spf1 a/8 -all")))).toMatchObject({ found: "a/8" });
    expect(cloud(await runT(zone("v=spf1 mx//28 -all")))).toMatchObject({ found: "mx//28" });
    expect(ids(await runT(zone("v=spf1 mx/8 -all")))).toEqual(["spf-wide-range"]);
    expect(ids(await runT(zone("v=spf1 a/16 mx/24 -all")))).toEqual(["spf-ok"]);
  });

  it("generated table: +ip4:3.0.0.0/8 (EC2) opens, +ip4:17.0.0.0/8 (no cloud) is only a wide range", async () => {
    expect(cloud(await run(spf("v=spf1 ip4:3.0.0.0/8 -all")))).toMatchObject({ found: "ip4:3.0.0.0/8" });
    expect(ids(await run(spf("v=spf1 ip4:17.0.0.0/8 -all")))).toEqual(["spf-wide-range"]);
  });

  it("generated table: +ip4:0.0.0.0/1 opens; an EC2 /16, ~ip4:3.0.0.0/8 and terms after -all do not", async () => {
    expect(cloud(await run(spf("v=spf1 ip4:0.0.0.0/1 -all")))).toBeDefined();
    expect(ids(await run(spf("v=spf1 ip4:3.0.0.0/16 -all")))).toEqual(["spf-ok"]);
    expect(ids(await run(spf("v=spf1 ~ip4:3.0.0.0/8 -all")))).toEqual(["spf-ok"]);
    expect(cloud(await run(spf("v=spf1 -all ip4:3.0.0.0/8")))).toBeUndefined();
  });

  it("generated table: +a/8 with an address in a cloud and a + ip6 /28 with cloud addresses open", async () => {
    expect(cloud(await run({ "example.com": { TXT: ["v=spf1 a/8 -all"], A: ["3.0.0.10"] } }))).toBeDefined();
    expect(cloud(await run(spf("v=spf1 ip6:2400:6500::/28 -all")))).toBeDefined();
  });
});
