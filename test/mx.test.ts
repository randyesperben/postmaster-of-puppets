import { describe, expect, it } from "vitest";
import { checkMx, zoneApex } from "../src/checks/mx.ts";
import { P4, P6, SOA } from "./helpers/check.ts";
import { fixtureResolver } from "./helpers/dns.ts";
import { idsWithSeverity } from "./helpers/findings.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

const run = (zone: Zone, domain = "example.com") => checkMx({ resolver: zoneResolver(zone) }, domain);

describe("checkMx", () => {
  it("mx-ok: hosts that resolve to public addresses", async () => {
    const r = await run({
      "example.com": { MX: ["20 mx2.example.com", "10 mx1.example.com"] },
      "mx1.example.com": { A: [P4] },
      "mx2.example.com": { AAAA: [P6] },
    });
    expect(idsWithSeverity(r)).toEqual(["mx-ok:pass"]);
    expect(r.findings[0]?.id).toBe("mx-ok");
    expect(r.status).toBe("pass");
    expect(r.hosts).toEqual([
      { preference: 10, host: "mx1.example.com", addresses: [P4] },
      { preference: 20, host: "mx2.example.com", addresses: [P6] },
    ]);
  });

  it("mx-null: a single 0 . declares no mail (RFC 7505)", async () => {
    const r = await run({ "example.com": { MX: ["0 ."] } });
    expect(idsWithSeverity(r)).toEqual(["mx-null:info"]);
    expect(r.nullMx).toBe(true);
    expect(r.status).toBe("pass");
  });

  it("mx-null with the recorded example.com answer", async () => {
    const r = await checkMx({ resolver: fixtureResolver() }, "example.com");
    expect(r.nullMx).toBe(true);
  });

  it("mx-null-with-others: a null MX next to a real one", async () => {
    const r = await run({ "example.com": { MX: ["0 .", "10 mx.example.com"] }, "mx.example.com": { A: [P4] } });
    expect(idsWithSeverity(r)).toContain("mx-null-with-others:critical");
    expect(r.status).toBe("fail");
    expect(r.nullMx).toBe(false);
  });

  it("mx-missing: no MX at all", async () => {
    const r = await run({ "example.com": { TXT: ["v=spf1 -all"] } });
    expect(idsWithSeverity(r)).toEqual(["mx-missing:warning"]);
    expect(r.status).toBe("weak");
    expect(r.lookup).toBe("nodata");
  });

  it("mx-cname: the target is an alias (RFC 2181 §10.3)", async () => {
    const r = await run({
      "example.com": { MX: ["10 mail.example.com"] },
      "mail.example.com": { CNAME: ["host.example.net"] },
      "host.example.net": { A: [P4] },
    });
    expect(idsWithSeverity(r)).toEqual(["mx-cname:warning"]);
    expect(r.findings[0]?.id).toBe("mx-cname");
    expect(r.hosts[0]?.addresses).toEqual([P4]);
  });

  it("mx-ip-literal: critical when every host is one, warning next to a good host", async () => {
    const literal = await run({ "example.com": { MX: ["10 192.0.2.1"] } });
    expect(idsWithSeverity(literal)).toEqual(["mx-ip-literal:critical"]);
    expect(literal.findings[0]?.id).toBe("mx-ip-literal");
    const mixed = await run({
      "example.com": { MX: ["10 192.0.2.1", "20 mx.example.com"] },
      "mx.example.com": { A: [P4] },
    });
    expect(idsWithSeverity(mixed)).toEqual(["mx-ip-literal:warning"]);
    expect(mixed.status).toBe("weak");
  });

  it("mx-unresolvable: a target with no address", async () => {
    const r = await run({ "example.com": { MX: ["10 gone.example.com"] } });
    expect(idsWithSeverity(r)).toEqual(["mx-unresolvable:critical"]);
    expect(r.status).toBe("fail");
  });

  it("mx-private-ip: a target on a private address", async () => {
    const r = await run({
      "example.com": { MX: ["10 mx.example.com"] },
      "mx.example.com": { A: ["10.0.0.5"], AAAA: ["fd00::5"] },
    });
    expect(idsWithSeverity(r)).toEqual(["mx-private-ip:critical"]);
    expect(r.findings[0]?.id).toBe("mx-private-ip");
  });

  it("lookup-failed when the MX lookup gets no answer", async () => {
    const r = await run({ "example.com": { $unreachable: true } });
    expect(idsWithSeverity(r)).toEqual(["lookup-failed:warning"]);
    expect(r.findings[0]?.group).toBe("mx");
    expect(r.status).toBe("unknown");
  });

  it("lookup-failed when a host's addresses cannot be read", async () => {
    const r = await run({ "example.com": { MX: ["10 mx.example.com"] }, "mx.example.com": { $unreachable: true } });
    expect(idsWithSeverity(r)).toEqual(["lookup-failed:warning"]);
    expect(r.status).toBe("unknown");
  });

  it("dnssec-broken in the MX group when SERVFAIL clears with CD", async () => {
    const r = await run({
      "example.com": { MX: ["10 mx.example.com"], $servfail: true },
      "mx.example.com": { A: [P4] },
    });
    expect(idsWithSeverity(r)).toEqual(["dnssec-broken:critical"]);
    expect(r.findings[0]?.group).toBe("mx");
    expect(r.status).toBe("fail");
  });

  it("dnssec-broken on a host's address: the host is not usable", async () => {
    const r = await run({
      "example.com": { MX: ["10 mx.example.com"] },
      "mx.example.com": { A: [P4], $servfail: true },
    });
    expect(idsWithSeverity(r)).toEqual(["dnssec-broken:critical"]);
    expect(r.findings[0]?.group).toBe("mx");
    expect(r.findings[0]?.found).toBe("mx.example.com A/AAAA");
    expect(r.status).toBe("fail");
  });

  it("dnssec-broken on one host next to a good one is a warning", async () => {
    const r = await run({
      "example.com": { MX: ["10 mx1.example.com", "20 mx2.example.com"] },
      "mx1.example.com": { A: [P4], $servfail: true },
      "mx2.example.com": { A: [P4] },
    });
    expect(idsWithSeverity(r)).toEqual(["dnssec-broken:warning"]);
    expect(r.status).toBe("weak");
  });

  it("mx-private-ip as a warning when one family is private and the other public", async () => {
    const r = await run({
      "example.com": { MX: ["10 mx.example.com"] },
      "mx.example.com": { A: ["10.0.0.5"], AAAA: [P6] },
    });
    expect(idsWithSeverity(r)).toEqual(["mx-private-ip:warning"]);
    expect(r.findings[0]?.found).toBe("mx.example.com 10.0.0.5");
    expect(r.status).toBe("weak");
  });

  it("a documentation address in an MX host is not reachable", async () => {
    const r = await run({ "example.com": { MX: ["10 mx.example.com"] }, "mx.example.com": { A: ["192.0.2.25"] } });
    expect(idsWithSeverity(r)).toEqual(["mx-private-ip:critical"]);
  });

  it("a null MX needs preference 0: 10 . alone is flagged", async () => {
    const r = await run({ "example.com": { MX: ["10 ."] } });
    expect(idsWithSeverity(r)).toEqual(["mx-null:warning"]);
    expect(r.findings[0]?.vars).toEqual({ preference: 10 });
    expect(r.nullMx).toBe(true);
    expect(r.status).toBe("weak");
  });

  it("past the host limit, broken first hosts do not make it critical", async () => {
    const zone: Zone = {
      "example.com": { MX: Array.from({ length: 12 }, (_, i) => `${i + 1} mx${i + 1}.example.com`) },
    };
    zone["mx11.example.com"] = { A: [P4] };
    zone["mx12.example.com"] = { A: [P4] };
    const r = await run(zone);
    expect(r.findings.some((f) => f.severity === "critical")).toBe(false);
    expect(r.findings.filter((f) => f.id === "mx-unresolvable")).toHaveLength(10);
    expect(r.status).toBe("unknown");
  });

  it("mx-missing says whether the implicit MX has an address (RFC 5321 §5.1)", async () => {
    const none = await run({ "example.com": { TXT: ["v=spf1 -all"] } });
    expect(idsWithSeverity(none)).toEqual(["mx-missing:warning"]);
    expect(none.findings[0]?.vars).toEqual({ implicit: "none" });
    const a = await run({ "example.com": { A: [P4], AAAA: [P6] } });
    expect(idsWithSeverity(a)).toEqual(["mx-missing:warning"]);
    expect(a.findings[0]?.vars).toEqual({ implicit: "address" });
    expect(a.findings[0]?.found).toBe(`${P4} ${P6}`);
  });

  it("reports a name that does not exist", async () => {
    const r = await run({}, "nope.example.com");
    expect(r.lookup).toBe("nxdomain");
    expect(r.findings).toEqual([]);
  });
});

describe("zoneApex", () => {
  it("is the name itself when it owns the SOA, the SOA owner in authority otherwise", async () => {
    const zone: Zone = { "example.com": { SOA, MX: ["0 ."] }, "mail.example.com": { A: ["192.0.2.1"] } };
    const ctx = { resolver: zoneResolver(zone) };
    expect(await zoneApex(ctx, "example.com")).toBe("example.com");
    expect(await zoneApex(ctx, "mail.example.com")).toBe("example.com");
    expect(await zoneApex(ctx, "nope.example.com")).toBe("example.com");
  });

  it("reads the recorded google.com answers", async () => {
    const ctx = { resolver: fixtureResolver() };
    expect(await zoneApex(ctx, "google.com")).toBe("google.com");
  });

  it("is unknown when the lookup fails", async () => {
    expect(
      await zoneApex({ resolver: zoneResolver({ "example.com": { $unreachable: true } }) }, "example.com"),
    ).toBeUndefined();
  });

  // A CNAME is never a zone apex (RFC 1034 §3.6.2): the alias's zone is its parent's.
  it("is the parent's zone for an alias, and unknown when the parent is an alias too or a TLD", async () => {
    const alias = zoneResolver({ "www.example.com": { CNAME: ["example.net"] }, "example.net": { A: ["192.0.2.1"] } });
    expect(await zoneApex({ resolver: alias }, "www.example.com")).toBe("example.com");
    const twice = zoneResolver({
      "a.example.com": { CNAME: ["example.net"] },
      "b.a.example.com": { CNAME: ["example.net"] },
      "example.net": { A: ["192.0.2.1"] },
    });
    expect(await zoneApex({ resolver: twice }, "b.a.example.com")).toBeUndefined();
    const apex = zoneResolver({ "example.com": { CNAME: ["example.net"] }, "example.net": { A: ["192.0.2.1"] } });
    expect(await zoneApex({ resolver: apex }, "example.com")).toBeUndefined();
  });

  // The parent of an alias that is a public suffix is no zone the domain's owner manages: a host
  // relative to co.uk would be “_dmarc.example”. The same PSL as DMARC's.
  it("is unknown for an alias whose parent is a public suffix of the PSL, ICANN or private", async () => {
    for (const parent of ["co.uk", "github.io"]) {
      const zone = zoneResolver({
        [parent]: { SOA },
        [`example.${parent}`]: { CNAME: ["example.net"] },
        "example.net": { A: ["192.0.2.1"] },
      });
      expect(await zoneApex({ resolver: zone }, `example.${parent}`), parent).toBeUndefined();
    }
    const below = zoneResolver({
      "example.co.uk": { SOA },
      "shop.example.co.uk": { CNAME: ["example.net"] },
      "example.net": { A: ["192.0.2.1"] },
    });
    expect(await zoneApex({ resolver: below }, "shop.example.co.uk")).toBe("example.co.uk");
  });
});
