// Report.simulation: one test per row of the table, the pct and t=y cases, sp and np below the
// asked level, no simulation without a verdict, and the exact authResults lines.
import { describe, expect, it } from "vitest";
import { checkDomain } from "../src/index.ts";
import { simulate } from "../src/simulate.ts";
import type { Report } from "../src/types.ts";
import { check, googleZone, input, P4, RUA, SOA } from "./helpers/check.ts";
import { type Node, type Zone, zoneResolver } from "./helpers/zone.ts";

const FAIL = (p: string) =>
  `mx.receiver.example; spf=pass smtp.mailfrom=sender.example.net; dkim=none; dmarc=fail (p=${p}) header.from=example.com`;
const OPEN = "mx.receiver.example; spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=pass header.from=example.com";
const NONE =
  "mx.receiver.example; spf=pass smtp.mailfrom=sender.example.net; dkim=none; dmarc=none header.from=example.com";

const dmarc = (tags: string) => `v=DMARC1; ${tags}; rua=mailto:${RUA}`;
const sim = async (zone: Zone, domain = "example.com") => (await check(zone, domain)).simulation;
const withDmarc = (tags: string) => sim(googleZone(dmarc(tags)));
function noDmarc(): Zone {
  const z = googleZone();
  delete z["_dmarc.example.com"];
  return z;
}

describe("simulation, one test per row of the table", () => {
  it("Can't tell: no simulation", async () => {
    const z = googleZone();
    z["_dmarc.example.com"] = { $unreachable: true };
    const r = await check(z);
    expect(r.verdict).toBe("cant-tell");
    expect(r.simulation).toBeUndefined();
  });

  it("DMARC got no answer: no simulation, also when the open SPF already decides Spoofable", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    z["_dmarc.example.com"] = { $unreachable: true };
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(r.simulation).toBeUndefined();
    // A parent's step without an answer leaves the name's own record, and its policy, known.
    const own = googleZone();
    (own["example.com"] as Node).TXT = ["v=spf1 +all"];
    own["_dmarc.com"] = { $unreachable: true };
    const parentless = await check(own);
    expect(parentless.findings.map((f) => f.id)).toContain("lookup-failed");
    expect(parentless.simulation?.reason).toBe("open-spf");
  });

  it("DNSSEC broken on _dmarc: no simulation either, the record behind it is unknown", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    z["_dmarc.example.com"] = { $servfail: true };
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(r.findings.some((f) => f.id === "dnssec-broken" && f.group === "dmarc")).toBe(true);
    expect(r.simulation).toBeUndefined();
  });

  it("a name that does not exist with no DMARC record: no simulation", async () => {
    const r = await check({ "example.com": { SOA } }, "nope.example.com");
    expect(r.outcome).toBe("nxdomain");
    expect(r.simulation).toBeUndefined();
  });

  it("unreachable: no simulation", () => {
    const r = {
      verdict: "cant-tell",
      outcome: "unreachable",
      domain: "example.com",
      findings: [],
    } as unknown as Report;
    expect(simulate(r, { failed: false, dnssecBroken: false })).toBeUndefined();
    // The outcome alone decides, whatever the verdict says.
    expect(simulate({ ...r, verdict: "spoofable" }, { failed: false, dnssecBroken: false })).toBeUndefined();
  });

  it("no applicable record: none, asks nothing, no-dmarc", async () => {
    expect(await sim(noDmarc())).toEqual({
      forgedDmarc: "none",
      asks: "nothing",
      reason: "no-dmarc",
      authResults: NONE,
    });
  });

  it("no DMARC with SPF open to everyone: still none (the row above wins)", async () => {
    const z = noDmarc();
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    expect((await sim(z))?.reason).toBe("no-dmarc");
  });

  it("SPF open through an include that returns +all, with reject: the forgery passes DMARC", async () => {
    const z = googleZone(dmarc("p=reject"));
    (z["_spf.google.com"] as Node).TXT = ["v=spf1 +all"];
    expect(await sim(z)).toEqual({
      forgedDmarc: "pass",
      asks: "nothing",
      reason: "open-spf",
      dmarcAsks: "reject",
      authResults: OPEN,
    });
  });

  // What DMARC would ask once the SPF is fixed, t=y and pct applied as in asks, so a caller can say
  // where fixing the SPF leads.
  it.each([
    ["p=quarantine", "quarantine"],
    ["p=reject; t=y", "quarantine"],
    ["p=quarantine; pct=50", "nothing"],
    ["p=none", "nothing"],
  ] as const)("SPF open with %s: dmarcAsks %s", async (tags, asks) => {
    const z = googleZone(dmarc(tags));
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    expect(await sim(z)).toMatchObject({ reason: "open-spf", asks: "nothing", dmarcAsks: asks });
  });

  it("SPF open at the Organizational Domain with aspf=r: the forgery passes with it in the envelope", async () => {
    const z: Zone = {
      "example.com": { SOA, TXT: ["v=spf1 +all"] },
      "_dmarc.example.com": { TXT: [dmarc("p=reject")] },
      "shop.example.com": { TXT: ["v=spf1 -all"] },
    };
    expect(await sim(z, "shop.example.com")).toEqual({
      forgedDmarc: "pass",
      asks: "nothing",
      reason: "open-spf",
      dmarcAsks: "reject",
      authResults:
        "mx.receiver.example; spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=pass header.from=shop.example.com",
    });
  });

  it("effective policy none: fail, asks nothing, policy-none; also an invalid p with a valid rua", async () => {
    expect(await withDmarc("p=none")).toEqual({
      forgedDmarc: "fail",
      asks: "nothing",
      reason: "policy-none",
      authResults: FAIL("none"),
    });
    expect((await withDmarc("p=bogus"))?.reason).toBe("policy-none");
  });

  it("t=y lowers reject one level: testing, asks quarantine", async () => {
    expect(await withDmarc("p=reject; t=y")).toEqual({
      forgedDmarc: "fail",
      asks: "quarantine",
      reason: "testing",
      authResults: FAIL("reject"),
    });
  });

  it("pct between 1 and 99 with reject: sampled, asks quarantine, reject for the sample", async () => {
    expect(await withDmarc("p=reject; pct=25")).toEqual({
      forgedDmarc: "fail",
      asks: "quarantine",
      reason: "sampled",
      sampled: { pct: 25, full: "reject" },
      authResults: FAIL("reject"),
    });
  });

  it("quarantine: fail, asks quarantine", async () => {
    expect(await withDmarc("p=quarantine")).toEqual({
      forgedDmarc: "fail",
      asks: "quarantine",
      reason: "quarantine",
      authResults: FAIL("quarantine"),
    });
  });

  it("reject: fail, asks reject", async () => {
    expect(await withDmarc("p=reject")).toEqual({
      forgedDmarc: "fail",
      asks: "reject",
      reason: "reject",
      authResults: FAIL("reject"),
    });
  });
});

describe("simulation: pct, t=y, sp and np", () => {
  it("quarantine with pct=25 and with pct=0: the drop says why, also when it lands on nothing", async () => {
    expect(await withDmarc("p=quarantine; pct=25")).toMatchObject({
      asks: "nothing",
      reason: "sampled",
      sampled: { pct: 25, full: "quarantine" },
    });
    const zero = await withDmarc("p=quarantine; pct=0");
    expect(zero).toMatchObject({ asks: "nothing", reason: "testing" });
    expect(zero).not.toHaveProperty("sampled");
    expect(await withDmarc("p=reject; pct=0")).toMatchObject({ asks: "quarantine", reason: "testing" });
  });

  it("reject with sp=none or np=none: subdomain says which asks less, sp first on a tie", async () => {
    expect((await withDmarc("p=reject; sp=none"))?.subdomain).toEqual({ asks: "nothing", tag: "sp" });
    expect((await withDmarc("p=reject; np=none"))?.subdomain).toEqual({ asks: "nothing", tag: "np" });
    expect((await withDmarc("p=reject; sp=none; np=none"))?.subdomain).toEqual({ asks: "nothing", tag: "sp" });
    expect((await withDmarc("p=reject; sp=quarantine; np=none"))?.subdomain).toEqual({ asks: "nothing", tag: "np" });
    // Asking as much as the name is no subdomain line.
    expect(await withDmarc("p=reject; sp=reject")).not.toHaveProperty("subdomain");
    expect(await withDmarc("p=quarantine; sp=reject")).not.toHaveProperty("subdomain");
  });

  it("t=y lowers sp and np with p, once", async () => {
    const s = await withDmarc("p=reject; sp=quarantine; t=y");
    expect(s).toMatchObject({ asks: "quarantine", reason: "testing", subdomain: { asks: "nothing", tag: "sp" } });
  });

  it("a subdomain that exists takes the Organizational Domain's sp, and its subdomains the same record", async () => {
    const z: Zone = {
      ...googleZone(dmarc("p=reject; sp=quarantine; np=none")),
      "shop.example.com": { A: [P4], TXT: ["v=spf1 -all"] },
    };
    const r = await checkDomain(input("shop.example.com"), { resolver: zoneResolver(z) });
    expect(r.dmarc.policyFrom).toBe("sp");
    expect(r.simulation).toMatchObject({
      asks: "quarantine",
      reason: "quarantine",
      subdomain: { asks: "nothing", tag: "np" },
      authResults:
        "mx.receiver.example; spf=pass smtp.mailfrom=sender.example.net; dkim=none; dmarc=fail (p=quarantine) header.from=shop.example.com",
    });
  });
});
