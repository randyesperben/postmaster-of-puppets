import { describe, expect, it, vi } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { DEFAULT_ORDER } from "../src/dns/endpoints.ts";
import { checkDomain } from "../src/index.ts";
import { check, googleZone, input, P4, RUA, SOA } from "./helpers/check.ts";
import { type Answerer, type Behavior, fakeFetch, recordedOrEmpty, type Rules, zones } from "./helpers/fetch.ts";
import { type Node, silentOn, type Zone, zoneResolver } from "./helpers/zone.ts";

/** A full check whose `hang` lookups only the limit ends, on fake timers. */
async function cut(zone: Zone, hang: (name: string) => boolean) {
  vi.useFakeTimers();
  try {
    const done = checkDomain(input(), { resolver: silentOn(zoneResolver(zone), hang), deadlineMs: 300 });
    await vi.advanceTimersByTimeAsync(300);
    return await done;
  } finally {
    vi.useRealTimers();
  }
}

describe("the time limit leaves the verdict open only through a lookup the deciding row needs", () => {
  // With DMARC at reject or quarantine and SPF answered, DKIM selectors, MTA-STS and TLS-RPT, or a
  // rua authorization cut by the limit do not give “Can't tell”; the outcome is partial and the
  // verdict stands.
  it("the DKIM selectors cut: Protected, DKIM unknown, the result partial", async () => {
    const r = await cut(googleZone(), (n) => n.includes("._domainkey."));
    expect(r.outcome).toBe("partial");
    expect(r.verdict).toBe("protected");
    expect(r.groups.dkim).toBe("unknown");
    expect(r.delivery).toBe("unknown");
  });

  it("MTA-STS and TLS-RPT cut: Protected", async () => {
    const r = await cut(googleZone(), (n) => n.startsWith("_mta-sts.") || n.startsWith("_smtp._tls."));
    expect(r.outcome).toBe("partial");
    expect(r.verdict).toBe("protected");
  });

  it("the authorization of an outside rua cut: Protected", async () => {
    const r = await cut(googleZone("v=DMARC1; p=reject; rua=mailto:agg@reports.example.net"), (n) =>
      n.endsWith(".reports.example.net"),
    );
    expect(r.outcome).toBe("partial");
    expect(r.verdict).toBe("protected");
  });

  it("an SPF include cut with DMARC at reject: Can't tell, and with no DMARC still Spoofable", async () => {
    const r = await cut(googleZone(), (n) => n === "_spf.google.com");
    expect(r.verdict).toBe("cant-tell");
    const none = googleZone();
    delete none["_dmarc.example.com"];
    expect((await cut(none, (n) => n === "_spf.google.com")).verdict).toBe("spoofable");
  });

  it("the DMARC lookup cut: Can't tell", async () => {
    expect((await cut(googleZone(), (n) => n === "_dmarc.example.com")).verdict).toBe("cant-tell");
  });

  // With +all in the domain's own SPF, answered in full, any DMARC answer gives Spoofable, so
  // DMARC that did not answer changes nothing.
  it("the DMARC lookup cut or unanswered with v=spf1 +all of the domain's own: Spoofable", async () => {
    const open = googleZone();
    (open["example.com"] as Node).TXT = ["v=spf1 +all"];
    const r = await cut(open, (n) => n === "_dmarc.example.com");
    expect(r.verdict).toBe("spoofable");
    expect(r.findings.map((f) => f.id)).toEqual(expect.arrayContaining(["spf-plus-all", "lookup-failed"]));
    const down = structuredClone(open);
    (down["_dmarc.example.com"] as Node).$unreachable = true;
    expect((await check(down)).verdict).toBe("spoofable");
    // The controls: any DMARC answer gives Spoofable too.
    expect((await check(open)).verdict).toBe("spoofable");
    delete open["_dmarc.example.com"];
    expect((await check(open)).verdict).toBe("spoofable");
  });
});

// Lookups without an answer around the term that opens the domain's own SPF: only those the
// forger's evaluation reaches leave the verdict open.
describe("lookups without an answer before and past the term that opens the SPF", () => {
  // The include comes before the +all, and receivers may stop at its temperror.
  it("v=spf1 +all of its own after an unanswered include: Can't tell", async () => {
    const open = googleZone();
    (open["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com +all"];
    (open["_dmarc.example.com"] as Node).$unreachable = true;
    (open["_spf.google.com"] as Node).$unreachable = true;
    expect((await check(open)).verdict).toBe("cant-tell");
  });

  // With the domain's own SPF open, a lookup past the term that opens it, which the forger's
  // evaluation never reaches, and the Organizational Domain's SPF change nothing.
  for (const dmarc of ["answered", "unanswered"]) {
    it(`its own SPF open to every address, then an include without an answer, DMARC ${dmarc}: Spoofable`, async () => {
      const open = googleZone();
      (open["example.com"] as Node).TXT = ["v=spf1 ip4:0.0.0.0/0 ip6:::/0 include:_spf.google.com -all"];
      (open["_spf.google.com"] as Node).$unreachable = true;
      if (dmarc === "unanswered") (open["_dmarc.example.com"] as Node).$unreachable = true;
      const r = await check(open);
      expect(r.findings.find((f) => f.id === "lookup-failed" && f.group === "spf")?.vars).toMatchObject({
        unreached: 1,
      });
      expect(r.verdict).toBe("spoofable");
    });

    // shop is shop.example.com, with v=spf1 +all of its own.
    it(`shop with v=spf1 +all, example.com's SPF unanswered, DMARC ${dmarc}: Spoofable`, async () => {
      const z: Zone = {
        "example.com": { SOA, TXT: ["v=spf1 include:_spf.example.net -all"] },
        "_spf.example.net": { $unreachable: true },
        "_dmarc.example.com":
          dmarc === "answered" ? { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] } : { $unreachable: true },
        "shop.example.com": { MX: ["1 smtp.google.com"], TXT: ["v=spf1 +all"] },
        "smtp.google.com": { A: [P4] },
      };
      const r = await check(z, "shop.example.com");
      expect(r.findings.some((f) => f.id === "lookup-failed" && f.group === "spf")).toBe(dmarc === "answered");
      expect(r.verdict).toBe("spoofable");
    });
  }

  it("an include without an answer before the term that opens the SPF still counts: Can't tell", async () => {
    const open = googleZone();
    (open["example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com ip4:0.0.0.0/0 ip6:::/0 -all"];
    (open["_spf.google.com"] as Node).$unreachable = true;
    const r = await check(open);
    expect(r.findings.find((f) => f.id === "lookup-failed" && f.group === "spf")?.vars?.unreached).toBeUndefined();
    expect(r.verdict).toBe("cant-tell");
  });

  // IPv4 ends at -ip4:0.0.0.0/0, IPv6 still reaches the include, whose missing answer can turn its
  // result into a permerror (RFC 7208 §5.2): it counts.
  it("an include that only IPv6 senders still reach, before ip6:::/0: Can't tell", async () => {
    const open = googleZone();
    (open["example.com"] as Node).TXT = ["v=spf1 -ip4:0.0.0.0/0 include:_spf.google.com ip6:::/0 -all"];
    (open["_spf.google.com"] as Node).$unreachable = true;
    const r = await check(open);
    expect(r.findings.find((f) => f.id === "lookup-failed" && f.group === "spf")?.vars?.unreached).toBeUndefined();
    expect(r.verdict).toBe("cant-tell");
  });

  // An a: lookup and a DNSSEC failure past the opening term are unreached too.
  it("an a: lookup without an answer and an include with DNSSEC broken past the opening term: Spoofable", async () => {
    const viaA = googleZone();
    (viaA["example.com"] as Node).TXT = ["v=spf1 ip4:0.0.0.0/0 ip6:::/0 a:host.example.net -all"];
    viaA["host.example.net"] = { $unreachable: true };
    const a = await check(viaA);
    expect(a.findings.find((f) => f.id === "lookup-failed" && f.group === "spf")?.vars).toMatchObject({ unreached: 1 });
    expect(a.verdict).toBe("spoofable");
    const broken = googleZone();
    (broken["example.com"] as Node).TXT = ["v=spf1 ip4:0.0.0.0/0 ip6:::/0 include:_spf.google.com -all"];
    (broken["_spf.google.com"] as Node).$servfail = true;
    const d = await check(broken);
    expect(d.findings.find((f) => f.id === "dnssec-broken" && f.group === "spf")?.vars).toMatchObject({ unreached: 1 });
    expect(d.verdict).toBe("spoofable");
  });

  it("the Organizational Domain's SPF with DNSSEC broken: Can't tell, with vars.org", async () => {
    const z: Zone = {
      "example.com": { SOA, TXT: ["v=spf1 include:_spf.example.net -all"] },
      "_spf.example.net": { TXT: ["v=spf1 ip4:192.0.32.0/24 -all"], $servfail: true },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] },
      "shop.example.com": { MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com -all"] },
      "smtp.google.com": { A: [P4] },
      "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    };
    const r = await check(z, "shop.example.com");
    expect(r.findings.find((f) => f.id === "dnssec-broken" && f.group === "spf")?.vars?.org).toBe("example.com");
    expect(r.verdict).toBe("cant-tell");
  });
});

describe("the PSL chunks load within the check's time limit", () => {
  const zone: Zone = { "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; rua=mailto:${RUA}`] } };
  const never = () => new Promise<never>(() => {});
  for (const [which, opts] of [
    ["psd-dmarc", { psl: never }],
    ["psl-rest", { psl: () => Promise.resolve([]), pslRest: never }],
  ] as const) {
    it(`${which} that never arrives: the DMARC reading ends unanswered at the limit`, async () => {
      vi.useFakeTimers();
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 200);
        let settled = false;
        const done = checkDmarc({ resolver: zoneResolver(zone), signal: ctrl.signal }, "news.mail.example.com", {
          exists: "yes",
          ...opts,
        }).finally(() => (settled = true));
        await vi.advanceTimersByTimeAsync(199);
        expect(settled, "still reading before the limit").toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        expect((await done).failed).toBe(true);
      } finally {
        vi.useRealTimers();
      }
    });
  }
});

// With the 76 selectors, the DKIM probes and _domainkey, a whole check's requests to the first
// operator fit under the per-operator cap, so none waits for a slot and DMARC never queues behind
// DKIM. Fake timers make the peak deterministic: every request of a wave goes out before the fake's
// 1 ms answer.
describe("the DoH queue holds a whole check", () => {
  async function overDoh(domain: string, answer: Answerer, rules: Rules = {}) {
    vi.useFakeTimers();
    try {
      const f = fakeFetch(rules, answer);
      vi.stubGlobal("fetch", f.fn);
      const t0 = Date.now();
      const groups = new Map<string, number>();
      const done = checkDomain(input(domain), {
        onProgress: (p) => p.type === "group" && groups.set(p.group, Date.now() - t0),
      });
      await vi.advanceTimersByTimeAsync(12_000);
      const r = await done;
      return { r, f, groups };
    } finally {
      vi.useRealTimers();
      vi.unstubAllGlobals();
    }
  }

  // The peak is the wave after the MX query, which goes alone: the DKIM names, transport, DMARC,
  // the zone's SPF and the MX hosts, 90 on the first operator for both domains (an SPF include
  // goes out once its record has answered). A request waits only with the cap full, so a peak
  // under 96 means none waited.
  for (const [what, domain, answer, peak] of [
    ["the test zone with the whole list", "example.com", zones(googleZone()), 90],
    ["microsoft.com from its recorded answers", "microsoft.com", recordedOrEmpty, 90],
  ] as const) {
    it(`${what}: ${peak} requests in flight to the first operator at most, under the cap of 96`, async () => {
      const { r, f } = await overDoh(domain, answer);
      expect(r.verdict).toBe("protected");
      expect(f.peakOf("cloudflare")).toBe(peak);
    });
  }

  // They do not wait for DKIM's 2.5 s timeout.
  it("with the _domainkey names mute, MX, SPF and DMARC arrive before DKIM", async () => {
    const mute = (_n: number, name: string): Behavior =>
      /(^|\.)_domainkey\.example\.com$/.test(name) ? "mute" : "answer";
    const { groups } = await overDoh(
      "example.com",
      zones(googleZone()),
      Object.fromEntries(DEFAULT_ORDER.map((op) => [op, mute])),
    );
    const dkim = groups.get("dkim") ?? Infinity;
    for (const g of ["mx", "spf", "dmarc"]) {
      expect([g, groups.get(g)! < 2500]).toEqual([g, true]);
      expect([g, groups.get(g)! < dkim]).toEqual([g, true]);
    }
  });
});
