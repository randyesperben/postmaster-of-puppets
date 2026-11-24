import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_ORDER } from "../src/dns/endpoints.ts";
import { checkDomain } from "../src/index.ts";
import type { Resolver } from "../src/dns/types.ts";
import type { Progress, Report } from "../src/types.ts";
import { bad, check, DKIM, googleZone, input, P4, RUA, SOA } from "./helpers/check.ts";
import { chunks, parseQueryUrl } from "./helpers/dns.ts";
import { fakeFetch, isProbe } from "./helpers/fetch.ts";
import { ids } from "./helpers/findings.ts";
import { rsaKey } from "./helpers/keys.ts";
import { type Node, type Zone, zoneResolver } from "./helpers/zone.ts";

// Other files refer to these by letter: case A is googleZone() of helpers/check.ts.
describe("six reference setups, A to F", () => {
  it("A: Google Workspace, reject with reports: Protected, delivery ok", async () => {
    const r = await check(googleZone());
    expect(r.verdict).toBe("protected");
    expect(r.delivery).toBe("ok");
    expect(r.mailUse).toBe("mail");
    expect(r.providers).toEqual(["google-workspace"]);
    expect(r.mx[0]?.provider).toBe("google-workspace");
    expect(r.zone).toBe("example.com");
    expect(bad(r)).toEqual([]);
  });

  it("B: DMARC at none with reports to an outside vendor: Spoofable, rua unauthorized", async () => {
    const z = googleZone("v=DMARC1; p=none; rua=mailto:reports@dmarc-vendor.example");
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(ids(r)).toContain("dmarc-policy-none");
    expect(ids(r)).toContain("dmarc-rua-unauthorized");
  });

  it("C: strict SPF and no DMARC: Spoofable", async () => {
    const r = await check({
      "example.com": { SOA, MX: ["10 mx.example.com"], TXT: ["v=spf1 ip4:192.0.32.10 -all"] },
      "mx.example.com": { A: [P4] },
    });
    expect(r.verdict).toBe("spoofable");
    expect(ids(r)).toContain("dmarc-missing");
  });

  it("D: a domain that sends and receives no mail: Protected, no-mail", async () => {
    const r = await check({
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
    });
    expect(r.verdict).toBe("protected");
    expect(r.mailUse).toBe("none-declared");
    expect(r.delivery).toBe("no-mail");
    // Already at reject: no DMARC change; only the DKIM wildcard of the set is missing.
    expect(r.findings.flatMap((f) => f.fixes).map((x) => x.name)).toEqual(["*._domainkey.example.com"]);
  });

  // Two SPF records authorize what their merge authorizes, so two v=spf1 -all are no sign of
  // sending next to a null MX; two that list a server are.
  it("D with two SPF records: v=spf1 -all twice authorizes no one, a server twice does", async () => {
    const twice = (spf: string) =>
      check({
        "example.com": { SOA, MX: ["0 ."], TXT: [spf, spf] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject;"] },
      });
    const none = await twice("v=spf1 -all");
    expect(none.mailUse).toBe("none-declared");
    expect(none.findings.find((f) => f.id === "mx-null")?.vars?.sending).toBeUndefined();
    const some = await twice("v=spf1 ip4:192.0.32.10 -all");
    expect(some.mailUse).toBe("mail");
    expect(some.findings.find((f) => f.id === "mx-null")?.vars).toMatchObject({ sending: 1 });
  });

  it("E: quarantine with pct=25: Spoofable", async () => {
    const r = await check(googleZone(`v=DMARC1; p=quarantine; pct=25; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("spoofable");
    expect(ids(r)).toEqual(expect.arrayContaining(["dmarc-policy-none", "dmarc-pct"]));
  });

  it("F: DMARC at reject with SPF +all: Spoofable", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    const r = await check(z);
    expect(r.verdict).toBe("spoofable");
    expect(ids(r)).toContain("spf-plus-all");
  });
});

describe("edge cases of the verdict: SPF permerror, pct, an include's +all, send-only, DNSSEC", () => {
  // RFC 7208 §4.5, §4.6, §4.6.4 and §5.2.
  it("+all behind an SPF permerror opens nothing: with p=reject the verdict is Protected", async () => {
    const cases: string[][] = [
      ["v=spf1 +all ip4:192.0.2.300"],
      ["v=spf1 +all", "v=spf1 -all"],
      ["v=spf1 include:nospf.example.net +all"],
      ["v=spf1 a:v1.example.net a:v2.example.net a:v3.example.net +all"],
    ];
    for (const txt of cases) {
      const z = googleZone();
      (z["example.com"] as Node).TXT = txt;
      const r = await check(z);
      expect(r.verdict, txt.join(" | ")).toBe("protected");
      expect(ids(r)).not.toContain("spf-plus-all");
    }
  });

  it("a duplicate exp= is a permerror before any term: +all behind it opens nothing (RFC 7208 §6)", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 exp=a.example.net exp=b.example.net +all"];
    const r = await check(z);
    expect(ids(r)).toContain("spf-duplicate-modifier");
    expect(ids(r)).not.toContain("spf-plus-all");
    expect(r.verdict).toBe("protected");
  });

  it("quarantine with pct=0 and with pct=25, reject with pct=0", async () => {
    expect((await check(googleZone(`v=DMARC1; p=quarantine; pct=0; rua=mailto:${RUA}`))).verdict).toBe("spoofable");
    expect((await check(googleZone(`v=DMARC1; p=quarantine; pct=25; rua=mailto:${RUA}`))).verdict).toBe("spoofable");
    expect((await check(googleZone(`v=DMARC1; p=reject; pct=0; rua=mailto:${RUA}`))).verdict).toBe("partly-protected");
  });

  it("an include that returns +all opens the domain", async () => {
    const z = googleZone();
    (z["_spf.google.com"] as Node).TXT = ["v=spf1 +all"];
    expect((await check(z)).verdict).toBe("spoofable");
  });

  it("a send-only domain on Amazon SES without MX does not get the set for domains without mail", async () => {
    const r = await check({
      "example.com": { SOA, TXT: ["v=spf1 include:amazonses.com ~all"] },
      "amazonses.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 -all"] },
    });
    expect(r.mailUse).toBe("mail");
    expect(ids(r)).toContain("mx-missing");
    const values = r.findings.flatMap((f) => f.fixes.map((x) => x.value));
    expect(values).not.toContain("v=spf1 -all");
    expect(values).not.toContain("v=DMARC1; p=reject");
    const firstStep = r.findings.flatMap((f) => f.fixes).find((x) => x.step?.n === 1);
    expect(firstStep?.value).toBe("v=DMARC1; p=none; rua=mailto:{rua}");
  });

  it("DNSSEC broken on DMARC gives Can't tell", async () => {
    const z = googleZone();
    (z["_dmarc.example.com"] as Node).$servfail = true;
    const r = await check(z);
    expect(r.verdict).toBe("cant-tell");
    expect(r.delivery).toBe("at-risk");
  });
});

describe("checkDomain", () => {
  // The MX answer alone is the probe; SPF, DKIM, DMARC and the transport start with it, while the
  // MX hosts' addresses are still out. One DoH round less.
  it("starts the other groups with the MX answer, before the MX hosts' addresses come back", async () => {
    const zone = googleZone();
    const base = zoneResolver(zone);
    let release = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const seenBeforeAddresses: string[] = [];
    let addressesBack = false;
    const resolver: Resolver = {
      async query(name, type, opts) {
        if (!addressesBack) seenBeforeAddresses.push(`${name} ${type}`);
        if (name === "smtp.google.com" && (type === "A" || type === "AAAA")) {
          await gate;
          addressesBack = true;
        }
        return base.query(name, type, opts);
      },
    };
    const done = checkDomain(input(), { resolver });
    await vi.waitFor(() => expect(seenBeforeAddresses).toContain("_dmarc.example.com TXT"));
    expect(seenBeforeAddresses).toContain("example.com TXT");
    release();
    const r = await done;
    expect(r.verdict).toBe("protected");
    expect(r.mx.map((h) => h.host)).toEqual(["smtp.google.com"]);
  });

  it("asks the MX question once", async () => {
    const resolver = zoneResolver(googleZone());
    await checkDomain(input(), { resolver });
    expect(resolver.asked.filter((q) => q === "example.com MX")).toHaveLength(1);
  });

  afterEach(() => vi.unstubAllGlobals());

  // MX may arrive after the others (its hosts' addresses go out with them): onProgress reports each
  // group as it arrives, in no fixed order, and a caller that shows MX first orders them itself.
  it("reports each group once as it arrives", async () => {
    const seen: Progress[] = [];
    await check(googleZone(), "example.com", { onProgress: (p) => seen.push(p) });
    const groups = seen.flatMap((p) => (p.type === "group" ? [p.group] : []));
    expect([...groups].sort()).toEqual(["dkim", "dmarc", "mx", "spf", "transport"]);
  });

  // An MX answer of NXDOMAIN already says the name does not exist, so the existence query with DO
  // is not asked again.
  it("an NXDOMAIN on MX decides existence: no second query for the name", async () => {
    const resolver = zoneResolver({ "example.com": { SOA } });
    const r = await checkDomain(input("nope.example.com"), { resolver });
    expect(r.exists).toBe("nxdomain");
    expect(resolver.asked.filter((q) => q.startsWith("nope.example.com A"))).toEqual([]);
  });

  it("nxdomain when the name does not exist", async () => {
    const r = await check({ "example.com": { SOA } }, "nope.example.com");
    expect(r.outcome).toBe("nxdomain");
  });

  it("nxdomain behind Compact Denial of Existence, and np rather than sp for the policy", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=reject; np=none; rua=mailto:${RUA}`] },
    };
    const r = await checkDomain(input("nope.example.com"), { resolver: zoneResolver(zone, { compactDenial: true }) });
    // A DMARC record covers the name, so the verdict comes from its np and the outcome is done.
    expect(r.exists).toBe("nxname");
    expect(r.outcome).toBe("done");
    expect(r.dmarc.policyFrom).toBe("np");
    expect(r.verdict).toBe("spoofable");
    // RFC 7489 receivers apply sp=reject there: np=none is the weaker reading and it decides.
    expect(r.findings.find((f) => f.id === "dmarc-subdomains-open")?.vars).toMatchObject({
      np: "none",
      sp: "reject",
      weaker: 1,
    });
  });

  it("a name that exists without MX takes sp", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "shop.example.com": { A: [P4] },
      "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=reject; np=none; rua=mailto:${RUA}`] },
    };
    const r = await checkDomain(input("shop.example.com"), { resolver: zoneResolver(zone, { compactDenial: true }) });
    expect(r.outcome).toBe("done");
    expect(r.dmarc.policyFrom).toBe("sp");
  });

  it("partial and Can't tell when the time limit runs out", async () => {
    const slow: Resolver = {
      async query(name, type, opts = {}) {
        const inner = zoneResolver(googleZone());
        if (type === "TXT" && name === "_dmarc.example.com") {
          await new Promise((resolve, reject) => {
            const t = setTimeout(resolve, 2000);
            opts.signal?.addEventListener("abort", () => (clearTimeout(t), reject(new Error("aborted"))), {
              once: true,
            });
          });
        }
        return inner.query(name, type, opts);
      },
    };
    vi.useFakeTimers();
    let r;
    try {
      const done = checkDomain(input(), { resolver: slow, deadlineMs: 50 });
      await vi.advanceTimersByTimeAsync(50);
      r = await done;
    } finally {
      vi.useRealTimers();
    }
    expect(r.outcome).toBe("partial");
    expect(r.verdict).toBe("cant-tell");
    expect(ids(r)).toContain("lookup-failed");
  });

  it("unreachable when no resolver answers: no group is reported", async () => {
    const fetch = vi.fn((_url: string) => Promise.reject(new TypeError("Failed to fetch")));
    vi.stubGlobal("fetch", fetch);
    const seen: Progress[] = [];
    const r = await checkDomain(input("visitor.example.net"), { onProgress: (p) => seen.push(p) });
    expect(r.outcome).toBe("unreachable");
    expect(r.verdict).toBe("cant-tell");
    expect(r.resolvers).toEqual([]);
    expect(seen.some((p) => p.type === "group")).toBe(false);
    // MX goes to the pair, the first failure sends the probe to all nine endpoints, then the
    // check stops.
    expect(fetch).toHaveBeenCalledTimes(2 + 9);
  });

  // The probe asks example.com, never the checked domain.
  it("a network that swallows DoH: the probe never carries the domain, unreachable before 6 s", async () => {
    vi.useFakeTimers();
    try {
      const urls: string[] = [];
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string, init?: RequestInit) => {
          urls.push(url);
          return new Promise((_, reject) =>
            init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))),
          );
        }),
      );
      let r: Report | undefined;
      const done = checkDomain(input("visitor.example.net")).then((x) => (r = x));
      await vi.advanceTimersByTimeAsync(5_999);
      expect(r?.outcome).toBe("unreachable");
      await done;
      const asked = urls.map((u) => parseQueryUrl(u));
      expect(asked.filter((q) => q.name === "visitor.example.net")).toHaveLength(2);
      expect(
        asked.filter((q) => q.name !== "visitor.example.net").every((q) => q.name === "example.com" && q.type === 6),
      ).toBe(true);
      expect(asked).toHaveLength(11);
    } finally {
      vi.useRealTimers();
    }
  });

  // Answers to the probe do not count in responded(), so a domain whose own DNS is silent while
  // every endpoint answers the probe could pass for a blocked network. The relay probe decides:
  // endpoints that answer it mean DoH works.
  // Can't tell names the lookups that failed.
  it("every endpoint answers the probe but not the domain: Can't tell, no blocked network", async () => {
    vi.useFakeTimers();
    try {
      const f = fakeFetch(
        Object.fromEntries(
          DEFAULT_ORDER.map((op) => [
            op,
            (_n: number, name: string, type: string) => (isProbe(name, type) ? "answer" : "mute"),
          ]),
        ),
      );
      vi.stubGlobal("fetch", f.fn);
      let r: Report | undefined;
      const done = checkDomain(input("visitor.example.net")).then((x) => (r = x));
      await vi.advanceTimersByTimeAsync(12_000);
      await done;
      expect(f.calls.filter((c) => c.probe).length).toBeGreaterThan(0);
      expect(r?.outcome).not.toBe("unreachable");
      expect(r?.verdict).toBe("cant-tell");
      expect(r?.findings.some((x) => x.id === "lookup-failed" && x.group === "dmarc")).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("follows the resolver order it is given", async () => {
    const hosts: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => (hosts.push(new URL(url).host), Promise.reject(new TypeError("Failed to fetch")))),
    );
    await checkDomain(input(), { resolverOrder: ["google", "cloudflare", "quad9"] });
    expect(hosts[0]).toBe("dns.google");
  });

  it("asks an extra DKIM selector it is given", async () => {
    const z = googleZone();
    delete z["google._domainkey.example.com"];
    z["custom2026._domainkey.example.com"] = { TXT: [DKIM] };
    const r = await check(z, "example.com", { extraSelectors: ["custom2026"] });
    expect(r.dkim.keys.map((k) => k.selector)).toEqual(["custom2026"]);
    expect(r.delivery).toBe("ok");
    expect(r.dkim.noAnswer).toEqual([]);
  });

  // A typed selector counts as keyless only when its lookup answered: one that got no answer may
  // hold the key, so dkim.noAnswer lists it.
  it("carries the selectors whose DKIM lookup got no answer, a typed one included", async () => {
    const z = googleZone();
    z["custom2026._domainkey.example.com"] = { $unreachable: true };
    const r = await check(z, "example.com", { extraSelectors: ["custom2026"] });
    expect(r.dkim.keys.map((k) => k.selector)).toEqual(["google"]);
    expect(r.dkim.noAnswer).toEqual(["custom2026"]);
  });
});

describe("text shown from TXT records", () => {
  it("decodes UTF-8 in what a finding shows", async () => {
    const z = googleZone();
    // The zone helper writes one octet per character: these two are the UTF-8 bytes of “é”.
    z["_mta-sts.example.com"] = { TXT: ["v=STSv1; id=caf\u00c3\u00a9"] };
    const r = await check(z);
    expect(r.findings.find((f) => f.id === "mta-sts-invalid")?.found).toBe("v=STSv1; id=café");
  });
});

describe("the delivery answer carries the rule that set it and that rule's finding", () => {
  it("no DMARC and a 1024-bit key: row 5, mail without DMARC, not the key", async () => {
    const z = googleZone();
    delete z["_dmarc.example.com"];
    z["google._domainkey.example.com"] = { TXT: [chunks(`v=DKIM1; k=rsa; p=${rsaKey(1024)}`)] };
    const r = await check(z);
    expect(ids(r)).toContain("dkim-key-1024");
    expect(r.delivery).toBe("at-risk");
    expect(r.deliveryCause).toEqual({ rule: 5 });
  });

  it("an unusable key: row 2 with that key's finding", async () => {
    const z = googleZone();
    z["google._domainkey.example.com"] = { TXT: [chunks(`v=DKIM1; k=rsa; p=${rsaKey(512)}`)] };
    const r = await check(z);
    expect(r.deliveryCause).toEqual({ rule: 2, finding: "dkim-key-under-1024" });
  });

  it("ptr in SPF and an MX host without an answer: row 6 for the failed lookup, not ptr", async () => {
    const z = googleZone();
    z["example.com"] = { SOA, MX: ["1 smtp.google.com"], TXT: ["v=spf1 ptr include:_spf.google.com ~all"] };
    z["smtp.google.com"] = { $unreachable: true };
    const r = await check(z);
    expect(ids(r)).toContain("spf-ptr");
    expect(r.delivery).toBe("unknown");
    expect(r.deliveryCause).toEqual({ rule: 6 });
  });

  it("everything in place: row 7", async () => {
    expect((await check(googleZone())).deliveryCause).toEqual({ rule: 7 });
  });
});
