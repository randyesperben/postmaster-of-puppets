import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeMessage, RCODE } from "../src/dns/codec.ts";
import { createDohResolver, LookupError } from "../src/dns/doh.ts";
import { DEFAULT_ORDER, ENDPOINT_URLS, RESOLVER_URLS } from "../src/dns/endpoints.ts";
import { lookup } from "../src/dns/lookup.ts";
import { buildMessage, FILTERED } from "./helpers/dns.ts";
import { all, type Behavior, fakeFetch } from "./helpers/fetch.ts";

const DMARC = "v=DMARC1; p=none;";

afterEach(() => {
  vi.useRealTimers();
});

describe("DoH request", () => {
  it("asks Cloudflare first with a simple GET: ?dns=, accept only, no-store, no redirects", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    const r = await doh.query("Example.com.", "txt");
    expect(r.resolver).toBe("cloudflare");
    expect(r.ad).toBe(true);
    expect(r.answers[0]?.data).toEqual(["from cloudflare"]);
    const c = f.calls[0];
    expect(c?.url.startsWith(`${RESOLVER_URLS.cloudflare}?dns=`)).toBe(true);
    expect(c?.name).toBe("example.com");
    expect(c?.type).toBe("TXT");
    expect(c?.init?.headers).toEqual({ accept: "application/dns-message" });
    expect(c?.init?.cache).toBe("no-store");
    expect(c?.init?.redirect).toBe("error");
    expect(doh.responded()).toEqual(["cloudflare"]);
  });

  // Neither changes whether the request needs a CORS preflight: the Fetch standard sends one only
  // for the use-CORS-preflight flag, a method that is not safelisted or an unsafe author header
  // (fetch.spec.whatwg.org, “HTTP fetch” and “HTTP-network-or-cache fetch”, read 2026-11-18).
  it("sends no Referer and no credentials, whatever the hosting headers say", async () => {
    const f = fakeFetch();
    await createDohResolver({ fetch: f.fn }).query("example.com", "TXT");
    expect(f.calls[0]?.init?.referrerPolicy).toBe("no-referrer");
    expect(f.calls[0]?.init?.credentials).toBe("omit");
  });

  it("asks Quad9 at its unfiltered address, which still validates DNSSEC", () => {
    expect(RESOLVER_URLS.quad9).toBe("https://dns10.quad9.net/dns-query");
  });

  it("knows the six operators in the default order, and their nine endpoints", () => {
    expect(DEFAULT_ORDER).toEqual(["cloudflare", "google", "quad9", "controld", "dns4eu", "cznic"]);
    expect(ENDPOINT_URLS).toEqual([
      "https://cloudflare-dns.com/dns-query",
      "https://1.1.1.1/dns-query",
      "https://dns.google/dns-query",
      "https://8.8.8.8/dns-query",
      "https://dns10.quad9.net/dns-query",
      "https://9.9.9.10/dns-query",
      "https://freedns.controld.com/p0",
      "https://unfiltered.joindns4.eu/dns-query",
      "https://odvr.nic.cz/dns-query",
    ]);
    // Quad9's filtered service answers blocklisted names with NXDOMAIN.
    expect(
      ENDPOINT_URLS.some((u) => u.includes("dns.quad9.net/") || u.includes("9.9.9.11") || u.includes("9.9.9.9/")),
    ).toBe(false);
  });

  it("sends ECS 0.0.0.0/0 in every query: plain, CD, DO, confirmed and the relay probe", async () => {
    const f = fakeFetch({ cloudflare: (n) => (n === 1 ? "network" : "answer") });
    const doh = createDohResolver({ fetch: f.fn });
    await doh.query("example.net", "MX", { confirm: true });
    await doh.query("example.net", "A", { cd: true });
    await doh.query("example.net", "A", { dnssecOk: true });
    expect(f.calls.some((c) => c.probe)).toBe(true);
    // RFC 7871 §6: option 8, length 4, family 1 (IPv4), source and scope prefix 0, no address.
    const ecs = [0, 8, 0, 4, 0, 1, 0, 0].join(",");
    for (const c of f.calls) {
      const b64 = (new URL(c.url).searchParams.get("dns") ?? "").replace(/-/g, "+").replace(/_/g, "/");
      const bytes = [...Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0))].join(",");
      expect(bytes.endsWith(ecs)).toBe(true);
    }
  });

  it("sets DO when asked and keeps DO and plain answers apart", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    await doh.query("example.com", "A");
    await doh.query("example.com", "A", { dnssecOk: true });
    await doh.query("example.com", "A", { dnssecOk: true });
    expect(f.calls.map((c) => c.dnssecOk)).toEqual([false, true]);
  });

  it("follows a custom order", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn, order: ["google", "cloudflare"] });
    expect((await doh.query("example.com", "TXT")).resolver).toBe("google");
  });

  it("passes CD through and keeps CD and non-CD answers apart", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    await doh.query("example.com", "A");
    await doh.query("example.com", "A", { cd: true });
    expect(f.calls.map((c) => c.cd)).toEqual([false, true]);
  });

  it("reports raw answers to onMessage, for recording fixtures", async () => {
    const f = fakeFetch();
    const seen: string[] = [];
    const doh = createDohResolver({
      fetch: f.fn,
      onMessage: (m) => seen.push(`${m.resolver} ${m.name} ${m.type} ${m.bytes.length > 12}`),
    });
    await doh.query("example.com", "MX");
    expect(seen).toEqual(["cloudflare example.com MX true"]);
  });

  it("returns Extended DNS Errors", async () => {
    const f = fakeFetch(all("servfail"));
    const r = await createDohResolver({ fetch: f.fn }).query("example.com", "A");
    expect(r.ede).toEqual([9]);
  });
});

describe("resolver failover", () => {
  for (const b of ["http500", "http429", "html", "network", "wrong-question"] as const) {
    it(`moves to the next resolver on ${b}`, async () => {
      // Both of Cloudflare's endpoints fail the same way.
      const f = fakeFetch({ cloudflare: b });
      const doh = createDohResolver({ fetch: f.fn });
      const r = await doh.query("example.com", "TXT");
      expect(r.resolver).toBe("google");
      expect(doh.responded()).toEqual(["google"]);
    });
  }

  it("a name DNS cannot carry fails alone, before any request, and drops no resolver", async () => {
    const f = fakeFetch();
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    for (const bad of [
      "a..example.com",
      `${"a".repeat(64)}.example.com`,
      "m\u00fcnchen.example.com",
      "a..example.com",
    ]) {
      const err = await doh.query(bad, "TXT").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LookupError);
      expect((err as LookupError).reason).toBe("bad-name");
    }
    expect(f.calls).toHaveLength(0);
    expect(switches).toEqual([]);
    expect((await doh.query("example.com", "TXT")).resolver).toBe("cloudflare");
  });

  for (const b of [
    "tc",
    "rcode-5",
    "rcode-1",
    "rcode-4",
    "filtered-4",
    "filtered-15",
    "filtered-16",
    "filtered-17",
    "filtered-18",
    "no-question",
    "wrong-id",
    "wrong-class",
  ] as const) {
    it(`does not take ${b} as an answer and asks the next resolver`, async () => {
      const f = fakeFetch({ cloudflare: b });
      const r = await createDohResolver({ fetch: f.fn }).query("example.com", "TXT");
      expect(r.resolver).toBe("google");
      expect(r.answers[0]?.data).toEqual(["from google"]);
    });
  }

  for (const b of ["tc", "rcode-5", "filtered-17"] as const) {
    it(`fails, never NODATA or NXDOMAIN, when every resolver answers ${b}`, async () => {
      const f = fakeFetch(all(b));
      const doh = createDohResolver({ fetch: f.fn });
      const err = await doh.query("example.com", "TXT").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(LookupError);
      // One request per operator: a working resolver's answer ends the operator for the query,
      // its endpoint by IP included, and no probe goes out.
      expect(f.calls.map((c) => c.host)).toEqual([
        "cloudflare-dns.com",
        "dns.google",
        "dns10.quad9.net",
        "freedns.controld.com",
        "unfiltered.joindns4.eu",
        "odvr.nic.cz",
      ]);
    });
  }

  // Recorded on 2026-11-18 from the two filtering services the engine does not use: Quad9's
  // NXDOMAIN with AD and EDE 17 for a name that has DMARC, and Cloudflare's 0.0.0.0 with EDE 16.
  const recorded = [
    { file: "dns.quad9.net._dmarc.isitblocked.org.TXT.bin", name: "_dmarc.isitblocked.org", type: "TXT", data: DMARC },
    {
      file: "security.cloudflare-dns.com.malware.testcategory.com.A.bin",
      name: "malware.testcategory.com",
      type: "A",
      data: "192.0.32.10",
    },
  ];
  it("the control: the unfiltered Cloudflare recorded the DMARC record that Quad9's filter hides", () => {
    const m = decodeMessage(
      new Uint8Array(readFileSync(`${FILTERED}cloudflare-dns.com._dmarc.isitblocked.org.TXT.bin`)),
    );
    expect(m.rcode).toBe(RCODE.NOERROR);
    expect(
      m.answers.filter((a) => a.type === "TXT").map((a) => (Array.isArray(a.data) ? a.data.join("") : a.data)),
    ).toEqual([DMARC]);
  });

  for (const r of recorded) {
    it(`a filtering resolver's recorded answer (${r.file}) never reaches the checks`, async () => {
      const bytes = new Uint8Array(readFileSync(`${FILTERED}${r.file}`));
      const f = fakeFetch({}, (op, name, type) =>
        op === "cloudflare"
          ? bytes
          : buildMessage({ qname: name, qtype: type, answers: [{ name, type, data: r.data }] }),
      );
      const switches: string[] = [];
      const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
      const l = await lookup(doh, r.name, r.type);
      expect(l.status).toBe("ok");
      expect(l.result?.resolver).toBe("google");
      expect(l.records.map((x) => (Array.isArray(x.data) ? x.data.join("") : x.data))).toEqual([r.data]);
      // The resolver works: it is asked again for the next name.
      await doh.query("example.org", "TXT");
      expect(f.calls.filter((c) => c.host === "cloudflare-dns.com")).toHaveLength(2);
      expect(switches).toEqual([]);
    });
  }

  it("TC, REFUSED and blocking EDEs come from a resolver that works: they drop no resolver", async () => {
    const f = fakeFetch({ cloudflare: (n) => ["tc", "rcode-5", "filtered-17"][n % 3] as Behavior });
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    for (const n of ["a", "b", "c", "d", "e", "f"])
      expect((await doh.query(`${n}.example.com`, "TXT")).resolver).toBe("google");
    expect(switches).toEqual([]);
    expect(f.calls.filter((c) => c.resolver === "cloudflare")).toHaveLength(6);
  });

  it("a name that times out while the resolver answers others moves on without dropping it", async () => {
    const f = fakeFetch({ cloudflare: (_n, name) => (name.startsWith("slow") ? "mute" : "answer") });
    const switches: string[] = [];
    const doh = createDohResolver({
      fetch: f.fn,
      timeoutMs: 30,
      onSwitch: (from, to) => switches.push(`${from}>${to}`),
    });
    const names = ["slow1", "slow2", ...Array.from({ length: 10 }, (_, i) => `fast${i}`)];
    const results = await Promise.all(names.map((n) => doh.query(`${n}.example.com`, "TXT")));
    expect(results.slice(0, 2).map((r) => r.resolver)).toEqual(["google", "google"]);
    expect(results.slice(2).every((r) => r.resolver === "cloudflare")).toBe(true);
    expect(switches).toEqual([]);
    expect((await doh.query("next.example.com", "TXT")).resolver).toBe("cloudflare");
  });

  it("gives up on a mute resolver after the per-query timeout", async () => {
    const f = fakeFetch({ cloudflare: "mute" });
    const doh = createDohResolver({ fetch: f.fn, timeoutMs: 30 });
    const t0 = performance.now();
    const r = await doh.query("example.com", "TXT");
    expect(r.resolver).toBe("google");
    expect(performance.now() - t0).toBeGreaterThanOrEqual(25);
  });

  it("a mute operator fails the relay probe too: it leaves the queue after one query", async () => {
    const f = fakeFetch({ cloudflare: "mute" });
    const switches: string[] = [];
    const doh = createDohResolver({
      fetch: f.fn,
      timeoutMs: 20,
      onSwitch: (from, to) => switches.push(`${from}>${to}`),
    });
    for (const n of ["a", "b", "c", "d"]) expect((await doh.query(`${n}.example.org`, "TXT")).resolver).toBe("google");
    expect(switches).toEqual(["cloudflare>google"]);
    const cloudflareHosts = f.queries().flatMap((c) => (c.resolver === "cloudflare" ? [c.host] : []));
    expect(cloudflareHosts).toEqual(["cloudflare-dns.com"]);
  });

  it("drops an endpoint after two failures with no answer of its own between them", async () => {
    // Both endpoints answer the probe (n = 0) and fail every query.
    const f = fakeFetch({ cloudflare: (n) => (n === 0 ? "answer" : "network") });
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    for (const n of ["a", "b", "c", "d"]) expect((await doh.query(`${n}.example.org`, "TXT")).resolver).toBe("google");
    expect(switches).toEqual(["cloudflare>google"]);
    // a: name fails, the probe's answer clears it, IP fails; b: name fails, IP fails twice and
    // goes; c: name fails twice and goes; d: Google alone.
    expect(
      f
        .queries()
        .filter((c) => c.resolver === "cloudflare")
        .map((c) => c.host),
    ).toEqual(["cloudflare-dns.com", "1.1.1.1", "cloudflare-dns.com", "1.1.1.1", "cloudflare-dns.com"]);
    expect(f.calls.filter((c) => c.probe)).toHaveLength(9);
  });

  it("forgives a failure followed by an answer", async () => {
    const f = fakeFetch({ cloudflare: (n) => (n % 2 === 1 ? "network" : "answer"), "cloudflare-ip": "answer" });
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    for (const n of ["a", "b", "c", "d", "e", "f"])
      expect((await doh.query(`${n}.example.org`, "TXT")).resolver).toBe("cloudflare");
    expect(switches).toEqual([]);
    expect(doh.responded()).toEqual(["cloudflare"]);
    // Odd queries fail on the name and are answered by IP; the name is never dropped.
    expect(
      f
        .queries()
        .map((c) => c.host)
        .filter((h) => h === "cloudflare-dns.com"),
    ).toHaveLength(6);
  });

  it("with every endpoint down, the probe empties the queue and later queries fail without a request", async () => {
    const f = fakeFetch(all("network"));
    const doh = createDohResolver({ fetch: f.fn });
    expect(doh.unreachable()).toBe(false);
    const first = await doh.query("a.example.org", "TXT").catch((e: unknown) => e);
    expect((first as LookupError).reason).toBe("unreachable");
    expect(doh.unreachable()).toBe(true);
    const sent = f.calls.length;
    const err = await doh.query("b.example.org", "TXT", { confirm: true }).catch((e: unknown) => e);
    expect((err as LookupError).reason).toBe("unreachable");
    expect((err as LookupError).message).toContain("none left");
    expect(f.calls.length).toBe(sent);
    expect(doh.responded()).toEqual([]);
  });

  it("an operator's endpoint by IP stands in when the one by name fails", async () => {
    const f = fakeFetch({ cloudflare: "network", "cloudflare-ip": "answer" });
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    const r = await doh.query("example.org", "TXT");
    expect(r.resolver).toBe("cloudflare");
    expect(f.queries().map((c) => c.host)).toEqual(["cloudflare-dns.com", "1.1.1.1"]);
    // The probe dropped the endpoint by name: the next query goes straight to the IP.
    await doh.query("example.net", "TXT");
    expect(
      f
        .queries()
        .map((c) => c.host)
        .slice(2),
    ).toEqual(["1.1.1.1"]);
    expect(switches).toEqual([]);
  });

  // It never carries the user's name.
  it("the relay probe asks example.com SOA of every endpoint at once, once per check", async () => {
    const f = fakeFetch({ cloudflare: "network", google: "network" });
    const switches: string[] = [];
    const doh = createDohResolver({ fetch: f.fn, onSwitch: (from, to) => switches.push(`${from}>${to}`) });
    const r = await doh.query("visitor.example.net", "MX", { confirm: true });
    const probes = f.calls.filter((c) => c.probe);
    expect(probes.map((c) => c.url.split("?")[0])).toEqual([...ENDPOINT_URLS]);
    expect(probes.every((c) => c.name === "example.com" && c.type === "SOA" && !c.cd && !c.dnssecOk)).toBe(true);
    // Every request is either the probe or the user's query: nothing else carries the name.
    expect(f.calls.filter((c) => !c.probe).every((c) => c.name === "visitor.example.net")).toBe(true);
    // The pair moves to the next two operators that answered the probe.
    expect(r.confirm).toBe("agreed");
    expect(f.queries().map((c) => c.host)).toEqual([
      "cloudflare-dns.com",
      "dns.google",
      "dns10.quad9.net",
      "freedns.controld.com",
    ]);
    expect(switches).toEqual(["cloudflare>quad9"]);
    await doh.query("other.example.net", "MX", { confirm: true });
    expect(f.calls.filter((c) => c.probe)).toHaveLength(9);
  });

  it("every endpoint mute: unreachable within two timeouts (5 s), before 6 s", async () => {
    vi.useFakeTimers();
    const f = fakeFetch(all("mute"));
    const doh = createDohResolver({ fetch: f.fn });
    let settled: unknown;
    const p = doh.query("visitor.example.net", "MX", { confirm: true }).catch((e: unknown) => (settled = e));
    await vi.advanceTimersByTimeAsync(5_100);
    await p;
    expect((settled as LookupError).reason).toBe("unreachable");
    expect(doh.unreachable()).toBe(true);
    expect(f.calls.filter((c) => c.probe)).toHaveLength(9);
    expect(f.queries().map((c) => c.host)).toEqual(["cloudflare-dns.com", "dns.google"]);
  });

  it("asks the next resolver on SERVFAIL and returns SERVFAIL only when all say so", async () => {
    const one = fakeFetch({ cloudflare: "servfail" });
    expect((await createDohResolver({ fetch: one.fn }).query("example.com", "A")).resolver).toBe("google");
    const every = fakeFetch(all("servfail"));
    const doh = createDohResolver({ fetch: every.fn });
    const r = await doh.query("example.com", "A");
    expect(r.rcode).toBe(2);
    expect(r.resolver).toBe("cloudflare");
    expect(doh.responded()).toEqual([...DEFAULT_ORDER]);
  });

  it("returns a SERVFAIL when the other resolvers fail outright", async () => {
    const f = fakeFetch({ ...all("network"), cloudflare: "servfail", quad9: "http500" });
    expect((await createDohResolver({ fetch: f.fn }).query("example.com", "A")).rcode).toBe(2);
  });
});
