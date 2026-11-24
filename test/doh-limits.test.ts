import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { base64url, encodeQuery } from "../src/dns/codec.ts";
import { deadline } from "../src/dns/deadline.ts";
import { createDohResolver, LookupError } from "../src/dns/doh.ts";
import { DEFAULT_ORDER, ENDPOINT_URLS, RESOLVER_URLS } from "../src/dns/endpoints.ts";
import { dnsResponse, fixturePath } from "./helpers/dns.ts";
import { all, type Behavior, fakeFetch, type Rules, zones } from "./helpers/fetch.ts";

afterEach(() => {
  vi.useRealTimers();
});

describe("stale answers (EDE 3 and 19)", () => {
  const SOA = ["ns1.example.org hostmaster.example.org 2026111801 7200 3600 1209600 300"];
  const z = { "example.com": { SOA, TXT: ["v=spf1 -all"] } };

  for (const code of [3, 19]) {
    it(`EDE ${code} is used but never confirms: the next operators confirm instead`, async () => {
      const f = fakeFetch({ cloudflare: `filtered-${code}`, google: `filtered-${code}` }, zones(z));
      const r = await createDohResolver({ fetch: f.fn }).query("example.com", "TXT", { confirm: true });
      expect(r.rcode).toBe(0);
      expect(r.confirm).toBe("agreed");
      expect(new Set(f.calls.map((c) => c.resolver))).toEqual(new Set(["cloudflare", "google", "quad9", "controld"]));
    });

    it(`EDE ${code} from every operator: the answer is used, unconfirmed`, async () => {
      const f = fakeFetch(all(`filtered-${code}`), zones(z));
      const r = await createDohResolver({ fetch: f.fn }).query("example.com", "TXT", { confirm: true });
      expect(r.rcode).toBe(3);
      expect(r.confirm).toBe("unconfirmed");
    });
  }

  it("a stale answer without confirm is used as it is", async () => {
    const f = fakeFetch({ cloudflare: "filtered-3" }, zones(z));
    const r = await createDohResolver({ fetch: f.fn }).query("example.com", "TXT");
    expect(r.resolver).toBe("cloudflare");
    expect(r.ede).toEqual([3]);
  });
});

describe("sharing and limits", () => {
  it("shares identical queries in flight and after", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    const [a, b] = await Promise.all([doh.query("example.com", "TXT"), doh.query("EXAMPLE.com.", "txt")]);
    await doh.query("example.com", "TXT");
    expect(a).toBe(b);
    expect(f.calls).toHaveLength(1);
  });

  it("keeps no failure: the same query asked again after a rejection goes out again", async () => {
    // Every endpoint answers the probe and fails its first query.
    const f = fakeFetch(
      Object.fromEntries(DEFAULT_ORDER.map((op) => [op, (n: number): Behavior => (n === 1 ? "network" : "answer")])),
    );
    const doh = createDohResolver({ fetch: f.fn });
    await expect(doh.query("example.org", "TXT")).rejects.toThrow(LookupError);
    expect((await doh.query("example.org", "TXT")).resolver).toBe("cloudflare");
    expect(f.queries()).toHaveLength(ENDPOINT_URLS.length + 1);
  });

  it("a new client starts clean after a check that was cancelled", async () => {
    const f = fakeFetch();
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(createDohResolver({ fetch: f.fn, signal: ctrl.signal }).query("example.com", "TXT")).rejects.toThrow(
      "cancelled",
    );
    expect((await createDohResolver({ fetch: f.fn }).query("example.com", "TXT")).resolver).toBe("cloudflare");
  });

  // 96: a whole check's first wave fits in one batch, and it stays under Google's 100 HTTP/2
  // streams. A network that drops DoH is still found by the MX probe and the relay probe.
  it("keeps at most 96 requests in flight per operator", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    await Promise.all(Array.from({ length: 100 }, (_, i) => doh.query(`s${i}._domainkey.example.com`, "TXT")));
    expect(f.calls).toHaveLength(100);
    expect(f.peak()).toBe(96);
    const g = fakeFetch();
    const both = createDohResolver({ fetch: g.fn });
    await Promise.all(Array.from({ length: 100 }, (_, i) => both.query(`s${i}.example.com`, "TXT", { confirm: true })));
    expect(g.peakOf("cloudflare")).toBe(96);
    expect(g.peakOf("google")).toBe(96);
    expect(g.peak()).toBe(192);
  });
});

describe("cancelling", () => {
  // Under load an attempt's own timeout can abort its signal while the fake still waits its
  // 1 ms, before it listens: the fake must reject like a real fetch, or the check hangs (the
  // relay-probe test below can then time out at 5 s on a busy machine).
  it("the fake fetch rejects a request whose signal aborted before it answered", async () => {
    const f = fakeFetch(all("mute"));
    const ctrl = new AbortController();
    const url = `${RESOLVER_URLS.cloudflare}?dns=${base64url(encodeQuery("example.org", "TXT"))}`;
    const p = f.fn(url, { signal: ctrl.signal });
    ctrl.abort();
    await expect(p).rejects.toThrow("aborted");
  });

  it("rejects every query with aborted when the check's signal aborts", async () => {
    const f = fakeFetch(all("mute"));
    const ctrl = new AbortController();
    const doh = createDohResolver({ fetch: f.fn, signal: ctrl.signal });
    const p = doh.query("example.com", "TXT");
    setTimeout(() => ctrl.abort(), 5);
    const err = await p.catch((e: unknown) => e);
    expect((err as LookupError).reason).toBe("aborted");
    await expect(doh.query("other.example.com", "TXT")).rejects.toThrow("cancelled");
  });

  it("lets one caller stop waiting without cancelling the shared query", async () => {
    const f = fakeFetch();
    const doh = createDohResolver({ fetch: f.fn });
    const ctrl = new AbortController();
    const mine = doh.query("example.com", "TXT", { signal: ctrl.signal });
    ctrl.abort();
    await expect(mine).rejects.toThrow("cancelled");
    expect((await doh.query("example.com", "TXT")).resolver).toBe("cloudflare");
    const done = new AbortController();
    done.abort();
    await expect(doh.query("example.com", "TXT", { signal: done.signal })).rejects.toThrow(LookupError);
  });

  it("aborting during the relay probe rejects every query with aborted and leaves nothing unhandled", async () => {
    const ctrl = new AbortController();
    // The abort fires when the first probe request goes out, before the fake answers it: no
    // wall-clock wait decides whether the probe has started (a fixed sleep is flaky under load).
    const muteAndAbortOnProbe = (n: number): Behavior => {
      if (n === 0) queueMicrotask(() => ctrl.abort());
      return "mute";
    };
    const f = fakeFetch(Object.fromEntries(DEFAULT_ORDER.map((op) => [op, muteAndAbortOnProbe])) as Rules);
    const doh = createDohResolver({ fetch: f.fn, signal: ctrl.signal, timeoutMs: 20 });
    const p = doh.query("example.org", "TXT", { confirm: true }).catch((e: unknown) => e);
    expect(((await p) as LookupError).reason).toBe("aborted");
    expect(f.calls.some((c) => c.probe)).toBe(true);
    expect(doh.unreachable()).toBe(false);
  });

  // It sends nothing to the endpoints dropped on the way.
  it("a check with every resolver mute ends after one timeout and one probe", async () => {
    vi.useFakeTimers();
    try {
      const f = fakeFetch(all("mute"));
      const d = deadline(500);
      const doh = createDohResolver({ fetch: f.fn, signal: d.signal, timeoutMs: 50 });
      let settled = false;
      const all100 = Promise.allSettled(
        Array.from({ length: 100 }, (_, i) => doh.query(`s${i}.example.org`, "TXT")),
      ).finally(() => (settled = true));
      // One timeout of 50 ms and the probe's, well before the limit of 500 ms.
      await vi.advanceTimersByTimeAsync(400);
      expect(settled).toBe(true);
      const results = await all100;
      d.dispose();
      expect(results.every((r) => r.status === "rejected" && (r.reason as LookupError).reason === "unreachable")).toBe(
        true,
      );
      // 96 queries fill Cloudflare's slots, time out, and the probe finds no one: the 4 that
      // waited for a slot never go out.
      expect(f.queries()).toHaveLength(96);
      expect(f.calls.filter((c) => c.probe)).toHaveLength(9);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("recorded answers through DoH", () => {
  it("serves a recorded Quad9 answer and reads it like the others", async () => {
    const bytes = new Uint8Array(readFileSync(fixturePath("google.com", "MX", { resolver: "quad9" })));
    const fn = (async () => dnsResponse(bytes)) as unknown as typeof fetch;
    const r = await createDohResolver({ fetch: fn, order: ["quad9"] }).query("google.com", "MX");
    expect(r.resolver).toBe("quad9");
    expect(r.answers.map((a) => a.data)).toEqual(["10 smtp.google.com"]);
  });
});
