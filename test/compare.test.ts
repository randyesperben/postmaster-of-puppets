// compare.ts: how two operators' answers are normalized and compared, on generated answers and on
// the answers the six operators gave when the fixtures were recorded.
import { describe, expect, it } from "vitest";
import { describe as describeAnswer, normalize, same, ttlOf } from "../src/dns/compare.ts";
import { DEFAULT_ORDER } from "../src/dns/endpoints.ts";
import type { DnsRecord, ResolverId } from "../src/dns/types.ts";
import { P4, P4B } from "./helpers/check.ts";
import { recordedBy, toResult } from "./helpers/dns.ts";

const D = "example.net";

describe("the normalized comparison", () => {
  const rec = (name: string, type: string, data: string | string[], ttl = 300): DnsRecord => ({
    name,
    type,
    ttl,
    data,
  });
  const answer = (answers: DnsRecord[], rcode = 0, authority: DnsRecord[] = []) => ({ rcode, answers, authority });

  it("ignores order, TTL, case and how TXT is split; keeps only SPF or DMARC where they count", () => {
    const a = normalize(D, "MX", answer([rec(D, "MX", "10 A.example.net", 60), rec(D, "MX", "20 b.example.net")]));
    const b = normalize(D, "MX", answer([rec(D, "MX", "20 b.example.net", 3600), rec(D, "MX", "10 a.example.net")]));
    expect(same(a, b)).toBe(true);
    const t1 = normalize(
      D,
      "TXT",
      answer([rec(D, "TXT", ["v=spf1 ", "-all"]), rec(D, "TXT", "google-site-verification=x")]),
    );
    const t2 = normalize(D, "TXT", answer([rec(D, "TXT", "v=spf1 -all")]));
    expect(same(t1, t2)).toBe(true);
    const d1 = normalize(
      `_dmarc.${D}`,
      "TXT",
      answer([rec(`_dmarc.${D}`, "TXT", "v=DMARC1; p=none"), rec(`_dmarc.${D}`, "TXT", "v=spf1 -all")]),
    );
    expect(d1.values).toEqual(["v=DMARC1; p=none"]);
  });

  it("tells data, NODATA and NXDOMAIN apart, NXNAME counting as NXDOMAIN (RFC 9824)", () => {
    const nodata = normalize(D, "TXT", answer([]));
    const nx = normalize(D, "TXT", answer([], 3));
    const nxname = normalize(D, "A", answer([], 0, [rec(D, "NSEC", `\\000.${D} RRSIG NSEC NXNAME`)]));
    expect([nodata.class, nx.class, nxname.class]).toEqual(["nodata", "nxdomain", "nxdomain"]);
    expect(same(nodata, nx)).toBe(false);
    expect(describeAnswer(nodata)).toBe("NODATA");
    expect(describeAnswer(nx)).toBe("NXDOMAIN");
  });

  it("compares addresses by public or private, never one by one", () => {
    const a = normalize(D, "A", answer([rec(D, "A", P4)]));
    const b = normalize(D, "A", answer([rec(D, "A", P4B), rec(D, "A", "192.0.32.12")]));
    const sunk = normalize(D, "A", answer([rec(D, "A", "0.0.0.0")]));
    expect(same(a, b)).toBe(true);
    expect(same(a, sunk)).toBe(false);
    expect(describeAnswer(sunk)).toBe("private");
  });

  // RFC 2308 §5.
  it("the wait is the records' TTL, or for an empty answer the lesser of the SOA's TTL and MINIMUM", () => {
    expect(ttlOf("TXT", answer([rec(D, "TXT", "a", 900), rec(D, "TXT", "b", 120)]))).toBe(120);
    expect(ttlOf("TXT", answer([], 0, [rec(D, "SOA", "ns. host. 1 2 3 4 3600", 600)]))).toBe(600);
    expect(ttlOf("TXT", answer([], 3, [rec(D, "SOA", "ns. host. 1 2 3 4 60", 600)]))).toBe(60);
    expect(ttlOf("TXT", answer([]))).toBeUndefined();
  });
});

describe("recorded answers of the six operators (2026-11-18)", () => {
  const queries: [string, string, string][] = [
    ["example.com", "MX", "data"],
    ["example.com", "TXT", "data"],
    ["_dmarc.example.com", "TXT", "data"],
    ["google.com", "MX", "data"],
    ["google.com", "TXT", "data"],
    ["nonexistent-xyz-12345.google.com", "TXT", "nxdomain"],
  ];
  for (const [name, type, cls] of queries) {
    it(`${name} ${type}: the codec reads the same normalized answer from all six`, () => {
      const read = (op: ResolverId) => {
        const bytes = recordedBy(op, name, type);
        if (!bytes) throw new Error(`no recorded ${name} ${type} of ${op}`);
        return normalize(name, type, toResult(bytes, op));
      };
      const first = read("cloudflare");
      expect(first.class).toBe(cls);
      for (const op of DEFAULT_ORDER) expect([op, same(read(op), first)]).toEqual([op, true]);
    });
  }
});
