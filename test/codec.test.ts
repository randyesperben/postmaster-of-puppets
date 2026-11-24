import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  base64url,
  decodeMessage,
  displayText,
  DnsFormatError,
  encodeQuery,
  typeCode,
  typeName,
} from "../src/dns/codec.ts";
import { normalizeName } from "../src/dns/names.ts";
import type { DnsRecord } from "../src/dns/types.ts";
import { buildMessage, FIXTURES } from "./helpers/dns.ts";

/** A record list in a stable order, for comparisons. */
function sorted(records: DnsRecord[]): string[] {
  return records.map((r) => `${r.name} ${r.type} ${JSON.stringify(r.data)}`).sort();
}

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("encodeQuery", () => {
  it("builds the RFC 8484 query: ID 0, RD and AD, one question, EDNS with ECS 0.0.0.0/0", () => {
    const q = encodeQuery("Example.COM.", "TXT");
    expect(hex(q)).toBe(
      "0000" +
        "0120" +
        "0001" +
        "0000" +
        "0000" +
        "0001" +
        "076578616d706c6503636f6d00" +
        "0010" +
        "0001" +
        "00" +
        "0029" +
        "1000" +
        "00000000" +
        "0008" +
        "0008000400010000",
    );
  });

  it("sets CD only when asked", () => {
    expect((encodeQuery("example.com", "A", { cd: true })[3] ?? 0) & 0x10).toBe(0x10);
    expect((encodeQuery("example.com", "A")[3] ?? 0) & 0x10).toBe(0);
  });

  it("encodes the root and refuses bad names", () => {
    expect(hex(encodeQuery(".", "NS").subarray(12, 13))).toBe("00");
    expect(() => encodeQuery("a..example.com", "A")).toThrow(RangeError);
    expect(() => encodeQuery(`${"a".repeat(64)}.com`, "A")).toThrow(RangeError);
    expect(() => encodeQuery("münchen.de", "A")).toThrow(RangeError);
    expect(() => encodeQuery(`${"abcdefghi.".repeat(26)}com`, "A")).toThrow(RangeError);
  });

  it("sets DO in the OPT record only when asked (RFC 3225 §3)", () => {
    const opt = (q: Uint8Array): string => hex(q.subarray(q.length - 16, q.length - 10));
    expect(opt(encodeQuery("example.com", "A", { dnssecOk: true }))).toBe("100000008000");
    expect(opt(encodeQuery("example.com", "A"))).toBe("100000000000");
  });

  it("reads \\DDD and \\X escapes, so a decoded name asks the same wire name again", () => {
    expect(hex(encodeQuery("a\\046b.Example.com", "A").subarray(12, 31))).toBe(
      "0361" + "2e62" + "076578616d706c6503636f6d00" + "0001",
    );
    expect(hex(encodeQuery("a\\.b.example.com", "A").subarray(12, 16))).toBe("03612e62");
    expect(hex(encodeQuery("\\195\\169.example.com", "A").subarray(12, 15))).toBe("02c3a9");
    expect(() => encodeQuery("\\256.example.com", "A")).toThrow(RangeError);
  });

  it("is URL-safe base64 without padding", () => {
    const s = base64url(encodeQuery("example.com", "TXT"));
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(base64url(Uint8Array.from([0xfb, 0xff]))).toBe("-_8");
  });
});

describe("type codes", () => {
  it("maps names and numbers both ways, with the RFC 3597 form for others", () => {
    expect(typeCode("txt")).toBe(16);
    expect(typeCode("TYPE65")).toBe(65);
    expect(typeName(65)).toBe("TYPE65");
    expect(typeName(257)).toBe("CAA");
    expect(() => typeCode("BOGUS")).toThrow(RangeError);
    expect(() => typeCode("TYPE70000")).toThrow(RangeError);
  });

  it("knows the DNSSEC types and NXNAME (RFC 9824 §9)", () => {
    expect([46, 47, 50, 128].map(typeName)).toEqual(["RRSIG", "NSEC", "NSEC3", "NXNAME"]);
  });

  it("normalizes names, lower-casing only A-Z (RFC 4343 §3)", () => {
    expect(normalizeName("Example.COM.")).toBe("example.com");
    expect(normalizeName("\u00c9xample.com")).toBe("\u00c9xample.com");
    expect(normalizeName(".")).toBe(".");
    expect(normalizeName("")).toBe(".");
  });
});

describe("decodeMessage on generated answers", () => {
  it("reads answers of each record type it decodes", () => {
    const answers = [
      { name: "example.com", type: "A", data: "192.0.2.1" },
      { name: "example.com", type: "AAAA", data: "2001:db8::1" },
      { name: "example.com", type: "MX", data: "10 mx.example.com" },
      { name: "example.com", type: "TXT", data: ["v=spf1 ", "-all"] },
      { name: "example.com", type: "CNAME", data: "target.example.net" },
      { name: "example.com", type: "NS", data: "ns1.example.org" },
      { name: "1.2.0.192.in-addr.arpa", type: "PTR", data: "host.example.com" },
      {
        name: "example.com",
        type: "SOA",
        data: "ns1.example.com hostmaster.example.com 2026111801 7200 3600 1209600 300",
      },
      { name: "example.com", type: "CAA", data: '0 issue "letsencrypt.org"' },
      { name: "_25._tcp.mx.example.com", type: "TLSA", data: "3 1 1 0becb1af" },
      {
        name: "example.com",
        type: "DS",
        data: "370 13 2 be74359954660069d5c63d200c39f5603827d7dd02b56f120ee9f3a86764247c",
      },
      {
        name: "example.com",
        type: "DNSKEY",
        data: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
      },
      { name: "example.com", type: "TYPE65", data: "0001" },
      { name: "example.com", type: "MX", data: "0 ." },
    ];
    const m = decodeMessage(buildMessage({ qname: "example.com", qtype: "A", answers, ad: true }));
    expect(m.rcode).toBe(0);
    expect(m.ad).toBe(true);
    expect(m.tc).toBe(false);
    expect(m.question).toEqual({ name: "example.com", type: "A", klass: 1 });
    expect(m.id).toBe(0);
    expect(m.answers.map((a) => a.data)).toEqual([
      "192.0.2.1",
      "2001:db8::1",
      "10 mx.example.com",
      ["v=spf1 ", "-all"],
      "target.example.net",
      "ns1.example.org",
      "host.example.com",
      "ns1.example.com hostmaster.example.com 2026111801 7200 3600 1209600 300",
      '0 issue "letsencrypt.org"',
      "3 1 1 0becb1af",
      "370 13 2 be74359954660069d5c63d200c39f5603827d7dd02b56f120ee9f3a86764247c",
      "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
      "\\# 2 0001",
      "0 .",
    ]);
  });

  it("writes IPv6 in the RFC 5952 short form", () => {
    const cases: [string, string][] = [
      ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"],
      ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"],
      ["0:0:0:0:0:0:0:1", "::1"],
      ["2001:db8:1:2:3:4:0:0", "2001:db8:1:2:3:4::"],
      ["0:0:0:0:0:0:0:0", "::"],
    ];
    for (const [input, out] of cases) {
      const m = decodeMessage(
        buildMessage({
          qname: "example.com",
          qtype: "AAAA",
          answers: [{ name: "example.com", type: "AAAA", data: input }],
        }),
      );
      expect(m.answers[0]?.data).toBe(out);
    }
  });

  it("writes IPv4-mapped addresses in mixed notation (RFC 5952 §5)", () => {
    const m = decodeMessage(
      buildMessage({
        qname: "example.com",
        qtype: "AAAA",
        answers: [
          { name: "example.com", type: "AAAA", data: "::ffff:c000:201" },
          { name: "example.com", type: "AAAA", data: "::c000:201" },
        ],
      }),
    );
    expect(m.answers.map((a) => a.data)).toEqual(["::ffff:192.0.2.1", "::c000:201"]);
  });

  it("escapes dots, backslashes and non-printable octets inside labels as \\DDD and lower-cases only A-Z", () => {
    const m = decodeMessage(
      buildMessage({
        qname: "example.com",
        qtype: "CNAME",
        answers: [{ name: "example.com", type: "CNAME", data: "A\\046B\\032\\092\\201.Example.com" }],
      }),
    );
    expect(m.answers[0]?.data).toBe("a\\046b\\032\\092\\201.example.com");
    // Read back, the escaped form asks the same octets again.
    expect(hex(encodeQuery(String(m.answers[0]?.data), "A").subarray(12, 19))).toBe("0661" + "2e62205c" + "c9");
  });

  it("reads NSEC and NSEC3 (RFC 4034 §4.1, RFC 5155 §3.2) with their type bit maps", () => {
    const m = decodeMessage(
      buildMessage({
        qname: "a.example.com",
        qtype: "A",
        authority: [
          { name: "a.example.com", type: "NSEC", data: "\\000.a.example.com RRSIG NSEC NXNAME" },
          { name: "example.com", type: "NSEC", data: "www.example.com A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY CAA" },
          {
            name: "h64kfa4p1acer2ebps9qsdk6dnp8b3jq.example.com",
            type: "NSEC3",
            data: "1 0 0 - H64KFA4P1ACER2EBPS9QSDK6DNP8B3JR NXNAME",
          },
          { name: "x.example.com", type: "NSEC3", data: "1 1 12 aabbccdd 0123456789ABCDEFGHIJKLMNOPQRSTUV A" },
        ],
      }),
    );
    expect(m.authority.map((a) => a.data)).toEqual([
      "\\000.a.example.com RRSIG NSEC NXNAME",
      "www.example.com A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY CAA",
      "1 0 0 - h64kfa4p1acer2ebps9qsdk6dnp8b3jr NXNAME",
      "1 1 12 aabbccdd 0123456789abcdefghijklmnopqrstuv A",
    ]);
  });

  it("refuses a type bit map with a bad window or length", () => {
    const head = [0, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    const nsec = (bitmap: number[]): Uint8Array =>
      Uint8Array.from([...head, 0, 47, 0, 1, 0, 0, 0, 60, 0, 1 + bitmap.length, 0, ...bitmap]);
    expect(decodeMessage(nsec([0, 1, 0x40])).answers[0]?.data).toBe(". A");
    expect(() => decodeMessage(nsec([0, 0]))).toThrow(DnsFormatError);
    expect(() => decodeMessage(nsec([0, 33, ...Array<number>(33).fill(0)]))).toThrow(DnsFormatError);
    expect(() => decodeMessage(nsec([0, 4, 0x40]))).toThrow(DnsFormatError);
    expect(() => decodeMessage(nsec([1, 1, 0x40, 0, 1, 0x40]))).toThrow(DnsFormatError);
  });

  it("keeps TXT octets for the rules and decodes UTF-8 only for display", () => {
    const m = decodeMessage(
      buildMessage({
        qname: "example.com",
        qtype: "TXT",
        answers: [{ name: "example.com", type: "TXT", data: ["caf\u00c3\u00a9 \u00ff"] }],
      }),
    );
    const raw = (m.answers[0]?.data as string[])[0] ?? "";
    expect(raw).toHaveLength(7);
    expect(displayText(raw)).toBe("caf\u00e9 \ufffd");
    expect(displayText("plain")).toBe("plain");
  });

  it("keeps TXT strings apart and byte-exact, one char per octet", () => {
    const long = `v=DKIM1; k=rsa; p=${"A".repeat(400)}`;
    const m = decodeMessage(
      buildMessage({
        qname: "example.com",
        qtype: "TXT",
        answers: [
          { name: "example.com", type: "TXT", data: long },
          { name: "example.com", type: "TXT", data: ["café"] },
        ],
      }),
    );
    expect(m.answers[0]?.data).toHaveLength(2);
    expect((m.answers[0]?.data as string[]).join("")).toBe(long);
    expect(m.answers[1]?.data).toEqual(["café"]);
  });

  it("reads rcode, Extended DNS Errors and the extended RCODE from OPT", () => {
    const m = decodeMessage(buildMessage({ qname: "example.com", qtype: "A", rcode: 2, ede: [9, 6] }));
    expect(m.rcode).toBe(2);
    expect(m.ede).toEqual([9, 6]);
    expect(decodeMessage(buildMessage({ qname: "example.com", qtype: "A", rcode: 16 })).rcode).toBe(16);
  });

  it("separates answer and authority and skips other classes", () => {
    const m = decodeMessage(
      buildMessage({
        qname: "nope.example.com",
        qtype: "TXT",
        rcode: 3,
        answers: [{ name: "version.bind", type: "TXT", data: ["x"], klass: 3 }],
        authority: [{ name: "example.com", type: "SOA", data: "ns.example.com h.example.com 1 2 3 4 5" }],
      }),
    );
    expect(m.answers).toEqual([]);
    expect(m.authority.map((a) => a.type)).toEqual(["SOA"]);
  });
});

describe("decodeMessage refuses broken messages", () => {
  const good = buildMessage({
    qname: "example.com",
    qtype: "A",
    answers: [{ name: "example.com", type: "A", data: "192.0.2.1" }],
  });

  it("truncated", () => {
    for (const cut of [5, 20, good.length - 3])
      expect(() => decodeMessage(good.subarray(0, cut))).toThrow(DnsFormatError);
  });

  it("a query instead of a response", () => {
    expect(() => decodeMessage(encodeQuery("example.com", "A"))).toThrow("not a response");
  });

  it("a compression pointer that loops or points forward", () => {
    const loop = Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]);
    expect(() => decodeMessage(loop)).toThrow("does not point back");
    const forward = Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 20, 0, 1, 0, 1]);
    expect(() => decodeMessage(forward)).toThrow(DnsFormatError);
    const cut = Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0]);
    expect(() => decodeMessage(cut)).toThrow("pointer runs past");
  });

  it("a label type that does not exist, a label past the end, a name over 255 octets", () => {
    expect(() => decodeMessage(Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0]))).toThrow(
      "unknown label type",
    );
    expect(() => decodeMessage(Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 5, 97]))).toThrow(
      "label runs past",
    );
    expect(() => decodeMessage(Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]))).toThrow("name runs past");
    const labels = Array.from({ length: 5 }, () => [63, ...Array<number>(63).fill(97)]).flat();
    expect(() =>
      decodeMessage(Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1])),
    ).toThrow("longer than 255");
  });

  it("RDATA whose length does not match its type", () => {
    const head = [0, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    const rr = (type: number, rdata: number[]): Uint8Array =>
      Uint8Array.from([...head, type >> 8, type & 0xff, 0, 1, 0, 0, 0, 60, 0, rdata.length, ...rdata]);
    expect(() => decodeMessage(rr(1, [1, 2, 3]))).toThrow("A record is not 4 octets");
    expect(() => decodeMessage(rr(28, [1, 2, 3]))).toThrow("AAAA record is not 16 octets");
    expect(() => decodeMessage(rr(16, [10, 97]))).toThrow("TXT string runs past");
    expect(() => decodeMessage(rr(257, [0, 9, 97]))).toThrow("CAA tag runs past");
    expect(() => decodeMessage(rr(2, [0, 1]))).toThrow("length does not match");
  });
});

// The same queries asked of Cloudflare, Google and Quad9 on 2026-11-18 by the fixture recorder (in
// the source of postmasterofpuppets.com) must read the same once TTLs and record order are set
// aside. Its recordings of full checks (microsoft.com, github.com) keep the first resolver only:
// there the resolvers disagree on the data itself (NXDOMAIN against NOERROR for some names under
// github.com), which says nothing about the codec.
describe("recorded answers from the three resolvers", () => {
  const cases = readdirSync(FIXTURES).flatMap((dir) =>
    readdirSync(join(FIXTURES, dir))
      .filter((f) => /^[A-Z0-9]+(\.cd)?(\.do)?\.bin$/.test(f))
      .map((f) => ({ dir, base: f.replace(/\.bin$/, "") }))
      .filter(({ base }) => ["google", "quad9"].every((r) => existsSync(join(FIXTURES, dir, `${base}.${r}.bin`)))),
  );

  it("has recorded cases", () => {
    expect(cases.length).toBeGreaterThanOrEqual(16);
  });

  const read = (dir: string, file: string) => decodeMessage(new Uint8Array(readFileSync(join(FIXTURES, dir, file))));
  const normal = (m: ReturnType<typeof decodeMessage>) => ({
    rcode: m.rcode,
    question: m.question,
    answers: sorted(m.answers),
    authority: m.authority.map((a) => `${a.name} ${a.type}`).sort(),
  });

  for (const { dir, base } of cases) {
    it(`${dir} ${base}`, () => {
      const cloudflare = normal(read(dir, `${base}.bin`));
      expect(normal(read(dir, `${base}.google.bin`))).toEqual(cloudflare);
      expect(normal(read(dir, `${base}.quad9.bin`))).toEqual(cloudflare);
    });
  }

  it("reads the cases that matter for the checks", () => {
    const dangling = read("selector1._domainkey.microsoft.com", "TXT.bin");
    expect(dangling.rcode).toBe(3);
    expect(dangling.answers[0]?.type).toBe("CNAME");
    const key = read("selector2._domainkey.microsoft.com", "TXT.bin");
    expect(key.answers.map((a) => a.type)).toEqual(["CNAME", "TXT"]);
    expect(key.answers[1]?.data[0]).toMatch(/^v=DKIM1; k=rsa; p=/);
    const broken = read("dnssec-failed.org", "A.bin");
    expect(broken.rcode).toBe(2);
    expect(broken.ede).toContain(9);
    expect(read("dnssec-failed.org", "A.cd.bin").rcode).toBe(0);
    expect(read("example.com", "MX.bin").answers[0]?.data).toBe("0 .");
    expect(read("google.com", "TLSA.bin").authority[0]?.type).toBe("SOA");
  });
});
