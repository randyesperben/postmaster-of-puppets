// Test-side DNS: a message builder for generated cases (example.com/.net/.org) and a resolver over
// the recorded fixtures in test/fixtures/dns/. The fake fetch that serves them as DoH is fetch.ts.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { decodeMessage, typeCode } from "../../src/dns/codec.ts";
import type { DnsResult, QueryOptions, Resolver, ResolverId } from "../../src/dns/types.ts";

/** The recorded answers, read from here whatever the working directory. */
export const FIXTURES = fileURLToPath(new URL("../fixtures/dns/", import.meta.url));
/** Answers of filtering resolvers, <resolver host>.<name>.<TYPE>.bin. */
export const FILTERED = fileURLToPath(new URL("../fixtures/filtered/", import.meta.url));

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}
function u32(n: number): number[] {
  return [...u16(Math.floor(n / 65536)), ...u16(n % 65536)];
}
/** Presentation form to wire form: unescaped dots split labels, \DDD and \X stand for one octet. */
function name(n: string): number[] {
  const labels: number[][] = [[]];
  for (let i = 0; i < n.length; i++) {
    const c = n[i];
    const label = labels[labels.length - 1] as number[];
    if (c === "\\") {
      const ddd = /^\d{3}/.exec(n.slice(i + 1));
      label.push(ddd ? Number(ddd[0]) : n.charCodeAt(i + 1));
      i += ddd ? 3 : 1;
    } else if (c === ".") labels.push([]);
    else label.push(n.charCodeAt(i) & 0xff);
  }
  if (labels.length > 1 && labels[labels.length - 1]?.length === 0) labels.pop();
  const out: number[] = [];
  if (!(labels.length === 1 && labels[0]?.length === 0)) for (const l of labels) out.push(l.length, ...l);
  out.push(0);
  return out;
}

/** RFC 4034 §4.1.2 type bit maps from type names. */
function bitmap(types: string[]): number[] {
  const windows = new Map<number, number[]>();
  for (const t of types) {
    const code = typeCode(t);
    const bits = windows.get(code >> 8) ?? [];
    const octet = (code & 0xff) >> 3;
    while (bits.length <= octet) bits.push(0);
    bits[octet] = (bits[octet] ?? 0) | (0x80 >> (code & 7));
    windows.set(code >> 8, bits);
  }
  return [...windows.entries()].sort((a, b) => a[0] - b[0]).flatMap(([w, bits]) => [w, bits.length, ...bits]);
}

function base32hex(s: string): number[] {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  const out: number[] = [];
  let acc = 0;
  let n = 0;
  for (const c of s.toUpperCase()) {
    acc = (acc << 5) | alphabet.indexOf(c);
    n += 5;
    if (n >= 8) {
      n -= 8;
      out.push((acc >> n) & 0xff);
    }
  }
  return out;
}
function octets(s: string): number[] {
  return [...s].map((c) => c.charCodeAt(0) & 0xff);
}
function hexBytes(h: string): number[] {
  return (h.match(/../g) ?? []).map((x) => parseInt(x, 16));
}

/** Splits a long TXT value into 255-octet strings, as DNS panels do. */
export function chunks(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += 255) out.push(s.slice(i, i + 255));
  return out.length ? out : [""];
}

function rdata(type: string, data: string | string[]): number[] {
  switch (type) {
    case "A":
      return String(data).split(".").map(Number);
    case "AAAA": {
      const [head = "", tail] = String(data).split("::");
      const h = head ? head.split(":") : [];
      const t = tail !== undefined && tail !== "" ? tail.split(":") : [];
      const groups = tail === undefined ? h : [...h, ...Array<string>(8 - h.length - t.length).fill("0"), ...t];
      return groups.flatMap((g) => u16(parseInt(g, 16)));
    }
    case "NS":
    case "CNAME":
    case "PTR":
      return name(String(data));
    case "MX": {
      const [pref, host = "."] = String(data).split(" ");
      return [...u16(Number(pref)), ...name(host)];
    }
    case "TXT":
      return (Array.isArray(data) ? data : chunks(data)).flatMap((s) => [s.length, ...octets(s)]);
    case "SOA": {
      const [m = "", r = "", ...nums] = String(data).split(" ");
      return [...name(m), ...name(r), ...nums.flatMap((x) => u32(Number(x)))];
    }
    case "CAA": {
      const m = /^(\d+) (\S+) "(.*)"$/.exec(String(data));
      if (!m) throw new Error(`bad CAA ${data}`);
      return [Number(m[1]), (m[2] ?? "").length, ...octets(m[2] ?? ""), ...octets(m[3] ?? "")];
    }
    case "TLSA": {
      const [a, b, c, h = ""] = String(data).split(" ");
      return [Number(a), Number(b), Number(c), ...hexBytes(h)];
    }
    case "DS": {
      const [tag, alg, dt, h = ""] = String(data).split(" ");
      return [...u16(Number(tag)), Number(alg), Number(dt), ...hexBytes(h)];
    }
    case "NSEC": {
      const [next = ".", ...types] = String(data).split(" ");
      return [...name(next), ...bitmap(types)];
    }
    case "NSEC3": {
      const [alg, flags, iter, salt = "-", next = "", ...types] = String(data).split(" ");
      const saltBytes = salt === "-" ? [] : hexBytes(salt);
      const hash = base32hex(next);
      return [
        Number(alg),
        Number(flags),
        ...u16(Number(iter)),
        saltBytes.length,
        ...saltBytes,
        hash.length,
        ...hash,
        ...bitmap(types),
      ];
    }
    case "DNSKEY": {
      const [flags, proto, alg, b64 = ""] = String(data).split(" ");
      return [...u16(Number(flags)), Number(proto), Number(alg), ...octets(atob(b64))];
    }
    default:
      return hexBytes(String(data));
  }
}

export interface Rec {
  name: string;
  type: string;
  data: string | string[];
  ttl?: number;
  klass?: number;
}

interface MessageSpec {
  qname: string;
  qtype: string;
  rcode?: number;
  ad?: boolean;
  answers?: Rec[];
  authority?: Rec[];
  ede?: number[];
  /** Header and question fields a well-behaved resolver never changes, to test refusals. */
  id?: number;
  tc?: boolean;
  qclass?: number;
  noQuestion?: boolean;
}

function rr(r: Rec): number[] {
  const body = rdata(r.type, r.data);
  return [
    ...name(r.name),
    ...u16(typeCode(r.type)),
    ...u16(r.klass ?? 1),
    ...u32(r.ttl ?? 300),
    ...u16(body.length),
    ...body,
  ];
}

export function buildMessage(spec: MessageSpec): Uint8Array {
  const rcode = spec.rcode ?? 0;
  const flags = 0x8000 | (spec.tc ? 0x0200 : 0) | 0x0100 | 0x0080 | (spec.ad ? 0x0020 : 0) | (rcode & 0x0f);
  const answers = spec.answers ?? [];
  const authority = spec.authority ?? [];
  const edeOpts = (spec.ede ?? []).flatMap((code) => [...u16(15), ...u16(2), ...u16(code)]);
  const opt = [0, ...u16(41), ...u16(1232), (rcode >> 4) & 0xff, 0, 0, 0, ...u16(edeOpts.length), ...edeOpts];
  const question = spec.noQuestion ? [] : [...name(spec.qname), ...u16(typeCode(spec.qtype)), ...u16(spec.qclass ?? 1)];
  return Uint8Array.from([
    ...u16(spec.id ?? 0),
    ...u16(flags),
    0,
    spec.noQuestion ? 0 : 1,
    ...u16(answers.length),
    ...u16(authority.length),
    0,
    1,
    ...question,
    ...answers.flatMap(rr),
    ...authority.flatMap(rr),
    ...opt,
  ]);
}

export function toResult(bytes: Uint8Array, resolver?: ResolverId): DnsResult {
  const m = decodeMessage(bytes);
  const r: DnsResult = { rcode: m.rcode, ad: m.ad, answers: m.answers, authority: m.authority };
  if (resolver) r.resolver = resolver;
  if (m.ede.length) r.ede = m.ede;
  return r;
}

/**
 * Path of a recorded answer: <name>/<TYPE>[.cd][.do][.<resolver>].bin, .cd and .do when it was
 * asked with the CD or the DO bit. A file with no resolver is Cloudflare's, the first operator.
 */
export function fixturePath(
  qname: string,
  type: string,
  opts: { cd?: boolean; dnssecOk?: boolean; resolver?: string } = {},
): string {
  const suffix = [opts.cd ? "cd" : "", opts.dnssecOk ? "do" : "", opts.resolver ?? ""].filter(Boolean).join(".");
  return `${FIXTURES}${qname.toLowerCase().replace(/\.$/, "")}/${type.toUpperCase()}${suffix ? `.${suffix}` : ""}.bin`;
}

/** The answer an operator gave when the fixtures were recorded, or undefined if none was saved. */
export function recordedBy(
  op: ResolverId,
  qname: string,
  type: string,
  flags: { cd?: boolean; dnssecOk?: boolean } = {},
): Uint8Array | undefined {
  const path = fixturePath(qname, type, { ...flags, ...(op === "cloudflare" ? {} : { resolver: op }) });
  return existsSync(path) ? new Uint8Array(readFileSync(path)) : undefined;
}

/**
 * Resolver over recorded answers. A name the recorder did not save is a test error by default,
 * never a silent NXDOMAIN; with missing "empty" it answers NOERROR with no records, as
 * recordedOrEmpty does over DoH (helpers/fetch.ts).
 */
export function fixtureResolver(
  variant?: "google" | "quad9",
  missing: "throw" | "empty" = "throw",
): Resolver & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    async query(qname: string, type: string, opts: QueryOptions = {}) {
      const path = fixturePath(qname, type, {
        cd: opts.cd === true,
        dnssecOk: opts.dnssecOk === true,
        ...(variant ? { resolver: variant } : {}),
      });
      asked.push(`${qname} ${type}${opts.cd ? " cd" : ""}${opts.dnssecOk ? " do" : ""}`);
      if (existsSync(path)) return toResult(new Uint8Array(readFileSync(path)));
      if (missing === "empty") return toResult(buildMessage({ qname, qtype: type }));
      throw new Error(`no fixture ${path}`);
    },
  };
}

/** Reads the question of a DoH GET URL. */
export function parseQueryUrl(url: string): {
  host: string;
  name: string;
  type: number;
  cd: boolean;
  dnssecOk: boolean;
} {
  const u = new URL(url);
  const b64 = (u.searchParams.get("dns") ?? "").replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  let pos = 12;
  const labels: string[] = [];
  while ((bytes[pos] ?? 0) !== 0) {
    const len = bytes[pos] ?? 0;
    labels.push(String.fromCharCode(...bytes.subarray(pos + 1, pos + 1 + len)));
    pos += len + 1;
  }
  pos += 1;
  const type = ((bytes[pos] ?? 0) << 8) | (bytes[pos + 1] ?? 0);
  // The OPT record follows the question: root name, type, class, then the TTL whose third octet
  // holds DO.
  const dnssecOk = ((bytes[pos + 4 + 7] ?? 0) & 0x80) !== 0;
  return { host: u.hostname, name: labels.join("."), type, cd: ((bytes[3] ?? 0) & 0x10) !== 0, dnssecOk };
}

export function dnsResponse(bytes: Uint8Array, status = 200, contentType = "application/dns-message"): Response {
  return new Response(new Uint8Array(bytes), { status, headers: { "content-type": contentType } });
}
