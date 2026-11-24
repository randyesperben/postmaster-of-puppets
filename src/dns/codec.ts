// Binary DNS messages (RFC 1035 §4) for DNS-over-HTTPS (RFC 8484): builds the query and reads
// the answer and authority sections. Own code because the existing packages need Node's
// Buffer or are no longer published.
import { MAX_WIRE_NAME, parseName, presentLabel } from "./names.ts";
import type { DnsRecord } from "./types.ts";

/**
 * The record types the engine names, with their codes (IANA DNS Parameters, Resource Record Types).
 */
const TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  OPT: 41,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  TLSA: 52,
  NXNAME: 128,
  CAA: 257,
} as const;
const TYPE_CODES: ReadonlyMap<string, number> = new Map(Object.entries(TYPES));
const TYPE_NAMES: ReadonlyMap<number, string> = new Map(Object.entries(TYPES).map(([k, v]) => [v, k]));

export const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3 } as const;

/** Class IN, the Internet (RFC 1035 §3.2.4): the only class the engine asks or reads. */
export const CLASS_IN = 1;

/** The EDNS option code of an Extended DNS Error (RFC 8914 §2). */
const EDE_OPTION = 15;

/** A message that cannot be read: truncated, looping pointers or bad lengths. */
export class DnsFormatError extends Error {
  override name = "DnsFormatError";
}

export interface DecodedMessage {
  id: number;
  rcode: number;
  ad: boolean;
  tc: boolean;
  question?: { name: string; type: string; klass: number };
  answers: DnsRecord[];
  authority: DnsRecord[];
  ede: number[];
}

export function typeName(code: number): string {
  return TYPE_NAMES.get(code) ?? `TYPE${code}`;
}

export function typeCode(name: string): number {
  const known = TYPE_CODES.get(name.toUpperCase());
  if (known !== undefined) return known;
  const m = /^TYPE(\d{1,5})$/i.exec(name);
  if (m && Number(m[1]) < 65536) return Number(m[1]);
  throw new RangeError(`unknown DNS type ${name}`);
}

function encodeName(name: string): number[] {
  return [...parseName(name).flatMap((l) => [l.length, ...l]), 0];
}

/**
 * Query with ID 0 (RFC 8484 §4.1, so HTTP caches can share it), RD and AD set (resolvers only
 * report AD when asked, RFC 6840 §5.7), CD on request, and an EDNS(0) OPT record that carries
 * Client Subnet 0.0.0.0/0 so no part of the user's address reaches authoritative servers
 * (RFC 7871 §7.1.2). EDNS is also what lets resolvers return Extended DNS Errors (RFC 8914).
 * DO on request (RFC 3225 §3): the only way to see the NSEC that tells a missing name under
 * Compact Denial of Existence (RFC 9824 §6).
 */
export function encodeQuery(name: string, type: string, opts: { cd?: boolean; dnssecOk?: boolean } = {}): Uint8Array {
  const flags = 0x0100 | 0x0020 | (opts.cd ? 0x0010 : 0); // RD, AD, CD
  const ecs = [0, 8, 0, 4, 0, 1, 0, 0]; // option 8, length 4, family 1 (IPv4), source /0, scope /0
  const bytes = [
    // Header (RFC 1035 §4.1.1): ID, flags, then one question, no answer or authority records and
    // one additional record.
    ...u16(0),
    ...u16(flags),
    ...u16(1),
    ...u16(0),
    ...u16(0),
    ...u16(1),
    // The question: name, type and class.
    ...encodeName(name),
    ...u16(typeCode(type)),
    ...u16(CLASS_IN),
    // The OPT record (RFC 6891 §6.1.2), whose TTL holds the extended RCODE, the version and the
    // flags (§6.1.3).
    0, // the root name
    ...u16(TYPES.OPT),
    ...u16(4096), // the UDP payload size, in place of the class
    ...u16(0), // extended RCODE 0, version 0
    ...u16(opts.dnssecOk ? 0x8000 : 0), // the DO bit (RFC 3225)
    ...u16(ecs.length), // RDLENGTH
    ...ecs,
  ];
  return Uint8Array.from(bytes);
}

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}

/** base64url without padding, as RFC 8484 §4.1 asks for the ?dns= parameter. */
export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** RFC 4648 §7 alphabet, as NSEC3 hashes are written (RFC 5155 §3.3). */
function base32hex(bytes: Uint8Array): string {
  const alphabet = "0123456789abcdefghijklmnopqrstuv";
  let s = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = ((acc << 8) | b) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      s += alphabet[(acc >> bits) & 31];
    }
  }
  if (bits > 0) s += alphabet[(acc << (5 - bits)) & 31];
  return s;
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** One char per octet, so string lengths are octet counts (SPF and DKIM limits are in octets). */
function octets(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

/**
 * A TXT string (one char per octet, as decodeMessage keeps it for the rules) as text to show:
 * UTF-8, with U+FFFD for bytes that are not (no `fatal`). Text that is not octets comes back as is.
 */
export function displayText(text: string): string {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0xff) return text;
    bytes[i] = c;
  }
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
}

// Plain fields, no parameter properties: Node can run the engine with type stripping only, which
// refuses syntax that is not erasable.
class Reader {
  readonly buf: Uint8Array;
  pos: number;
  constructor(buf: Uint8Array) {
    this.buf = buf;
    this.pos = 0;
  }

  need(n: number): void {
    if (this.pos + n > this.buf.length) throw new DnsFormatError("message truncated");
  }
  u8(): number {
    this.need(1);
    return this.buf[this.pos++] ?? 0;
  }
  u16(): number {
    return (this.u8() << 8) | this.u8();
  }
  u32(): number {
    return this.u16() * 65536 + this.u16();
  }
  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** A name with compression pointers (RFC 1035 §4.1.4); pointers may only go backwards. */
  name(): string {
    const labels: string[] = [];
    let pos = this.pos;
    let jumped = false;
    let length = 1;
    for (;;) {
      if (pos >= this.buf.length) throw new DnsFormatError("name runs past the message");
      const len = this.buf[pos] ?? 0;
      if (len === 0) {
        pos += 1;
        break;
      }
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= this.buf.length) throw new DnsFormatError("pointer runs past the message");
        const target = ((len & 0x3f) << 8) | (this.buf[pos + 1] ?? 0);
        if (target >= pos) throw new DnsFormatError("compression pointer does not point back");
        if (!jumped) this.pos = pos + 2;
        jumped = true;
        pos = target;
        continue;
      }
      if (len & 0xc0) throw new DnsFormatError("unknown label type");
      if (pos + 1 + len > this.buf.length) throw new DnsFormatError("label runs past the message");
      length += len + 1;
      if (length > MAX_WIRE_NAME) throw new DnsFormatError("name longer than 255 octets");
      labels.push(presentLabel(this.buf.subarray(pos + 1, pos + 1 + len)));
      pos += 1 + len;
    }
    if (!jumped) this.pos = pos;
    return labels.length === 0 ? "." : labels.join(".");
  }
}

function ipv6(b: Uint8Array): string {
  // RFC 5952 §5: an IPv4-mapped address (::ffff:0:0/96, RFC 4291 §2.5.5.2) in mixed notation.
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff)
    return `::ffff:${Array.from(b.subarray(12)).join(".")}`;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i] ?? 0) << 8) | (b[i + 1] ?? 0));
  // RFC 5952 §4.2: collapse the longest run of two or more zero groups, the first one on ties.
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const h = groups.map((g) => g.toString(16));
  if (best < 0) return h.join(":");
  return `${h.slice(0, best).join(":")}::${h.slice(best + bestLen).join(":")}`;
}

/** RFC 4034 §4.1.2: window blocks in increasing order, each 1 to 32 octets of bits. */
function typeBitmap(r: Reader, end: number): string[] {
  const types: string[] = [];
  let last = -1;
  while (r.pos < end) {
    const block = r.u8();
    const len = r.u8();
    if (block <= last || len < 1 || len > 32 || r.pos + len > end) throw new DnsFormatError("bad type bit map");
    last = block;
    const bits = r.bytes(len);
    for (let i = 0; i < len * 8; i++)
      if ((bits[i >> 3] ?? 0) & (0x80 >> (i & 7))) types.push(typeName(block * 256 + i));
  }
  return types;
}

function rdata(r: Reader, type: number, len: number): string | string[] {
  const end = r.pos + len;
  r.need(len);
  const sub = (): Uint8Array => r.bytes(end - r.pos);
  let data: string | string[];
  switch (type) {
    case TYPES.A: {
      if (len !== 4) throw new DnsFormatError("A record is not 4 octets");
      data = Array.from(r.bytes(4)).join(".");
      break;
    }
    case TYPES.AAAA: {
      if (len !== 16) throw new DnsFormatError("AAAA record is not 16 octets");
      data = ipv6(r.bytes(16));
      break;
    }
    case TYPES.NS:
    case TYPES.CNAME:
    case TYPES.PTR:
      data = r.name();
      break;
    case TYPES.MX: {
      const pref = r.u16();
      data = `${pref} ${r.name()}`;
      break;
    }
    case TYPES.SOA: {
      const mname = r.name();
      const rname = r.name();
      const nums = [r.u32(), r.u32(), r.u32(), r.u32(), r.u32()];
      data = `${mname} ${rname} ${nums.join(" ")}`;
      break;
    }
    case TYPES.TXT: {
      const strings: string[] = [];
      while (r.pos < end) {
        const n = r.u8();
        if (r.pos + n > end) throw new DnsFormatError("TXT string runs past its record");
        strings.push(octets(r.bytes(n)));
      }
      data = strings;
      break;
    }
    case TYPES.CAA: {
      const flags = r.u8();
      const tagLen = r.u8();
      if (r.pos + tagLen > end) throw new DnsFormatError("CAA tag runs past its record");
      const tag = octets(r.bytes(tagLen));
      data = `${flags} ${tag} "${octets(sub())}"`;
      break;
    }
    case TYPES.TLSA: {
      const head = [r.u8(), r.u8(), r.u8()];
      data = `${head.join(" ")} ${hex(sub())}`;
      break;
    }
    case TYPES.DS: {
      const keyTag = r.u16();
      const head = [keyTag, r.u8(), r.u8()];
      data = `${head.join(" ")} ${hex(sub())}`;
      break;
    }
    case TYPES.NSEC:
      data = [r.name(), ...typeBitmap(r, end)].join(" ");
      break;
    case TYPES.NSEC3: {
      // RFC 5155 §3.2: algorithm, flags, iterations, then salt and next hashed owner, each
      // after its length.
      const head = [r.u8(), r.u8(), r.u16()];
      const field = (): Uint8Array => {
        const n = r.u8();
        if (r.pos + n > end) throw new DnsFormatError("NSEC3 field runs past its record");
        return r.bytes(n);
      };
      const salt = field();
      const next = field();
      data = [...head, salt.length ? hex(salt) : "-", base32hex(next), ...typeBitmap(r, end)].join(" ");
      break;
    }
    case TYPES.DNSKEY: {
      const flags = r.u16();
      const head = [flags, r.u8(), r.u8()];
      data = `${head.join(" ")} ${base64(sub())}`;
      break;
    }
    default:
      // RFC 3597 §5: unknown types in their generic form.
      data = `\\# ${len} ${hex(sub())}`;
  }
  if (r.pos !== end) throw new DnsFormatError(`${typeName(type)} record length does not match its data`);
  return data;
}

interface RawRecord extends DnsRecord {
  code: number;
  klass: number;
  raw?: Uint8Array;
}

function record(r: Reader): RawRecord {
  const name = r.name();
  const code = r.u16();
  const klass = r.u16();
  const ttl = r.u32();
  const len = r.u16();
  if (code === TYPES.OPT) {
    // OPT: the class is the UDP size and the TTL carries the extended RCODE (RFC 6891 §6.1.3).
    return { name, type: "OPT", ttl, data: "", code, klass, raw: r.bytes(len) };
  }
  return { name, type: typeName(code), ttl, data: rdata(r, code, len), code, klass };
}

function strip({ name, type, ttl, data }: RawRecord): DnsRecord {
  return { name, type, ttl, data };
}

export function decodeMessage(buf: Uint8Array): DecodedMessage {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  if (!(flags & 0x8000)) throw new DnsFormatError("not a response");
  const counts = [r.u16(), r.u16(), r.u16(), r.u16()] as const;
  let question: DecodedMessage["question"];
  for (let i = 0; i < counts[0]; i++) {
    const name = r.name();
    const type = typeName(r.u16());
    const klass = r.u16();
    if (i === 0) question = { name, type, klass };
  }
  const answers: DnsRecord[] = [];
  const authority: DnsRecord[] = [];
  const ede: number[] = [];
  let rcode = flags & 0x0f;
  for (let i = 0; i < counts[1]; i++) {
    const rec = record(r);
    if (rec.klass === CLASS_IN) answers.push(strip(rec));
  }
  for (let i = 0; i < counts[2]; i++) {
    const rec = record(r);
    if (rec.klass === CLASS_IN) authority.push(strip(rec));
  }
  for (let i = 0; i < counts[3]; i++) {
    const rec = record(r);
    if (rec.code !== TYPES.OPT || !rec.raw) continue;
    rcode |= (rec.ttl >>> 24) << 4;
    // Options: an Extended DNS Error's first two octets are its INFO-CODE (RFC 8914 §2).
    const o = new Reader(rec.raw);
    while (o.pos < rec.raw.length) {
      const code = o.u16();
      const len = o.u16();
      const body = o.bytes(len);
      if (code === EDE_OPTION && len >= 2) ede.push(((body[0] ?? 0) << 8) | (body[1] ?? 0));
    }
  }
  const out: DecodedMessage = { id, rcode, ad: !!(flags & 0x0020), tc: !!(flags & 0x0200), answers, authority, ede };
  if (question) out.question = question;
  return out;
}
