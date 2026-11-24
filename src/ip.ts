// Address helpers for MX targets and SPF ip4/ip6 terms: parsing, prefixes and the ranges no mail
// server can reach. No imports and no Node or DOM types, so any runtime can load this file.

/**
 * Prefix lengths shorter than these are wide SPF ranges, IPv4 then IPv6: checks/spf-walk.ts
 * flags them, and data/cloud-ranges.ts holds the cloud providers' ranges cut into blocks of these
 * sizes.
 */
export const WIDE_PREFIX = [16, 32] as const;

/** Dotted-quad IPv4 with each octet 0 to 255, no leading zeros (RFC 7208 §5.6 ip4-network). */
export function parseIpv4(s: string): number[] | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return undefined;
  const octets = m.slice(1).map(Number);
  if (octets.some((o, i) => o > 255 || (m[i + 1] ?? "").length > String(o).length)) return undefined;
  return octets;
}

/** Eight 16-bit groups, or undefined when the text is not an IPv6 address. */
export function parseIpv6(s: string): number[] | undefined {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(":")) return undefined;
  let text = s;
  // A trailing dotted quad (::ffff:192.0.2.1) becomes two groups.
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (v4) {
    const o = parseIpv4(v4[1] ?? "");
    if (!o) return undefined;
    const hi = (((o[0] ?? 0) << 8) | (o[1] ?? 0)).toString(16);
    const lo = (((o[2] ?? 0) << 8) | (o[3] ?? 0)).toString(16);
    text = `${text.slice(0, -(v4[1] ?? "").length)}${hi}:${lo}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const part = (h: string): string[] => (h === "" ? [] : h.split(":"));
  const head = part(halves[0] ?? "");
  const tail = halves.length === 2 ? part(halves[1] ?? "") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return undefined;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return undefined;
  return groups.map((g) => parseInt(g, 16));
}

/** The address as a 32- or 128-bit number, with its width; undefined when it is not an address. */
export function toBits(addr: string): { bits: bigint; width: 32 | 128 } | undefined {
  const v4 = parseIpv4(addr);
  if (v4) return { bits: v4.reduce((n, o) => (n << 8n) | BigInt(o), 0n), width: 32 };
  const v6 = parseIpv6(addr);
  if (v6) return { bits: v6.reduce((n, g) => (n << 16n) | BigInt(g), 0n), width: 128 };
  return undefined;
}

type Prefix = { bits: bigint; width: 32 | 128; len: number };

function prefix(cidr: string): Prefix {
  const [net = "", len = ""] = cidr.split("/");
  const b = toBits(net);
  if (!b) throw new Error(`bad prefix ${cidr}`);
  return { ...b, len: Number(len) };
}

function within(a: { bits: bigint; width: number }, p: Prefix): boolean {
  if (a.width !== p.width) return false;
  const shift = BigInt(p.width - p.len);
  return a.bits >> shift === p.bits >> shift;
}

// Addresses no other mail server can reach: every block whose “Globally Reachable” is False (or
// N/A) in the IANA special-purpose registries, read on 2026-11-18
// (https://www.iana.org/assignments/iana-ipv4-special-registry/ and
// .../iana-ipv6-special-registry/), plus multicast (224.0.0.0/4, ff00::/8), which is never a mail
// host. Documentation ranges are included: an MX that points at one was copied from an example and
// receives nothing. Marked pure, so a bundle that never calls isUnreachableAddress (one that only
// parses addresses) leaves both tables out instead of building them when it starts (esbuild “Pure”
// annotations, esbuild.github.io/api/#pure, read 2026-11-19).
const UNREACHABLE = /* @__PURE__ */ [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "::/128",
  "::1/128",
  "::ffff:0:0/96",
  "64:ff9b:1::/48",
  "100::/64",
  "100:0:0:1::/64",
  "2001::/23",
  "2001:db8::/32",
  "3fff::/20",
  "5f00::/16",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
].map(prefix);

// Blocks marked Globally Reachable: True inside an unreachable one above.
const REACHABLE_INSIDE = /* @__PURE__ */ [
  "192.0.0.9/32",
  "192.0.0.10/32",
  "2001:1::1/128",
  "2001:1::2/128",
  "2001:1::3/128",
  "2001:3::/32",
  "2001:4:112::/48",
  "2001:20::/28",
  "2001:30::/28",
].map(prefix);

/**
 * Whether no other mail server can reach the address: inside UNREACHABLE and not REACHABLE_INSIDE.
 */
export function isUnreachableAddress(addr: string): boolean {
  const a = toBits(addr);
  if (!a) return false;
  return UNREACHABLE.some((p) => within(a, p)) && !REACHABLE_INSIDE.some((p) => within(a, p));
}
