// Generated case zones on example.com/.net/.org. Each answer is built as a binary DNS message
// and read back with the engine's codec, so the cases go through the same parser as real ones.
import { LookupError } from "../../src/dns/doh.ts";
import type { QueryOptions, Resolver } from "../../src/dns/types.ts";
import { buildMessage, type Rec, toResult } from "./dns.ts";

type Data = string | string[];

export interface Node {
  [type: string]: Data[] | boolean | number | undefined;
  /** SERVFAIL without CD; the records still come with CD (broken DNSSEC). */
  $servfail?: boolean;
  /**
   * Extended DNS Error on the SERVFAIL of $servfail and $dead: 9 “DNSKEY Missing” by default, a
   * DNSSEC code (RFC 8914 §4). false is a SERVFAIL without EDE, 22 one that is not about DNSSEC.
   */
  $ede?: number | false;
  /** SERVFAIL with and without CD. */
  $dead?: boolean;
  /** No resolver answers (network down for this name). */
  $unreachable?: boolean;
  /**
   * NXDOMAIN although names exist below: a server that denies an empty non-terminal, as unsigned
   * Route 53 zones do (RFC 8020 §5).
   */
  $nxdomain?: boolean;
}

export type Zone = Record<string, Node>;

/** The SOA of every case zone, also the one an empty answer's authority carries. */
export const SOA_RECORD = "ns1.example.net hostmaster.example.net 2026111801 7200 3600 1209600 300";

/** RFC 4592, simplified: the closest *.<ancestor> answers a name that does not exist. */
function wildcard(zone: Zone, name: string): Node | undefined {
  if (Object.keys(zone).some((k) => k.endsWith(`.${name}`))) return undefined;
  const labels = name.split(".");
  for (let i = 1; i < labels.length; i++) {
    const w = zone[`*.${labels.slice(i).join(".")}`];
    if (w) return w;
  }
  return undefined;
}

/** Apexes default to the registrable-looking last two labels of every name. */
function apexOf(zone: Zone, name: string): string {
  const labels = name.split(".");
  for (let i = 0; i < labels.length; i++) {
    const n = labels.slice(i).join(".");
    if (zone[n]?.SOA) return n;
  }
  return labels.slice(-2).join(".");
}

export interface ZoneOptions {
  /**
   * Compact Denial of Existence (RFC 9824), as Cloudflare signs: a name that does not exist
   * answers NOERROR with no records, and only a query with DO sees the NSEC with NXNAME.
   * "without-nxname": the NSEC of a name that does not exist lists only RRSIG and NSEC, the map
   * of an empty non-terminal, as signed Route 53 and Azure zones answer.
   */
  compactDenial?: boolean | "without-nxname";
  /**
   * The zone is signed and the resolver validates it: answers to a query with DO carry AD
   * (RFC 4035 §3.2.3; RFC 6840 §5.8 sets AD only when DO or AD was asked).
   */
  signed?: boolean;
}

/**
 * The wire answer a zone gives, as an authoritative server behind a resolver would; "unreachable"
 * for a name marked $unreachable. Also served over a fake DoH fetch (helpers/fetch.ts).
 */
export function zoneAnswer(
  zone: Zone,
  qname: string,
  qtype: string,
  opts: QueryOptions = {},
  zoneOptions: ZoneOptions = {},
): Uint8Array | "unreachable" {
  const z: Zone = Object.fromEntries(Object.entries(zone).map(([k, v]) => [k.toLowerCase(), v]));
  const name = qname.toLowerCase().replace(/\.$/, "");
  const type = qtype.toUpperCase();
  const node = z[name];
  if (node?.$unreachable) return "unreachable";
  if (node?.$dead || (node?.$servfail && !opts.cd)) {
    return buildMessage({ qname: name, qtype: type, rcode: 2, ede: node.$ede === false ? [] : [node.$ede ?? 9] });
  }
  const authority: Rec[] = [{ name: apexOf(z, name), type: "SOA", data: SOA_RECORD }];
  const answers: Rec[] = [];
  const ad = zoneOptions.signed === true && opts.dnssecOk === true;
  let current = name;
  for (let hops = 0; hops < 8; hops++) {
    const n = z[current] ?? wildcard(z, current);
    const own = n?.[type];
    if (Array.isArray(own)) {
      for (const d of own) answers.push({ name: current, type, data: d });
      return buildMessage({ qname: name, qtype: type, answers, ad });
    }
    const cname = n?.CNAME;
    if (type !== "CNAME" && Array.isArray(cname) && typeof cname[0] === "string") {
      answers.push({ name: current, type: "CNAME", data: cname[0] });
      current = cname[0].toLowerCase();
      continue;
    }
    // RFC 8020: a name with names below it exists even with no records of its own.
    const exists = !n?.$nxdomain && (n !== undefined || Object.keys(z).some((k) => k.endsWith(`.${current}`)));
    const soaAnswer = type === "SOA" && current === apexOf(z, current) && exists;
    if (soaAnswer) {
      answers.push({ name: current, type: "SOA", data: SOA_RECORD });
      return buildMessage({ qname: name, qtype: type, answers, ad });
    }
    if (zoneOptions.compactDenial && answers.length === 0) {
      // RFC 9824 §3.1 and §3.2: an NSEC at the name, NXNAME when it does not exist.
      const types = exists
        ? Object.keys(n ?? {}).filter((k) => !k.startsWith("$"))
        : zoneOptions.compactDenial === true
          ? ["NXNAME"]
          : [];
      if (opts.dnssecOk)
        authority.push({
          name: current,
          type: "NSEC",
          data: [`\\000.${current}`, ...types, "RRSIG", "NSEC"].join(" "),
        });
      return buildMessage({ qname: name, qtype: type, answers, authority, ad });
    }
    return buildMessage({ qname: name, qtype: type, rcode: exists ? 0 : 3, answers, authority, ad });
  }
  throw new Error(`CNAME loop at ${name}`);
}

export function zoneResolver(zone: Zone, zoneOptions: ZoneOptions = {}): Resolver & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    async query(qname: string, qtype: string, opts: QueryOptions = {}) {
      const name = qname.toLowerCase().replace(/\.$/, "");
      const type = qtype.toUpperCase();
      asked.push(`${name} ${type}${opts.cd ? " cd" : ""}${opts.dnssecOk ? " do" : ""}`);
      if (opts.signal?.aborted) throw new LookupError("aborted", "cancelled");
      const bytes = zoneAnswer(zone, name, type, opts, zoneOptions);
      if (bytes === "unreachable") throw new LookupError("unreachable", `no resolver answered ${name}`);
      return toResult(bytes);
    },
  };
}

/**
 * `inner`, but a query for a name `quiet` picks (trailing dot dropped, lower case) never answers
 * until its signal aborts, then fails as an aborted fetch does. Only a limit or an abort ends it.
 */
export function silentOn(inner: Resolver, quiet: (name: string) => boolean): Resolver {
  return {
    query: (name, type, opts) =>
      quiet(name.replace(/\.$/, "").toLowerCase())
        ? new Promise((_, reject) => {
            const abort = () => reject(new DOMException("aborted", "AbortError"));
            if (opts?.signal?.aborted) abort();
            else opts?.signal?.addEventListener("abort", abort, { once: true });
          })
        : inner.query(name, type, opts),
  };
}
