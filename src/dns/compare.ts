// Normalized form of an answer, for the cross-check of the queries that decide the verdict.
// Two operators agree when the class of their answer and the records that count are the same,
// without TTL or order, names in lower case and TXT strings joined.
//
// Addresses (A, AAAA) are compared by what the checks read from them, reachable or not
// (isUnreachableAddress), never one by one: large MX pools hand out a few addresses of many on
// each query (Microsoft 365, Google), so two operators rarely return the same set, while a
// resolver that sinks a name answers 0.0.0.0, which no mail server can reach. The two classes
// read "public" and "private" in vars.first and vars.second, the words a person knows.
import type { DnsRecord, DnsResult } from "./types.ts";
import { isUnreachableAddress } from "../ip.ts";
import { RCODE } from "./codec.ts";

type AnswerClass = "data" | "nodata" | "nxdomain";

export interface Normalized {
  class: AnswerClass;
  /** Sorted, deduplicated values of the records that count. */
  values: string[];
}

/** The answer as the cross-check reads it: what counts for the name and type that were asked. */
export interface Answer {
  rcode: number;
  answers: DnsRecord[];
  authority: DnsRecord[];
}

/** TXT records that count at a name: DMARC under _dmarc, SPF elsewhere, stray quotes and all. */
function counts(name: string, text: string): boolean {
  const dmarc = name.toLowerCase().startsWith("_dmarc.");
  return dmarc ? /^["'\s]*v\s*=\s*dmarc1/i.test(text) : /^["'\s]*v\s*=\s*spf1/i.test(text);
}

function value(name: string, type: string, r: DnsRecord): string | undefined {
  const data = Array.isArray(r.data) ? r.data.join("") : String(r.data);
  if (type === "TXT") return counts(name, data) ? data : undefined;
  if (type === "A" || type === "AAAA") return isUnreachableAddress(data) ? "private" : "public";
  return data.toLowerCase();
}

/**
 * NOERROR whose NSEC or NSEC3 holds NXNAME: Compact Denial of Existence, an NXDOMAIN (RFC 9824 §2).
 * Unlike nxnameAt (lookup.ts), which decides that a name does not exist, any owner counts here:
 * this only sorts two operators' answers to the same question into the same class.
 */
function nxname(a: Answer): boolean {
  return a.authority.some(
    (r) => (r.type === "NSEC" || r.type === "NSEC3") && String(r.data).split(" ").includes("NXNAME"),
  );
}

export function normalize(name: string, type: string, a: Answer): Normalized {
  const values = [
    ...new Set(
      a.answers
        .filter((r) => r.type === type)
        .map((r) => value(name, type, r))
        .filter((v): v is string => v !== undefined),
    ),
  ].sort();
  if (values.length > 0) return { class: "data", values };
  if (a.rcode === RCODE.NXDOMAIN || nxname(a)) return { class: "nxdomain", values };
  return { class: "nodata", values };
}

export function same(x: Normalized, y: Normalized): boolean {
  return x.class === y.class && x.values.length === y.values.length && x.values.every((v, i) => v === y.values[i]);
}

/** How the answer reads to a person: the records that count, or NODATA and NXDOMAIN. */
export function describe(n: Normalized): string {
  if (n.class === "nxdomain") return "NXDOMAIN";
  if (n.class === "nodata") return "NODATA";
  return n.values.join(" | ");
}

/**
 * Seconds until caches may hold the newer answer: the TTL of the records asked, or for an empty
 * answer the lesser of the SOA's TTL and its MINIMUM field (RFC 2308 §5). undefined when the
 * answer carries neither.
 */
export function ttlOf(type: string, a: Answer): number | undefined {
  const records = a.answers.filter((r) => r.type === type);
  if (records.length > 0) return Math.min(...records.map((r) => r.ttl));
  const soa = a.authority.find((r) => r.type === "SOA");
  if (!soa) return undefined;
  const minimum = Number(String(soa.data).split(" ")[6]);
  return Number.isFinite(minimum) ? Math.min(soa.ttl, minimum) : soa.ttl;
}

/** The answer of a DnsResult or of its second operator, in the form the comparison reads. */
export function answerOf(r: Pick<DnsResult, "rcode" | "answers"> & { authority?: DnsRecord[] }): Answer {
  return { rcode: r.rcode, answers: r.answers, authority: r.authority ?? [] };
}
