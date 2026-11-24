// One lookup as the checks see it, the same over DoH and over test fixtures. A SERVFAIL from
// every resolver is asked again with CD (checking disabled): an answer then means the domain's
// DNSSEC is broken, so validating receivers cannot see the record, but only when a resolver says
// the SERVFAIL was about DNSSEC (an Extended DNS Error, RFC 8914).
import type { FindingVars } from "../finding-vars.ts";
import type { NameExists } from "../types.ts";
import type { DnsRecord, DnsResult, QueryOptions, Resolver } from "./types.ts";
import { RCODE } from "./codec.ts";
import { canonicalName } from "./names.ts";
import { answerOf, describe, normalize, ttlOf } from "./compare.ts";

export type LookupStatus = "ok" | "nodata" | "nxdomain" | "failed" | "dnssec-broken";

/**
 * Why a lookup failed: no usable answer, two operators that answered differently, or one
 * operator alone in the whole time.
 */
type FailReason = "no-answer" | "disagree" | "unconfirmed";

export interface Lookup {
  name: string;
  type: string;
  status: LookupStatus;
  /** Records of the asked type; with dnssec-broken, what the CD answer shows as published. */
  records: DnsRecord[];
  /** Everything in the answer section, CNAME chain included. */
  answers: DnsRecord[];
  authority: DnsRecord[];
  result?: DnsResult;
  error?: unknown;
  /** With status "failed". */
  reason?: FailReason;
  /**
   * With reason "disagree": each operator's answer as a person reads it, "<operator>: <answer>".
   */
  first?: string;
  second?: string;
  /**
   * With reason "disagree": seconds until caches may agree, the longer TTL of the two (RFC 2308 §5
   * for empty answers).
   */
  waitSeconds?: number;
}

/**
 * RFC 8914 §4.2-§4.13: 1 Unsupported DNSKEY Algorithm, 2 Unsupported DS Digest Type, 5 DNSSEC
 * Indeterminate, 6 DNSSEC Bogus, 7 Signature Expired, 8 Signature Not Yet Valid, 9 DNSKEY Missing,
 * 10 RRSIGs Missing, 11 No Zone Key Bit Set, 12 NSEC Missing.
 */
const DNSSEC_EDE = new Set([1, 2, 5, 6, 7, 8, 9, 10, 11, 12]);

function saysDnssec(r: DnsResult): boolean {
  return (r.ede ?? []).some((code) => DNSSEC_EDE.has(code));
}

function classify(name: string, type: string, result: DnsResult): Lookup {
  const records = result.answers.filter((a) => a.type === type);
  const base = { name, type, records, answers: result.answers, authority: result.authority, result };
  if (result.rcode === RCODE.NOERROR) return { ...base, status: records.length > 0 ? "ok" : "nodata" };
  if (result.rcode === RCODE.NXDOMAIN) return { ...base, status: "nxdomain" };
  return { ...base, status: "failed" };
}

/** What a person reads about two operators that answered differently, and how long to wait. */
function disagreement(
  name: string,
  t: string,
  first: DnsResult,
  second: NonNullable<DnsResult["second"]>,
): Partial<Lookup> {
  const wait = [ttlOf(t, answerOf(first)), ttlOf(t, answerOf(second))].filter((n): n is number => n !== undefined);
  return {
    reason: "disagree",
    first: `${first.resolver ?? "resolver"}: ${describe(normalize(name, t, answerOf(first)))}`,
    second: `${second.resolver}: ${describe(normalize(name, t, answerOf(second)))}`,
    ...(wait.length > 0 ? { waitSeconds: Math.max(...wait) } : {}),
  };
}

export async function lookup(
  resolver: Resolver,
  name: string,
  type: string,
  signal?: AbortSignal,
  opts: AskOptions = {},
): Promise<Lookup> {
  const t = type.toUpperCase();
  const confirm = opts.confirm === true;
  const query: QueryOptions = { ...(signal ? { signal } : {}), ...(opts.dnssecOk ? { dnssecOk: true } : {}) };
  const empty = { name, type: t, records: [], answers: [], authority: [] };
  const failed = (extra: Partial<Lookup>): Lookup => ({ ...empty, status: "failed", reason: "no-answer", ...extra });
  let first: DnsResult;
  try {
    first = await resolver.query(name, t, confirm ? { ...query, confirm: true } : query);
  } catch (error) {
    return failed({ error });
  }
  // Neither answer of a disagreement counts: a majority would trust a stale cache after a change.
  if (first.confirm === "disagree" && first.second)
    return failed({ result: first, ...disagreement(name, t, first, first.second) });
  if (first.confirm === "unconfirmed") return failed({ result: first, reason: "unconfirmed" });
  if (first.rcode !== RCODE.SERVFAIL) return classify(name, t, first);
  // The CD retry goes to one operator: it only tells DNSSEC from other failures, and its answer
  // never decides the verdict on its own (dnssec-broken counts as no answer for the rules).
  let second: DnsResult;
  try {
    second = await resolver.query(name, t, { ...query, cd: true });
  } catch (error) {
    return failed({ result: first, error });
  }
  const c = classify(name, t, second);
  if (c.status === "failed") return { ...c, result: first, reason: "no-answer" };
  // Without a DNSSEC code the CD answer may only be a retry that worked (a lame or unreachable
  // authoritative server): nothing says validating receivers fail on it.
  if (!saysDnssec(first) && !saysDnssec(second)) return failed({ result: first });
  return { ...c, status: "dnssec-broken" };
}

/** The vars of a lookup-failed finding (finding-vars.ts, FindingVars). */
export function failedVars(l: Lookup): FindingVars {
  const vars: FindingVars = { reason: l.reason ?? "no-answer", name: l.name };
  if (l.first !== undefined) vars.first = l.first;
  if (l.second !== undefined) vars.second = l.second;
  if (l.waitSeconds !== undefined) vars.waitSeconds = l.waitSeconds;
  return vars;
}

/**
 * Whether a name exists, from one A query with DO: "nxdomain" on NXDOMAIN, "nxname" on NOERROR
 * with an NSEC at the name (or an NSEC3) whose type bit map holds NXNAME, the signal of Compact
 * Denial of Existence (RFC 9824 §2 and §6), which Cloudflare-signed zones send instead of
 * NXDOMAIN. Asked of two operators (it decides sp against np). A CNAME at the name means it
 * exists, wherever the chain ends (RFC 6604 §3). No `exists` when no answer tells (no resolver
 * answered, SERVFAIL, REFUSED, or a name DNS cannot carry), and then `failure`, the vars of its
 * lookup-failed finding (failedVars).
 */
export async function existence(ctx: Ctx, name: string): Promise<{ exists?: NameExists; failure?: FindingVars }> {
  let owner: string;
  let r: DnsResult;
  const opts: QueryOptions = { dnssecOk: true, confirm: true, ...(ctx.signal ? { signal: ctx.signal } : {}) };
  const none = (extra: Partial<Lookup> = {}) => ({
    failure: failedVars({ name, type: "A", status: "failed", records: [], answers: [], authority: [], ...extra }),
  });
  try {
    owner = canonicalName(name);
    r = await ctx.resolver.query(name, "A", opts);
  } catch {
    return none();
  }
  // Two operators that disagree, or one alone, decide nothing: sp against np stays open.
  if (r.confirm === "disagree" && r.second) return none(disagreement(name, "A", r, r.second));
  if (r.confirm === "disagree" || r.confirm === "unconfirmed") return none({ reason: r.confirm });
  if (r.answers.some((a) => a.name === owner)) return { exists: "yes" };
  if (r.rcode === RCODE.NXDOMAIN) return { exists: "nxdomain" };
  if (r.rcode !== RCODE.NOERROR) return none();
  return { exists: nxnameAt(r, owner) ? "nxname" : "yes" };
}

/**
 * NOERROR whose NSEC at the name (or an NSEC3) holds NXNAME: Compact Denial of Existence says the
 * name does not exist (RFC 9824 §2 and §3.1). Only an answer to a query with DO carries the NSEC.
 */
export function nxnameAt(r: Pick<DnsResult, "rcode" | "authority">, name: string): boolean {
  if (r.rcode !== RCODE.NOERROR) return false;
  const owner = canonicalName(name);
  return r.authority.some((a) => {
    // NSEC: next name, then the types; NSEC3: algorithm, flags, iterations, salt, next hash, types.
    const fields = String(a.data).split(" ");
    if (a.type === "NSEC" && a.name === owner) return fields.slice(1).includes("NXNAME");
    if (a.type === "NSEC3") return fields.slice(5).includes("NXNAME");
    return false;
  });
}

/**
 * The joined strings of each TXT record (RFC 7208 §3.3 and RFC 6376 §3.6.2.2 join without spaces).
 */
export function txt(l: Lookup): string[] {
  return l.records.map((r) => (Array.isArray(r.data) ? r.data.join("") : r.data));
}

/** What every check receives: the resolver and the check's signal. */
export interface Ctx {
  resolver: Resolver;
  signal?: AbortSignal;
}

/**
 * confirm: the query decides the verdict, so two operators must agree.
 * dnssecOk: the DO bit, to read AD and an NSEC with NXNAME (RFC 3225, RFC 9824 §5).
 */
export interface AskOptions {
  confirm?: boolean;
  dnssecOk?: boolean;
}

export function ask(ctx: Ctx, name: string, type: string, opts: AskOptions = {}): Promise<Lookup> {
  return lookup(ctx.resolver, name, type, ctx.signal, opts);
}
