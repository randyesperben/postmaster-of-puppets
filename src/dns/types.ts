// The types of the engine's DNS layer: the DoH operators, a DNS record and a resolver's answer,
// and the Resolver interface a caller may put in place of the operators (LookupOptions.resolver).

/**
 * The public DNS-over-HTTPS operators the engine asks; `operators` (operators.ts) lists their
 * endpoints.
 */
export type ResolverId = "cloudflare" | "google" | "quad9" | "controld" | "dns4eu" | "cznic";

/**
 * A DNS record in presentation form (RFC 1035 §5.1): names in lower case (A-Z only, other octets
 * that need it as \DDD) and without the final dot, the type by its mnemonic ("TXT"), and a TXT
 * record's data as its character-strings, one character per octet.
 */
export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  data: string | string[];
}
/** A resolver's answer to one query. */
export interface DnsResult {
  /** The response code: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN (RFC 1035 §4.1.1). */
  rcode: number;
  /**
   * The AD bit: the resolver validated the answer with DNSSEC. With confirm "agreed", the AND of
   * both operators' bits.
   */
  ad: boolean;
  answers: DnsRecord[];
  authority: DnsRecord[];
  /** Extended DNS Error codes (RFC 8914). */
  ede?: number[];
  /** The DNS-over-HTTPS operator that answered; absent from a resolver of LookupOptions. */
  resolver?: ResolverId;
  /**
   * Only when the query asked to confirm: two operators gave the same answer, different ones, or
   * only one answered.
   */
  confirm?: "agreed" | "disagree" | "unconfirmed";
  /** With "disagree": the other operator's answer. */
  second?: { resolver: ResolverId; rcode: number; answers: DnsRecord[]; authority: DnsRecord[] };
}
/**
 * What a query may ask of a resolver: `cd` sets Checking Disabled, `dnssecOk` the DO bit
 * (RFC 3225), `confirm` asks two independent operators and compares their answers, and `signal`
 * ends the query. Resolver explains what the engine expects of each.
 */
export interface QueryOptions {
  /** Checking Disabled (RFC 4035 §3.2.2). */
  cd?: boolean;
  /** The DO bit (RFC 3225); a resolver that does not know it answers as without it. */
  dnssecOk?: boolean;
  /** Ask two operators and compare (DnsResult.confirm). */
  confirm?: boolean;
  /** Aborts the query: it must then reject. */
  signal?: AbortSignal;
}
/**
 * What the engine asks its DNS questions of. By default checkDomain asks public DNS-over-HTTPS
 * operators over `fetch`; LookupOptions.resolver puts another one in their place.
 *
 * `query` resolves to the answer, whatever its rcode, and rejects when no answer came, which the
 * check reports as a lookup without an answer. Names in the answer follow DnsRecord. The options:
 * `cd` sets Checking Disabled, which the engine asks after a SERVFAIL to tell broken DNSSEC from
 * other failures, and only an Extended DNS Error about DNSSEC (`ede`) makes it broken DNSSEC;
 * `dnssecOk` sets the DO bit (RFC 3225), which the denial of existence needs; `confirm` asks for
 * the answer of two independent operators, compared (DnsResult.confirm): a resolver that cannot
 * do it answers without `confirm` and the engine uses that answer as it is. The query must reject
 * once `signal` aborts: the time limit and LookupOptions.signal end a check through it.
 */
export interface Resolver {
  /** The answer to `name` and `type` (a mnemonic, "TXT"), as the interface says. */
  query(name: string, type: string, opts?: QueryOptions): Promise<DnsResult>;
}
